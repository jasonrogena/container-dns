use hickory_proto::rr::{LowerName, Record, RecordType};
use hickory_server::authority::{AuthorityObject, Catalog};
use ipnet::IpNet;
use opentelemetry::global;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    env::consts,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    rc::Rc,
    sync::Arc,
    time::{self, Duration},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::LocalSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{Level, debug, error, info, instrument, span, warn};

use crate::{
    containers::{Host, IpAddrType, linux::Linux},
    dns::{
        container::{
            authority::{self, Authority},
            load,
            record_handler::{
                self, ARecordHandler, RecordHandler, RecordHandlerLookupObject, SrvRecordHandler,
                ZoneRecordHandler,
            },
            store::{RecordHandlerLookupObjects, Store, StoreRequest, StoreUpdateRequest},
        },
        settings::{RecordTtls, Settings},
    },
    metrics::{self as metrics_mod, Metrics},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The Operating System {0} is currently not supported")]
    UnsupportedOs(String),
    #[error("A Hickory protocol error was thrown: {0}")]
    HickoryProto(#[from] hickory_proto::ProtoError),
    #[error("An IO error was thrown")]
    Io(#[from] std::io::Error),
    #[error("An error thrown by the container authority: {0}")]
    Authority(#[from] authority::Error),
    #[error("An error thrown by a record handler: {0}")]
    RecordHandler(#[from] record_handler::Error),
    #[error("An error occurred while setting up metrics: {0}")]
    Metrics(#[from] metrics_mod::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_ip_addr: IpAddr,
    pub listen_port: u16,
    pub refresh_interval: Duration,
    pub allowed_record_networks: Vec<IpNet>,
    pub allowed_query_networks: Vec<IpNet>,
    pub record_ttls: RecordTtls,
    pub tcp_timeout: Duration,
    pub max_ongoing_requests: usize,
    /// OTLP gRPC endpoint for exporting metrics (e.g. "http://localhost:4317").
    /// If not set, metrics are not exported.
    pub otlp_endpoint: Option<String>,
    /// DNS domain appended to this host's hostname to form its FQDN and the zone
    /// this server is authoritative for (e.g. "cybertron.lan" yields the host FQDN
    /// "<hostname>.cybertron.lan"). No trailing dot needed. Defaults to "local".
    #[serde(default = "default_domain")]
    pub domain: String,
}

fn default_domain() -> String {
    "local".to_string()
}

pub struct Server {
    shutdown_token: CancellationToken,
    store_request_tx: mpsc::Sender<StoreRequest>,
    settings: Settings,
    domain: String,
    metrics: Arc<Metrics>,
    // Held to keep the meter provider (and its export loop) alive for the
    // lifetime of the server.
    _meter_provider: Option<SdkMeterProvider>,
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, Error> {
        info!("Initializing the DNS server");

        let (store_request_tx, store_request_rx) =
            mpsc::channel::<StoreRequest>(config.max_ongoing_requests);
        let domain = config.domain.clone();
        let host = Self::get_host(&domain)?;
        let zone_name = Self::get_zone_name(host.clone())?;
        let shutdown_token = CancellationToken::new();
        let config_clone = config.clone();
        let settings = Settings {
            record_ttls: config.record_ttls,
            allowed_record_networks: config.allowed_record_networks.clone().into_iter().collect(),
            refresh_interval: config.refresh_interval,
        };

        let meter_provider = match &config.otlp_endpoint {
            Some(endpoint) => {
                let provider = metrics_mod::init_otlp(endpoint)?;
                global::set_meter_provider(provider.clone());
                Some(provider)
            }
            None => None,
        };
        let meter = global::meter("container-dns");
        let metrics = Arc::new(Metrics::new(&meter));

        let mut catalog = Catalog::new();
        let container_authority =
            Authority::new(zone_name.clone(), store_request_tx.clone(), metrics.clone());
        catalog.upsert(
            container_authority.origin().clone(),
            vec![Arc::new(container_authority)],
        );

        tokio::spawn(async move {
            let mut hickory_server = hickory_server::server::ServerFuture::with_access(
                catalog,
                &[],
                &config_clone.allowed_query_networks,
            );

            let socket_addr = match config.bind_ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    SocketAddr::V4(SocketAddrV4::new(ipv4_addr, config.listen_port))
                }
                IpAddr::V6(ipv6_addr) => {
                    SocketAddr::V6(SocketAddrV6::new(ipv6_addr, config.listen_port, 0, 0))
                }
            };

            match UdpSocket::bind(socket_addr).await {
                Ok(udp_socket) => hickory_server.register_socket(udp_socket),
                Err(e) => error!(
                    "An error was raised while trying to bind a UDP socket: {:?}",
                    e
                ),
            }

            match TcpListener::bind(socket_addr).await {
                Ok(tcp_listener) => {
                    hickory_server.register_listener(tcp_listener, config.tcp_timeout)
                }
                Err(e) => error!(
                    "An error was raised while trying to bind to a TCP port: {:?}",
                    e
                ),
            }

            info!(
                bind_address = config.bind_ip_addr.to_string(),
                port = config.listen_port,
                "Server started"
            );

            if let Err(e) = hickory_server.block_until_done().await {
                error!(
                    "An error was thrown while attempting to wait for DNS server: {:?}",
                    e
                );
            }
        });

        let mut store = Store::new(shutdown_token.clone(), store_request_rx);
        tokio::spawn(async move { store.start().await });

        Ok(Self {
            shutdown_token,
            store_request_tx,
            settings,
            domain,
            metrics,
            _meter_provider: meter_provider,
        })
    }

    pub async fn start(&self, local_set: LocalSet) {
        let mut refresh_interval = tokio::time::interval(self.settings.refresh_interval);
        let settings = self.settings.clone();
        let metrics = self.metrics.clone();
        let domain = self.domain.clone();
        local_set
            .run_until(async move {
                if let Ok(host) = Self::get_host(&domain) {
                    loop {
                        if let Some(lookup_objects) = Self::get_updated_lookup_objects(
                            host.clone(),
                            settings.clone(),
                            &metrics,
                        ) {
                            let req = StoreRequest::UPDATE(StoreUpdateRequest { lookup_objects });
                            if let Err(e) = self.store_request_tx.send(req).await {
                                error!(
                                    "An error occurred sending an update message to the store: {:?}",
                                    e
                                );
                            }
                        }
                        refresh_interval.tick().await;
                    }
                }
            })
            .await;
    }

    fn get_host(domain: &str) -> Result<Rc<dyn Host>, Error> {
        let host: Rc<dyn Host> = match consts::OS {
            "linux" => Rc::new(Linux::new(domain.to_string())),
            unsupported_os => return Err(Error::UnsupportedOs(unsupported_os.to_string())),
        };

        Ok(host)
    }

    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_token.cancel();

        Ok(())
    }

    fn get_zone_name(host: Rc<dyn Host>) -> Result<LowerName, Error> {
        Ok(ZoneRecordHandler::get_zone_name(host.clone())?)
    }

    #[instrument(skip(metrics))]
    fn get_updated_lookup_objects(
        host: Rc<dyn Host>,
        settings: Settings,
        metrics: &Metrics,
    ) -> Option<RecordHandlerLookupObjects> {
        info!("Started container discovery");
        let zone_name = match Self::get_zone_name(host.clone()) {
            Ok(z) => z,
            Err(e) => {
                error!("Couldn't determine the zone name: {:?}", e);
                return None;
            }
        };

        let timing = time::Instant::now();
        let mut record_handlers: HashMap<(RecordType, LowerName), Box<dyn RecordHandler>> =
            HashMap::new();

        let mut zone_record_handler =
            ZoneRecordHandler::new(zone_name.clone(), host.clone(), false, settings.clone());
        if let Err(e) = zone_record_handler.update_records() {
            warn!(
                "An error was thrown while trying to get NS names for container. Defaulting to an empty list of names: {:?}",
                e
            );
        }
        record_handlers.insert(
            (RecordType::NS, zone_name.clone()),
            Box::new(zone_record_handler),
        );

        let containers = match host.containers() {
            Ok(ok) => ok,
            Err(e) => {
                warn!(
                    "Could not get the host's containers due to an error: {:?}",
                    e
                );
                vec![]
            }
        };
        info!("Discovered {} containers", containers.len());

        let host_fqdn_hostname = match host.fqdn_hostname() {
            Ok(name) => name,
            Err(e) => {
                warn!("An error was thrown trying to get the hostname: {:?}", e);
                return None;
            }
        };
        let load_map = load::priorities_and_weights(&containers);

        // DNS-SD browse state, accumulated across all containers and materialised
        // into PTR/TXT records after the container loop.
        //   ptr_targets:   service-type (browse) name -> set of instance names
        //   service_types: every service-type name, for the _services._dns-sd._udp meta PTR
        //   txt_data:      instance name -> per-replica (pid, TXT values) for reconciliation
        let mut ptr_targets: HashMap<LowerName, HashSet<LowerName>> = HashMap::new();
        let mut service_types: HashSet<LowerName> = HashSet::new();
        let mut txt_data: HashMap<LowerName, Vec<(u32, Vec<String>)>> = HashMap::new();

        for (container_index, cur_proc) in containers.iter().enumerate() {
            let span = span!(
                Level::INFO,
                "get_container_records",
                index = format!("{}/{}", container_index + 1, containers.len())
            );
            let _enter = span.enter();
            let listening_services = match SrvRecordHandler::get_listening_services(
                cur_proc.clone(),
            ) {
                Ok(ok) => ok,
                Err(e) => {
                    warn!(
                        "An error was thrown while trying to get listening services for a container: {:?}",
                        e
                    );
                    HashSet::new()
                }
            };
            debug!(
                "Current process has {} listening services",
                listening_services.len()
            );

            // Read the container's DNS-SD TXT metadata once (mount-namespace file
            // read), then match it to each service by (protocol, port) endpoint.
            let container_metadata = match cur_proc.metadata() {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "An error was thrown while trying to read container metadata. Defaulting to none: {:?}",
                        e
                    );
                    vec![]
                }
            };

            for cur_service in listening_services {
                let srv_and_type_names = match SrvRecordHandler::get_service_and_type_names(
                    &cur_service,
                    cur_proc.clone(),
                    &host_fqdn_hostname,
                ) {
                    Ok(ok) => ok,
                    Err(e) => {
                        warn!(
                            service = cur_service.to_string(),
                            "An error was thrown while trying to get SVC names for container. Defaulting to an empty list of names: {:?}",
                            e
                        );
                        HashSet::new()
                    }
                };

                // TXT values for this endpoint, if the container declared any.
                let service_metadata = container_metadata
                    .iter()
                    .find(|m| m.protocol == cur_service.protocol && m.port == cur_service.port)
                    .map(|m| m.values.clone());

                for (instance_name, service_type_name) in srv_and_type_names {
                    match record_handlers.entry((RecordType::SRV, instance_name.clone())) {
                        Entry::Occupied(mut occupied_entry) => {
                            let (priority, weight) =
                                load_map.get(&cur_proc.pid()).copied().unwrap_or((0, 100));
                            if let Err(e) = occupied_entry.get_mut().add_container(
                                cur_proc.clone(),
                                priority,
                                weight,
                            ) {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = instance_name.to_string(),
                                    "An error was thrown while attempting to append SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                        }
                        Entry::Vacant(vacant_entry) => {
                            let mut handler = SrvRecordHandler::new(
                                HashSet::from([instance_name.clone()]),
                                cur_service.clone(),
                                settings.clone(),
                                vec![cur_proc.clone()],
                                containers.clone(),
                                host_fqdn_hostname.clone(),
                                load_map.clone(),
                            );
                            if let Err(e) = handler.update_records() {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = instance_name.to_string(),
                                    "An error was thrown while attempting to create SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                            vacant_entry.insert(Box::new(handler));
                        }
                    }

                    // DNS-SD browse: the service type points to this instance, and
                    // the instance's TXT collects each replica's declared values.
                    ptr_targets
                        .entry(service_type_name.clone())
                        .or_default()
                        .insert(instance_name.clone());
                    service_types.insert(service_type_name);
                    if let Some(values) = &service_metadata {
                        txt_data
                            .entry(instance_name)
                            .or_default()
                            .push((cur_proc.pid(), values.clone()));
                    }
                }
            }

            let a_names = match ARecordHandler::get_names(
                cur_proc.clone(),
                &containers,
                &host_fqdn_hostname,
            ) {
                Ok(ok) => ok,
                Err(e) => {
                    warn!(
                        "An error was thrown while trying to get A names for container. Defaulting to an empty list of names: {:?}",
                        e
                    );
                    HashSet::new()
                }
            };

            for cur_name in a_names {
                match record_handlers.entry((RecordType::A, cur_name.clone())) {
                    Entry::Occupied(mut occupied_entry) => {
                        if let Err(e) =
                            occupied_entry
                                .get_mut()
                                .add_container(cur_proc.clone(), 0, 100)
                        {
                            warn!(
                                a_name = cur_name.to_string(),
                                "An error was thrown while attempting to add A DNS names for container: {:?}",
                                e
                            );
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        let mut handler = ARecordHandler::new(
                            HashSet::from([cur_name.clone()]),
                            settings.clone(),
                            Some(IpAddrType::V4),
                            vec![cur_proc.clone()],
                        );
                        if let Err(e) = handler.update_records() {
                            warn!(
                                a_name = cur_name.to_string(),
                                "An error was thrown while attempting to add A DNS names for container: {:?}",
                                e
                            );
                        }
                        vacant_entry.insert(Box::new(handler));
                    }
                }
                match record_handlers.entry((RecordType::AAAA, cur_name.clone())) {
                    Entry::Occupied(mut occupied_entry) => {
                        if let Err(e) =
                            occupied_entry
                                .get_mut()
                                .add_container(cur_proc.clone(), 0, 100)
                        {
                            warn!(
                                aaaa_name = cur_name.to_string(),
                                "An error was thrown while attempting to add AAAA DNS names for container: {:?}",
                                e
                            );
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        let mut handler = ARecordHandler::new(
                            HashSet::from([cur_name.clone()]),
                            settings.clone(),
                            Some(IpAddrType::V6),
                            vec![cur_proc.clone()],
                        );
                        if let Err(e) = handler.update_records() {
                            warn!(
                                aaaa_name = cur_name.to_string(),
                                "An error was thrown while attempting to add AAAA DNS names for container: {:?}",
                                e
                            );
                        }
                        vacant_entry.insert(Box::new(handler));
                    }
                }
            }
        }

        let mut lookup_objects: RecordHandlerLookupObjects = record_handlers
            .into_iter()
            .map(|(k, v)| (k, v.lookup_object()))
            .collect();

        // DNS-SD browse PTR records: one RRset per service type, pointing at each
        // instance (replicas already collapsed into a single instance name).
        let ptr_ttl = settings.record_ttls.ptr.as_secs() as u32;
        for (service_type_name, instances) in ptr_targets {
            let records: Vec<Record> = instances
                .iter()
                .map(|instance| record_handler::ptr_record(&service_type_name, instance, ptr_ttl))
                .collect();
            lookup_objects.insert(
                (RecordType::PTR, service_type_name),
                RecordHandlerLookupObject::new(records, None),
            );
        }

        // DNS-SD service-type enumeration: _services._dns-sd._udp.<fqdn> -> every type.
        if !service_types.is_empty() {
            match record_handler::dns_sd_services_name(&host_fqdn_hostname) {
                Ok(meta_name) => {
                    let records: Vec<Record> = service_types
                        .iter()
                        .map(|service_type| {
                            record_handler::ptr_record(&meta_name, service_type, ptr_ttl)
                        })
                        .collect();
                    lookup_objects.insert(
                        (RecordType::PTR, meta_name),
                        RecordHandlerLookupObject::new(records, None),
                    );
                }
                Err(e) => warn!(
                    "Could not build the DNS-SD service enumeration name; skipping the meta PTR: {:?}",
                    e
                ),
            }
        }

        // TXT records: one RRset per instance. When replicas disagree, the lowest
        // PID (stable, unlike load-derived SRV priority) wins and we warn.
        let txt_ttl = settings.record_ttls.txt.as_secs() as u32;
        for (instance_name, mut entries) in txt_data {
            entries.sort_by_key(|(pid, _)| *pid);
            let Some((_, winner)) = entries.first().cloned() else {
                continue;
            };
            if entries.iter().any(|(_, values)| *values != winner) {
                warn!(
                    instance = instance_name.to_string(),
                    "container-dns TXT metadata diverges across replicas; using the lowest-PID container's values"
                );
            }
            let record = record_handler::txt_record(&instance_name, winner, txt_ttl);
            lookup_objects.insert(
                (RecordType::TXT, instance_name),
                RecordHandlerLookupObject::new(vec![record], None),
            );
        }

        let elapsed = timing.elapsed();
        info!("Finished in {:?}", elapsed);
        metrics
            .zone_refresh_duration
            .record(elapsed.as_secs_f64(), &[]);
        metrics.zone_size.record(lookup_objects.len() as u64, &[]);

        Some(lookup_objects)
    }
}
