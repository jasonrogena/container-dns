use hickory_proto::rr::{LowerName, RecordType};
use hickory_server::authority::{AuthorityObject, Catalog};
use ipnet::IpNet;
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
use tracing::{Level, debug, error, info, span, warn};

use crate::{
    containers::{Host, IpAddrType, linux::Linux},
    dns::{
        container::{
            authority::{self, Authority},
            record_handler::{
                self, ARecordHandler, RecordHandler, SrvRecordHandler, ZoneRecordHandler,
            },
            store::{RecordHandlerLookupObjects, Store, StoreRequest, StoreUpdateRequest},
        },
        settings::{RecordTtls, Settings},
    },
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
}

#[derive(Clone)]
pub struct ServerConfig {
    pub bind_ip_addr: IpAddr,
    pub listen_port: u16,
    pub refresh_interval: Duration,
    pub allowed_networks: Vec<IpNet>,
    pub record_ttls: RecordTtls,
    pub tcp_timeout: Duration,
    pub max_ongoing_requests: usize,
}

pub struct Server {
    shutdown_token: CancellationToken,
    store_request_tx: mpsc::Sender<StoreRequest>,
    settings: Settings,
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, Error> {
        info!("Initializing the DNS server");

        let (store_request_tx, store_request_rx) =
            mpsc::channel::<StoreRequest>(config.max_ongoing_requests);
        let host = Self::get_host()?;
        let zone_name = Self::get_zone_name(host.clone())?;
        let shutdown_token = CancellationToken::new();
        let config_clone = config.clone();
        let settings = Settings {
            record_ttls: config.record_ttls,
            allowed_networks: config.allowed_networks.clone().into_iter().collect(),
            refresh_interval: config.refresh_interval,
        };

        let mut catalog = Catalog::new();
        let container_authority = Authority::new(zone_name.clone(), store_request_tx.clone());
        catalog.upsert(
            container_authority.origin().clone(),
            vec![Arc::new(container_authority)],
        );

        tokio::spawn(async move {
            let mut hickory_server = hickory_server::server::ServerFuture::with_access(
                catalog,
                &[],
                &config_clone.allowed_networks,
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
        })
    }

    pub async fn start(&self, local_set: LocalSet) {
        let mut refresh_interval = tokio::time::interval(self.settings.refresh_interval);
        let settings = self.settings.clone();
        local_set.run_until(async move {
            if let Ok(host) = Self::get_host() {
                loop {
                    if let Some(lookup_objects) = Self::get_updated_lookup_objects(host.clone(), settings.clone()) {
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
        }).await;
    }

    fn get_host() -> Result<Rc<dyn Host>, Error> {
        let host: Rc<dyn Host> = match consts::OS {
            "linux" => Rc::new(Linux::new()),
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

    fn get_updated_lookup_objects(
        host: Rc<dyn Host>,
        settings: Settings,
    ) -> Option<RecordHandlerLookupObjects> {
        info!("update_container_records() started");
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
        info!("update_containers() gotten {} containers", containers.len());

        let host_fqdn_hostname = match host.fqdn_hostname() {
            Ok(name) => name,
            Err(e) => {
                warn!("An error was thrown trying to get the hostname: {:?}", e);
                return None;
            }
        };
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
            for cur_service in listening_services {
                let srv_names = match SrvRecordHandler::get_service_names(
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
                for cur_name in srv_names {
                    match record_handlers.entry((RecordType::SRV, cur_name.clone())) {
                        Entry::Occupied(mut occupied_entry) => {
                            if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone())
                            {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = cur_name.to_string(),
                                    "An error was thrown while attempting to append SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                        }
                        Entry::Vacant(vacant_entry) => {
                            let mut handler = SrvRecordHandler::new(
                                HashSet::from([cur_name.clone()]),
                                cur_service.clone(),
                                settings.clone(),
                                vec![cur_proc.clone()],
                                containers.clone(),
                                host_fqdn_hostname.clone(),
                            );
                            if let Err(e) = handler.update_records() {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = cur_name.to_string(),
                                    "An error was thrown while attempting to create SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                            vacant_entry.insert(Box::new(handler));
                        }
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
                        if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone()) {
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
                        if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone()) {
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

        let lookup_objects = record_handlers
            .into_iter()
            .map(|(k, v)| (k, v.lookup_object()))
            .collect();

        info!("update_container_records() done in {:?}", timing.elapsed());

        Some(lookup_objects)
    }
}
