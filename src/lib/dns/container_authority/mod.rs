use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    env::consts,
    ffi::OsString,
    net::IpAddr,
    rc::Rc,
    time::{self, Duration},
};

use hickory_proto::{
    op::ResponseCode,
    rr::{
        LowerName, Record, RecordData, RecordType,
        rdata::{A, AAAA, NS, SRV},
    },
};
use hickory_resolver::Name;
use hickory_server::{
    authority::{
        AuthorityObject, LookupControlFlow, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
};
use ipnet::IpNet;
use rand::rng;
use rand::seq::SliceRandom;
use tokio::{
    sync::{mpsc, oneshot},
    task::LocalSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{Level, debug, error, info, span, warn};

use crate::containers::{
    Container, Host, IpAddrType, NetworkService, TransportProtocol, linux::Linux,
};

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The Operating System {0} is currently not supported")]
    UnsupportedOs(String),
    #[error(
        "An error occurred while working with the system for identifying isoated processes: {0}"
    )]
    Containers(#[from] crate::containers::Error),
    #[error("Could not determine the hostname")]
    Hostname(),
    #[error("A Hickory protocol error was thrown: {0}")]
    HickoryProto(#[from] hickory_proto::ProtoError),
    #[error("Could not find process with PID {0}")]
    ProcessNotFound(u32),
    #[error("Could not send a request to the authority store: {0}")]
    RequestSendError(#[from] mpsc::error::SendError<ContainerAuthorityRequest>),
    #[error("Could not receive a message expected from a different thread: {0}")]
    OneshotRecvError(#[from] oneshot::error::RecvError),
}

#[derive(Clone)]
pub struct RecordTtls {
    srv: Duration,
    a: Duration,
    ns: Duration,
}

impl Default for RecordTtls {
    fn default() -> Self {
        Self {
            srv: Duration::from_secs(60),
            a: Duration::from_secs(60),
            ns: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone)]
pub struct ContainerAuthorityConfig {
    pub(crate) record_ttls: RecordTtls,
    pub(crate) allowed_networks: HashSet<IpNet>,
    pub(crate) refresh_interval: Duration,
}

fn get_lower_hostname(hostname: OsString) -> Result<LowerName, Error> {
    let hostname = Name::from_ascii(hostname.into_string().map_err(|_e| Error::Hostname())?)?;

    Ok(hostname.into())
}

fn container_fqdn_hostname(
    container: Rc<dyn Container>,
    host_fqdn_hostname: &OsString,
) -> Result<OsString, Error> {
    let mut hostname = container.hostname()?;
    hostname.push(".");
    hostname.push(host_fqdn_hostname);

    Ok(hostname)
}

fn get_container_indexed_name(
    container: Rc<dyn Container>,
    all_containers: &Vec<Rc<dyn Container>>,
    host_fqdn_hostname: &OsString,
) -> Result<LowerName, Error> {
    let container_fqdn = container_fqdn_hostname(container.clone(), host_fqdn_hostname)?;
    let mut same_hostname_containers: Vec<Rc<dyn Container>> = vec![];
    for cur_container in all_containers.iter() {
        if container_fqdn_hostname(cur_container.clone(), host_fqdn_hostname)? == container_fqdn {
            same_hostname_containers.push(cur_container.clone());
        }
    }
    same_hostname_containers.sort_by_key(|a| a.pid());

    let mut index: i32 = -1;
    for (i, cur_container) in same_hostname_containers.iter().enumerate() {
        if cur_container.pid() == container.pid() {
            index = i as i32;
            break;
        }
    }

    if index == -1 {
        return Err(Error::ProcessNotFound(container.pid()));
    }

    let fqdn_lower_name = get_lower_hostname(container_fqdn)?;

    Ok(fqdn_lower_name.prepend_label(format!("{}", index))?.into())
}

fn address_in_allowed_networks(config: &ContainerAuthorityConfig, ip_addr: &IpAddr) -> bool {
    for cur_network in &config.allowed_networks {
        if cur_network.contains(ip_addr) {
            return true;
        }
    }

    false
}

pub struct ContainerAuthorityRequest {
    pub name: LowerName,
    pub rtype: RecordType,
    pub response_sender: oneshot::Sender<ContainerAuthorityResponse>,
}

pub struct ContainerAuthorityResponse {
    pub lookup_object: Box<dyn LookupObject>,
}

pub struct ContainerAuthority {
    zone_name: LowerName,
    request_tx: mpsc::Sender<ContainerAuthorityRequest>,
}

impl ContainerAuthority {
    pub fn new() -> Result<(Self, mpsc::Receiver<ContainerAuthorityRequest>), Error> {
        let zone_name = ZoneRecordHandler::get_zone_name(ContainerAuthorityStore::host()?)?;

        let (tx, rx) = mpsc::channel::<ContainerAuthorityRequest>(10);

        Ok((
            Self {
                zone_name,
                request_tx: tx,
            },
            rx,
        ))
    }

    pub async fn start_store(
        local_set: LocalSet,
        config: ContainerAuthorityConfig,
        shutdown_token: CancellationToken,
        rx: mpsc::Receiver<ContainerAuthorityRequest>,
    ) {
        let mut refresh_interval = tokio::time::interval(config.refresh_interval);
        local_set.run_until(async move {
            let mut store = match ContainerAuthorityStore::new(config, rx) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "An error was thrown while initializing the zone store: {:?}",
                        e
                    );
                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = refresh_interval.tick() => {
                        store.update_containers();
                    },
                    res = store.handle_next_request() => {
                        if let Err(e) = res {
                            error!("An error was thrown as the store attempted to handle a request: {:?}", e);
                        }
                    },
                };
                if shutdown_token.is_cancelled() {
                    info!("Thread updating container authority terminated");
                    return;
                }
            }
        }).await;
    }

    async fn send_request(
        &self,
        name: LowerName,
        rtype: RecordType,
    ) -> Result<Box<dyn LookupObject>, Error> {
        let (tx, rx) = oneshot::channel();
        let request = ContainerAuthorityRequest {
            name,
            rtype,
            response_sender: tx,
        };
        self.request_tx.send(request).await?;

        Ok(rx.await?.lookup_object)
    }
}

#[async_trait::async_trait]
impl AuthorityObject for ContainerAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn can_validate_dnssec(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::Refused)
    }

    fn origin(&self) -> &LowerName {
        &self.zone_name
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        match rtype {
            RecordType::A | RecordType::AAAA | RecordType::SRV | RecordType::NS => {
                match self.send_request(name.clone(), rtype).await {
                    Ok(ok) => LookupControlFlow::Break(Ok(ok)),
                    Err(e) => {
                        error!(
                            "An error was thrown while trying to query a DNS record. Sending back an empty response to the resolver: {:?}",
                            e
                        );
                        LookupControlFlow::Skip
                    }
                }
            }
            _ => LookupControlFlow::Skip,
        }
    }

    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        _last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
            .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        LookupControlFlow::Skip
    }
}

type RecordHandlers = HashMap<(RecordType, LowerName), Rc<dyn ContainerRecordHandler>>;

pub struct ContainerAuthorityStore {
    host: Rc<dyn Host>,
    record_handlers: RecordHandlers,
    config: ContainerAuthorityConfig,
    request_rx: mpsc::Receiver<ContainerAuthorityRequest>,
    zone_name: LowerName,
}

impl ContainerAuthorityStore {
    fn new(
        config: ContainerAuthorityConfig,
        request_rx: mpsc::Receiver<ContainerAuthorityRequest>,
    ) -> Result<Self, Error> {
        let host: Rc<dyn Host> = Self::host()?;
        let zone_name = ZoneRecordHandler::get_zone_name(host.clone())?;
        Ok(Self {
            host,
            record_handlers: HashMap::new(),
            config,
            request_rx,
            zone_name,
        })
    }

    fn host() -> Result<Rc<dyn Host>, Error> {
        let host: Rc<dyn Host> = match consts::OS {
            "linux" => Rc::new(Linux::new()),
            unsupported_os => return Err(Error::UnsupportedOs(unsupported_os.to_string())),
        };

        Ok(host)
    }

    async fn handle_next_request(&mut self) -> Result<(), Error> {
        if let Some(request) = self.request_rx.recv().await {
            let pair = (request.rtype, request.name);
            let lookup_object = match self.record_handlers.get(&pair) {
                Some(handler) => handler.lookup_object(),
                None => Box::new(ContainerAuthorityLookupObject::default()),
            };

            if request
                .response_sender
                .send(ContainerAuthorityResponse { lookup_object })
                .is_err()
            {
                error!(
                    rtype = pair.0.to_string(),
                    name = pair.1.to_string(),
                    "Could not send back a response for request"
                );
            }
        }

        Ok(())
    }

    fn update_containers(&mut self) {
        info!("update_containers() started");
        let timing = time::Instant::now();
        let mut record_handlers: HashMap<(RecordType, LowerName), Box<dyn ContainerRecordHandler>> =
            HashMap::new();

        let mut zone_record_handler = ZoneRecordHandler::new(
            self.zone_name.clone(),
            self.host.clone(),
            false,
            self.config.clone(),
        );
        if let Err(e) = zone_record_handler.update_records() {
            warn!(
                "An error was thrown while trying to get NS names for container. Defaulting to an empty list of names: {:?}",
                e
            );
        }
        record_handlers.insert(
            (RecordType::NS, self.zone_name.clone()),
            Box::new(zone_record_handler),
        );

        let containers = match self.host.containers() {
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

        let host_fqdn_hostname = match self.host.fqdn_hostname() {
            Ok(name) => name,
            Err(e) => {
                warn!("An error was thrown trying to get the hostname: {:?}", e);
                return;
            }
        };
        for (container_index, cur_proc) in containers.iter().enumerate() {
            let span = span!(
                Level::INFO,
                "get_container_records",
                index = format!("{}/{}", container_index + 1, containers.len())
            );
            let _enter = span.enter();
            let listening_services = match ContainerSrvRecordHandler::get_listening_services(
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
                let srv_names = match ContainerSrvRecordHandler::get_service_names(
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
                            let mut handler = ContainerSrvRecordHandler::new(
                                cur_service.clone(),
                                self.config.clone(),
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

            let a_names = match ContainerARecordHandler::get_names(
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
                        let mut handler = ContainerARecordHandler::new(
                            self.config.clone(),
                            Some(IpAddrType::V4),
                            vec![cur_proc.clone()],
                            containers.clone(),
                            host_fqdn_hostname.clone(),
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
                        let mut handler = ContainerARecordHandler::new(
                            self.config.clone(),
                            Some(IpAddrType::V6),
                            vec![cur_proc.clone()],
                            containers.clone(),
                            host_fqdn_hostname.clone(),
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

        self.record_handlers
            .retain(|k, _| record_handlers.contains_key(k));
        for (k, v) in record_handlers.drain() {
            info!(
                record_type = k.0.to_string(),
                name = k.1.to_string(),
                "Updating DNS record"
            );
            match self.record_handlers.entry(k) {
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.insert(v.into());
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(v.into());
                }
            }
        }

        info!(
            "Done updating DNS records in authority in {:?}",
            timing.elapsed()
        );
    }
}

trait ContainerRecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error>;
    fn lookup_object(&self) -> Box<dyn LookupObject>;
}

struct ContainerSrvRecordHandler {
    service: NetworkService,
    containers: Vec<Rc<dyn Container>>,
    all_containers: Vec<Rc<dyn Container>>,
    host_fqdn_hostname: OsString,
    config: ContainerAuthorityConfig,
    lookup_object: ContainerAuthorityLookupObject,
}

impl ContainerSrvRecordHandler {
    pub(crate) fn new(
        service: NetworkService,
        config: ContainerAuthorityConfig,
        containers: Vec<Rc<dyn Container>>,
        all_containers: Vec<Rc<dyn Container>>,
        host_fqdn_hostname: OsString,
    ) -> Self {
        Self {
            service,
            containers,
            all_containers,
            config,
            host_fqdn_hostname,
            lookup_object: ContainerAuthorityLookupObject::default(),
        }
    }

    fn sort_containers(&mut self) {
        self.containers.sort_by_key(|a| a.pid());
    }

    fn update_records(&mut self) -> Result<(), Error> {
        self.sort_containers();
        let mut containers = self.containers.clone();
        containers.shuffle(&mut rng());
        let mut records: Vec<Record> = vec![];

        for (priority, cur_proc) in (0_u16..).zip(self.containers.iter()) {
            let indexed_name = get_container_indexed_name(
                cur_proc.clone(),
                &self.all_containers,
                &self.host_fqdn_hostname,
            )?;
            let srv = SRV::new(priority, 100, self.service.port, indexed_name.into());
            for cur_name in
                Self::get_service_names(&self.service, cur_proc.clone(), &self.host_fqdn_hostname)?
            {
                records.push(Record::from_rdata(
                    cur_name.into(),
                    self.config.record_ttls.srv.as_secs() as u32,
                    srv.clone().into_rdata(),
                ));
            }
        }

        let mut additionals_handler = ContainerARecordHandler::new(
            self.config.clone(),
            None,
            self.containers.clone(),
            self.all_containers.clone(),
            self.host_fqdn_hostname.clone(),
        );
        if let Err(e) = additionals_handler.update_records() {
            error!(
                service = self.service.to_string(),
                "Could not generate additional SRV records: {:?}", e
            );
        }
        self.lookup_object =
            ContainerAuthorityLookupObject::new(records, Some(additionals_handler.records));

        Ok(())
    }

    fn get_listening_services(
        container: Rc<dyn Container>,
    ) -> Result<HashSet<NetworkService>, Error> {
        let mut active_network_services: HashSet<NetworkService> = HashSet::new();
        let mut all_services: HashMap<(TransportProtocol, u16), Vec<NetworkService>> =
            HashMap::new();

        for cur_service in container.network_services()? {
            match all_services.entry((cur_service.protocol, cur_service.port)) {
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.get_mut().push(cur_service);
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(vec![cur_service]);
                }
            }
        }

        for cur_addr in container.ip_addresses(None)? {
            for cur_listening_socket in container.listening_tcp_socket_addresses(&cur_addr)? {
                if let Some(services) =
                    all_services.get(&(TransportProtocol::Tcp, cur_listening_socket.port()))
                {
                    for cur_service in services {
                        active_network_services.insert(cur_service.clone());
                    }
                }
            }
        }

        Ok(active_network_services)
    }

    fn get_service_names(
        service: &NetworkService,
        container: Rc<dyn Container>,
        host_fqdn_hostname: &OsString,
    ) -> Result<HashSet<LowerName>, Error> {
        let container_fqdn = get_lower_hostname(container_fqdn_hostname(
            container.clone(),
            host_fqdn_hostname,
        )?)?;
        let mut names: HashSet<LowerName> = HashSet::new();

        let proto_str = match service.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
        };

        names.insert(Self::prepend_srv_name_labels(
            &container_fqdn,
            proto_str,
            &service.name,
        )?);
        for cur_alias in service.aliases.clone() {
            names.insert(Self::prepend_srv_name_labels(
                &container_fqdn,
                proto_str,
                &cur_alias,
            )?);
        }

        Ok(names)
    }

    fn prepend_srv_name_labels(
        container_fqdn: &LowerName,
        proto_str: &str,
        service_name: &str,
    ) -> Result<LowerName, Error> {
        let prepended = container_fqdn.prepend_label(format!("_{}", proto_str))?;

        Ok(prepended
            .prepend_label(format!("_{}", service_name))?
            .into())
    }
}

impl ContainerRecordHandler for ContainerSrvRecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error> {
        self.containers.push(container);
        self.update_records()
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(self.lookup_object.clone())
    }
}

struct ContainerARecordHandler {
    addr_type: Option<IpAddrType>,
    containers: Vec<Rc<dyn Container>>,
    all_containers: Vec<Rc<dyn Container>>,
    host_fqdn_hostname: OsString,
    config: ContainerAuthorityConfig,
    records: Vec<Record>,
}

impl ContainerARecordHandler {
    fn new(
        config: ContainerAuthorityConfig,
        addr_type: Option<IpAddrType>,
        containers: Vec<Rc<dyn Container>>,
        all_containers: Vec<Rc<dyn Container>>,
        host_fqdn_hostname: OsString,
    ) -> Self {
        Self {
            addr_type,
            containers,
            all_containers,
            config,
            records: vec![],
            host_fqdn_hostname,
        }
    }

    fn sort_containers(&mut self) {
        self.containers.sort_by_key(|a| a.pid());
    }

    fn gen_records(&self) -> Result<Vec<Record>, Error> {
        let mut records: Vec<Record> = vec![];
        for cur_proc in self.containers.iter() {
            let cur_proc_names = Self::get_names(
                cur_proc.clone(),
                &self.all_containers,
                &self.host_fqdn_hostname,
            )?;
            for cur_ip in cur_proc.ip_addresses(self.addr_type)? {
                if !address_in_allowed_networks(&self.config, &cur_ip) {
                    continue;
                }

                let rdata = match cur_ip {
                    IpAddr::V4(ipv4_addr) => {
                        let a: A = ipv4_addr.into();
                        a.into_rdata()
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let aaaa: AAAA = ipv6_addr.into();
                        aaaa.into_rdata()
                    }
                };

                for cur_name in &cur_proc_names {
                    records.push(Record::from_rdata(
                        cur_name.clone().into(),
                        self.config.record_ttls.a.as_secs() as u32,
                        rdata.clone(),
                    ));
                }
            }
        }

        Ok(records)
    }

    fn update_records(&mut self) -> Result<(), Error> {
        self.sort_containers();
        let mut containers = self.containers.clone();
        containers.shuffle(&mut rng());

        self.records = self.gen_records()?;

        Ok(())
    }

    fn get_names(
        container: Rc<dyn Container>,
        all_containers: &Vec<Rc<dyn Container>>,
        host_fqdn_hostname: &OsString,
    ) -> Result<HashSet<LowerName>, Error> {
        let mut names: HashSet<LowerName> = HashSet::new();
        names.insert(get_container_indexed_name(
            container.clone(),
            all_containers,
            host_fqdn_hostname,
        )?);
        names.insert(get_lower_hostname(container_fqdn_hostname(
            container.clone(),
            host_fqdn_hostname,
        )?)?);

        Ok(names)
    }
}

impl ContainerRecordHandler for ContainerARecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error> {
        self.containers.push(container);
        self.update_records()
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(ContainerAuthorityLookupObject::new(
            self.records.clone(),
            None,
        ))
    }
}

struct ZoneRecordHandler {
    host: Rc<dyn Host>,
    is_target: bool,
    config: ContainerAuthorityConfig,
    zone_name: LowerName,
    lookup_object: ContainerAuthorityLookupObject,
}

impl ZoneRecordHandler {
    fn new(
        zone_name: LowerName,
        host: Rc<dyn Host>,
        is_target: bool,
        config: ContainerAuthorityConfig,
    ) -> Self {
        Self {
            host: host.clone(),
            is_target,
            config: config.clone(),
            zone_name,
            lookup_object: ContainerAuthorityLookupObject::default(),
        }
    }

    fn update_records(&mut self) -> Result<(), Error> {
        self.lookup_object = match self.is_target {
            true => {
                let records = Self::get_target_records(self.host.clone(), &self.config)?;
                ContainerAuthorityLookupObject::new(records, None)
            }
            false => {
                let records = Self::get_ns_records(self.host.clone(), &self.config)?;
                let mut additionals_handler = Self::new(
                    self.zone_name.clone(),
                    self.host.clone(),
                    true,
                    self.config.clone(),
                );
                if let Err(e) = additionals_handler.update_records() {
                    error!(
                        zone_name = self.zone_name.to_string(),
                        "Could not generate additional zone records: {:?}", e
                    );
                }

                ContainerAuthorityLookupObject::new(
                    records,
                    Some(additionals_handler.lookup_object.records),
                )
            }
        };

        Ok(())
    }

    fn get_zone_name(host: Rc<dyn Host>) -> Result<LowerName, Error> {
        get_lower_hostname(host.fqdn_hostname()?)
    }

    fn get_ns_target_name(host: Rc<dyn Host>) -> Result<Name, Error> {
        Ok(get_lower_hostname(host.fqdn_hostname()?)?.prepend_label("ns")?)
    }

    fn get_target_records(
        host: Rc<dyn Host>,
        config: &ContainerAuthorityConfig,
    ) -> Result<Vec<Record>, Error> {
        let mut records = vec![];
        let target_name = Self::get_ns_target_name(host.clone())?;

        for cur_ip in host.ip_addresses(None)? {
            if !address_in_allowed_networks(config, &cur_ip) {
                continue;
            }

            let rdata = match cur_ip {
                IpAddr::V4(ipv4_addr) => {
                    let a: A = ipv4_addr.into();
                    a.into_rdata()
                }
                IpAddr::V6(ipv6_addr) => {
                    let aaaa: AAAA = ipv6_addr.into();
                    aaaa.into_rdata()
                }
            };

            records.push(Record::from_rdata(
                target_name.clone(),
                config.record_ttls.a.as_secs() as u32,
                rdata.clone(),
            ));
        }

        Ok(records)
    }

    fn get_ns_records(
        host: Rc<dyn Host>,
        config: &ContainerAuthorityConfig,
    ) -> Result<Vec<Record>, Error> {
        let ns = NS(Self::get_ns_target_name(host.clone())?);

        Ok(vec![Record::from_rdata(
            Self::get_zone_name(host)?.into(),
            config.record_ttls.ns.as_secs() as u32,
            ns.into_rdata(),
        )])
    }
}

impl ContainerRecordHandler for ZoneRecordHandler {
    fn add_container(&mut self, _container: Rc<dyn Container>) -> Result<(), Error> {
        Ok(())
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(self.lookup_object.clone())
    }
}

#[derive(Clone, Default)]
struct ContainerAuthorityLookupObject {
    records: Vec<Record>,
    additionals: Option<Vec<Record>>,
}

impl ContainerAuthorityLookupObject {
    fn new(records: Vec<Record>, additionals: Option<Vec<Record>>) -> Self {
        Self {
            records,
            additionals,
        }
    }
}

impl LookupObject for ContainerAuthorityLookupObject {
    fn is_empty(&self) -> bool {
        self.records.len() == 0
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.records.iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        match &self.additionals {
            Some(a) => Some(Box::new(Self::new(a.clone(), None))),
            None => None,
        }
    }
}
