use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    ffi::OsString,
    net::IpAddr,
    rc::Rc,
};

use hickory_proto::rr::{
    LowerName, Record, RecordData,
    rdata::{A, AAAA, NS, SRV},
};
use hickory_resolver::Name;
use hickory_server::authority::LookupObject;
use rand::rng;
use rand::seq::SliceRandom;
use tracing::error;

use crate::{
    containers::{Container, Host, IpAddrType, NetworkService, TransportProtocol},
    dns::settings::Settings,
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

fn address_in_allowed_networks(config: &Settings, ip_addr: &IpAddr) -> bool {
    for cur_network in &config.allowed_networks {
        if cur_network.contains(ip_addr) {
            return true;
        }
    }

    false
}

pub trait RecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error>;
    fn lookup_object(&self) -> Box<dyn LookupObject>;
}

pub struct SrvRecordHandler {
    names: HashSet<LowerName>,
    service: NetworkService,
    containers: Vec<Rc<dyn Container>>,
    all_containers: Vec<Rc<dyn Container>>,
    host_fqdn_hostname: OsString,
    config: Settings,
    lookup_object: RecordHandlerLookupObject,
}

impl SrvRecordHandler {
    pub(crate) fn new(
        names: HashSet<LowerName>,
        service: NetworkService,
        config: Settings,
        containers: Vec<Rc<dyn Container>>,
        all_containers: Vec<Rc<dyn Container>>,
        host_fqdn_hostname: OsString,
    ) -> Self {
        Self {
            names,
            service,
            containers,
            all_containers,
            config,
            host_fqdn_hostname,
            lookup_object: RecordHandlerLookupObject::default(),
        }
    }

    fn sort_containers(&mut self) {
        self.containers.sort_by_key(|a| a.pid());
    }

    pub fn update_records(&mut self) -> Result<(), Error> {
        self.sort_containers();
        let mut containers = self.containers.clone();
        containers.shuffle(&mut rng());
        let mut records: Vec<Record> = vec![];
        let mut indexed_names: HashSet<LowerName> = HashSet::new();

        for (priority, cur_proc) in (0_u16..).zip(containers.iter()) {
            let indexed_name = get_container_indexed_name(
                cur_proc.clone(),
                &self.all_containers,
                &self.host_fqdn_hostname,
            )?;
            indexed_names.insert(indexed_name.clone());

            let srv = SRV::new(priority, 100, self.service.port, indexed_name.into());
            for cur_name in &self.names {
                records.push(Record::from_rdata(
                    cur_name.into(),
                    self.config.record_ttls.srv.as_secs() as u32,
                    srv.clone().into_rdata(),
                ));
            }
        }

        let mut additionals_handler = ARecordHandler::new(
            indexed_names,
            self.config.clone(),
            None,
            self.containers.clone(),
        );
        if let Err(e) = additionals_handler.update_records() {
            error!(
                service = self.service.to_string(),
                "Could not generate additional SRV records: {:?}", e
            );
        }
        self.lookup_object =
            RecordHandlerLookupObject::new(records, Some(additionals_handler.records));

        Ok(())
    }

    pub fn get_listening_services(
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

    pub fn get_service_names(
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

impl RecordHandler for SrvRecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error> {
        self.containers.push(container);
        self.update_records()
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(self.lookup_object.clone())
    }
}

pub struct ARecordHandler {
    names: HashSet<LowerName>,
    addr_type: Option<IpAddrType>,
    containers: Vec<Rc<dyn Container>>,
    config: Settings,
    records: Vec<Record>,
}

impl ARecordHandler {
    pub fn new(
        names: HashSet<LowerName>,
        config: Settings,
        addr_type: Option<IpAddrType>,
        containers: Vec<Rc<dyn Container>>,
    ) -> Self {
        Self {
            names,
            addr_type,
            containers,
            config,
            records: vec![],
        }
    }

    fn sort_containers(&mut self) {
        self.containers.sort_by_key(|a| a.pid());
    }

    fn gen_records(&self) -> Result<Vec<Record>, Error> {
        // Since Record doesn't implement the Hash trait, we can't use HashSet
        let mut records: HashMap<(IpAddr, LowerName), Record> = HashMap::new();
        for cur_proc in self.containers.iter() {
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

                for cur_name in &self.names {
                    records.insert(
                        (cur_ip, cur_name.clone()),
                        Record::from_rdata(
                            cur_name.clone().into(),
                            self.config.record_ttls.a.as_secs() as u32,
                            rdata.clone(),
                        ),
                    );
                }
            }
        }

        Ok(records.values().cloned().collect())
    }

    pub fn update_records(&mut self) -> Result<(), Error> {
        self.sort_containers();
        let mut containers = self.containers.clone();
        containers.shuffle(&mut rng());

        self.records = self.gen_records()?;

        Ok(())
    }

    pub fn get_names(
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

impl RecordHandler for ARecordHandler {
    fn add_container(&mut self, container: Rc<dyn Container>) -> Result<(), Error> {
        self.containers.push(container);
        self.update_records()
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(RecordHandlerLookupObject::new(self.records.clone(), None))
    }
}

pub struct ZoneRecordHandler {
    host: Rc<dyn Host>,
    is_target: bool,
    config: Settings,
    zone_name: LowerName,
    lookup_object: RecordHandlerLookupObject,
}

impl ZoneRecordHandler {
    pub fn new(
        zone_name: LowerName,
        host: Rc<dyn Host>,
        is_target: bool,
        config: Settings,
    ) -> Self {
        Self {
            host: host.clone(),
            is_target,
            config: config.clone(),
            zone_name,
            lookup_object: RecordHandlerLookupObject::default(),
        }
    }

    pub fn update_records(&mut self) -> Result<(), Error> {
        self.lookup_object = match self.is_target {
            true => {
                let records = Self::get_target_records(self.host.clone(), &self.config)?;
                RecordHandlerLookupObject::new(records, None)
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

                RecordHandlerLookupObject::new(
                    records,
                    Some(additionals_handler.lookup_object.records),
                )
            }
        };

        Ok(())
    }

    pub fn get_zone_name(host: Rc<dyn Host>) -> Result<LowerName, Error> {
        get_lower_hostname(host.fqdn_hostname()?)
    }

    fn get_ns_target_name(host: Rc<dyn Host>) -> Result<Name, Error> {
        Ok(get_lower_hostname(host.fqdn_hostname()?)?.prepend_label("container-ns")?)
    }

    fn get_target_records(host: Rc<dyn Host>, config: &Settings) -> Result<Vec<Record>, Error> {
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

    fn get_ns_records(host: Rc<dyn Host>, config: &Settings) -> Result<Vec<Record>, Error> {
        let ns = NS(Self::get_ns_target_name(host.clone())?);

        Ok(vec![Record::from_rdata(
            Self::get_zone_name(host)?.into(),
            config.record_ttls.ns.as_secs() as u32,
            ns.into_rdata(),
        )])
    }
}

impl RecordHandler for ZoneRecordHandler {
    fn add_container(&mut self, _container: Rc<dyn Container>) -> Result<(), Error> {
        Ok(())
    }

    fn lookup_object(&self) -> Box<dyn LookupObject> {
        Box::new(self.lookup_object.clone())
    }
}

#[derive(Clone, Default)]
pub struct RecordHandlerLookupObject {
    records: Vec<Record>,
    additionals: Option<Vec<Record>>,
}

impl RecordHandlerLookupObject {
    fn new(records: Vec<Record>, additionals: Option<Vec<Record>>) -> Self {
        Self {
            records,
            additionals,
        }
    }
}

impl LookupObject for RecordHandlerLookupObject {
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
