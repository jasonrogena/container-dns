use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    rc::Rc,
    time::Duration,
};

use super::*;

#[derive(Eq, PartialEq, Clone)]
struct TestOkContainer {
    pub hostname: OsString,
    pub ip_addresses: HashSet<IpAddr>,
    pub listening_tcp_socket_addresses: HashSet<SocketAddr>,
    pub listening_udp_socket_addresses: HashSet<SocketAddr>,
    pub network_services: HashSet<NetworkService>,
    pub pid: u32,
}

impl Default for TestOkContainer {
    fn default() -> Self {
        Self {
            hostname: "test-container".into(),
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]
                .into_iter()
                .collect(),
            listening_tcp_socket_addresses: vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 10),
                8080,
            ))]
            .into_iter()
            .collect(),
            listening_udp_socket_addresses: HashSet::new(),
            network_services: vec![NetworkService {
                name: "test-service".to_string(),
                aliases: vec!["alias1".to_string()],
                port: 2342,
                protocol: TransportProtocol::Tcp,
            }]
            .into_iter()
            .collect(),
            pid: 2321,
        }
    }
}

impl Container for TestOkContainer {
    fn hostname(&self) -> Result<OsString, crate::containers::Error> {
        Ok(self.hostname.clone())
    }

    fn ip_addresses(
        &self,
        _addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, crate::containers::Error> {
        Ok(self.ip_addresses.clone())
    }

    fn listening_tcp_socket_addresses(
        &self,
        _address: &IpAddr,
    ) -> Result<HashSet<std::net::SocketAddr>, crate::containers::Error> {
        Ok(self.listening_tcp_socket_addresses.clone())
    }

    fn listening_udp_socket_addresses(
        &self,
        _address: &IpAddr,
    ) -> Result<HashSet<std::net::SocketAddr>, crate::containers::Error> {
        Ok(self.listening_udp_socket_addresses.clone())
    }

    fn network_services(&self) -> Result<HashSet<NetworkService>, crate::containers::Error> {
        Ok(self.network_services.clone())
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

#[allow(dead_code)]
struct TestErrContainer {}

impl Container for TestErrContainer {
    fn hostname(&self) -> Result<OsString, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn ip_addresses(
        &self,
        _addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn listening_tcp_socket_addresses(
        &self,
        _address: &IpAddr,
    ) -> Result<HashSet<std::net::SocketAddr>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn listening_udp_socket_addresses(
        &self,
        _address: &IpAddr,
    ) -> Result<HashSet<std::net::SocketAddr>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn network_services(&self) -> Result<HashSet<NetworkService>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn pid(&self) -> u32 {
        0
    }
}

#[derive(PartialEq, Clone)]
struct TestOkHost {
    pub fqdn_hostname: OsString,
    pub containers: Vec<Rc<dyn Container>>,
    pub ip_addresses: HashSet<IpAddr>,
}

impl Default for TestOkHost {
    fn default() -> Self {
        Self {
            fqdn_hostname: "test-host".into(),
            containers: vec![Rc::new(TestOkContainer::default())],
            ip_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))]
                .into_iter()
                .collect(),
        }
    }
}

impl Host for TestOkHost {
    fn fqdn_hostname(&self) -> Result<OsString, crate::containers::Error> {
        Ok(self.fqdn_hostname.clone())
    }

    fn containers(&self) -> Result<Vec<Rc<dyn Container>>, crate::containers::Error> {
        Ok(self.containers.clone())
    }

    fn ip_addresses(
        &self,
        _addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, crate::containers::Error> {
        Ok(self.ip_addresses.clone())
    }
}

#[allow(dead_code)]
struct TestErrHost {}

impl Host for TestErrHost {
    fn fqdn_hostname(&self) -> Result<OsString, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn containers(&self) -> Result<Vec<Rc<dyn Container>>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }

    fn ip_addresses(
        &self,
        _addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, crate::containers::Error> {
        Err(crate::containers::Error::Generic("test".to_string()))
    }
}

#[test]
fn test_srv_get_service_names() {
    let test_host = TestOkHost::default();
    let test_container = TestOkContainer::default();
    let network_services = test_container.network_services.clone();
    let test_service = network_services.iter().next().unwrap();
    let service_names = SrvRecordHandler::get_service_names(
        test_service,
        Rc::new(test_container),
        &test_host.fqdn_hostname,
    )
    .unwrap();

    let expected_names: HashSet<LowerName> = vec![
        Name::from_ascii("_test-service._tcp.test-container.test-host")
            .unwrap()
            .into(),
        Name::from_ascii("_alias1._tcp.test-container.test-host")
            .unwrap()
            .into(),
    ]
    .into_iter()
    .collect();

    assert_eq!(service_names, expected_names);
}

#[test]
fn test_srv_get_service_names_udp() {
    let test_host = TestOkHost::default();
    let udp_service = NetworkService {
        name: "dns".to_string(),
        aliases: vec!["domain".to_string()],
        port: 53,
        protocol: TransportProtocol::Udp,
    };
    let service_names = SrvRecordHandler::get_service_names(
        &udp_service,
        Rc::new(TestOkContainer::default()),
        &test_host.fqdn_hostname,
    )
    .unwrap();

    let expected_names: HashSet<LowerName> = vec![
        Name::from_ascii("_dns._udp.test-container.test-host")
            .unwrap()
            .into(),
        Name::from_ascii("_domain._udp.test-container.test-host")
            .unwrap()
            .into(),
    ]
    .into_iter()
    .collect();

    assert_eq!(service_names, expected_names);
}

#[test]
fn test_get_listening_services_includes_udp() {
    let container = TestOkContainer {
        listening_udp_socket_addresses: vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 10),
            53,
        ))]
        .into_iter()
        .collect(),
        network_services: vec![
            NetworkService {
                name: "dns".to_string(),
                aliases: vec![],
                port: 53,
                protocol: TransportProtocol::Udp,
            },
            NetworkService {
                name: "http".to_string(),
                aliases: vec![],
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
        ]
        .into_iter()
        .collect(),
        ..TestOkContainer::default()
    };

    let services = SrvRecordHandler::get_listening_services(Rc::new(container)).unwrap();

    assert!(
        services
            .iter()
            .any(|s| s.name == "dns" && s.protocol == TransportProtocol::Udp)
    );
    assert!(!services.iter().any(|s| s.name == "http"));
}

fn make_settings() -> Settings {
    Settings {
        record_ttls: crate::dns::settings::RecordTtls::default(),
        allowed_record_networks: HashSet::new(),
        refresh_interval: Duration::from_secs(30),
    }
}

fn srv_priorities(handler: &SrvRecordHandler) -> Vec<u16> {
    let lookup = handler.lookup_object();
    let mut priorities: Vec<u16> = lookup
        .iter()
        .filter_map(|r| {
            if let hickory_proto::rr::RData::SRV(srv) = r.data() {
                Some(srv.priority())
            } else {
                None
            }
        })
        .collect();
    priorities.sort();
    priorities.dedup();
    priorities
}

#[test]
fn test_srv_priority_single_container_is_always_zero() {
    let host_fqdn: OsString = "test-host".into();
    let service = NetworkService {
        name: "http".into(),
        aliases: vec![],
        port: 8080,
        protocol: TransportProtocol::Tcp,
    };
    let container = Rc::new(TestOkContainer {
        pid: 100,
        ..TestOkContainer::default()
    });
    let names =
        SrvRecordHandler::get_service_names(&service, container.clone(), &host_fqdn).unwrap();

    // Simulate the container having host-wide rank 14 (14 other less-loaded containers on host)
    let mut load_map = HashMap::new();
    load_map.insert(100u32, (14u16, 88u16));

    let mut handler = SrvRecordHandler::new(
        names,
        service,
        make_settings(),
        vec![container.clone()],
        vec![container],
        host_fqdn,
        load_map,
    );
    handler.update_records().unwrap();

    assert_eq!(srv_priorities(&handler), vec![0]);
}

#[test]
fn test_srv_priority_two_containers_get_zero_and_one() {
    let host_fqdn: OsString = "test-host".into();
    let service = NetworkService {
        name: "http".into(),
        aliases: vec![],
        port: 8080,
        protocol: TransportProtocol::Tcp,
    };
    // Two containers with the same hostname; pid 200 has lower host-wide rank (lower load)
    let container_a = Rc::new(TestOkContainer {
        pid: 100,
        hostname: "grafana".into(),
        ..TestOkContainer::default()
    });
    let container_b = Rc::new(TestOkContainer {
        pid: 200,
        hostname: "grafana".into(),
        ..TestOkContainer::default()
    });
    let all: Vec<Rc<dyn Container>> = vec![container_a.clone(), container_b.clone()];
    let names =
        SrvRecordHandler::get_service_names(&service, container_a.clone(), &host_fqdn).unwrap();

    // pid 200 ranked 5th host-wide (lower load), pid 100 ranked 14th (higher load)
    let mut load_map = HashMap::new();
    load_map.insert(100u32, (14u16, 70u16));
    load_map.insert(200u32, (5u16, 90u16));

    let mut handler = SrvRecordHandler::new(
        names,
        service,
        make_settings(),
        vec![container_a, container_b],
        all,
        host_fqdn,
        load_map,
    );
    handler.update_records().unwrap();

    assert_eq!(srv_priorities(&handler), vec![0, 1]);
}
