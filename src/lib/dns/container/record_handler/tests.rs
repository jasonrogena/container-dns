use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    rc::Rc,
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

    assert!(services
        .iter()
        .any(|s| s.name == "dns" && s.protocol == TransportProtocol::Udp));
    assert!(!services.iter().any(|s| s.name == "http"));
}
