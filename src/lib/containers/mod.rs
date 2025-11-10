use std::{
    collections::HashSet,
    ffi::OsString,
    fmt::{self, Display},
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use serde::{Deserialize, Serialize};

pub mod linux;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An I/O error was thrown while trying to process a process: {0}")]
    Io(#[from] std::io::Error),
    #[error("Thead panicked with: {0}")]
    Thread(String),
    #[error("A generic error was thrown while trying to get isolated process information: {0}")]
    Generic(String),
    #[error("A Hickory protocol error was thrown: {0}")]
    HickoryProto(#[from] hickory_proto::ProtoError),
}

#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum IpAddrType {
    V4,
    V6,
}

#[derive(Debug, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
        };

        write!(f, "{}", name)
    }
}

#[derive(Debug, Eq, Hash, PartialEq, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    pub name: String,
    pub aliases: Vec<String>,
    pub port: u16,
    pub protocol: TransportProtocol,
}

impl Display for NetworkService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}/{}", self.name, self.port, self.protocol)
    }
}

pub trait Container {
    fn hostname(&self) -> Result<OsString, Error>;
    fn ip_addresses(&self, addr_type: Option<IpAddrType>) -> Result<HashSet<IpAddr>, Error>;
    fn listening_tcp_socket_addresses(
        &self,
        address: &IpAddr,
    ) -> Result<HashSet<SocketAddr>, Error>;
    fn network_services(&self) -> Result<HashSet<NetworkService>, Error>;
    fn pid(&self) -> u32;
}

impl Display for dyn Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PID in host: {}", self.pid())
    }
}

impl PartialEq for dyn Container {
    fn eq(&self, other: &Self) -> bool {
        self.pid() == other.pid()
    }
}

pub trait Host {
    fn fqdn_hostname(&self) -> Result<OsString, Error>;
    fn containers(&self) -> Result<Vec<Rc<dyn Container>>, Error>;
    fn ip_addresses(&self, addr_type: Option<IpAddrType>) -> Result<HashSet<IpAddr>, Error>;
}

impl fmt::Debug for dyn Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").finish()
    }
}
