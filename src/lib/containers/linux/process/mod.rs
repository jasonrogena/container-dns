use libc::pid_t;
use nix::errno;
use nix::unistd::gethostname;
use procfs::net::TcpNetEntry;
use servicefile::parse_servicefile;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use sysctl::{Ctl, CtlValue, Sysctl, SysctlError};
use tracing::{debug, error, info, instrument, warn};

use crate::containers::linux::{get_ip_addresses, run_in_namespace};
use crate::containers::{self, Container, IpAddrType, NetworkService};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An I/O error was thrown while trying to process a process: {0}")]
    Io(#[from] std::io::Error),
    #[error("A unix error number was thrown while working with a linux process: {0}")]
    Errno(#[from] errno::Errno),
    #[error("Could not determine the hostname as seen by the PID {0}")]
    Hostname(i32),
    #[error("An error while trying to obtain process information from procfs: {0}")]
    Procfs(#[from] procfs::ProcError),
    #[error("An error occurred while trying to access sysctl: {0}")]
    Sysctl(#[from] SysctlError),
    #[error("An error was thrown while trying to read the /etc/services file: {0}")]
    ServiceFile(String),
    #[error("An error was thrown while trying to get the hostname for process: {0}")]
    DetailedHostname(String),
}

#[derive(Debug)]
pub struct LinuxProcess {
    pub pid: pid_t,
    hostname: OsString,
}

impl LinuxProcess {
    pub fn new(pid: pid_t) -> Result<LinuxProcess, Error> {
        Ok(LinuxProcess {
            pid,
            hostname: Self::get_hostname(pid)?,
        })
    }

    #[instrument]
    fn get_hostname(pid: pid_t) -> Result<OsString, Error> {
        run_in_namespace(pid, super::namespaces::Type::Uts, pid, |pid: i32| {
            let hostname = match gethostname()
                .map_err(|e| super::ChildProcessError::Generic(e.to_string()))?
                .to_str()
            {
                Some(s) => s.to_string(),
                None => {
                    return Err(super::ChildProcessError::Generic(
                        Error::Hostname(pid).to_string(),
                    ));
                }
            };

            Ok(hostname.into())
        })
        .map_err(|e| Error::DetailedHostname(e.to_string()))
    }

    #[instrument]
    fn is_ip_addr_listening(address: &IpAddr, tcp_net_entry: &TcpNetEntry) -> Result<bool, Error> {
        if tcp_net_entry.remote_address.port() != 0 {
            // Only entries in /proc/<pid>/net/tcp with the remote port set to 0
            // match sockets that are listening
            return Ok(false);
        }

        // Check value of /proc/sys/net/ipv6/bindv6only. If set to 0, dual stack is enabled and
        // listening on wildcard ipv6 address also means it is listening on ipv4 address
        let dualstack =
            Ctl::new("net.ipv6.bindv6only")?.value()? == CtlValue::String("0".to_string());

        if address.is_ipv4() {
            if tcp_net_entry.local_address.is_ipv4() {
                if tcp_net_entry.local_address.ip() != Ipv4Addr::UNSPECIFIED
                    && tcp_net_entry.local_address.ip() != *address
                {
                    return Ok(false);
                }
            } else if tcp_net_entry.local_address.is_ipv6() {
                if !dualstack || tcp_net_entry.local_address.ip() != Ipv6Addr::UNSPECIFIED {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        } else if address.is_ipv6() {
            if tcp_net_entry.local_address.is_ipv4() {
                return Ok(false);
            } else if tcp_net_entry.local_address.is_ipv6() {
                if tcp_net_entry.local_address.ip() != Ipv6Addr::UNSPECIFIED
                    && tcp_net_entry.local_address.ip() != *address
                {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        Ok(true)
    }
}

impl Container for LinuxProcess {
    fn pid(&self) -> u32 {
        self.pid as u32
    }

    #[instrument]
    fn hostname(&self) -> Result<OsString, containers::Error> {
        Ok(self.hostname.clone())
    }

    #[instrument]
    fn ip_addresses(
        &self,
        addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, containers::Error> {
        let input = (self.pid, addr_type);
        run_in_namespace(
            self.pid,
            super::namespaces::Type::Net,
            input,
            |(pid, addr_type)| {
                let ip_addresses = get_ip_addresses(addr_type)
                    .map_err(|e| containers::linux::ChildProcessError::Generic(e.to_string()))?;
                info!(
                    pid = pid,
                    "The number of IP addresses in container are {}",
                    ip_addresses.len()
                );
                debug!("IP Addresses: {:?}", ip_addresses);
                Ok(ip_addresses)
            },
        )
        .map_err(|e| containers::Error::Generic(e.to_string()))
    }

    #[instrument]
    fn listening_tcp_socket_addresses(
        &self,
        address: &IpAddr,
    ) -> Result<HashSet<SocketAddr>, containers::Error> {
        let proc_process = procfs::process::Process::new(self.pid)
            .map_err(|e| containers::Error::Generic(e.to_string()))?;
        let mut sock_addr: HashMap<u16, SocketAddr> = HashMap::new();
        let mut tcp_entries = proc_process
            .tcp()
            .map_err(|e| containers::Error::Generic(e.to_string()))?;
        tcp_entries.extend(
            proc_process
                .tcp6()
                .map_err(|e| containers::Error::Generic(e.to_string()))?,
        );

        for cur_entry in tcp_entries {
            if Self::is_ip_addr_listening(address, &cur_entry)
                .map_err(|e| containers::Error::Generic(e.to_string()))?
            {
                match sock_addr.entry(cur_entry.local_address.port()) {
                    Entry::Vacant(v) => {
                        v.insert(cur_entry.local_address);
                    }
                    Entry::Occupied(mut o) => {
                        // Only replace value in HashMap if cur_entry is more generic. Sockets with unspecified IPv6 addresses
                        // are considered more generic than those with unspecified IPv4 addresses
                        if cur_entry.local_address.ip() == Ipv6Addr::UNSPECIFIED
                            || (cur_entry.local_address.ip() == Ipv4Addr::UNSPECIFIED
                                && o.get().ip() != Ipv6Addr::UNSPECIFIED)
                        {
                            o.insert(cur_entry.local_address);
                        }
                    }
                }
            }
        }
        info!(
            pid = self.pid,
            "The number of listening TCP services in container are {}",
            sock_addr.len()
        );

        Ok(sock_addr.into_values().collect())
    }

    #[instrument]
    fn network_services(&self) -> Result<HashSet<NetworkService>, containers::Error> {
        run_in_namespace(self.pid, super::namespaces::Type::Mount, self.pid, |pid: pid_t| {
            let mut services: HashSet<NetworkService> = HashSet::new();
            let entries = match parse_servicefile(true).map_err(|e| Error::ServiceFile(e.to_string())) {
                Ok(o) => o,
                Err(e) => {
                    warn!(pid = pid, "An error was thrown while trying to parse the /etc/services file for the process. Returning an empty list: {:?}", e);
                    return Ok(services);
                }
            };

            for cur_entry in entries {
                let transport_protocol = match cur_entry.protocol.to_lowercase().trim() {
                    "tcp" => containers::TransportProtocol::Tcp,
                    "udp" => containers::TransportProtocol::Udp,
                    _ => {
                        debug!(pid = pid, "The transport protocol in the provided service entry is unknown: {:?}", cur_entry);
                        continue
                    },
                };
                services.insert(NetworkService { name: cur_entry.name, aliases: cur_entry.aliases, port: cur_entry.port as u16, protocol: transport_protocol });
            }

            info!(pid = pid, "The number of registered services in container are {}", services.len());
            debug!(pid = pid, "Services {:?}", services);

            Ok(services)
        }).map_err(|e| containers::Error::Generic(e.to_string()))
    }
}
