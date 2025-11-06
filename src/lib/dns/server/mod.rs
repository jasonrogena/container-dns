use hickory_server::authority::{AuthorityObject, Catalog};
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::LocalSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::dns::{
    container::{
        authority::{self, Authority},
        store::Store,
    },
    settings::{RecordTtls, Settings},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("A Hickory protocol error was thrown: {0}")]
    HickoryProto(#[from] hickory_proto::ProtoError),
    #[error("An IO error was thrown")]
    Io(#[from] std::io::Error),
    #[error("An error thrown by the container authority: {0}")]
    Authority(#[from] authority::Error),
}

#[derive(Clone)]
pub struct ServerConfig {
    pub bind_ip_addr: IpAddr,
    pub listen_port: u16,
    pub refresh_interval: Duration,
    pub allowed_networks: Vec<IpNet>,
    pub record_ttls: RecordTtls,
    pub tcp_timeout: Duration,
}

pub struct Server {
    // hickory_server: hickory_server::server::ServerFuture<Catalog>,
    shutdown_token: CancellationToken,
}

impl Server {
    pub async fn new(local_set: LocalSet, config: ServerConfig) -> Result<Self, Error> {
        info!("Initializing the DNS server");

        let mut catalog = Catalog::new();

        let (container_authority, container_authority_rx) = Authority::new()?;

        catalog.upsert(
            container_authority.origin().clone(),
            vec![Arc::new(container_authority)],
        );

        let shutdown_token = CancellationToken::new();
        let config_clone = config.clone();
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

        Store::start(
            local_set,
            Settings {
                record_ttls: config.record_ttls,
                allowed_networks: config.allowed_networks.clone().into_iter().collect(),
                refresh_interval: config.refresh_interval,
            },
            shutdown_token.clone(),
            container_authority_rx,
        )
        .await;

        Ok(Self {
            // hickory_server,
            shutdown_token,
        })
    }

    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_token.cancel();

        Ok(())
    }
}
