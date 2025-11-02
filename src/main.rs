use std::{
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use container_dns::dns::container_authority::RecordTtls;
use container_dns::dns::server::{Server, ServerConfig};
use ipnet::IpNet;
use tokio::task::LocalSet;
use tracing::Level;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let local_set = LocalSet::new();
    _ = Server::new(
        local_set,
        ServerConfig {
            bind_ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            listen_port: 5454,
            refresh_interval: Duration::from_secs(60),
            allowed_networks: vec![IpNet::V4("192.168.10.0/24".parse().unwrap())],
            record_ttls: RecordTtls::default(),
            tcp_timeout: Duration::from_secs(60),
        },
    )
    .await
    .unwrap();
}
