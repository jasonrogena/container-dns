use super::*;
use std::net::{SocketAddrV4, SocketAddrV6};

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ipv6(addr: Ipv6Addr) -> IpAddr {
    IpAddr::V6(addr)
}

fn sa4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

fn sa6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
}

fn is_dualstack() -> bool {
    Ctl::new("net.ipv6.bindv6only")
        .and_then(|c| c.value())
        .map(|v| v == CtlValue::String("0".to_string()))
        .unwrap_or(false)
}

#[test]
fn remote_port_nonzero_returns_false() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa4(Ipv4Addr::new(192, 168, 1, 10), 80);
    let remote = sa4(Ipv4Addr::new(10, 0, 0, 1), 54321);
    assert!(!LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv4_addr_ipv4_local_exact_match_returns_true() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa4(Ipv4Addr::new(192, 168, 1, 10), 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv4_addr_ipv4_local_wildcard_returns_true() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa4(Ipv4Addr::UNSPECIFIED, 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv4_addr_ipv4_local_mismatch_returns_false() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa4(Ipv4Addr::new(10, 0, 0, 1), 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(!LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv4_addr_ipv6_local_unspecified_respects_dualstack() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa6(Ipv6Addr::UNSPECIFIED, 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    let result = LinuxProcess::is_socket_bound(&addr, local, remote).unwrap();
    assert_eq!(result, is_dualstack());
}

#[test]
fn ipv4_addr_ipv6_local_non_unspecified_returns_false() {
    let addr = ipv4(192, 168, 1, 10);
    let local = sa6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(!LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv6_addr_ipv6_local_exact_match_returns_true() {
    let ip6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let addr = ipv6(ip6);
    let local = sa6(ip6, 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv6_addr_ipv6_local_wildcard_returns_true() {
    let addr = ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let local = sa6(Ipv6Addr::UNSPECIFIED, 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv6_addr_ipv6_local_mismatch_returns_false() {
    let addr = ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let local = sa6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(!LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}

#[test]
fn ipv6_addr_ipv4_local_returns_false() {
    let addr = ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let local = sa4(Ipv4Addr::new(192, 168, 1, 10), 80);
    let remote = sa4(Ipv4Addr::UNSPECIFIED, 0);
    assert!(!LinuxProcess::is_socket_bound(&addr, local, remote).unwrap());
}
