#!/usr/bin/env python3
# End-to-end test for container-dns using Linux namespaces (no Docker).
#
# Requires:
#   - root or CAP_SYS_ADMIN + CAP_NET_ADMIN (for unshare and namespace entry)
#   - container-dns binary (pass path as first arg, default: ./target/release/container-dns)
#   - python3, ip, dig
#
# Usage:
#   cargo build --release
#   sudo python3 tests/e2e.py

import os
import random
import socket
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TESTS_DIR = Path(__file__).parent


def random_hostname() -> str:
    # RFC 1123 DNS label: [a-z0-9][a-z0-9-]{0,61}[a-z0-9], max 63 chars.
    # Prefix "e2e-" satisfies the leading-letter requirement; the 8-char
    # alphanumeric suffix ensures the label ends on [a-z0-9] with no hyphens.
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"e2e-{suffix}"


def dns_query(name: str, qtype: str, port: int) -> bool:
    """Return True if dig gets at least one answer record."""
    result = subprocess.run(
        ["dig", "+short", "+timeout=1", "+tries=1", "@127.0.0.1", "-p", str(port), name, qtype],
        capture_output=True, text=True,
    )
    return bool(result.stdout.strip())


def get_srv_priorities(name: str, port: int) -> list:
    """Return the list of SRV priorities from dig output (one per answer record)."""
    result = subprocess.run(
        ["dig", "+short", "+timeout=1", "+tries=1", "@127.0.0.1", "-p", str(port), name, "SRV"],
        capture_output=True, text=True,
    )
    priorities = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if parts:
            priorities.append(int(parts[0]))
    return priorities


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_container(hostname: str, ready_pipe: Path) -> subprocess.Popen:
    bind_script = TESTS_DIR / "bind_ports.py"
    return subprocess.Popen([
        "unshare", "--net", "--uts", "--fork",
        "bash", "-c",
        f"hostname '{hostname}' && "
        f"ip link set lo up && "
        f"python3 '{bind_script}' & "
        f"echo ready > '{ready_pipe}' && "
        f"wait",
    ])


def stop_container(proc: subprocess.Popen) -> None:
    subprocess.run(["pkill", "-P", str(proc.pid)], check=False, capture_output=True)
    proc.terminate()
    proc.wait()


def start_dns(binary: str, work: Path) -> tuple:
    """Write config and start container-dns. Returns (proc, port)."""
    port = free_port()
    template = (TESTS_DIR / "e2e_config.toml").read_text()
    config = work / f"config-{port}.toml"
    config.write_text(template.replace("{listen_port}", str(port)))
    proc = subprocess.Popen([binary, "--config-path", str(config), "serve"])
    return proc, port


def test_basic_records(binary: str, work: Path, zone: str) -> None:
    """One container: assert A record and TCP/UDP SRV records are served."""
    hostname = random_hostname()
    ready_pipe = work / "ready-basic"
    os.mkfifo(str(ready_pipe))

    container_proc = None
    dns_proc = None
    try:
        container_proc = start_container(hostname, ready_pipe)
        with open(ready_pipe) as f:
            f.read()

        dns_proc, dns_port = start_dns(binary, work)

        a_name = f"{hostname}.{zone}."
        deadline = time.monotonic() + 10
        while not dns_query(a_name, "A", dns_port):
            if time.monotonic() >= deadline:
                sys.exit(f"FAIL basic_records: timed out waiting for A record {a_name}")
            time.sleep(0.05)

        for name in (
            f"_http._tcp.{hostname}.{zone}.",
            f"_domain._udp.{hostname}.{zone}.",
        ):
            if not dns_query(name, "SRV", dns_port):
                sys.exit(f"FAIL basic_records: no SRV records for {name}")

        print("PASS: basic_records")

    finally:
        if dns_proc:
            dns_proc.terminate()
            dns_proc.wait()
        if container_proc:
            stop_container(container_proc)


def test_srv_priority_ordering(binary: str, work: Path, zone: str) -> None:
    """Two containers with the same hostname: SRV priorities must be {0, 1}."""
    hostname = random_hostname()
    ready_pipe_1 = work / "ready-srv-1"
    ready_pipe_2 = work / "ready-srv-2"
    os.mkfifo(str(ready_pipe_1))
    os.mkfifo(str(ready_pipe_2))

    container_proc_1 = None
    container_proc_2 = None
    dns_proc = None
    try:
        container_proc_1 = start_container(hostname, ready_pipe_1)
        container_proc_2 = start_container(hostname, ready_pipe_2)
        with open(ready_pipe_1) as f:
            f.read()
        with open(ready_pipe_2) as f:
            f.read()

        dns_proc, dns_port = start_dns(binary, work)

        srv_name = f"_http._tcp.{hostname}.{zone}."
        deadline = time.monotonic() + 10
        priorities = []
        while len(priorities) < 2:
            if time.monotonic() >= deadline:
                sys.exit(
                    f"FAIL srv_priority_ordering: timed out waiting for 2 SRV records for {srv_name}"
                )
            priorities = get_srv_priorities(srv_name, dns_port)
            time.sleep(0.05)

        if set(priorities) != {0, 1}:
            sys.exit(
                f"FAIL srv_priority_ordering: expected priorities {{0, 1}}, got {sorted(priorities)}"
            )

        print("PASS: srv_priority_ordering")

    finally:
        if dns_proc:
            dns_proc.terminate()
            dns_proc.wait()
        if container_proc_1:
            stop_container(container_proc_1)
        if container_proc_2:
            stop_container(container_proc_2)


def main() -> None:
    binary = sys.argv[1] if len(sys.argv) > 1 else "./target/release/container-dns"
    zone = f"{socket.gethostname()}.cybertron.lan"

    with tempfile.TemporaryDirectory() as work_str:
        work = Path(work_str)
        test_basic_records(binary, work, zone)
        test_srv_priority_ordering(binary, work, zone)


if __name__ == "__main__":
    main()
