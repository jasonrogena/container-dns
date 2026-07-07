# container-dns

A DNS server that automatically exposes services running inside Linux containers, without depending on any specific container engine.

## Why container-dns?

Install container-dns on a host with containers and it will expose services running in the containers, discoverable from each container's own hostname and `/etc/services` — no sidecars, no labels, and no coupling to a container runtime.

- **No sidecars or registry** — services come from the container's own hostname and its standard `/etc/services`, not from engine-specific labels, a discovery agent, or a separate registry to keep in sync.
- **Engine-agnostic** — Docker, Podman, LXC, systemd-nspawn, or anything using Linux namespaces. No runtime API is ever queried.
- **Standards-based** — publishes DNS-SD (RFC 6763) + SRV (RFC 2782), so it's browsable by off-the-shelf tooling (`dig`, `avahi-browse`, Prometheus DNS-SD, Caddy dynamic upstreams) instead of a bespoke scheme.
- **Load-aware** — SRV priority/weight track each container's real-time load, so clients prefer the least-loaded replica.
- **Rich metadata** — containers advertise per-endpoint info (health-check paths, expected status, …) via TXT records.

## Example

Two containers on the `node1.internal` host — `grafana` and `sabnzbd` — each expose an `http` service. All they do is name that service (and its port) in the standard `/etc/services`:

`/etc/services` inside the `grafana` container:

```
http    3000/tcp
```

`/etc/services` inside the `sabnzbd` container:

```
http    8080/tcp
```

`grafana` optionally advertises extra metadata for its endpoint in `/etc/container-dns/txt`:

```ini
[3000/tcp]
txtvers=1
path=/api/health
```

That's the whole setup — no labels, no restart, no runtime API. A client now discovers everything with ordinary DNS queries. Each record type answers one plain question: **PTR** lists what exists, **SRV** gives the host and port to connect to, **A** resolves a host to an IP, and **TXT** carries extra metadata.

```console
# What service types does this host expose?
$ dig +short _services._dns-sd._udp.node1.internal. PTR
_http._tcp.node1.internal.

# Which containers serve HTTP? (one name per instance)
$ dig +short _http._tcp.node1.internal. PTR
grafana._http._tcp.node1.internal.
sabnzbd._http._tcp.node1.internal.

# Where do I reach grafana? SRV returns priority, weight, port (3000), and target host.
$ dig +short grafana._http._tcp.node1.internal. SRV
0 100 3000 0.grafana.node1.internal.

# What is that host's IP address?
$ dig +short 0.grafana.node1.internal. A
192.0.2.10

# Any extra info about the service? Here, the health-check path grafana advertised.
$ dig +short grafana._http._tcp.node1.internal. TXT
"txtvers=1" "path=/api/health"
```

## How It Works

Discovered services are published using standard [DNS-Based Service Discovery (DNS-SD, RFC 6763)](https://datatracker.ietf.org/doc/html/rfc6763), so the zone is browsable and consumable by off-the-shelf tooling (`avahi-browse`, `dns-sd`, Prometheus DNS-SD) rather than a bespoke scheme:

- Each service is a **Service Instance Name** `<container-hostname>._<service>._<proto>.<host-fqdn>` (RFC 6763 §4.1), owning its `SRV` and `TXT` records.
- Clients **browse** a service type via its `PTR` records, and enumerate all types via the `_services._dns-sd._udp.<host-fqdn>` meta-query (RFC 6763 §9), scoped to the host's own zone.
- Per-service metadata is carried in `TXT` records using the RFC 6763 §6 `key=value` format.
- Underlying host/port bindings use `SRV` (RFC 2782), with priority/weight derived from container load.

As much as possible, we rely on native Linux constructs to discover the properties for the containers to expose making container-dns compatible with Docker, Podman, LXC, systemd-nspawn, or anything else that uses Linux namespaces, without depending on any engine-specific API:

- A container of interest is defined as any process in a **different network namespace** from the host.
- Container hostnames are read by entering each container's **UTS namespace** and reading the hostname.
- Container IP addresses are enumerated by entering each container's **network namespace**.
- Listening ports are discovered from `/proc/<pid>/net/tcp` rather than querying a runtime.
- Service names are resolved by entering each container's **mount namespace** and reading its `/etc/services`.
- Service metadata (published as TXT) is read by entering each container's **mount namespace** and reading `/etc/container-dns/txt`.
- Container load is measured by entering each container's **mount namespace** and reading `/proc/loadavg`, which reflects the load of the container's PID namespace since kernel 4.14.

## DNS Records

container-dns exposes the following DNS records for the host, containers, and services running in the containers:

### Per Host

| Record | Name | Value |
|--------|------|-------|
| `NS` | `<host-fqdn>.` | `container-ns.<host-fqdn>.` |
| `A`/`AAAA` | `container-ns.<host-fqdn>.` | Host's IP addresses |
| `PTR` | `_services._dns-sd._udp.<host-fqdn>.` | Every `_<service>._<proto>.<host-fqdn>.` service type present (DNS-SD service-type enumeration, RFC 6763 §9) |

The zone served is the host's own FQDN, so no external delegation is needed beyond pointing a zone at this server.

### Per Container

Where `<index>` is the container's position among containers sharing the same hostname, ordered by PID (starting at 0).

| Record | Name | Value |
|--------|------|-------|
| `A` | `<container-hostname>.<host-fqdn>.` | Container's IPv4 addresses |
| `AAAA` | `<container-hostname>.<host-fqdn>.` | Container's IPv6 addresses |
| `A` | `<index>.<container-hostname>.<host-fqdn>.` | Container's IPv4 addresses |
| `AAAA` | `<index>.<container-hostname>.<host-fqdn>.` | Container's IPv6 addresses |

### Per Service

For each port matched to a service name in `/etc/services` (including aliases):

Records use [DNS-SD](https://datatracker.ietf.org/doc/html/rfc6763) Service Instance
Names (RFC 6763 §4.1): the container hostname is the instance label, prepended to
the service type.

| Record | Name | Value |
|--------|------|-------|
| `SRV` | `<container-hostname>._<service>._<proto>.<host-fqdn>.` | Priority, weight, port, `<index>.<container-hostname>.<host-fqdn>.` |
| `TXT` | `<container-hostname>._<service>._<proto>.<host-fqdn>.` | Service metadata read from the container's `/etc/container-dns/txt` (RFC 6763 §6 `key=value`) |
| `PTR` | `_<service>._<proto>.<host-fqdn>.` | Each `<container-hostname>._<service>._<proto>.<host-fqdn>.` instance (DNS-SD browse) |

Priority and weight are both derived from each container's 1-minute load average, read from `/proc/loadavg` inside the container's namespace:

- **Priority**: containers are ranked by load ascending — the least-loaded container gets priority 0 (highest preference per RFC 2782). Useful for selecting the best container on the same host.
- **Weight**: `clamp(100 / (1 + load_avg), 1, 100)` — an absolute scalar so values are comparable across hosts.

**Example** — host `node1.internal`, two containers both named `redis`, one idle (load 0.0) and one busy (load 2.0):

```
redis._redis._tcp.node1.internal.  SRV  0 100 6379 0.redis.node1.internal.
redis._redis._tcp.node1.internal.  SRV  1  33 6379 1.redis.node1.internal.
```

### Service Metadata

A container may describe its endpoints for consumers (e.g. an HTTP uptime monitor) by shipping an INI-style file at **`/etc/container-dns/txt`**, read from the container's mount namespace. Sections are keyed by `port/proto`; each line is a raw [RFC 6763 §6](https://datatracker.ietf.org/doc/html/rfc6763#section-6) TXT `key=value` string. The values become the `TXT` record at the service's Service Instance Name:

```ini
# /etc/container-dns/txt
[8080/tcp]
txtvers=1
path=/api/health
expect=200

[3478/udp]
check=stun-binding
```

Because a service instance carries a single `TXT` record but may be served by several containers (replicas sharing a hostname), the metadata from the **lowest-PID** container wins; divergence between replicas is logged.

## Configuration

```toml
[dns_server]
bind_ip_addr = "0.0.0.0"
listen_port = 5353
allowed_record_networks = ["10.0.0.0/8", "192.168.0.0/16"]
allowed_query_networks = ["10.0.0.0/8", "192.168.0.0/16"]
max_ongoing_requests = 100
tcp_timeout = { secs = 5, nanos = 0 }
refresh_interval = { secs = 30, nanos = 0 }
# DNS domain appended to this host's hostname to form its FQDN and the zone this
# server is authoritative for (hostname "node1" + "internal" -> node1.internal).
# No trailing dot. Defaults to "local".
domain = "internal"
# Optional: export metrics via OTLP gRPC. Omit to disable metric export.
otlp_endpoint = "http://localhost:4317"

[dns_server.record_ttls]
srv = { secs = 60, nanos = 0 }
a = { secs = 60, nanos = 0 }
aaaa = { secs = 60, nanos = 0 }
ns = { secs = 3600, nanos = 0 }
# ptr and txt default to 60s if omitted
ptr = { secs = 60, nanos = 0 }
txt = { secs = 60, nanos = 0 }
```

### Metrics

When `otlp_endpoint` is configured, the following metrics are exported via OTLP gRPC:

| Metric | Type | Description |
|---|---|---|
| `dns_zone_size` | Gauge | Number of unique (record type, name) pairs in the DNS zone after each refresh |
| `dns_zone_refresh_duration_seconds` | Histogram | Duration of each zone refresh in seconds |
| `dns_query_duration_seconds` | Histogram | Duration of each DNS query in seconds |
| `dns_queries_total{status="success"}` | Counter | Total successful DNS queries |
| `dns_queries_total{status="failure"}` | Counter | Total failed DNS queries |


## Usage

```
container-dns [OPTIONS] <COMMAND>

Options:
  -c, --config-path <PATH>  Path to the configuration file  [default: /etc/container-dns/config.toml]
  -l, --log-level <LEVEL>   error | warn | info | debug | trace  [default: info]

Commands:
  serve   Start the DNS server
```

```sh
# Using the default config path
container-dns serve

# Specifying a custom config path
container-dns --config-path /path/to/config.toml serve
```

Must run as a user with permission to read `/proc/<pid>/ns/*` for all processes (typically root).

### Service Discovery with Caddy

Caddy can use SRV records published by container-dns to dynamically route traffic to containers across multiple hosts. Each `srv` block queries a different host's container-dns zone; Caddy merges the results and selects upstreams according to SRV priority and weight, which reflect the real-time load of each container. `{labels.3}` extracts the subdomain from the incoming request (e.g., `grafana` from `grafana.apps.example.com`) and is used as the container hostname — the leading instance label of the DNS-SD Service Instance Name (`<host>._<service>._<proto>.<fqdn>`).

Continuing the [example above](#example), a request to `grafana.apps.example.com` makes Caddy look up `grafana._http._tcp.<host>` on each host and proxy to the resolved target and port (`0.grafana.node1.internal:3000`):

```caddy
*.apps.example.com {
    reverse_proxy {
        dynamic multi {
            srv {labels.3}._http._tcp.node1.internal {
                refresh 15s
                grace_period 2m
            }
            srv {labels.3}._http._tcp.node2.internal {
                refresh 15s
                grace_period 2m
            }
        }
    }
}
```

This works because each container names its endpoint `http` in its own `/etc/services` (as `grafana` does with `http 3000/tcp` above), so container-dns publishes the matching `_http._tcp` records. Since it reads each container's `/etc/services` independently via the mount namespace, the same service name can sit on any port without conflict between containers.

For Caddy to resolve container-dns names, configure systemd-resolved on the Caddy host to forward queries for each container host's zone to the corresponding container-dns instance. Create one drop-in file per host (`/etc/systemd/resolved.conf.d/<host>.conf`):

```ini
# Queries for node1.internal forwarded to node1's container-dns
[Resolve]
DNS=<node1-container-dns-ip>:<port>
Domains=~node1.internal
```

```ini
# Queries for node2.internal forwarded to node2's container-dns
[Resolve]
DNS=<node2-container-dns-ip>:<port>
Domains=~node2.internal
```

The `~` prefix makes each entry a routing-only rule — only names under the specified FQDN are forwarded to that host's container-dns; all other queries go to the default resolver.
