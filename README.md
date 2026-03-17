# container-dns

A DNS server that automatically exposes services running inside Linux containers, without depending on any specific container engine.

## Design Decisions

As much as possible, we rely on native Linux constructs to discover the properties for the containers to expose making container-dns compatible with Docker, Podman, LXC, systemd-nspawn, or anything else that uses Linux namespaces, without depending on any engine-specific API:

- A container of interest is defined as any process in a **different network namespace** from the host.
- Container hostnames are read by entering each container's **UTS namespace** and reading the hostname.
- Container IP addresses are enumerated by entering each container's **network namespace**.
- Listening ports are discovered from `/proc/<pid>/net/tcp` rather than querying a runtime.
- Service names are resolved by entering each container's **mount namespace** and reading its `/etc/services`.
- Container load is measured by entering each container's **mount namespace** and reading `/proc/loadavg`, which reflects the load of the container's PID namespace since kernel 4.14.

## DNS Records

container-dns exposes the following DNS records for the host, containers, and services running in the containers:

### Per Host

| Record | Name | Value |
|--------|------|-------|
| `NS` | `<host-fqdn>.` | `container-ns.<host-fqdn>.` |
| `A`/`AAAA` | `container-ns.<host-fqdn>.` | Host's IP addresses |

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

| Record | Name | Value |
|--------|------|-------|
| `SRV` | `_<service>._<proto>.<container-hostname>.<host-fqdn>.` | Priority, weight, port, `<index>.<container-hostname>.<host-fqdn>.` |

Priority and weight are both derived from each container's 1-minute load average, read from `/proc/loadavg` inside the container's namespace:

- **Priority**: containers are ranked by load ascending — the least-loaded container gets priority 0 (highest preference per RFC 2782). Useful for selecting the best container on the same host.
- **Weight**: `clamp(100 / (1 + load_avg), 1, 100)` — an absolute scalar so values are comparable across hosts.

**Example** — host `node1.internal`, two containers both named `redis`, one idle (load 0.0) and one busy (load 2.0):

```
_redis._tcp.redis.node1.internal.  SRV  0 100 6379 0.redis.node1.internal.
_redis._tcp.redis.node1.internal.  SRV  1  33 6379 1.redis.node1.internal.
```

## Configuration

```toml
[dns_server]
bind_ip_addr = "0.0.0.0"
listen_port = 5353
allowed_networks = ["10.0.0.0/8", "192.168.0.0/16"]
max_ongoing_requests = 100

[dns_server.refresh_interval]
secs = 30
nanos = 0

[dns_server.tcp_timeout]
secs = 5
nanos = 0

[dns_server.record_ttls.srv]
secs = 60
nanos = 0

[dns_server.record_ttls.a]
secs = 60
nanos = 0

[dns_server.record_ttls.ns]
secs = 3600
nanos = 0
```

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

Caddy can use SRV records published by container-dns to dynamically route traffic to containers. The `dynamic srv` upstream resolver queries container-dns for the service matching the incoming hostname and proxies to whatever containers are currently registered.

```caddy
*.apps.example.com {
    reverse_proxy {
        dynamic multi {
            srv _default_http._tcp.{labels.3}.<host-fqdn> {
                refresh 15s
                grace_period 2m
            }
        }
    }
}
```

`{labels.3}` extracts the subdomain from the incoming request (e.g., `myapp` from `myapp.apps.example.com`) and uses it as the container hostname to look up in container-dns. The `resolvers` directive (commented out above) can be used to point Caddy directly at container-dns if it is not the system resolver.

For this to work, each container must declare its service in `/etc/services` with the `default_http` alias so that container-dns publishes the right SRV record. For example, two containers — `home-assistant` and `nextcloud` — would each have an entry like this in their own `/etc/services`:

```
# /etc/services inside the home-assistant container
home-assistant    8123/tcp    default_http

# /etc/services inside the nextcloud container
nextcloud    80/tcp    default_http
```

container-dns reads each container's `/etc/services` independently via its mount namespace, so the alias can be assigned to any port without conflict between containers.

For Caddy to resolve container-dns names without the `resolvers` override, configure systemd-resolved to forward queries for the host's zone to container-dns (`/etc/systemd/resolved.conf.d/container-dns.conf`):

```ini
[Resolve]
DNS=<container-dns-ip>:<port>
Domains=~<host-fqdn>
```

The `~` prefix makes this a routing-only rule — only names under `<host-fqdn>` are forwarded to container-dns; all other queries go to the default resolver.
