```
*.apps.rogena.me {
    reverse_proxy {
        dynamic multi {
            srv _default_http_authenticated._tcp.{labels.3}.ironhide.cybertron.lan {
                refresh 15s
                grace_period 2m
            }
        }
    }
}
```