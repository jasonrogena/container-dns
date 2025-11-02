```
*.service.example.com {
    reverse_proxy {
        dynamic multi {
            dynamic srv _http._tcp.{labels.1}.node1.local {
                resolvers 192.168.1.2
                refresh 15s
                grace_period 5m 
            }

            dynamic srv _http._tcp.{labels.1}.node2.local {
                resolvers 192.168.1.3
                refresh 15s
                grace_period 5m 
            }
        }
    }
}
```