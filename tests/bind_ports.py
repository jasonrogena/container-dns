#!/usr/bin/env python3
# Binds TCP:80 (http) and UDP:53 (domain) then sleeps.
# Run inside a network namespace to simulate a container.
import socket
import time
import threading


def tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 80))
    s.listen(1)
    time.sleep(86400)


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 53))
    time.sleep(86400)


threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
time.sleep(86400)
