from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def load_networks(subnets_file: str) -> tuple[ipaddress.IPv4Network, ...]:
    path = Path(subnets_file)
    lines = path.read_text(encoding="utf-8").splitlines()
    nets: list[ipaddress.IPv4Network] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        nets.append(ipaddress.ip_network(s, strict=False))
    return tuple(nets)


def ipv4_in_pool(ip: str, networks: tuple[ipaddress.IPv4Network, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return any(addr in net for net in networks)
