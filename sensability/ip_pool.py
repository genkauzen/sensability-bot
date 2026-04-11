from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

import httpx


def merge_ipv4_networks(
    *groups: tuple[ipaddress.IPv4Network, ...],
) -> tuple[ipaddress.IPv4Network, ...]:
    out: list[ipaddress.IPv4Network] = []
    for g in groups:
        out.extend(g)
    return tuple(out)


def parse_cidr_text(text: str) -> tuple[ipaddress.IPv4Network, ...]:
    nets: list[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        nets.append(ipaddress.ip_network(s, strict=False))
    return tuple(nets)


def fetch_cidr_networks_from_url(url: str, *, timeout: float = 25.0) -> tuple[ipaddress.IPv4Network, ...]:
    with httpx.Client(timeout=timeout) as c:
        r = c.get(url)
        r.raise_for_status()
    return parse_cidr_text(r.text)


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


@lru_cache(maxsize=1)
def load_potential_networks(subnets_file: str) -> tuple[ipaddress.IPv4Network, ...]:
    """Подсети для проверки «потенциала» (±2 к первым трем октетам от network_address)."""
    path = Path(subnets_file)
    if not path.is_file():
        return tuple()
    lines = path.read_text(encoding="utf-8").splitlines()
    nets: list[ipaddress.IPv4Network] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        nets.append(ipaddress.ip_network(s, strict=False))
    return tuple(nets)


def ipv4_near_potential_prefix(
    ip: str,
    ref: ipaddress.IPv4Network,
    *,
    delta: int = 2,
) -> bool:
    """Первые три октета полученного адреса в пределах ±delta от первых трёх октетов сети (как у 151.236.102/24 vs 151.236.104.x)."""
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if not isinstance(a, ipaddress.IPv4Address):
        return False
    r = ref.network_address
    return (
        abs(a.packed[0] - r.packed[0]) <= delta
        and abs(a.packed[1] - r.packed[1]) <= delta
        and abs(a.packed[2] - r.packed[2]) <= delta
    )


def ipv4_in_any_potential(
    ip: str,
    potential_nets: tuple[ipaddress.IPv4Network, ...],
    *,
    delta: int = 2,
) -> bool:
    if not potential_nets:
        return False
    return any(ipv4_near_potential_prefix(ip, net, delta=delta) for net in potential_nets)
