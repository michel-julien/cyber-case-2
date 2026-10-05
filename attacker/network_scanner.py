import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests

from settings import AttackSettings


@dataclass(frozen=True)
class DiscoveredService:
    """HTTP service found through the lab network"""

    host: str
    base_url: str
    routes: list[dict]


def _json(response):
    try:
        return response.json()
    except ValueError:
        return {}


def _probe_url(base_url: str, timeout: float) -> DiscoveredService | None:
    """only use the generic HTTP root to discover an application"""
    try:
        response = requests.get(f"{base_url}/", timeout=timeout)
    except requests.RequestException:
        return None

    body = _json(response)
    if response.status_code != 200:
        return None

    # a secure service can answer the generic root request without exposing
    # its route inventory, empty list lets report that
    # protection and continue with the controlled test configuration.
    routes = body.get("routes", [])
    if not isinstance(routes, list):
        routes = []

    host = base_url.split("//", 1)[-1].split(":", 1)[0]
    return DiscoveredService(host=host, base_url=base_url, routes=routes)


def _infer_local_subnet() -> ipaddress.IPv4Network:
    """use attacker's container address when no subnet is configured"""
    local_ip = socket.gethostbyname(socket.gethostname())
    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def _probe_host(host: str, settings: AttackSettings) -> DiscoveredService | None:
    base_url = f"http://{host}:{settings.scan_port}"
    return _probe_url(base_url, settings.scan_timeout)


def scan_network(settings: AttackSettings, output=print) -> list[DiscoveredService]:
    """only scan the configured school subnet for the exposed route registry"""
    network = ipaddress.ip_network(
        settings.scan_subnet, strict=False
    ) if settings.scan_subnet else _infer_local_subnet()
    hosts = [str(host) for host in network.hosts()]
    output(
        f"scanning Docker network school: {network} "
        f"(TCP/{settings.scan_port})"
    )

    with ThreadPoolExecutor(max_workers=settings.scan_workers) as executor:
        discoveries = [
            service
            for service in executor.map(
                lambda host: _probe_host(host, settings), hosts
            )
            if service is not None
        ]

    for service in discoveries:
        output(f"school service discovered at {service.base_url}")
    return discoveries


def discover_target(settings: AttackSettings, output=print) -> DiscoveredService | None:
    """discover a target by scanning, or probe an explicitly supplied URL"""
    if settings.target_url:
        output(f"probing explicit target: {settings.target_url}")
        return _probe_url(settings.target_url, settings.scan_timeout)

    for attempt in range(1, 31):
        try:
            discoveries = scan_network(settings, output=output)
        except (OSError, ValueError) as error:
            output(f"network scan failed: {error}")
            return None

        if discoveries:
            if any(service.routes for service in discoveries):
                output("school route inventory exposed by a discovered service")
            else:
                output("school service discovered without an exposed route inventory")
            return discoveries[0]

        output(f"waiting for a school service ({attempt}/30)")
        time.sleep(1)

    return None
