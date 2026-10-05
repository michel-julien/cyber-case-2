from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveredRoutes:
    """sensitive paths selected from the server-provided route inventory"""

    login: str
    admin: str
    school_map: str
    robot_network: str
    confidential_files: str


def _find_path(routes: list[dict], category: str) -> str | None:
    for route in routes:
        if route.get("category") == category:
            return route.get("path")
    return None


def discover_routes(routes: list[dict]) -> DiscoveredRoutes | None:
    """rresolve every path by category no application path is hard coded here!!"""
    paths = {
        "login": _find_path(routes, "authentication"),
        "admin": _find_path(routes, "authorization"),
        "school_map": _find_path(routes, "network_map"),
        "robot_network": _find_path(routes, "robot_network"),
        "confidential_files": _find_path(routes, "confidential"),
    }
    if not all(paths.values()):
        return None
    return DiscoveredRoutes(**paths)


def use_supplied_routes(route_map: dict[str, str] | None) -> DiscoveredRoutes | None:
    """use paths supplied by the lab operator when discovery is protected to gu further for app_secure"""
    if not route_map or not all(route_map.values()):
        return None
    return DiscoveredRoutes(**route_map)
