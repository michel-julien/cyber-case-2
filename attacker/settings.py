import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AttackSettings:
    """configuration read from the environment for one lab run"""

    password_file: Path
    target_username: str
    target_url: str | None
    scan_subnet: str | None
    scan_port: int
    request_timeout: float
    scan_timeout: float
    scan_workers: int
    supplied_password: str | None
    supplied_routes: dict[str, str] | None


def load_settings() -> AttackSettings:
    base_dir = Path(__file__).resolve().parent
    target_url = os.getenv("TARGET_URL", "").strip().rstrip("/") or None
    supplied_route_values = {
        "login": os.getenv("SUPPLIED_LOGIN_PATH", "").strip(),
        "admin": os.getenv("SUPPLIED_ADMIN_PATH", "").strip(),
        "school_map": os.getenv("SUPPLIED_SCHOOL_PATH", "").strip(),
        "robot_network": os.getenv("SUPPLIED_ROBOT_PATH", "").strip(),
        "confidential_files": os.getenv(
            "SUPPLIED_CONFIDENTIAL_PATH", ""
        ).strip(),
    }
    supplied_routes = (
        supplied_route_values
        if all(supplied_route_values.values())
        else None
    )

    return AttackSettings(
        password_file=Path(
            os.getenv("PASSWORD_FILE", str(base_dir / "most-use-passwords.txt"))
        ),
        target_username=os.getenv("TARGET_USERNAME", "admin"),
        target_url=target_url,
        scan_subnet=os.getenv("SCHOOL_SUBNET") or None,
        scan_port=int(os.getenv("SCHOOL_HTTP_PORT", "5000")),
        request_timeout=float(os.getenv("REQUEST_TIMEOUT", "5")),
        scan_timeout=float(os.getenv("SCAN_TIMEOUT", "0.4")),
        scan_workers=int(os.getenv("SCAN_WORKERS", "32")),
        supplied_password=os.getenv("SUPPLIED_PASSWORD") or None,
        supplied_routes=supplied_routes,
    )
