import os
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, session

from passwords import verify_password
from storage import get_user, get_user_by_id, initialize_database


BASE_DIR = Path(__file__).resolve().parent
CONFIDENTIAL_FILES_DIR = Path(
    os.getenv("CONFIDENTIAL_FILES_DIR", str(BASE_DIR / "confidential_files"))
)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY") or secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "60"))
failed_logins = defaultdict(deque)
failed_logins_lock = threading.Lock()

SCHOOL_CLASSES = {
    "french": {"route": "/french", "class_name": "French"},
    "english": {"route": "/english", "class_name": "English"},
    "library": {"route": "/library", "class_name": "Library"},
    "technology": {"route": "/technology", "class_name": "Technology"},
}


def _login_key(username: str) -> str:
    return f"{request.remote_addr}:{username.lower()}"


def _trim_failures(key: str, now: float) -> deque:
    failures = failed_logins[key]
    while failures and now - failures[0] >= LOCKOUT_SECONDS:
        failures.popleft()
    return failures


def _login_allowed(key: str) -> bool:
    with failed_logins_lock:
        return len(_trim_failures(key, time.monotonic())) < MAX_FAILED_ATTEMPTS


def _record_failure(key: str) -> bool:
    with failed_logins_lock:
        failures = _trim_failures(key, time.monotonic())
        failures.append(time.monotonic())
        return len(failures) >= MAX_FAILED_ATTEMPTS


def _clear_failures(key: str) -> None:
    with failed_logins_lock:
        failed_logins.pop(key, None)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id or get_user_by_id(user_id) is None:
            session.clear()
            return jsonify(error="authentication required"), 401
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        user = get_user_by_id(user_id) if user_id else None
        if user is None:
            session.clear()
            return jsonify(error="authentication required"), 401
        if user["role"] != "admin":
            return jsonify(error="admin access required"), 403
        return view(*args, **kwargs)

    return wrapped_view


def class_response(class_key: str):
    return jsonify(network="school", **SCHOOL_CLASSES[class_key]), 200


@app.get("/")
def index():
    # no internal route inventory is exposed
    return jsonify(service="secure school application", status="ok"), 200


@app.get("/health")
def health():
    return jsonify(status="ok"), 200


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form.to_dict()
    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="invalid credentials"), 400

    key = _login_key(username)
    if not _login_allowed(key):
        return jsonify(error="too many failed attempts"), 429

    user = get_user(username)
    valid = (
        user is not None
        and bool(user["is_active"])
        and not bool(user["password_reset_required"])
        and verify_password(user["password_hash"], password)
    )
    if not valid:
        locked = _record_failure(key)
        if locked:
            return jsonify(error="too many failed attempts"), 429
        return jsonify(error="invalid credentials"), 401

    _clear_failures(key)
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify(
        decision="ALLOW",
        message="login successful",
        username=user["username"],
        role=user["role"],
    ), 200


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return jsonify(decision="LOGOUT"), 200


@app.get("/school")
@login_required
def school_network():
    # authenticated users get only the class map, no internal robot paths
    return jsonify(network="school", classes=list(SCHOOL_CLASSES.values())), 200


@app.get("/french")
@login_required
def french_class():
    return class_response("french")


@app.get("/english")
@login_required
def english_class():
    return class_response("english")


@app.get("/library")
@login_required
def library_class():
    return class_response("library")


@app.get("/technology")
@login_required
def technology_class():
    return class_response("technology")


@app.get("/admin")
@admin_required
def admin():
    return jsonify(
        access="admin",
        message="rights verification successful",
        username=session.get("username"),
        role="admin",
    ), 200


@app.get("/technology/robots")
@admin_required
def robots():
    # robot control stays behind network segmentation and authorization
    return jsonify(
        access="granted",
        message="robot access authorized",
        network="robot-internal",
    ), 200


@app.get("/confidential_files")
@admin_required
def confidential_files():
    files = sorted(
        file.name
        for file in CONFIDENTIAL_FILES_DIR.glob("*.md")
        if file.is_file()
    )
    return jsonify(
        access="granted",
        message="access to confidential files authorized",
        files=files,
    ), 200


initialize_database()


if __name__ == "__main__":
    app.run(
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", "5000")),
    )
