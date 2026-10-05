import json
import os
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, session

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
CONFIDENTIAL_FILES_DIR = BASE_DIR / "confidential_files"

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "vulnerable-local-secret")

with USERS_FILE.open(encoding="utf-8") as file:
    users = json.load(file)["users"]


# deliberately static map of the school's fictional network
# robotics laboratory belongs to the Technology class
SCHOOL_ROUTES = {
    "french": {
        "route": "/french",
        "class_name": "French",
        "type": "classroom",
        "resources": ["interactive whiteboard", "student workstations"],
    },
    "english": {
        "route": "/english",
        "class_name": "English",
        "type": "classroom",
        "resources": ["interactive whiteboard", "student workstations"],
    },
    "library": {
        "route": "/library",
        "class_name": "Library",
        "type": "documentation center",
        "resources": ["library catalog", "library workstations"],
    },
    "technology": {
        "route": "/technology",
        "class_name": "Technology",
        "type": "robotics laboratory",
        "resources": [
            "student computers",
            "research servers",
            "control network",
        ],
        "robot_routes": {
            "amr": {
                "route": "/technology/robots/amr",
                "name": "AMR",
                "type": "autonomous mobile robot",
                "firmware": "outdated",
                "status": "position to be checked",
            },
            "industrial_arm": {
                "route": "/technology/robots/industrial-arm",
                "name": "Industrial arm",
                "type": "industrial robot",
                "firmware": "outdated",
                "status": "available",
            },
            "cameras": {
                "route": "/technology/robots/cameras",
                "name": "Laboratory cameras",
                "type": "video sensors",
                "status": "active",
            },
            "lidar": {
                "route": "/technology/robots/lidar",
                "name": "LiDAR sensors",
                "type": "distance sensors",
                "status": "active",
            },
            "control_computers": {
                "route": "/technology/robots/control-computers",
                "name": "Control computers",
                "type": "control systems",
                "status": "connected",
            },
        },
    },
}


@app.get("/health")
def health():
    return jsonify(status="ok")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return jsonify(decision="DENY", error="authentication required"), 401
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return jsonify(decision="DENY", error="authentication required"), 401

        user = next(
            (item for item in users if item["username"] == session["username"]),
            None,
        )
        role = user.get("privilège", user.get("role", "user")) if user else "user"
        if role != "admin":
            return jsonify(decision="DENY", error="admin access required"), 403

        return view(*args, **kwargs)

    return wrapped_view


def school_class_response(class_key):
    return jsonify(network="school", **SCHOOL_ROUTES[class_key]), 200


def robot_response(robot_key):
    robot = SCHOOL_ROUTES["technology"]["robot_routes"][robot_key]
    return jsonify(network="school", parent_class="Technology", **robot), 200


def build_public_route_registry():
    """route inventory that is accidentally ㅋㅋㅋ exposed on the network"""
    routes = [
        {
            "path": "/",
            "name": "public route registry",
            "category": "route_registry",
            "method": "GET",
            "access": "public",
        },
        {
            "path": "/health",
            "name": "health check",
            "category": "discovery",
            "method": "GET",
            "access": "public",
        },
        {
            "path": "/login",
            "name": "login",
            "category": "authentication",
            "method": "POST",
            "access": "public",
        },
        {
            "path": "/logout",
            "name": "logout",
            "category": "authentication",
            "method": "POST",
            "access": "authenticated",
        },
        {
            "path": "/school",
            "name": "school network map",
            "category": "network_map",
            "method": "GET",
            "access": "authenticated",
        },
        {
            "path": "/admin",
            "name": "admin dashboard",
            "category": "authorization",
            "method": "GET",
            "access": "admin",
        },
        {
            "path": "/technology/robots",
            "name": "robot network",
            "category": "robot_network",
            "method": "GET",
            "access": "admin",
        },
        {
            "path": "/confidential_files",
            "name": "confidential files",
            "category": "confidential",
            "method": "GET",
            "access": "admin",
        },
        {
            "path": "/confidential-files",
            "name": "confidential files alias",
            "category": "confidential_alias",
            "method": "GET",
            "access": "admin",
        },
    ]

    for class_key, class_route in SCHOOL_ROUTES.items():
        routes.append(
            {
                "path": class_route["route"],
                "name": f"{class_key} class",
                "category": "class",
                "class_name": class_route["class_name"],
                "method": "GET",
                "access": "authenticated",
            }
        )

        if class_key != "technology":
            continue

        for robot_key, robot_route in class_route["robot_routes"].items():
            routes.append(
                {
                    "path": robot_route["route"],
                    "name": robot_route["name"],
                    "category": "robot_device",
                    "parent_class": "Technology",
                    "robot_key": robot_key,
                    "method": "GET",
                    "access": "admin",
                }
            )

    return routes


@app.get("/")
def public_route_registry():
    # the internal route inventory is public
    return jsonify(
        network="school",
        message="public route registry exposed by the school network",
        routes=build_public_route_registry(),
    ), 200


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form.to_dict()
    username = data.get("username")
    password = data.get("password")

    user = next(
        (item for item in users if item["username"] == username),
        None,
    )

    # passwords are stored and compared in plain text...json
    # no attempt-rate limiting
    if user is not None and user["password"] == password:
        session["username"] = username
        role = user.get("privilège", user.get("role", "user"))
        message = (
            f"connection successful with account: {username} "
            f"and password: {password}"
        )
        print(f"[VULN] LOGIN ALLOW user={username}", flush=True)
        return jsonify(
            decision="ALLOW",
            message=message,
            username=username,
            role=role,
        ), 200

    print(f"[VULN] LOGIN DENY user={username}", flush=True)
    return jsonify(decision="DENY", message="connection refused"), 401


@app.get("/school")
@login_required
def school_network():
    return jsonify(network="school", routes=SCHOOL_ROUTES), 200


@app.get("/french")
@login_required
def french_class():
    return school_class_response("french")


@app.get("/english")
@login_required
def english_class():
    return school_class_response("english")


@app.get("/library")
@login_required
def library_class():
    return school_class_response("library")


@app.get("/technology")
@login_required
def technology_class():
    return school_class_response("technology")


@app.get("/admin")
@admin_required
def admin():
    return jsonify(
        access="admin",
        message="rights verification in progress",
        result="admin user has admin access",
        username=session["username"],
        role="admin",
    ), 200


@app.get("/technology/robots")
@admin_required
def robots():
    return jsonify(
        access="granted",
        message="robot check in progress",
        network="school",
        parent_class="Technology",
        robots=SCHOOL_ROUTES["technology"]["robot_routes"],
        username=session["username"],
    ), 200


@app.get("/technology/robots/amr")
@admin_required
def amr():
    return robot_response("amr")


@app.get("/technology/robots/industrial-arm")
@admin_required
def industrial_arm():
    return robot_response("industrial_arm")


@app.get("/technology/robots/cameras")
@admin_required
def cameras():
    return robot_response("cameras")


@app.get("/technology/robots/lidar")
@admin_required
def lidar():
    return robot_response("lidar")


@app.get("/technology/robots/control-computers")
@admin_required
def control_computers():
    return robot_response("control_computers")


@app.get("/confidential_files")
@app.get("/confidential-files")
@admin_required
def confidential_files():
    files = sorted(
        file.name
        for file in CONFIDENTIAL_FILES_DIR.iterdir()
        if file.is_file() and file.suffix == ".md"
    )
    return jsonify(
        access="granted",
        message="access to confidential files",
        username=session["username"],
        files=files,
    ), 200


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(decision="LOGOUT"), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
