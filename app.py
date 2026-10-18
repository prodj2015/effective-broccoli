import os
import hmac
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from flask import Flask, request, render_template, Response, jsonify
from pymongo import MongoClient, DESCENDING

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096  # reject oversized request bodies


def client_ip():
    # Render sits behind Cloudflare, which sets these headers itself.
    # X-Forwarded-For is NOT used: Render appends to it, so visitors can spoof it.
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("True-Client-IP")
        or request.remote_addr
    )


MONGO_URI = os.environ["MONGO_URI"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "90"))

visits = MongoClient(MONGO_URI)["sitedb"]["visits"]
try:
    # Old records delete themselves (helps with POPIA data minimisation).
    visits.create_index("time", expireAfterSeconds=RETENTION_DAYS * 86400)
except Exception as exc:
    print("Index creation failed:", exc)


# ---------- input cleaning: never trust what the browser sends ----------

def number(value, low, high):
    if isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f or not (low <= f <= high):  # f != f catches NaN
        return None
    return f


def text(value, limit=40):
    return value[:limit] if isinstance(value, str) else None


def clean_device(d):
    if not isinstance(d, dict):
        return None
    out = {}
    for key in ("screen_w", "screen_h", "viewport_w", "viewport_h"):
        n = number(d.get(key), 0, 20000)
        if n is not None:
            out[key] = int(n)
    ratio = number(d.get("pixel_ratio"), 0, 20)
    if ratio is not None:
        out["pixel_ratio"] = round(ratio, 2)
    for key in ("timezone", "language"):
        t = text(d.get(key))
        if t:
            out[key] = t
    for key in ("touch", "dark_mode"):
        if isinstance(d.get(key), bool):
            out[key] = d[key]
    return out or None


def clean_location(loc):
    if not isinstance(loc, dict):
        return None
    lat = number(loc.get("lat"), -90, 90)
    lon = number(loc.get("lon"), -180, 180)
    if lat is None or lon is None:
        return None
    out = {"lat": round(lat, 4), "lon": round(lon, 4)}  # 4 decimals is about 11 m
    acc = number(loc.get("accuracy"), 0, 1_000_000)
    if acc is not None:
        out["accuracy"] = int(acc)
    return out


# ---------- auth ----------

def require_admin(view):
    def wrapped(*args, **kwargs):
        auth = request.authorization
        ok = (
            auth is not None
            and hmac.compare_digest(auth.username or "", "admin")
            and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)
        )
        if not ok:
            return Response(
                "Login required", 401,
                {"WWW-Authenticate": 'Basic realm="Admin"'},
            )
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ---------- routes ----------

@app.route("/")
def index():
    result = visits.insert_one({
        "ip": client_ip(),
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "time": datetime.now(timezone.utc),
    })
    return render_template(
        "index.html", retention=RETENTION_DAYS, visit_id=str(result.inserted_id)
    )


@app.route("/collect", methods=["POST"])
def collect():
    """Called by the page only after the visitor clicks a consent button."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(ok=False), 400
    try:
        oid = ObjectId(str(data.get("visit_id", "")))
    except (InvalidId, TypeError):
        return jsonify(ok=False), 400

    ip = client_ip()
    # The IP must match the visit, and each field can be set only once.
    device = clean_device(data.get("device"))
    if device:
        visits.update_one(
            {"_id": oid, "ip": ip, "device": {"$exists": False}},
            {"$set": {"device": device}},
        )
    location = clean_location(data.get("location"))
    if location:
        visits.update_one(
            {"_id": oid, "ip": ip, "location": {"$exists": False}},
            {"$set": {"location": location}},
        )
    return jsonify(ok=True)


@app.route("/admin")
@require_admin
def admin():
    rows = list(visits.find().sort("time", DESCENDING).limit(200))
    return render_template("admin.html", rows=rows, total=visits.count_documents({}))


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
