import os
import hmac
from datetime import datetime, timezone

from flask import Flask, request, render_template, Response
from pymongo import MongoClient, DESCENDING

app = Flask(__name__)


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


@app.route("/")
def index():
    visits.insert_one({
        "ip": client_ip(),
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "time": datetime.now(timezone.utc),
    })
    return render_template("index.html", retention=RETENTION_DAYS)


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
