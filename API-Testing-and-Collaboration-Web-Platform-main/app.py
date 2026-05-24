"""
API Testing Platform - Flask + SQLite only.
Server-rendered pages: /, /login, /signup, /dashboard. REST API under /api/*.
"""
import os
import json
import time
import functools
import traceback
from flask import Flask, request, jsonify, make_response, redirect, url_for, render_template, flash
from flask_cors import CORS
import jwt
import bcrypt
import requests as http_requests

from db import get_db, init_db, row_to_dict, safe_json

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
CORS(app, supports_credentials=True)

# Initialize database tables for serverless environments
try:
    init_db()
except Exception as _e:
    print("init_db failed:", _e)

CALL_LOG = []


@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler - returns JSON with error details for debugging."""
    tb = traceback.format_exc()
    print("UNHANDLED EXCEPTION:", tb)
    # For HTML routes, render a friendly error page
    if request.accept_mimetypes.accept_html:
        return f"""<html><body style='font-family:monospace;padding:2rem;background:#0f0f1a;color:#f38ba8'>
<h2>Internal Error</h2><pre style='color:#cdd6f4;font-size:0.85rem'>{tb}</pre>
<a href='/dashboard' style='color:#89b4fa'>Back to Dashboard</a></body></html>""", 500
    return jsonify({"error": str(e), "traceback": tb}), 500


def get_token():
    return request.cookies.get("token") or (request.headers.get("Authorization") or "").replace("Bearer ", "")


def sign_token(user_id, email="", name="", role="member"):
    return jwt.encode(
        {
            "userId": str(user_id),
            "email": email,
            "name": name,
            "role": role,
            "exp": int(time.time()) + 7 * 24 * 3600,
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )


def require_auth(f):
    """Validate JWT only — no DB lookup so Vercel cold-starts don't log users out."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        token = get_token()
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user_id = payload.get("userId")
            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401
            return f(user_id=str(user_id), *args, **kwargs)
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
    return wrapped


def get_current_user():
    """Return (user_id, user_dict) or None. Falls back to JWT payload if DB is empty (Vercel cold start)."""
    token = get_token()
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload.get("userId")
        if not user_id:
            return None
        # Try DB first (accurate data); fall back to JWT payload on cold starts
        try:
            conn = get_db()
            row = conn.execute("SELECT id, email, name, role FROM users WHERE id = ?", (int(user_id),)).fetchone()
            conn.close()
            if row:
                return str(row["id"]), {"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"]}
        except Exception:
            pass
        # Fallback: trust JWT payload (survives Vercel SQLite cold-start resets)
        return str(user_id), {
            "id": user_id,
            "email": payload.get("email", ""),
            "name": payload.get("name", "User"),
            "role": payload.get("role", "member"),
        }
    except Exception:
        return None


def can_access_workspace(user_id, workspace_id):
    conn = get_db()
    row = conn.execute(
        "SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
        (int(workspace_id), int(user_id)),
    ).fetchone()
    conn.close()
    return row is not None


# ---- Health ----
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


# ---- Auth (API) ----
@app.route("/api/auth/signup", methods=["POST"])
def signup_api():
    try:
        data = request.get_json() or {}
        em = (data.get("email") or "").strip()
        pw = data.get("password") if isinstance(data.get("password"), str) else ""
        nm = (data.get("name") or "").strip()
        if not em or not pw or not nm:
            return jsonify({"error": "Email, password and name required"}), 400
        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE email = ?", (em,)).fetchone():
            conn.close()
            return jsonify({"error": "Email already registered"}), 400
        hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
        cur = conn.execute("INSERT INTO users (email, password, name) VALUES (?, ?, ?)", (em, hashed, nm))
        user_id = cur.lastrowid
        cur = conn.execute("INSERT INTO workspaces (name, type, owner_id) VALUES (?, 'personal', ?)", (f"{nm}'s Workspace", user_id))
        ws_id = cur.lastrowid
        conn.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (?, ?)", (ws_id, user_id))
        conn.commit()
        conn.close()
        token = sign_token(user_id, email=em, name=nm, role="member")
        resp = make_response(jsonify({"user": {"id": user_id, "email": em, "name": nm, "role": "member"}, "workspaceId": str(ws_id)}), 201)
        resp.set_cookie("token", token, max_age=7 * 24 * 3600, httponly=True, samesite="Lax")
        return resp
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"error": "Email already registered"}), 400
        return jsonify({"error": str(e) or "Signup failed"}), 500


@app.route("/api/auth/login", methods=["POST"])
def login_api():
    try:
        data = request.get_json() or {}
        em = data.get("email")
        pw = data.get("password")
        if not em or not pw:
            return jsonify({"error": "Email and password required"}), 400
        conn = get_db()
        row = conn.execute("SELECT id, email, name, role, password FROM users WHERE email = ?", (em,)).fetchone()
        conn.close()
        if not row or not bcrypt.checkpw(pw.encode("utf-8"), row["password"].encode("utf-8")):
            return jsonify({"error": "Invalid credentials"}), 401
        token = sign_token(row["id"], email=row["email"], name=row["name"], role=row["role"])
        resp = make_response(jsonify({"user": {"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"]}}))
        resp.set_cookie("token", token, max_age=7 * 24 * 3600, httponly=True, samesite="Lax")
        return resp
    except Exception:
        return jsonify({"error": "Login failed"}), 500


@app.route("/api/auth/logout", methods=["POST"])
def logout_api():
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("token", "", max_age=0)
    return resp


@app.route("/api/auth/me")
@require_auth
def me(user_id):
    try:
        init_db()
        conn = get_db()
        row = conn.execute("SELECT id, email, name, role FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if row:
            user = {"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"]}
            ws_rows = conn.execute(
                "SELECT w.id, w.name, w.type FROM workspaces w INNER JOIN workspace_members wm ON wm.workspace_id = w.id WHERE wm.user_id = ?",
                (int(user_id),),
            ).fetchall()
            conn.close()
            workspaces = [{"_id": str(r["id"]), "name": r["name"], "type": r["type"]} for r in ws_rows]
            return jsonify({"user": user, "workspaces": workspaces})
        conn.close()
    except Exception:
        pass
    # Fallback: token is valid but DB is empty (Vercel cold start)
    # Decode JWT to get embedded user info
    try:
        token = get_token()
        payload = __import__('jwt').decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = {
            "id": user_id,
            "email": payload.get("email", ""),
            "name": payload.get("name", "User"),
            "role": payload.get("role", "member"),
        }
        return jsonify({"user": user, "workspaces": []})
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401


# ---- HTML pages ----
@app.route("/")
def index():
    user = get_current_user()
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        em = (request.form.get("email") or "").strip()
        pw = request.form.get("password") or ""
        if not em or not pw:
            flash("Email and password are required.", "error")
            return render_template("login.html", error="Email and password required")
        conn = get_db()
        row = conn.execute("SELECT id, email, name, role, password FROM users WHERE email = ?", (em,)).fetchone()
        conn.close()
        if not row or not bcrypt.checkpw(pw.encode("utf-8"), row["password"].encode("utf-8")):
            flash("Invalid email or password.", "error")
            return render_template("login.html", error="Invalid credentials")
        token = sign_token(row["id"], email=row["email"], name=row["name"], role=row["role"])
        flash("Welcome back!", "success")
        resp = make_response(redirect(url_for("dashboard")))
        resp.set_cookie("token", token, max_age=7 * 24 * 3600, httponly=True, samesite="Lax")
        return resp
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if request.method == "POST":
        em = (request.form.get("email") or "").strip()
        pw = request.form.get("password") or ""
        nm = (request.form.get("name") or "").strip()
        if not em or not pw or not nm:
            flash("Email, password and name are required.", "error")
            return render_template("signup.html", error="Email, password and name required")
        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE email = ?", (em,)).fetchone():
            conn.close()
            flash("That email is already registered.", "error")
            return render_template("signup.html", error="Email already registered")
        hashed = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
        cur = conn.execute("INSERT INTO users (email, password, name) VALUES (?, ?, ?)", (em, hashed, nm))
        user_id = cur.lastrowid
        cur = conn.execute("INSERT INTO workspaces (name, type, owner_id) VALUES (?, 'personal', ?)", (f"{nm}'s Workspace", user_id))
        ws_id = cur.lastrowid
        conn.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (?, ?)", (ws_id, user_id))
        conn.commit()
        conn.close()
        token = sign_token(user_id, email=em, name=nm, role="member")
        flash("Account created. Welcome!", "success")
        resp = make_response(redirect(url_for("dashboard")))
        resp.set_cookie("token", token, max_age=7 * 24 * 3600, httponly=True, samesite="Lax")
        return resp
    return render_template("signup.html")


@app.route("/logout", methods=["GET", "POST"])
def logout_page():
    resp = make_response(redirect(url_for("login_page")))
    resp.set_cookie("token", "", max_age=0)
    return resp


@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for("login_page"))
    user_id, user_dict = user
    try:
        init_db()  # Ensure tables exist on cold start
        conn = get_db()
        ws_rows = conn.execute(
            "SELECT w.id, w.name, w.type FROM workspaces w INNER JOIN workspace_members wm ON wm.workspace_id = w.id WHERE wm.user_id = ?",
            (int(user_id),),
        ).fetchall()
        workspaces = [{"id": r["id"], "name": r["name"], "type": r["type"]} for r in ws_rows]
        conn.close()
    except Exception:
        workspaces = []
    return render_template("dashboard.html", user=user_dict, workspaces=workspaces)


@app.route("/analytics")
def analytics_page():
    user = get_current_user()
    if not user:
        return redirect(url_for("login_page"))
    user_id, user_dict = user
    try:
        init_db()
        conn = get_db()
        ws_rows = conn.execute(
            "SELECT w.id, w.name FROM workspaces w INNER JOIN workspace_members wm ON wm.workspace_id = w.id WHERE wm.user_id = ?",
            (int(user_id),),
        ).fetchall()
        workspaces = [{"id": r["id"], "name": r["name"]} for r in ws_rows]
        conn.close()
    except Exception:
        workspaces = []
    return render_template("analytics.html", user=user_dict, workspaces=workspaces)


@app.route("/notifications")
def notifications_page():
    user = get_current_user()
    if not user:
        return redirect(url_for("login_page"))
    try:
        init_db()
    except Exception:
        pass
    return render_template("notifications.html", user=user[1])


# ---- Workspaces (API) ----
@app.route("/api/workspaces", methods=["GET"])
@require_auth
def list_workspaces(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT w.id, w.name, w.type, w.owner_id FROM workspaces w INNER JOIN workspace_members wm ON wm.workspace_id = w.id WHERE wm.user_id = ?",
        (int(user_id),),
    ).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "name": r["name"], "type": r["type"], "ownerId": str(r["owner_id"])} for r in rows])


@app.route("/api/workspaces", methods=["POST"])
@require_auth
def create_workspace(user_id):
    data = request.get_json() or {}
    name = data.get("name") or "New Workspace"
    wtype = data.get("type") or "team"
    conn = get_db()
    cur = conn.execute("INSERT INTO workspaces (name, type, owner_id) VALUES (?, ?, ?)", (name, wtype, int(user_id)))
    ws_id = cur.lastrowid
    conn.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (?, ?)", (ws_id, int(user_id)))
    conn.commit()
    row = conn.execute("SELECT id, name, type FROM workspaces WHERE id = ?", (ws_id,)).fetchone()
    conn.close()
    return jsonify({"_id": str(row["id"]), "name": row["name"], "type": row["type"], "ownerId": user_id}), 201


@app.route("/api/workspaces/<int:wid>")
@require_auth
def get_workspace(user_id, wid):
    conn = get_db()
    row = conn.execute(
        "SELECT w.id, w.name, w.type FROM workspaces w INNER JOIN workspace_members wm ON wm.workspace_id = w.id WHERE w.id = ? AND wm.user_id = ?",
        (wid, int(user_id)),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"_id": str(row["id"]), "name": row["name"], "type": row["type"]})


# ---- Collections (API) ----
@app.route("/api/collections")
@require_auth
def list_collections(user_id):
    workspace_id = request.args.get("workspaceId")
    if not workspace_id:
        return jsonify({"error": "workspaceId required"}), 400
    if not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "Forbidden"}), 403
    conn = get_db()
    rows = conn.execute("SELECT id, name, workspace_id FROM collections WHERE workspace_id = ?", (int(workspace_id),)).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "name": r["name"], "workspaceId": str(r["workspace_id"])} for r in rows])


@app.route("/api/collections", methods=["POST"])
@require_auth
def create_collection(user_id):
    data = request.get_json() or {}
    name = data.get("name") or "New Collection"
    workspace_id = data.get("workspaceId")
    if not workspace_id:
        return jsonify({"error": "workspaceId required"}), 400
    if not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "Forbidden"}), 403
    conn = get_db()
    cur = conn.execute("INSERT INTO collections (name, workspace_id) VALUES (?, ?)", (name, int(workspace_id)))
    cid = cur.lastrowid
    row = conn.execute("SELECT id, name, workspace_id FROM collections WHERE id = ?", (cid,)).fetchone()
    conn.commit()
    conn.close()
    return jsonify({"_id": str(row["id"]), "name": row["name"], "workspaceId": str(row["workspace_id"])}), 201


@app.route("/api/collections/<int:cid>", methods=["PATCH"])
@require_auth
def update_collection(user_id, cid):
    conn = get_db()
    row = conn.execute("SELECT id, workspace_id FROM collections WHERE id = ?", (cid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not can_access_workspace(user_id, str(row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json() or {}
    if data.get("name"):
        conn.execute("UPDATE collections SET name = ?, updated_at = datetime('now') WHERE id = ?", (data["name"], cid))
        conn.commit()
    row = conn.execute("SELECT id, name, workspace_id FROM collections WHERE id = ?", (cid,)).fetchone()
    conn.close()
    return jsonify({"_id": str(row["id"]), "name": row["name"], "workspaceId": str(row["workspace_id"])})


@app.route("/api/collections/<int:cid>", methods=["DELETE"])
@require_auth
def delete_collection(user_id, cid):
    conn = get_db()
    row = conn.execute("SELECT id, workspace_id FROM collections WHERE id = ?", (cid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not can_access_workspace(user_id, str(row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    conn.execute("DELETE FROM collections WHERE id = ?", (cid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---- Requests (API) ----
def api_request_to_json(r):
    return {
        "_id": str(r["id"]),
        "name": r["name"],
        "method": r["method"],
        "url": r["url"],
        "headers": safe_json(r["headers"]),
        "queryParams": safe_json(r["query_params"]),
        "body": r["body"] or "",
        "bodyType": r["body_type"] or "json",
        "collectionId": str(r["collection_id"]) if r["collection_id"] else None,
        "workspaceId": str(r["workspace_id"]),
        "createdBy": str(r["created_by"]) if r["created_by"] else None,
    }


@app.route("/api/requests")
@require_auth
def list_requests(user_id):
    workspace_id = request.args.get("workspaceId")
    if not workspace_id:
        return jsonify({"error": "workspaceId required"}), 400
    if not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "Forbidden"}), 403
    collection_id = request.args.get("collectionId")
    conn = get_db()
    if collection_id:
        rows = conn.execute(
            "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE workspace_id = ? AND collection_id = ? ORDER BY updated_at DESC",
            (int(workspace_id), int(collection_id)),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE workspace_id = ? ORDER BY updated_at DESC",
            (int(workspace_id),),
        ).fetchall()
    conn.close()
    return jsonify([api_request_to_json(dict(r)) for r in rows])


@app.route("/api/requests/<int:rid>")
@require_auth
def get_request(user_id, rid):
    conn = get_db()
    row = conn.execute(
        "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE id = ?",
        (rid,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not can_access_workspace(user_id, str(row["workspace_id"])):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(api_request_to_json(dict(row)))


@app.route("/api/requests", methods=["POST"])
@require_auth
def create_request(user_id):
    data = request.get_json() or {}
    workspace_id = data.get("workspaceId")
    if not workspace_id:
        return jsonify({"error": "workspaceId required"}), 400
    if not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "Forbidden"}), 403
    name = data.get("name") or "Untitled"
    method = data.get("method") or "GET"
    url = data.get("url") or ""
    headers = json.dumps(data.get("headers") or {})
    query_params = json.dumps(data.get("queryParams") or {})
    body = data.get("body") or ""
    body_type = data.get("bodyType") or "json"
    collection_id = data.get("collectionId")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO api_requests (name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (name, method, url, headers, query_params, body, body_type, int(collection_id) if collection_id else None, int(workspace_id), int(user_id)),
    )
    rid = cur.lastrowid
    snap = {"name": name, "method": method, "url": url, "headers": data.get("headers") or {}, "queryParams": data.get("queryParams") or {}, "body": body, "bodyType": body_type, "collectionId": collection_id, "workspaceId": workspace_id, "createdBy": user_id}
    conn.execute("INSERT INTO request_history (request_id, snapshot, version, created_by) VALUES (?, ?, 1, ?)", (rid, json.dumps(snap), int(user_id)))
    conn.commit()
    row = conn.execute(
        "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE id = ?",
        (rid,),
    ).fetchone()
    conn.close()
    return jsonify(api_request_to_json(dict(row))), 201


@app.route("/api/requests/<int:rid>", methods=["PATCH"])
@require_auth
def update_request(user_id, rid):
    conn = get_db()
    row = conn.execute("SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id FROM api_requests WHERE id = ?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not can_access_workspace(user_id, str(row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json() or {}
    updates = []
    params = []
    for key, col in [("name", "name"), ("method", "method"), ("url", "url"), ("body", "body"), ("bodyType", "body_type")]:
        if key in data and data[key] is not None:
            updates.append(f"{col} = ?")
            params.append(data[key])
    if "headers" in data:
        updates.append("headers = ?")
        params.append(json.dumps(data["headers"]) if data["headers"] is not None else "{}")
    if "queryParams" in data:
        updates.append("query_params = ?")
        params.append(json.dumps(data["queryParams"]) if data["queryParams"] is not None else "{}")
    if "collectionId" in data:
        updates.append("collection_id = ?")
        params.append(int(data["collectionId"]) if data["collectionId"] else None)
    if updates:
        params.append(rid)
        conn.execute("UPDATE api_requests SET " + ", ".join(updates) + ", updated_at = datetime('now') WHERE id = ?", params)
        count = conn.execute("SELECT COUNT(*) AS c FROM request_history WHERE request_id = ?", (rid,)).fetchone()["c"]
        snap = {
            "name": data.get("name", row["name"]),
            "method": data.get("method", row["method"]),
            "url": data.get("url", row["url"]),
            "headers": data.get("headers") if "headers" in data else safe_json(row["headers"]),
            "queryParams": data.get("queryParams") if "queryParams" in data else safe_json(row["query_params"]),
            "body": data.get("body", row["body"]),
            "bodyType": data.get("bodyType", row["body_type"]),
            "collectionId": data.get("collectionId") if "collectionId" in data else (str(row["collection_id"]) if row["collection_id"] else None),
            "workspaceId": str(row["workspace_id"]),
        }
        conn.execute("INSERT INTO request_history (request_id, snapshot, version, created_by) VALUES (?, ?, ?, ?)", (rid, json.dumps(snap), count + 1, int(user_id)))
        conn.commit()
    row = conn.execute(
        "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE id = ?",
        (rid,),
    ).fetchone()
    conn.close()
    return jsonify(api_request_to_json(dict(row)))


@app.route("/api/requests/<int:rid>", methods=["DELETE"])
@require_auth
def delete_request(user_id, rid):
    conn = get_db()
    row = conn.execute("SELECT id, workspace_id FROM api_requests WHERE id = ?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not can_access_workspace(user_id, str(row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    conn.execute("DELETE FROM api_requests WHERE id = ?", (rid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/requests/history/<int:rid>")
@require_auth
def request_history(user_id, rid):
    conn = get_db()
    req_row = conn.execute("SELECT workspace_id FROM api_requests WHERE id = ?", (rid,)).fetchone()
    if not req_row or not can_access_workspace(user_id, str(req_row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    rows = conn.execute("SELECT id, request_id, snapshot, version, created_at FROM request_history WHERE request_id = ? ORDER BY version DESC", (rid,)).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "requestId": str(r["request_id"]), "snapshot": safe_json(r["snapshot"]), "version": r["version"], "createdAt": r["created_at"]} for r in rows])


@app.route("/api/requests/<int:rid>/revert/<int:version>", methods=["POST"])
@require_auth
def revert_request(user_id, rid, version):
    conn = get_db()
    hist = conn.execute("SELECT snapshot FROM request_history WHERE request_id = ? AND version = ?", (rid, version)).fetchone()
    if not hist:
        conn.close()
        return jsonify({"error": "Version not found"}), 404
    req_row = conn.execute("SELECT id, workspace_id FROM api_requests WHERE id = ?", (rid,)).fetchone()
    if not req_row or not can_access_workspace(user_id, str(req_row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    snap = safe_json(hist["snapshot"])
    conn.execute(
        "UPDATE api_requests SET name = ?, method = ?, url = ?, headers = ?, query_params = ?, body = ?, body_type = ?, collection_id = ?, updated_at = datetime('now') WHERE id = ?",
        (snap.get("name"), snap.get("method"), snap.get("url"), json.dumps(snap.get("headers", {})), json.dumps(snap.get("queryParams", {})), snap.get("body", ""), snap.get("bodyType", "json"), int(snap["collectionId"]) if snap.get("collectionId") else None, rid),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id, name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by FROM api_requests WHERE id = ?",
        (rid,),
    ).fetchone()
    conn.close()
    return jsonify(api_request_to_json(dict(row)))


# ---- Execute ----
def log_api_call(user_id, workspace_id, method, url, status, response_time):
    CALL_LOG.append({"userId": user_id, "workspaceId": workspace_id, "method": method, "url": url, "status": status, "responseTime": response_time, "at": time.time()})
    if len(CALL_LOG) > 5000:
        CALL_LOG[:1000] = []


@app.route("/api/execute", methods=["POST"])
@require_auth
def execute(user_id):
    try:
        data = request.get_json() or {}
        method = (data.get("method") or "GET").upper()
        url = data.get("url")
        if not url:
            return jsonify({"error": "url required"}), 400
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return jsonify({"error": "Invalid method"}), 400
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        parsed = urlparse(url)
        qs = data.get("queryParams") or {}
        new_qs = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in qs.items():
            if v is not None and v != "":
                new_qs[k] = [str(v)]
        new_query = urlencode(new_qs, doseq=True)
        final_url = urlunparse(parsed._replace(query=new_query))
        headers = {"Content-Type": "application/json", **(data.get("headers") or {})}
        body = data.get("body")
        if method != "GET" and body is not None and body != "":
            req_body = body if isinstance(body, str) else json.dumps(body)
        else:
            req_body = None
        start = time.time()
        resp = http_requests.request(method, final_url, headers=headers, data=req_body, timeout=30)
        response_time = int((time.time() - start) * 1000)
        try:
            data_out = resp.json()
        except Exception:
            data_out = resp.text
        workspace_id = data.get("workspaceId")
        if workspace_id:
            log_api_call(user_id, workspace_id, method, final_url, resp.status_code, response_time)
            if resp.status_code >= 400:
                conn = get_db()
                conn.execute(
                    "INSERT INTO notifications (user_id, type, title, body, meta) VALUES (?, 'api_failed', 'API request failed', ?, ?)",
                    (int(user_id), f"{method} {final_url} → {resp.status_code}", json.dumps({"url": final_url, "method": method, "status": resp.status_code})),
                )
                conn.commit()
                conn.close()
        return jsonify({"status": resp.status_code, "statusText": resp.reason, "responseTime": response_time, "headers": dict(resp.headers), "data": data_out})
    except Exception as e:
        msg = str(e) if e else "Request failed"
        if request.get_json():
            d = request.get_json()
            if d.get("workspaceId"):
                log_api_call(user_id, d["workspaceId"], (d.get("method") or "GET").upper(), d.get("url") or "", 0, 0)
        return jsonify({"error": msg, "responseTime": 0}), 502


# ---- Mock ----
@app.route("/api/mock/server/<workspace_id>/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def mock_server(workspace_id, path):
    path = "/" + path
    conn = get_db()
    row = conn.execute(
        "SELECT status_code, response_body FROM mock_endpoints WHERE workspace_id = ? AND path = ? AND method = ?",
        (int(workspace_id), path, request.method),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Mock not found", "path": path, "method": request.method}), 404
    body = safe_json(row["response_body"])
    return jsonify(body) if isinstance(body, dict) else body, row["status_code"]


@app.route("/api/mock/endpoints")
@require_auth
def list_mock_endpoints(user_id):
    workspace_id = request.args.get("workspaceId")
    if not workspace_id or not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "workspaceId required"}), 400 if not workspace_id else (jsonify({"error": "Forbidden"}), 403)
    conn = get_db()
    rows = conn.execute("SELECT id, path, method, status_code, response_body, workspace_id FROM mock_endpoints WHERE workspace_id = ?", (int(workspace_id),)).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "path": r["path"], "method": r["method"], "statusCode": r["status_code"], "responseBody": safe_json(r["response_body"]), "workspaceId": str(r["workspace_id"])} for r in rows])


@app.route("/api/mock/endpoints", methods=["POST"])
@require_auth
def create_mock_endpoint(user_id):
    data = request.get_json() or {}
    workspace_id = data.get("workspaceId")
    path = data.get("path")
    if not workspace_id or not path:
        return jsonify({"error": "workspaceId and path required"}), 400
    if not can_access_workspace(user_id, workspace_id):
        return jsonify({"error": "Forbidden"}), 403
    path = path if path.startswith("/") else "/" + path
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO mock_endpoints (path, method, status_code, response_body, workspace_id) VALUES (?, ?, ?, ?, ?)",
        (path, data.get("method") or "GET", data.get("statusCode") or 200, json.dumps(data.get("responseBody") or {}), int(workspace_id)),
    )
    rid = cur.lastrowid
    row = conn.execute("SELECT id, path, method, status_code, response_body, workspace_id FROM mock_endpoints WHERE id = ?", (rid,)).fetchone()
    conn.commit()
    conn.close()
    return jsonify({"_id": str(row["id"]), "path": row["path"], "method": row["method"], "statusCode": row["status_code"], "responseBody": safe_json(row["response_body"]), "workspaceId": str(row["workspace_id"])}), 201


@app.route("/api/mock/endpoints/<int:eid>", methods=["DELETE"])
@require_auth
def delete_mock_endpoint(user_id, eid):
    conn = get_db()
    row = conn.execute("SELECT id, workspace_id FROM mock_endpoints WHERE id = ?", (eid,)).fetchone()
    if not row or not can_access_workspace(user_id, str(row["workspace_id"])):
        conn.close()
        return jsonify({"error": "Not found"}), 404
    conn.execute("DELETE FROM mock_endpoints WHERE id = ?", (eid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---- Analytics ----
@app.route("/api/analytics")
@require_auth
def analytics(user_id):
    workspace_id = request.args.get("workspaceId")
    now = time.time()
    cutoff = now - 24 * 3600
    list_log = [c for c in CALL_LOG if c["userId"] == user_id and (not workspace_id or c["workspaceId"] == workspace_id) and c["at"] > cutoff]
    success = sum(1 for c in list_log if 200 <= c["status"] < 300)
    failed = sum(1 for c in list_log if c["status"] >= 400 or c["status"] == 0)
    avg_time = (sum(c["responseTime"] for c in list_log) / len(list_log)) if list_log else 0
    return jsonify({
        "totalCalls": len(list_log),
        "success": success,
        "failed": failed,
        "successRate": (success / len(list_log) * 100) if list_log else 0,
        "avgResponseTimeMs": round(avg_time),
        "recent": [{"method": c["method"], "url": c["url"], "status": c["status"], "responseTime": c["responseTime"]} for c in list_log[-20:]][::-1],
    })


# ---- Notifications ----
@app.route("/api/notifications")
@require_auth
def list_notifications(user_id):
    conn = get_db()
    rows = conn.execute("SELECT id, user_id, type, title, body, read, meta, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (int(user_id),)).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "userId": str(r["user_id"]), "type": r["type"], "title": r["title"], "body": r["body"], "read": bool(r["read"]), "meta": safe_json(r["meta"]), "createdAt": r["created_at"]} for r in rows])


@app.route("/api/notifications/<int:nid>/read", methods=["PATCH"])
@require_auth
def mark_notification_read(user_id, nid):
    conn = get_db()
    conn.execute("UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?", (nid, int(user_id)))
    conn.commit()
    row = conn.execute("SELECT id, user_id, type, title, body, read, created_at FROM notifications WHERE id = ?", (nid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"_id": str(row["id"]), "userId": str(row["user_id"]), "type": row["type"], "title": row["title"], "body": row["body"], "read": True, "createdAt": row["created_at"]})


@app.route("/api/notifications/read-all", methods=["PATCH"])
@require_auth
def mark_all_read(user_id):
    conn = get_db()
    conn.execute("UPDATE notifications SET read = 1 WHERE user_id = ?", (int(user_id),))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---- AI ----
@app.route("/api/ai/suggest", methods=["POST"])
@require_auth
def ai_suggest(user_id):
    data = request.get_json() or {}
    prompt = data.get("prompt") or ""
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    lower = prompt.lower()
    method = "GET"
    if "post" in lower or "create" in lower or "add" in lower:
        method = "POST"
    elif "put" in lower or "update" in lower:
        method = "PUT"
    elif "delete" in lower or "remove" in lower:
        method = "DELETE"
    elif "patch" in lower:
        method = "PATCH"
    import re
    url_match = re.search(r"https?://[^\s]+", prompt)
    url = url_match.group(0) if url_match else "https://api.example.com/"
    body = "{}" if method in ("POST", "PUT", "PATCH") else None
    return jsonify({"method": method, "url": url, "headers": {"Content-Type": "application/json"}, "body": body})


@app.route("/api/ai/debug", methods=["POST"])
@require_auth
def ai_debug(user_id):
    data = request.get_json() or {}
    status = data.get("statusCode", 0)
    suggestion = "Check the request URL and parameters."
    if status == 401:
        suggestion = "Add or fix Authorization header."
    elif status == 404:
        suggestion = "Verify the URL path and resource ID."
    elif status in (422, 400):
        suggestion = "Validate request body format and required fields."
    return jsonify({"suggestion": suggestion})


# ---- Comments ----
def can_access_request(user_id, request_id):
    conn = get_db()
    row = conn.execute("SELECT workspace_id FROM api_requests WHERE id = ?", (int(request_id),)).fetchone()
    conn.close()
    if not row:
        return False
    return can_access_workspace(user_id, str(row["workspace_id"]))


@app.route("/api/comments/request/<int:request_id>")
@require_auth
def list_comments(user_id, request_id):
    if not can_access_request(user_id, request_id):
        return jsonify({"error": "Forbidden"}), 403
    conn = get_db()
    rows = conn.execute(
        "SELECT c.id, c.request_id, c.user_id, c.text, c.mentions, c.created_at, u.name, u.email FROM comments c JOIN users u ON u.id = c.user_id WHERE c.request_id = ? ORDER BY c.created_at ASC",
        (request_id,),
    ).fetchall()
    conn.close()
    return jsonify([{"_id": str(r["id"]), "requestId": str(r["request_id"]), "userId": {"name": r["name"], "email": r["email"]}, "text": r["text"], "mentions": safe_json(r["mentions"]), "createdAt": r["created_at"]} for r in rows])


@app.route("/api/comments/request/<int:request_id>", methods=["POST"])
@require_auth
def create_comment(user_id, request_id):
    if not can_access_request(user_id, request_id):
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json() or {}
    text = data.get("text") or ""
    mention_ids = data.get("mentions") or []
    conn = get_db()
    cur = conn.execute("INSERT INTO comments (request_id, user_id, text, mentions) VALUES (?, ?, ?, ?)", (request_id, int(user_id), text, json.dumps(mention_ids)))
    cid = cur.lastrowid
    for uid in mention_ids:
        conn.execute(
            "INSERT INTO notifications (user_id, type, title, body, meta) VALUES (?, 'mention', 'You were mentioned', ?, ?)",
            (int(uid), text[:100], json.dumps({"requestId": request_id, "commentId": cid})),
        )
    row = conn.execute(
        "SELECT c.id, c.request_id, c.user_id, c.text, c.created_at, u.name, u.email FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?",
        (cid,),
    ).fetchone()
    conn.commit()
    conn.close()
    return jsonify({"_id": str(row["id"]), "requestId": str(row["request_id"]), "userId": {"name": row["name"], "email": row["email"]}, "text": row["text"], "createdAt": row["created_at"]}), 201


if __name__ == "__main__":
    init_db()
    PORT = int(os.environ.get("PORT", 5000))
    print(f"Server: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=True)
