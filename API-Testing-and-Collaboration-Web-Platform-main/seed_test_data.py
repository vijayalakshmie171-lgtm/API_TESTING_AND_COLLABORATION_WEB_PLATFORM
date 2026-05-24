"""
Seed test data for the API Testing platform.
Run: python seed_test_data.py
Then log in with: test@example.com / test123
"""
import bcrypt
import json
from db import get_db, init_db

def seed():
    init_db()
    conn = get_db()

    # Test user (password: test123)
    existing = conn.execute("SELECT id FROM users WHERE email = ?", ("test@example.com",)).fetchone()
    if existing:
        user_id = existing["id"]
        print("Test user already exists (test@example.com). Skipping user creation.")
    else:
        hashed = bcrypt.hashpw(b"test123", bcrypt.gensalt(rounds=10)).decode("utf-8")
        cur = conn.execute(
            "INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)",
            ("test@example.com", hashed, "Test User", "member"),
        )
        user_id = cur.lastrowid
        print("Created test user: test@example.com / test123")

    # Workspace
    ws_row = conn.execute("SELECT id FROM workspaces WHERE owner_id = ? LIMIT 1", (user_id,)).fetchone()
    if ws_row:
        workspace_id = ws_row["id"]
        print("Using existing workspace.")
    else:
        cur = conn.execute(
            "INSERT INTO workspaces (name, type, owner_id) VALUES (?, 'personal', ?)",
            ("Test User's Workspace", user_id),
        )
        workspace_id = cur.lastrowid
        conn.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (?, ?)", (workspace_id, user_id))
        print("Created workspace.")

    # Collections
    collections = [
        ("Sample APIs", workspace_id),
        ("Auth & Users", workspace_id),
    ]
    for name, wid in collections:
        if not conn.execute("SELECT id FROM collections WHERE name = ? AND workspace_id = ?", (name, wid)).fetchone():
            conn.execute("INSERT INTO collections (name, workspace_id) VALUES (?, ?)", (name, wid))
    conn.commit()
    col1 = conn.execute("SELECT id FROM collections WHERE workspace_id = ? AND name = ?", (workspace_id, "Sample APIs")).fetchone()
    col1_id = col1["id"] if col1 else None

    # API Requests
    requests_data = [
        {"name": "GET posts list", "method": "GET", "url": "https://jsonplaceholder.typicode.com/posts", "headers": {}, "query_params": {"_limit": "5"}, "body": "", "body_type": "json", "collection_id": col1_id},
        {"name": "GET single post", "method": "GET", "url": "https://jsonplaceholder.typicode.com/posts/1", "headers": {}, "query_params": {}, "body": "", "body_type": "json", "collection_id": col1_id},
        {"name": "POST create post", "method": "POST", "url": "https://jsonplaceholder.typicode.com/posts", "headers": {"Content-Type": "application/json"}, "query_params": {}, "body": json.dumps({"title": "Test", "body": "Hello", "userId": 1}), "body_type": "json", "collection_id": col1_id},
        {"name": "GET users", "method": "GET", "url": "https://jsonplaceholder.typicode.com/users", "headers": {}, "query_params": {}, "body": "", "body_type": "json", "collection_id": col1_id},
        {"name": "Untitled Request", "method": "GET", "url": "https://api.github.com/", "headers": {}, "query_params": {}, "body": "", "body_type": "json", "collection_id": None},
    ]
    for r in requests_data:
        existing_req = conn.execute("SELECT id FROM api_requests WHERE name = ? AND workspace_id = ?", (r["name"], workspace_id)).fetchone()
        if not existing_req:
            cur = conn.execute(
                """INSERT INTO api_requests (name, method, url, headers, query_params, body, body_type, collection_id, workspace_id, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (r["name"], r["method"], r["url"], json.dumps(r["headers"]), json.dumps(r["query_params"]), r["body"], r["body_type"], r["collection_id"], workspace_id, user_id),
            )
            req_id = cur.lastrowid
            snap = {**r, "workspaceId": str(workspace_id), "createdBy": str(user_id)}
            conn.execute("INSERT INTO request_history (request_id, snapshot, version, created_by) VALUES (?, ?, 1, ?)", (req_id, json.dumps(snap), user_id))
    conn.commit()
    print("Created sample API requests.")

    # Mock endpoints
    if not conn.execute("SELECT id FROM mock_endpoints WHERE workspace_id = ? LIMIT 1", (workspace_id,)).fetchone():
        conn.execute("INSERT INTO mock_endpoints (path, method, status_code, response_body, workspace_id) VALUES (?, ?, ?, ?, ?)", ("/users", "GET", 200, json.dumps([{"id": 1, "name": "Mock User"}]), workspace_id))
        conn.execute("INSERT INTO mock_endpoints (path, method, status_code, response_body, workspace_id) VALUES (?, ?, ?, ?, ?)", ("/health", "GET", 200, json.dumps({"status": "ok"}), workspace_id))
        conn.commit()
        print("Created mock endpoints: GET /users, GET /health")

    # Notifications
    if not conn.execute("SELECT id FROM notifications WHERE user_id = ? LIMIT 1", (user_id,)).fetchone():
        conn.execute("INSERT INTO notifications (user_id, type, title, body, read) VALUES (?, ?, ?, ?, ?)", (user_id, "api_failed", "Sample: API request failed", "GET https://example.com → 404", 0))
        conn.execute("INSERT INTO notifications (user_id, type, title, body, read) VALUES (?, ?, ?, ?, ?)", (user_id, "request_updated", "Sample: Request updated", "GET posts list was updated", 1))
        conn.commit()
        print("Created sample notifications.")

    conn.close()
    print("\nDone. Log in with: test@example.com / test123")


if __name__ == "__main__":
    seed()
