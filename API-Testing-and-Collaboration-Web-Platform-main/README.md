# API Testing and Collaboration Platform

Flask + SQLite app for testing APIs, organizing requests in workspaces and collections, with history, mocks, and AI suggestions (Postman-like).

## Features

- **Auth**: Signup / Login / Logout (JWT in HttpOnly cookies)
- **API testing**: GET, POST, PUT, PATCH, DELETE with URL, headers, query params, body
- **Workspaces & collections**: Organize requests
- **History & versions**: Revert to previous request versions
- **Execute**: Send requests and view response (status, headers, body)
- **AI assistant**: Natural language → suggested method, URL, body
- **Analytics**: Success/failure rates, response times (24h)
- **Mock server**: Define mock endpoints per workspace
- **Notifications** and **comments** on requests

## Tech stack

- **Backend**: Python 3, Flask, Flask-CORS, PyJWT, bcrypt, SQLite3, requests

## Prerequisites

- Python 3.8+

## Run locally

1. **Create venv and install**

   ```bash
   python -m venv venv
   venv\Scripts\activate   # Windows
   # source venv/bin/activate   # macOS/Linux
   pip install -r requirements.txt
   ```

2. **Seed test data (optional)**

   ```bash
   python seed_test_data.py
   ```
   Then log in with **test@example.com** / **test123**.

3. **Run the app**

   ```bash
   python app.py
   ```

   Open http://127.0.0.1:5000 — login, signup, dashboard with “Send request” form.  
   Data is stored in `api-platform.sqlite` (or set `SQLITE_PATH` in env).

## Deploy to Vercel

1. Push to GitHub.
2. Vercel → Import repo → **Root Directory** leave empty (`.`).
3. **Framework Preset**: Flask. **Build Command**: `pip install -r requirements.txt`.
4. Deploy. The app is a single Flask serverless function; SQLite uses `/tmp` (ephemeral).

## Scripts

- `python app.py` — run Flask (default port 5000; set `PORT` if needed).
- `python seed_test_data.py` — create test user and sample requests.
