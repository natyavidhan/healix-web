Healix Web (minimal)

This is a minimal Flask app for demo purposes that supports email/password registration and login backed by MongoDB.

Setup (Windows PowerShell):

1. Create a virtual env and activate it:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and edit values, then set environment variables in the shell or use a dotenv loader. Example for PowerShell:

```powershell
copy .env.example .env
$env:MONGO_URI = 'mongodb://localhost:27017/healix'
$env:SECRET_KEY = 'change-me'
```

4. Run:

```powershell
python main.py
```

Notes:
- This app uses `MONGO_URI` to connect to MongoDB. Ensure a running MongoDB instance is accessible.
- Google sign-in is a placeholder route. For production use implement OAuth2 via `authlib` or `google-auth`.
- Passwords are hashed with Werkzeug security utilities.

API endpoints:
- POST /api/register {email, password}
- POST /api/login {email, password} -> {authenticated: true|false}
- POST /api/logout

Templates are in `templates/`.
