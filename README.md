Healix Web (JWT Authentication)

This is a Flask app with JWT-based authentication for the Healix mobile/web app. It supports email/password registration and login backed by MongoDB.

Features:
- JWT access and refresh tokens
- Protected API endpoints
- CORS enabled for React Native/mobile apps
- Password hashing with Werkzeug

Setup (Windows PowerShell):

1. Create a virtual env and activate it:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
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
$env:JWT_SECRET_KEY = 'jwt-secret-change-me'
```

4. Run:

```powershell
python main.py
```

API endpoints:
- POST /api/register {full_name, email, password, dob, gender, blood_group, ...} -> {access_token, refresh_token}
- POST /api/login {email, password} -> {authenticated, access_token, refresh_token}
- POST /api/refresh (requires refresh token in Authorization header) -> {access_token}
- GET /api/user (requires access token) -> {user}
- POST /api/logout

React Native Integration:
- Configure API_BASE_URL in `healix-app/lib/api.ts` to point to your Flask server
- Use the helper functions: registerUser(), loginUser(), getCurrentUser(), logoutUser()
- Tokens are automatically stored in AsyncStorage and refreshed when needed

Notes:
- Google sign-in is a placeholder route. For production use implement OAuth2 via `authlib` or `google-auth`.
- For production, use environment variables and a proper secret management system.
- Deploy with a production WSGI server like Gunicorn or uWSGI.
