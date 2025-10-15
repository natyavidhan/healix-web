import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/healix")
SECRET_KEY = os.environ.get("SECRET_KEY", "secret")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialize MongoDB client
client = MongoClient(MONGO_URI)
db = client.get_default_database() if client else None
users = db.users


def find_user_by_email(email: str):
	if not email:
		return None
	return users.find_one({"email": email.lower()})


@app.route("/")
def index():
	return render_template("index.html")


@app.route("/register")
def register_page():
	return render_template("register.html")


@app.route("/login")
def login_page():
	return render_template("login.html")


@app.route("/dashboard")
def dashboard_page():
	user = session.get("user")
	if not user:
		return redirect(url_for("login_page"))
	return render_template("dashboard.html", user=user)


@app.route("/auth/google")
def auth_google():
	# Placeholder for Google OAuth integration.
	# A real implementation would redirect to Google's OAuth 2.0 consent screen.
	return render_template("google_placeholder.html")


@app.route("/api/register", methods=["POST"])
def api_register():
	data = request.get_json() or {}
	full_name = (data.get("full_name") or "").strip()
	email = (data.get("email") or "").strip().lower()
	password = data.get("password") or ""
	# Additional details (matching details.tsx)
	dob = (data.get("dob") or "").strip()
	gender = (data.get("gender") or "").strip()
	blood_group = (data.get("blood_group") or "").strip()
	height_cm = (data.get("height_cm") or "").strip()
	weight_kg = (data.get("weight_kg") or "").strip()
	known_conditions = (data.get("known_conditions") or "").strip()
	allergies = (data.get("allergies") or "").strip()
	food_tolerance = (data.get("food_tolerance") or "").strip()
	smoking = (data.get("smoking") or "").strip()
	alcohol = (data.get("alcohol") or "").strip()
	physical_activity = (data.get("physical_activity") or "").strip()
	diet_type = (data.get("diet_type") or "").strip()

	if not email or not password:
		return jsonify({"success": False, "message": "Email and password required"}), 400

	# Basic required health fields
	if not dob or not gender or not blood_group:
		return jsonify({"success": False, "message": "DOB, gender and blood group are required"}), 400

	if find_user_by_email(email):
		return jsonify({"success": False, "message": "Email already registered"}), 400

	hashed = generate_password_hash(password)
	user_doc = {
		"full_name": full_name,
		"email": email,
		"password": hashed,
		"dob": dob,
		"gender": gender,
		"blood_group": blood_group,
		"height_cm": height_cm,
		"weight_kg": weight_kg,
		"known_conditions": known_conditions,
		"allergies": allergies,
		"food_tolerance": food_tolerance,
		"smoking": smoking,
		"alcohol": alcohol,
		"physical_activity": physical_activity,
		"diet_type": diet_type,
	}
	users.insert_one(user_doc)
	return jsonify({"success": True, "message": "User registered"})


@app.route("/api/login", methods=["POST"])
def api_login():
	data = request.get_json() or {}
	email = (data.get("email") or "").strip().lower()
	password = data.get("password") or ""

	if not email or not password:
		return jsonify({"success": False, "message": "Email and password required"}), 400

	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "authenticated": False})

	stored = user.get("password")
	if not stored or not check_password_hash(stored, password):
		return jsonify({"success": True, "authenticated": False})

	# Authentication successful
	session["user"] = {"email": user.get("email")}
	return jsonify({"success": True, "authenticated": True})


@app.route("/api/logout", methods=["POST"])
def api_logout():
	session.pop("user", None)
	return jsonify({"success": True})


if __name__ == "__main__":
	# For development only. In production use a WSGI server.
	app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

