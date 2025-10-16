

import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

from ocr import extract_text_from_file, normalize_ocr_with_groq, prescription_extraction
# Configuration
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/healix")
SECRET_KEY = os.environ.get("SECRET_KEY", "secret")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

# Enable CORS for React Native app
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize JWT
jwt = JWTManager(app)

# Initialize MongoDB client
client = MongoClient(MONGO_URI)
db = client.get_default_database() if client else None
users = db.users
medications = db.medications
prescriptions = db.prescriptions


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
	
	# Create JWT tokens
	access_token = create_access_token(identity=email)
	refresh_token = create_refresh_token(identity=email)
	
	return jsonify({
		"success": True,
		"message": "User registered",
		"access_token": access_token,
		"refresh_token": refresh_token
	})


@app.route("/api/login", methods=["POST"])
def api_login():
	data = request.get_json() or {}
	email = (data.get("email") or "").strip().lower()
	password = data.get("password") or ""

	if not email or not password:
		return jsonify({"success": False, "message": "Email and password required"}), 400

	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "authenticated": False, "message": "Invalid credentials"})

	stored = user.get("password")
	if not stored or not check_password_hash(stored, password):
		return jsonify({"success": False, "authenticated": False, "message": "Invalid credentials"})

	# Authentication successful - create JWT tokens
	access_token = create_access_token(identity=email)
	refresh_token = create_refresh_token(identity=email)
	
	# Also set session for web UI compatibility
	session["user"] = {"email": user.get("email"), "full_name": user.get("full_name")}
	
	return jsonify({
		"success": True,
		"authenticated": True,
		"access_token": access_token,
		"refresh_token": refresh_token
	})


@app.route("/api/logout", methods=["POST"])
def api_logout():
	session.pop("user", None)
	return jsonify({"success": True})


@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
	"""Refresh access token using refresh token"""
	identity = get_jwt_identity()
	access_token = create_access_token(identity=identity)
	return jsonify({"success": True, "access_token": access_token})


@app.route("/api/user", methods=["GET"])
@jwt_required()
def api_user():
	"""Get current user profile - requires JWT token"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	
	# Remove password from response
	user.pop("password", None)
	user.pop("_id", None)  # Remove MongoDB _id
	
	return jsonify({"success": True, "user": user})


@app.route("/api/medications", methods=["POST"])
@jwt_required()
def api_create_medication():
	"""Create a new medication for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	
	data = request.get_json() or {}
	
	# Validate required fields
	required_fields = ["name", "frequency_per_day", "times", "duration_days", "start_date", "status"]
	for field in required_fields:
		if field not in data:
			return jsonify({"success": False, "message": f"Missing required field: {field}"}), 400
	
	# Create medication document
	medication_doc = {
		"user_id": str(user["_id"]),
		"name": data.get("name"),
		"brand_name": data.get("brand_name"),
		"form": data.get("form"),
		"strength": data.get("strength"),
		"dosage": data.get("dosage"),
		"frequency_per_day": data.get("frequency_per_day"),
		"times": data.get("times"),  # Array of time strings
		"duration_days": data.get("duration_days"),
		"start_date": data.get("start_date"),
		"end_date": data.get("end_date"),
		"instructions": data.get("instructions"),
		"source": data.get("source", "manual_add"),
		"status": data.get("status", "active"),
		"created_at": data.get("created_at"),
		"updated_at": data.get("updated_at"),
	}
	
	result = medications.insert_one(medication_doc)
	medication_doc["_id"] = str(result.inserted_id)
	
	return jsonify({"success": True, "medication": medication_doc}), 201


@app.route("/api/medications", methods=["GET"])
@jwt_required()
def api_get_medications():
	"""Get all medications for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	
	# Find all medications for this user
	user_medications = list(medications.find({"user_id": str(user["_id"])}))
	
	# Convert ObjectId to string for JSON serialization
	for med in user_medications:
		med["_id"] = str(med["_id"])
	
	return jsonify({"success": True, "medications": user_medications})


@app.route("/api/medications/<medication_id>", methods=["PUT"])
@jwt_required()
def api_update_medication(medication_id):
	"""Update a medication"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	
	data = request.get_json() or {}
	
	# Find the medication and verify ownership
	from bson import ObjectId
	try:
		med = medications.find_one({"_id": ObjectId(medication_id), "user_id": str(user["_id"])})
	except:
		return jsonify({"success": False, "message": "Invalid medication ID"}), 400
	
	if not med:
		return jsonify({"success": False, "message": "Medication not found or unauthorized"}), 404
	
	# Update fields
	update_data = {}
	updatable_fields = [
		"name", "brand_name", "form", "strength", "dosage", 
		"frequency_per_day", "times", "duration_days", "start_date", 
		"end_date", "instructions", "status", "updated_at"
	]
	
	for field in updatable_fields:
		if field in data:
			update_data[field] = data[field]
	
	if update_data:
		medications.update_one({"_id": ObjectId(medication_id)}, {"$set": update_data})
	
	# Get updated medication
	updated_med = medications.find_one({"_id": ObjectId(medication_id)})
	updated_med["_id"] = str(updated_med["_id"])
	
	return jsonify({"success": True, "medication": updated_med})


@app.route("/api/medications/<medication_id>", methods=["DELETE"])
@jwt_required()
def api_delete_medication(medication_id):
	"""Delete a medication"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	
	# Find and delete the medication, verifying ownership
	from bson import ObjectId
	try:
		result = medications.delete_one({"_id": ObjectId(medication_id), "user_id": str(user["_id"])})
	except:
		return jsonify({"success": False, "message": "Invalid medication ID"}), 400
	
	if result.deleted_count == 0:
		return jsonify({"success": False, "message": "Medication not found or unauthorized"}), 404
	
	return jsonify({"success": True, "message": "Medication deleted"})


# ---------------------- PRESCRIPTIONS API ----------------------
@app.route("/api/prescriptions", methods=["POST"])
@jwt_required()
def api_create_prescription():
	"""Create a new prescription with a list of medications for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	data = request.get_json() or {}
	doctor = (data.get("doctor") or "").strip()
	date = (data.get("date") or "").strip()
	medications_payload = data.get("medications") or []

	if not doctor or not date:
		return jsonify({"success": False, "message": "Doctor and date are required"}), 400
	if not isinstance(medications_payload, list) or len(medications_payload) == 0:
		return jsonify({"success": False, "message": "Medications list is required"}), 400

	# Basic validation for medications structure (required subset)
	for idx, med in enumerate(medications_payload):
		missing = [k for k in ["name", "frequency_per_day", "times", "duration_days", "start_date", "status"] if k not in med]
		if missing:
			return jsonify({"success": False, "message": f"Medication #{idx+1} missing fields: {', '.join(missing)}"}), 400

	prescription_doc = {
		"user_id": str(user["_id"]),
		"doctor": doctor,
		"date": date,
		"medications": medications_payload,
		"created_at": data.get("created_at") or None,
		"updated_at": data.get("updated_at") or None,
	}

	result = prescriptions.insert_one(prescription_doc)
	prescription_doc["_id"] = str(result.inserted_id)

	return jsonify({"success": True, "prescription": prescription_doc}), 201


@app.route("/api/prescriptions", methods=["GET"])
@jwt_required()
def api_get_prescriptions():
	"""Get all prescriptions for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	user_prescriptions = list(prescriptions.find({"user_id": str(user["_id"])}))
	for p in user_prescriptions:
		p["_id"] = str(p["_id"])

	return jsonify({"success": True, "prescriptions": user_prescriptions})


# ---------------------- OCR UPLOAD/EXTRACTION API ----------------------
@app.route("/api/prescriptions/ocr", methods=["POST"])
@jwt_required()
def api_extract_prescription_from_file():
	"""
	Upload a prescription file (PDF/Image), extract text via OCR, normalize it, and
	return structured medical data: { doctor, date, medicines }.

	Request:
		Content-Type: multipart/form-data
		Form field: file -> the uploaded file

	Response (200):
		{
		  "success": true,
		  "extracted": { "doctor": str|None, "date": str|None, "medicines": [ ... ] }
		}
	"""
	# Validate authentication/user exists
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	# Validate file in request
	if "file" not in request.files:
		return jsonify({"success": False, "message": "No file part in request"}), 400

	file = request.files["file"]
	if not file or file.filename == "":
		return jsonify({"success": False, "message": "No file selected"}), 400

	# Optional: quick extension check (pdf/images). We keep permissive and let OCR handle specifics.
	# allowed_ext = {"pdf", "png", "jpg", "jpeg"}
	# ext = (file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else "")
	# if ext not in allowed_ext:
	#     return jsonify({"success": False, "message": "Unsupported file type"}), 400

	try:
		# Step 1: OCR extraction from the uploaded file
		raw_ocr = extract_text_from_file(file, ocr_api_key=os.environ.get("OCR_KEY", "helloworld"))
	except Exception as e:
		return jsonify({"success": False, "message": f"OCR extraction failed: {str(e)}"}), 500

	# Step 2: Normalize OCR using Groq (best-effort)
	try:
		normalized = normalize_ocr_with_groq(raw_ocr)
	except Exception:
		# Fallback: use raw OCR if Groq not configured/available
		normalized = raw_ocr

	# Step 3: Extract structured prescription data
	try:
		extracted = prescription_extraction(normalized)
	except Exception as e:
		return jsonify({"success": False, "message": f"Extraction failed: {str(e)}"}), 500

	return jsonify({"success": True, "extracted": extracted}), 200

if __name__ == "__main__":
	# For development only. In production use a WSGI server.
	app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

