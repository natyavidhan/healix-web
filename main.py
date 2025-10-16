

import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import base64
import qrcode
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash

from ocr import (
	extract_text_from_file,
	normalize_ocr_with_groq,
	prescription_extraction,
	normalize_report,
	report_extraction,
)
from rag_system import RAGService
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
reports = db.reports
rag = RAGService(db)
doctors = db.doctors


def find_user_by_email(email: str):
	if not email:
		return None
	return users.find_one({"email": email.lower()})


def find_doctor_by_email(email: str):
	if not email:
		return None
	return doctors.find_one({"email": email.lower()})


def get_session_user():
	return session.get("user")


def get_session_doctor():
	return session.get("doctor")


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


# ---------------------- DOCTOR PAGES ----------------------
@app.route("/doctor/register")
def doctor_register_page():
	return render_template("doctor_register.html")


@app.route("/doctor/login")
def doctor_login_page():
	return render_template("doctor_login.html")


@app.route("/doctor/dashboard")
def doctor_dashboard_page():
	doctor_sess = get_session_doctor()
	if not doctor_sess:
		return redirect(url_for("doctor_login_page"))

	doc = find_doctor_by_email(doctor_sess.get("email"))
	if not doc:
		session.pop("doctor", None)
		return redirect(url_for("doctor_login_page"))

	# Ensure doctor has a short code
	if not doc.get("code"):
		code = str(doc["_id"])[:8]
		doctors.update_one({"_id": doc["_id"]}, {"$set": {"code": code}})
		doc["code"] = code

	# Build QR code PNG as base64
	link_url = url_for("link_doctor_get", code=doc["code"], _external=True)
	img = qrcode.make(link_url)
	buf = BytesIO()
	img.save(buf, format="PNG")
	qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

	# Patient summaries
	patient_docs = []
	for pid in (doc.get("patients") or []):
		try:
			uid = ObjectId(pid) if isinstance(pid, str) else pid
			u = users.find_one({"_id": uid})
			if u:
				patient_docs.append({
					"_id": str(u["_id"]),
					"full_name": u.get("full_name") or u.get("email"),
					"email": u.get("email"),
					"gender": u.get("gender"),
					"dob": u.get("dob"),
				})
		except Exception:
			continue

	return render_template("doctor_dashboard.html", doctor=doc, qr_b64=qr_b64, link_url=link_url, patients=patient_docs)


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


# ---------------------- DOCTOR AUTH APIs ----------------------
@app.route("/api/doctor/register", methods=["POST"])
def api_doctor_register():
	data = request.get_json() or {}
	full_name = (data.get("full_name") or "").strip()
	email = (data.get("email") or "").strip().lower()
	password = data.get("password") or ""
	hospital = (data.get("hospital") or "").strip()
	speciality = (data.get("speciality") or "").strip()

	if not email or not password:
		return jsonify({"success": False, "message": "Email and password required"}), 400

	if find_doctor_by_email(email):
		return jsonify({"success": False, "message": "Email already registered"}), 400

	hashed = generate_password_hash(password)
	doc = {
		"full_name": full_name,
		"email": email,
		"password": hashed,
		"hospital": hospital,
		"speciality": speciality,
		"patients": [],
	}
	res = doctors.insert_one(doc)
	session["doctor"] = {"email": email, "full_name": full_name}
	return jsonify({"success": True, "id": str(res.inserted_id)})


@app.route("/api/doctor/login", methods=["POST"])
def api_doctor_login():
	data = request.get_json() or {}
	email = (data.get("email") or "").strip().lower()
	password = data.get("password") or ""

	if not email or not password:
		return jsonify({"success": False, "message": "Email and password required"}), 400

	doc = find_doctor_by_email(email)
	if not doc or not check_password_hash(doc.get("password"), password):
		return jsonify({"success": False, "authenticated": False, "message": "Invalid credentials"})

	session["doctor"] = {"email": doc.get("email"), "full_name": doc.get("full_name")}
	return jsonify({"success": True, "authenticated": True})


@app.route("/api/doctor/logout", methods=["POST"])
def api_doctor_logout():
	session.pop("doctor", None)
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


@app.route("/api/prescriptions/<prescription_id>", methods=["DELETE"])
@jwt_required()
def api_delete_prescription(prescription_id):
	"""Delete a prescription for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	from bson import ObjectId
	try:
		result = prescriptions.delete_one({"_id": ObjectId(prescription_id), "user_id": str(user["_id"])})
	except Exception:
		return jsonify({"success": False, "message": "Invalid prescription ID"}), 400

	if result.deleted_count == 0:
		return jsonify({"success": False, "message": "Prescription not found or unauthorized"}), 404

	return jsonify({"success": True, "message": "Prescription deleted"})


# ---------------------- LINK FLOW (QR) ----------------------
@app.route("/link/doctor/<code>", methods=["GET"])
def link_doctor_get(code):
	doc = doctors.find_one({"code": code})
	if not doc:
		return render_template("link_doctor.html", error="Invalid or expired link", code=code)
	return render_template("link_doctor.html", doctor=doc, code=code)


@app.route("/link/doctor/<code>", methods=["POST"])
def link_doctor_post(code):
	doc = doctors.find_one({"code": code})
	if not doc:
		return jsonify({"success": False, "message": "Invalid link"}), 400

	patient = get_session_user()
	if not patient:
		return jsonify({"success": False, "requires_login": True, "login_url": url_for('login_page') + f"?next=/link/doctor/{code}"})

	u = find_user_by_email(patient.get("email"))
	if not u:
		return jsonify({"success": False, "message": "User not found"}), 404

	pid = str(u["_id"])
	doctors.update_one({"_id": doc["_id"]}, {"$addToSet": {"patients": pid}})
	return jsonify({"success": True, "message": "Linked with doctor"})


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


# ---------------------- REPORTS OCR UPLOAD/EXTRACTION API ----------------------
@app.route("/api/reports/ocr", methods=["POST"])
@jwt_required()
def api_extract_report_from_file():
	"""
	Upload a lab report file (PDF/Image), extract text via OCR, normalize it, and
	return structured report data: { date, tests: [...] }.

	Request:
		Content-Type: multipart/form-data
		Form field: file -> the uploaded file

	Response (200):
		{
		  "success": true,
		  "report": { "date": str|None, "tests": [...] }
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

	try:
		# Step 1: OCR extraction from the uploaded file
		raw_ocr = extract_text_from_file(file, ocr_api_key=os.environ.get("OCR_KEY", "helloworld"))
	except Exception as e:
		return jsonify({"success": False, "message": f"OCR extraction failed: {str(e)}"}), 500

	# Step 2: Normalize OCR using Groq (best-effort) for report format
	try:
		normalized = normalize_report(raw_ocr)
	except Exception:
		normalized = raw_ocr

	# Step 3: Extract structured report data
	try:
		structured = report_extraction(normalized)
	except Exception as e:
		return jsonify({"success": False, "message": f"Report extraction failed: {str(e)}"}), 500

	return jsonify({"success": True, "report": structured}), 200


# ---------------------- REPORTS DELETE API ----------------------
@app.route("/api/reports/<report_id>", methods=["DELETE"])
@jwt_required()
def api_delete_report(report_id):
	"""Delete a report for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	from bson import ObjectId
	try:
		result = reports.delete_one({"_id": ObjectId(report_id), "user_id": str(user["_id"])})
	except Exception:
		return jsonify({"success": False, "message": "Invalid report ID"}), 400

	if result.deleted_count == 0:
		return jsonify({"success": False, "message": "Report not found or unauthorized"}), 404

	return jsonify({"success": True, "message": "Report deleted"})


# ---------------------- REPORTS CREATE/LIST API ----------------------
@app.route("/api/reports", methods=["POST"])
@jwt_required()
def api_create_report():
	"""Create a new report for the authenticated user

	Expected JSON body:
	{
	  "name": string,            # required
	  "date": string,            # required (YYYY-MM-DD or ISO)
	  "summary": string,         # required (e.g., "Tests: 5")
	  "tests": [                 # optional: array of test rows
		{ "name": str, "result": str, "units": str?, "reference": str? }
	  ],
	  "file_uri": string?,       # optional (client local URI)
	  "mime_type": string?,
	  "size_bytes": number?
	}
	"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	data = request.get_json() or {}
	name = (data.get("name") or "").strip()
	date = (data.get("date") or "").strip()
	summary = (data.get("summary") or "").strip()
	tests = data.get("tests") or []

	if not name or not date or not summary:
		return jsonify({"success": False, "message": "Name, date and summary are required"}), 400

	# Basic shape validation for tests if provided
	if tests and not isinstance(tests, list):
		return jsonify({"success": False, "message": "tests must be an array"}), 400

	report_doc = {
		"user_id": str(user["_id"]),
		"name": name,
		"date": date,
		"summary": summary,
		"tests": tests,
		"file_uri": data.get("file_uri"),
		"mime_type": data.get("mime_type"),
		"size_bytes": data.get("size_bytes"),
		"created_at": data.get("created_at") or None,
		"updated_at": data.get("updated_at") or None,
	}

	result = reports.insert_one(report_doc)
	report_doc["_id"] = str(result.inserted_id)
	return jsonify({"success": True, "report": report_doc}), 201


@app.route("/api/reports", methods=["GET"])
@jwt_required()
def api_get_reports():
	"""Get all reports for the authenticated user"""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	user_reports = list(reports.find({"user_id": str(user["_id"]) }))
	for r in user_reports:
		r["_id"] = str(r["_id"])

	return jsonify({"success": True, "reports": user_reports}), 200


# ---------------------- DOCTOR: Patient management ----------------------
@app.route("/doctor/patients")
def doctor_patients_list():
	doctor_sess = get_session_doctor()
	if not doctor_sess:
		return redirect(url_for("doctor_login_page"))
	doc = find_doctor_by_email(doctor_sess.get("email"))
	if not doc:
		session.pop("doctor", None)
		return redirect(url_for("doctor_login_page"))

	pdata = []
	for pid in (doc.get("patients") or []):
		try:
			u = users.find_one({"_id": ObjectId(pid)})
			if u:
				pdata.append({
					"_id": str(u["_id"]),
					"full_name": u.get("full_name") or u.get("email"),
					"email": u.get("email"),
					"gender": u.get("gender"),
					"dob": u.get("dob"),
				})
		except Exception:
			continue
	return render_template("doctor_dashboard.html", doctor=doc, patients=pdata)


def _doctor_has_patient(doc, pid: str) -> bool:
	return pid in [str(x) for x in (doc.get("patients") or [])]


@app.route("/doctor/patients/<pid>")
def doctor_patient_history(pid):
	doctor_sess = get_session_doctor()
	if not doctor_sess:
		return redirect(url_for("doctor_login_page"))
	doc = find_doctor_by_email(doctor_sess.get("email"))
	if not doc:
		session.pop("doctor", None)
		return redirect(url_for("doctor_login_page"))

	if not _doctor_has_patient(doc, pid):
		return "Forbidden", 403

	try:
		user_obj = users.find_one({"_id": ObjectId(pid)})
		if not user_obj:
			return "User not found", 404
	except Exception:
		return "Invalid ID", 400

	meds = list(medications.find({"user_id": pid}))
	prescs = list(prescriptions.find({"user_id": pid}))
	reps = list(reports.find({"user_id": pid}))
	for x in meds:
		x["_id"] = str(x["_id"])  # stringify ids
	for x in prescs:
		x["_id"] = str(x["_id"])  # stringify ids
	for x in reps:
		x["_id"] = str(x["_id"])  # stringify ids

	return render_template(
		"patient_history.html",
		patient={
			"_id": str(user_obj["_id"]),
			"full_name": user_obj.get("full_name") or user_obj.get("email"),
			"email": user_obj.get("email"),
			"gender": user_obj.get("gender"),
			"dob": user_obj.get("dob"),
			"blood_group": user_obj.get("blood_group"),
		},
		medications=meds,
		prescriptions=prescs,
		reports=reps,
		doctor=doc,
	)


# ---------------------- AI: RAG Ingest & Chat ----------------------
@app.route("/api/ai/ingest", methods=["POST"])
@jwt_required()
def api_ai_ingest():
	"""Build/rebuild the per-user vector index from Mongo data."""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404
	try:
		stats = rag.ingest_user(email)
		return jsonify({"success": True, "stats": stats})
	except Exception as e:
		return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/ai/chat", methods=["POST"])
@jwt_required()
def api_ai_chat():
	"""Query the user's personal RAG and synthesize an answer via Groq."""
	email = get_jwt_identity()
	user = find_user_by_email(email)
	if not user:
		return jsonify({"success": False, "message": "User not found"}), 404

	data = request.get_json() or {}
	query = (data.get("query") or "").strip()
	k = int(data.get("k") or 5)
	if not query:
		return jsonify({"success": False, "message": "Missing 'query'"}), 400

	try:
		result = rag.answer(email, query, k=k)
		return jsonify({"success": True, **result})
	except Exception as e:
		return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
	# For development only. In production use a WSGI server.
	app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

