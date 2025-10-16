# =====================================================================
# Healix OCR & Prescription Extraction Pipeline
# =====================================================================
# Handles OCR extraction, AI normalization, and structured medicine extraction
# =====================================================================

import os
import re
import json
import requests
import subprocess
import tempfile
from dotenv import load_dotenv
from groq import Groq
from typing import List

# New: Local OCR via docTR
from doctr.io import DocumentFile
from doctr.models import ocr_predictor

load_dotenv()

# =====================================================================
# SECTION 1: OCR Extraction from File
# =====================================================================

DOCTR_MODEL = None


def _get_doctr_model():
    global DOCTR_MODEL
    if DOCTR_MODEL is None:
        # Load once to avoid heavy reloads on each request
        DOCTR_MODEL = ocr_predictor(pretrained=True)
    return DOCTR_MODEL


def _doctr_result_to_text(result) -> str:
    """Flatten docTR result into plain text, line by line."""
    lines: List[str] = []
    try:
        for page in result.pages:
            for block in page.blocks:
                for line in block.lines:
                    words = [w.value for w in line.words]
                    if words:
                        lines.append(" ".join(words))
    except Exception as e:
        # Fallback to exported dict if object API changes
        try:
            exported = result.export()
            for page in exported.get("pages", []):
                for block in page.get("blocks", []):
                    for line in block.get("lines", []):
                        words = [w.get("value", "") for w in line.get("words", []) if w.get("value")]
                        if words:
                            lines.append(" ".join(words))
        except Exception:
            # As a last resort, just string the result
            lines.append(str(result))
    return "\n".join(lines)


def extract_text_from_file(file, ocr_api_key="helloworld"):
    """
    Extract text from an uploaded file using docTR (local OCR).

    Args:
        file: Flask file object (image or PDF)
        ocr_api_key: Unused (kept for backward compatibility)

    Returns:
        str: Extracted raw text from file
    """
    # Save upload to a temporary path
    suffix = '_' + (file.filename or 'upload')
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        file.save(tmp)
        tmp_path = tmp.name

    try:
        ext = os.path.splitext(tmp_path)[1].lower()
        if ext == '.pdf':
            doc = DocumentFile.from_pdf(tmp_path)
        else:
            # Accept single image path; docTR will handle decoding
            doc = DocumentFile.from_images(tmp_path)

        model = _get_doctr_model()
        result = model(doc)
        text = _doctr_result_to_text(result)
        return text
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

# =====================================================================
# SECTION 2: OCR Normalization via Groq AI
# =====================================================================

def normalize_prescription(ocr_text):
    """
    Normalizes noisy OCR output using Groq LLaMA model.
    Extracts doctor name, prescription date, and medicines.
    
    Args:
        ocr_text: Raw OCR output
        
    Returns:
        str: Cleaned prescription text
    """
    client = Groq(api_key=os.environ.get("GROQ_KEY"))
    
    prompt = (
        "You are a medical prescription text normalizer. "
        "Given the following raw OCR output from a prescription, extract and clean: "
        "1. Doctor's name (label it as 'Doctor: [name]')\n"
        "2. Date of prescription (label it as 'Date: [date in YYYY-MM-DD format]')\n"
        "3. Medicine names, dosages, and instructions (format: MEDICINE_NAME (DOSAGE), instructions)\n\n"
        "OCR:\n" + ocr_text + "\n\n"
        "Return ONLY the cleaned prescription text:\n"
        "Doctor: [name]\n"
        "Date: [date]\n"
        "[medicine 1]\n"
        "[medicine 2]\n"
        "...\n\n"
        "NO EXTRA TEXT, NOTES, OR EXPLANATIONS."
    )
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    
    return chat_completion.choices[0].message.content

# Back-compat: older imports expect this name
def normalize_ocr_with_groq(ocr_text: str) -> str:
    return normalize_prescription(ocr_text)

def normalize_report(ocr_text):
    """
    Normalizes noisy OCR output using Groq LLaMA model.
    Extracts doctor name, prescription date, and medicines.
    
    Args:
        ocr_text: Raw OCR output
        
    Returns:
        str: Cleaned prescription text
    """
    client = Groq(api_key=os.environ.get("GROQ_KEY"))
    
    prompt = f"""
You are a medical report text normalizer. 
Given the following raw OCR output from a lab report, extract and clean:

1. Test names and results (format: TEST_NAME, RESULT, UNITS, REFERENCE_INTERVAL)
2. Reference ranges (if applicable) for the tests
3. Date of report (label it as 'Date: [date in YYYY-MM-DD format]')

OCR:

{ocr_text}

Return ONLY the cleaned report data:

Date: [date]

[Test 1 Name]: [Result], [Units], [Reference Interval]
[Test 2 Name]: [Result], [Units], [Reference Interval]
...

NO EXTRA TEXT, NOTES, OR EXPLANATIONS.
"""
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    
    return chat_completion.choices[0].message.content

# =====================================================================
# SECTION 3: Prescription Data Extraction
# =====================================================================

def extract_medicine_details(line):
    """
    Parses a medicine line into structured data.
    
    Format: "MEDICINE_NAME (DOSAGE), instructions"
    Examples:
        - "GLIMEPIRIDE 1 MG, take as directed"
        - "VILDAGLIPTIN + METFORMIN (50 + 1000), take as directed"
    
    Args:
        line: Single medicine line
        
    Returns:
        dict: Medicine data or None if parsing fails
    """
    # Split by comma: medicine part | instructions part
    parts = line.split(',', 1)
    if not parts:
        return None
    
    med_part = parts[0].strip()
    instructions = parts[1].strip() if len(parts) > 1 else ""
    
    # Extract name and strength
    pattern = r'^([A-Za-z0-9\s\+\-]+?)(?:\s*[\(\[]?\s*([\d\.]+\s*(?:\+\s*[\d\.]+)?)\s*(?:mg|ml|g)?\s*[\)\]]?)?$'
    match = re.match(pattern, med_part, re.IGNORECASE)
    
    if match:
        name = match.group(1).strip().title()
        strength = match.group(2).strip() if match.group(2) else ""
        
        # Add units if missing
        if strength and not any(unit in strength for unit in ["mg", "ml", "g"]):
            units_match = re.search(r'(mg|ml|g)', med_part, re.IGNORECASE)
            if units_match:
                strength = strength + " " + units_match.group(1)
        
        return {
            "name": name,
            "strength": strength,
            "form": "tablet",
            "dosage": "1 unit",
            "frequency_per_day": 1,
            "duration_days": None,
            "instructions": instructions
        }
    
    return None


def prescription_extraction(normalized_text):
    """
    Extracts structured prescription data from normalized text.
    
    Format:
        Doctor: [name]
        Date: [YYYY-MM-DD]
        [medicine 1]
        [medicine 2]
    
    Args:
        normalized_text: Cleaned text from normalize_prescription()
        
    Returns:
        dict: {doctor, date, medicines}
    """
    lines = [l.strip() for l in normalized_text.split('\n') if l.strip()]
    
    doctor = None
    date = None
    medicines = []
    
    for line in lines:
        # Extract doctor
        doctor_match = re.match(r'^Doctor:\s*(.+)$', line, re.IGNORECASE)
        if doctor_match:
            doctor = doctor_match.group(1).strip()
            continue
        
        # Extract date
        date_match = re.match(r'^Date:\s*(.+)$', line, re.IGNORECASE)
        if date_match:
            date = date_match.group(1).strip()
            continue
        
        # Extract medicine
        med = extract_medicine_details(line)
        if med:
            medicines.append(med)
    
    return {"doctor": doctor, "date": date, "medicines": medicines}


# =====================================================================
# SECTION 3b: Report Data Extraction (Regex -> JSON)
# =====================================================================

def report_extraction(normalized_text: str):
    """
    Convert normalized lab report text into structured JSON using regex.

    Expected input format (one item per line):
        Date: <YYYY-MM-DD>

        <TEST NAME>: <RESULT>, <UNITS>, <REFERENCE>

    Returns dict:
        {
          "date": str|None,
          "tests": [
             {"name": str, "result": str, "units": str|None, "reference": str|None}
          ]
        }
    """
    lines = [l.strip() for l in (normalized_text or "").split("\n") if l.strip()]

    date = None
    tests: List[dict] = []

    # Regexes for headers
    rx_date = re.compile(r"^Date:\s*(.+)$", re.IGNORECASE)

    # Regex for test lines: name before first colon; then CSV of result, units, reference (some may be empty)
    # Example: "Creatinine: 1.00, mg/dL, 0.70 - 1.30"
    rx_test = re.compile(r"^(?P<name>[^:]+):\s*(?P<body>.+)$")

    for line in lines:
        # Headers first
        m = rx_date.match(line)
        if m:
            date = m.group(1).strip() or None
            continue

        # Tests
        m = rx_test.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        body = m.group("body").strip()

        # Split by commas into up to 3 parts: result, units, reference
        parts = [p.strip() for p in body.split(",")]
        # Ensure length 3
        if len(parts) < 3:
            parts = parts + ["" for _ in range(3 - len(parts))]
        result_val, units, reference = parts[0], parts[1], ",".join(parts[2:]).strip() if len(parts) > 2 else ""

        tests.append({
            "name": name,
            "result": result_val,
            "units": units or None,
            "reference": reference or None,
        })

    return {
        "date": date,
        "tests": tests,
    }

# =====================================================================
# SECTION 4: Flask Test Endpoint
# =====================================================================

if __name__ == "__main__":
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    @app.route('/upload', methods=['POST'])
    def upload():
        """
        Upload and process a prescription image/PDF.
        
        Pipeline:
            1. Extract text from file using OCR.space
            2. Normalize with Groq AI
            3. Extract doctor, date, and medicines
            
        Returns:
            JSON: {doctor, date, medicines}
        """
        if 'file' not in request.files:
            return "No file part", 400
        
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400
        
        # Step 1: OCR extraction
        raw_ocr = extract_text_from_file(file, ocr_api_key=os.environ.get("OCR_KEY", "helloworld"))
        print("Raw OCR text:", raw_ocr)
        
        # Step 2: Groq normalization
        # try:
        #     normalized = normalize_prescription(raw_ocr)
        # except Exception as e:
        #     print("Groq normalization failed:", e)
        #     normalized = raw_ocr
        # print("Normalized OCR text:", normalized)
        
        # # Step 3: Prescription extraction
        # prescription_data = prescription_extraction(normalized)
        # print("Extracted prescription data:", prescription_data)
        
        # return jsonify(prescription_data)
        # return jsonify({"raw_ocr": raw_ocr})
        report = normalize_report(raw_ocr)
        print("Normalized Report text:\n", report)
        structured = report_extraction(report)
        print("Structured Report:", structured)
        return jsonify({"report": structured})

    app.run(debug=True)