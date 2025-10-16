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

load_dotenv()

# =====================================================================
# SECTION 1: OCR Extraction from File
# =====================================================================

def extract_text_from_file(file, ocr_api_key="helloworld"):
    """
    Extracts text from an uploaded file using OCR.space API.
    File is temporarily uploaded to tmpfiles.org.
    
    Args:
        file: Flask file object
        ocr_api_key: OCR.space API key
        
    Returns:
        str: Extracted raw text from file
    """
    # Save file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='_' + file.filename) as tmp:
        file.save(tmp)
        tmp_path = tmp.name

    # Upload to tmpfiles.org using curl
    curl_cmd = ['curl', '-s', '-F', f'file=@{tmp_path}', 'https://tmpfiles.org/api/v1/upload']
    result = subprocess.run(curl_cmd, capture_output=True, text=True)
    
    try:
        tmpfiles_result = json.loads(result.stdout)
    except Exception as e:
        print('curl output:', result.stdout)
        raise Exception('Could not parse tmpfiles.org response')
    
    if tmpfiles_result.get('status') != 'success':
        print('tmpfiles.org response:', tmpfiles_result)
        raise Exception('File upload failed: ' + str(tmpfiles_result.get('message', 'Unknown error')))
    
    # Convert to raw download URL format
    file_url = tmpfiles_result['data']['url']
    match = re.match(r'http://tmpfiles\.org/(\d+)/([\w\-\.]+)', file_url)
    if match:
        file_url = f'https://tmpfiles.org/dl/{match.group(1)}/{match.group(2)}'

    # Clean up temp file
    os.remove(tmp_path)

    # Detect file extension for OCR.space
    ext = os.path.splitext(file.filename)[1].lower().replace('.', '')
    filetype_param = f"&filetype={ext}" if ext else ""

    print("File URL:", file_url)

    # Call OCR.space API
    ocr_url = f"https://api.ocr.space/parse/imageurl?apikey={ocr_api_key}&url={file_url}{filetype_param}"
    ocr_response = requests.get(ocr_url)
    ocr_result = ocr_response.json()

    print("OCR API response:", ocr_result)

    # Extract text
    parsed_text = ""
    if ocr_result.get("ParsedResults"):
        parsed_text = ocr_result["ParsedResults"][0].get("ParsedText", "")
    return parsed_text

# =====================================================================
# SECTION 2: OCR Normalization via Groq AI
# =====================================================================

def normalize_ocr_with_groq(ocr_text):
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
        normalized_text: Cleaned text from normalize_ocr_with_groq()
        
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
        try:
            normalized = normalize_ocr_with_groq(raw_ocr)
        except Exception as e:
            print("Groq normalization failed:", e)
            normalized = raw_ocr
        print("Normalized OCR text:", normalized)
        
        # Step 3: Prescription extraction
        prescription_data = prescription_extraction(normalized)
        print("Extracted prescription data:", prescription_data)
        
        return jsonify(prescription_data)

    app.run(debug=True)