import requests
import time
import os
import magic
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader
from mutagen import File as AudioFile
import string
from fpdf import FPDF
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

API_KEY = "4cd6af0e44088f1a5c05c4f244e4c7d3dd9b8f4eaf920114e1f23301c5b0a3a5"
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

scan_result_text = ""
metadata_text = ""

def upload_file(file_path):
    global scan_result_text
    headers = {"x-apikey": API_KEY}
    files = {"file": open(file_path, "rb")}
    logging.debug(f"Uploading file: {file_path}")
    try:
        response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files, timeout=30)
        response.raise_for_status()
        logging.debug(f"Upload response: {response.status_code} - {response.text}")
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            logging.info(f"File uploaded successfully. Analysis ID: {analysis_id}")
            return analysis_id
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {str(e)}")
        return None
    finally:
        files["file"].close()

def check_analysis(analysis_id, max_wait_time=60, max_retries=6):
    global scan_result_text
    headers = {"x-apikey": API_KEY}
    start_time = time.time()
    retry_count = 0
    logging.debug(f"Checking analysis for ID: {analysis_id}")

    while True:
        if time.time() - start_time > max_wait_time:
            logging.warning("Timeout waiting for analysis to complete.")
            return None

        try:
            response = requests.get(VT_ANALYSIS_URL.format(analysis_id), headers=headers, timeout=15)
            response.raise_for_status()
            result = response.json()
            status = result["data"]["attributes"]["status"]
            logging.debug(f"Analysis status: {status}")

            if status == "completed":
                stats = result["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                scan_result_text = "=== VirusTotal Scan Results ===\n"
                scan_result_text += f"Malicious: {malicious}\nSuspicious: {suspicious}\nHarmless: {harmless}\nUndetected: {undetected}\n"
                scan_result_text += "\n[!] File is MALICIOUS or SUSPICIOUS\n" if (malicious or suspicious) else "\n[+] File is SAFE\n"

                logging.info(f"Analysis completed: {scan_result_text}")
                return stats

            retry_count += 1
            if retry_count >= max_retries:
                logging.warning("Max retries reached while waiting for analysis.")
                return None

            logging.debug("...still analyzing. Retrying in 5 seconds.")
            time.sleep(5)
        except requests.exceptions.RequestException as e:
            logging.error(f"Analysis request failed: {e}")
            return None
        except (KeyError, ValueError) as e:
            logging.error(f"Invalid response format: {e}")
            return None

def extract_general_metadata(file_path):
    global metadata_text
    metadata_text += "\n=== General Metadata ===\n"
    metadata_text += f"File Name: {os.path.basename(file_path)}\n"
    metadata_text += f"File Size: {os.path.getsize(file_path)} bytes\n"
    metadata_text += f"File Type: {magic.from_file(file_path)}\n"

def extract_image_metadata(file_path):
    global metadata_text
    metadata_text += "\n=== Image Metadata ===\n"
    try:
        with Image.open(file_path) as img:
            metadata_text += f"Format: {img.format}\nSize: {img.size}\nMode: {img.mode}\n"
            if hasattr(img, "_getexif"):
                exifdata = img._getexif()
                if exifdata:
                    for tag_id, value in exifdata.items():
                        tag = TAGS.get(tag_id, tag_id)
                        metadata_text += f"{tag:25}: {value}\n"
    except Exception as e:
        metadata_text += f"[!] Could not extract image metadata: {e}\n"

def extract_pdf_metadata(file_path):
    global metadata_text
    metadata_text += "\n=== PDF Metadata ===\n"
    try:
        reader = PdfReader(file_path)
        info = reader.metadata
        for key, value in info.items():
            metadata_text += f"{key[1:] if key.startswith('/') else key} : {value}\n"
    except Exception as e:
        metadata_text += f"[!] Could not extract PDF metadata: {e}\n"

def extract_audio_metadata(file_path):
    global metadata_text
    metadata_text += "\n=== Audio Metadata ===\n"
    try:
        audio = AudioFile(file_path)
        for key in audio:
            metadata_text += f"{key} : {audio[key]}\n"
    except Exception as e:
        metadata_text += f"[!] Could not extract audio metadata: {e}\n"

def extract_hidden_text(file_path):
    global metadata_text
    metadata_text += "\n=== Hidden Text (LSB Decode) ===\n"
    try:
        img = Image.open(file_path)
        img = img.convert('RGB')
        data = np.array(img)
        bits = []
        for row in data:
            for pixel in row:
                for color in pixel:
                    bits.append(color & 1)
        chars = []
        for b in range(0, len(bits), 8):
            byte = bits[b:b+8]
            if len(byte) < 8:
                break
            char = chr(int("".join(map(str, byte)), 2))
            if char == '\0':
                break
            chars.append(char)
        hidden_text = ''.join(chars)
        metadata_text += f"{hidden_text}\n" if hidden_text else "[!] No hidden message found.\n"
    except Exception as e:
        metadata_text += f"[!] Error extracting hidden text: {e}\n"

def extract_and_clean_trailing_text(file_path, tail_bytes=2048):
    global metadata_text
    metadata_text += f"\n=== Cleaned Embedded Text (Last {tail_bytes} bytes) ===\n"
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            if file_size < tail_bytes:
                f.seek(0)
            else:
                f.seek(-tail_bytes, os.SEEK_END)
            tail_data = f.read()
        clean_decoded = ''.join(char if char in string.printable else '' for char in tail_data.decode('utf-8', errors='replace'))
        metadata_text += f"{clean_decoded}\n"
    except Exception as e:
        metadata_text += f"[!] Error reading and cleaning trailing bytes: {e}\n"

def extract_all_metadata(file_path):
    global metadata_text
    metadata_text = ""
    extract_general_metadata(file_path)
    ext = file_path.lower()
    if ext.endswith(('.jpg', '.jpeg', '.png', '.bmp')):
        extract_image_metadata(file_path)
        extract_hidden_text(file_path)
    elif ext.endswith('.pdf'):
        extract_pdf_metadata(file_path)
    elif ext.endswith(('.mp3', '.wav', '.flac', '.ogg', '.m4a')):
        extract_audio_metadata(file_path)
    extract_and_clean_trailing_text(file_path)

class PDFReport(FPDF):
    def header(self):
        self.set_fill_color(240, 240, 240)  # Light grey background
        self.rect(0, 0, 210, 297, 'F')  # Full A4 size
        self.set_fill_color(173, 216, 230)  # Light blue header
        self.set_font("Arial", "B", 16)
        self.set_text_color(0, 0, 0)  # Black text
        self.cell(0, 15, "File Analysis Report", ln=1, align="C", fill=True)
        self.ln(5)

    def chapter_title(self, title, bg_color=(135, 206, 250)):  # Light blue for section titles
        self.set_fill_color(*bg_color)
        self.set_text_color(0, 0, 0)  # Black text
        self.set_draw_color(0, 0, 0)  # Black border
        self.set_line_width(0.3)
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, f"  {title}", ln=1, fill=True)
        self.ln(3)

    def chapter_body(self, body):
        self.set_font("Arial", "", 10)  # Use Arial font
        self.set_text_color(33, 33, 33)  # Dark gray text
        self.set_fill_color(250, 250, 250)  # Light grey inner box
        self.multi_cell(0, 8, body, 0, 'L', fill=True)
        self.ln()

    def add_section(self, title, content, is_scan_result=False):
        if not self.page_no():
            self.add_page()
        if is_scan_result:
            self.set_font("Arial", "B", 16)
            color = (255, 0, 0) if "MALICIOUS" in title.upper() else (0, 128, 0)  # Red for malicious, green for safe
            self.set_text_color(*color)
            self.cell(0, 15, title, ln=1, align="C")
            self.ln(5)
        else:
            self.chapter_title(title)
        self.set_text_color(33, 33, 33)  # Reset to dark gray for body
        self.chapter_body(content)

def save_report(file_path, scan_result, metadata):
    file_name = os.path.basename(file_path)
    report_path = os.path.join(os.path.dirname(file_path), f"{file_name}_report.pdf")
    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    title = "File is MALICIOUS" if "MALICIOUS" in scan_result else "File is SAFE"
    pdf.add_section(title, scan_result, is_scan_result=True)
    pdf.add_section("File Metadata", metadata)
    pdf.output(report_path)
    logging.info(f"[+] Report saved to {report_path}")
    return report_path

def scan_file(file_path):
    global scan_result_text, metadata_text
    scan_result_text = ""
    metadata_text = ""
    analysis_id = upload_file(file_path)
    if analysis_id:
        results = check_analysis(analysis_id)
        if results:
            extract_all_metadata(file_path)
            output_pdf = save_report(file_path, scan_result_text, metadata_text)
            return {
                "status": "success",
                "message": "Scan completed",
                "results": results,
                "scan_result": scan_result_text,
                "metadata": metadata_text,
                "pdf_path": output_pdf
            }
    extract_all_metadata(file_path)
    scan_result_text = "Scan result unavailable due to timeout or error\n"
    output_pdf = save_report(file_path, scan_result_text, metadata_text)
    return {
        "status": "success",
        "message": "Scan completed with metadata only (analysis failed)",
        "results": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
        "scan_result": scan_result_text,
        "metadata": metadata_text,
        "pdf_path": output_pdf
    }

def clear_hidden_data(file_path):
    try:
        with Image.open(file_path) as img:
            logging.debug(f"Original mode: {img.mode}")
            if img.mode not in ("RGB", "RGBA", "L"):
                img = img.convert("RGB")

            pixels = list(img.getdata())
            cleaned_pixels = []

            for px in pixels:
                if isinstance(px, int):  # Grayscale 'L' mode
                    cleaned_px = px & ~1
                else:
                    # Zero out LSB of R, G, B channels
                    cleaned_px = tuple((v & ~1 if i < 3 else v) for i, v in enumerate(px))
                cleaned_pixels.append(cleaned_px)

            cleaned_img = Image.new(img.mode, img.size)
            cleaned_img.putdata(cleaned_pixels)

            clean_dir = os.path.join("temp", "clean_images")
            os.makedirs(clean_dir, exist_ok=True)
            base, ext = os.path.splitext(os.path.basename(file_path))
            cleaned_file_path = os.path.join(clean_dir, f"{base}_cleaned{ext}")

            cleaned_img.save(cleaned_file_path, format=img.format)

        message = f"[+] Hidden data and metadata cleared. Cleaned image saved to {cleaned_file_path}"
        logging.info(message)
        print(message)
        return cleaned_file_path

    except Exception as e:
        logging.exception("Exception during image cleaning:")
        print(f"[!] Failed to clear hidden data and metadata: {e}")
        return None

