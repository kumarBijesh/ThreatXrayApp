from flask import Flask, render_template, request, jsonify, send_file
from scripts import url as url_scanner
from scripts import file as file_scanner
import logging
import os

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/anonymous')
def anonymous():
    return render_template('anonymous.html')

@app.route('/anonUrlScan')
def anonUrlScan():
    return render_template('anonUrlScan.html')

@app.route('/anonFileScan')
def anonFileScan():
    return render_template('anonFileScan.html')

@app.route('/anonImageScan')
def anonImageScan():
    return render_template('anonImageScan.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')




@app.route('/favicon.ico')
def favicon():
    return send_file('static/favicon.ico', mimetype='image/x-icon')  # Serve the favicon file

# FOR URL
@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    logging.debug(f'Received URL: {url}')
    if not url:
        logging.error('No URL provided')
        return jsonify({"status": "error", "message": "No URL provided"})
    analysis_id = url_scanner.submit_url(url)
    if analysis_id:
        results = url_scanner.check_url_analysis(analysis_id)
        logging.debug(f'Scan results: {results}')
        return jsonify({"status": "success", "message": "Scan completed", "results": results})
    logging.error('Submission failed')
    return jsonify({"status": "error", "message": "Scan failed"})

@app.route('/file_scan', methods=['POST'])
def file_scan():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file provided"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"})

    temp_dir = os.path.join("temp", "uploads")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        result = file_scanner.scan_file(file_path)
        if result.get("pdf_path"):
            result["pdf_url"] = f"/download_pdf/{os.path.basename(result['pdf_path'])}"
        return jsonify(result)
    except Exception as e:
        logging.error(f"Exception in file_scan: {str(e)}")
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"})
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

# For image scanning
@app.route('/image_scan', methods=['POST'])
def image_scan():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file provided"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"})

    temp_dir = os.path.join("temp", "uploads")
    clean_dir = os.path.join("temp", "clean_images")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    if not os.path.exists(clean_dir):
        os.makedirs(clean_dir)
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        result = file_scanner.scan_file(file_path)
        if result.get("pdf_path"):
            result["pdf_url"] = f"/download_pdf/{os.path.basename(result['pdf_path'])}"
        
        # Clear hidden data and metadata, saving to temp/clean_images
        cleaned_file_path = file_scanner.clear_hidden_data(file_path)
        if cleaned_file_path:
            cleaned_filename = os.path.basename(cleaned_file_path)
            result["clean_image_url"] = f"/download_clean_image/{cleaned_filename}"
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Exception in image_scan: {str(e)}")
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"})
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/download_pdf/<filename>', methods=['GET'])
def download_pdf(filename):
    pdf_path = os.path.join("temp", "uploads", filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    else:
        return jsonify({"status": "error", "message": "PDF not found"}), 404

@app.route('/download_clean_image/<filename>', methods=['GET'])
def download_clean_image(filename):
    clean_image_path = os.path.join("temp", "clean_images", filename)
    if os.path.exists(clean_image_path):
        return send_file(clean_image_path, as_attachment=True)
    else:
        return jsonify({"status": "error", "message": "Clean image not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)