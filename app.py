from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
from scripts import url as url_scanner
from scripts import file as file_scanner
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
from datetime import datetime
from pytz import timezone
# from models import ScanHistory

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)
    filesize = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('scan_histories', lazy=True))

# Recreate the database tables
with app.app_context():
    db.create_all()

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

@app.route('/LoginImageScan')
def login_image_scan():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('LoginImageScan.html', first_name=user.first_name)

@app.route('/LoginUrlScan')
def login_url_scan():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('LoginUrlScan.html', first_name=user.first_name)

@app.route('/LoginFileScan')
def login_file_scan():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('LoginFileScan.html', first_name=user.first_name)



@app.route('/LoginHistory')
def login_history():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    history = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).all()

    # Convert timestamps to IST for display (handle UTC timestamps)
    ist = timezone('Asia/Kolkata')
    for entry in history:
        if entry.timestamp.tzinfo is None:
            # Assume UTC if naive
            entry.timestamp = entry.timestamp.replace(tzinfo=timezone('UTC')).astimezone(ist)
        else:
            entry.timestamp = entry.timestamp.astimezone(ist)

    return render_template('history.html', first_name=user.first_name, history=history)







@app.route('/clear_history', methods=['POST'])
def clear_history():
    user_id = session.get('user_id')
    if user_id:
        # Assuming you have a ScanHistory model with a user_id field
        ScanHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
    return redirect(url_for('login_history'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        logging.debug(f"Login attempt - Email: {email}")

        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        logging.debug(f"Signup form - First Name: {first_name}, Last Name: {last_name}, Email: {email}")

        if not first_name or not last_name or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'error')
            return render_template('signup.html')

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password_hash=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during registration: {str(e)}")
            flash('Registration failed. Try again.', 'error')
            return render_template('signup.html')
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view the dashboard', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    return render_template('dashboard.html', first_name=user.first_name)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/favicon.ico')
def favicon():
    return send_file('static/favicon.ico', mimetype='image/x-icon')

# @app.route('/scan', methods=['POST'])
# def scan_url():
#     url = request.form.get('url')
#     logging.debug(f'Received URL: {url}')
#     if not url:
#         return jsonify({"status": "error", "message": "No URL provided"})
#     analysis_id = url_scanner.submit_url(url)
#     if analysis_id:
#         results = url_scanner.check_url_analysis(analysis_id)
#         return jsonify({"status": "success", "message": "Scan completed", "results": results})
    
#     #Added for url inserting in db
#     if 'user_id' in session:
#         user_id = session['user_id']
#         new_history = ScanHistory(
#             user_id=user_id,
#             filename=url,                  # the scanned URL
#             filetype='URL',
#             filesize='N/A',
#             status="Malicious" if results.get("is_malicious") else "Suspicious" if results.get("is_suspicious") else "Clean"
#         )
#         db.session.add(new_history)
#         db.session.commit()

#     return jsonify({"status": "error", "message": "Scan failed"})

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    logging.debug(f'Received URL: {url}')
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})

    analysis_id = url_scanner.submit_url(url)
    if not analysis_id:
        return jsonify({"status": "error", "message": "Scan failed to submit"})

    stats = url_scanner.check_url_analysis(analysis_id)

    # ✅ Determine verdict from raw stats
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)

    if malicious_count > 0:
        verdict = "Malicious"
    elif suspicious_count > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    # ✅ Save to DB before returning response
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            new_history = ScanHistory(
                user_id=user_id,
                filename=url,
                filetype='URL',
                filesize='N/A',
                status=verdict
            )
            db.session.add(new_history)
            db.session.commit()
            print("✅ URL scan history saved:", new_history)
        except Exception as e:
            db.session.rollback()
            logging.error(f"❌ Error saving URL history: {e}")

    return jsonify({"status": "success", "message": "Scan completed", "results": stats, "verdict": verdict})







@app.route('/file_scan', methods=['POST'])
def file_scan():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file provided"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"})

    temp_dir = os.path.join("temp", "uploads")
    os.makedirs(temp_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        result = file_scanner.scan_file(file_path)
        if result.get("pdf_path"):
            result["pdf_url"] = f"/download_pdf/{os.path.basename(result['pdf_path'])}"
        
        # ADDED HERE FOR INSERTING 
        if 'user_id' in session:
            status = result.get("verdict", "Unknown")
            filesize = f"{os.path.getsize(file_path) / 1024:.2f} KB"
            new_history = ScanHistory(
                user_id=session['user_id'],
                filename=file.filename,
                filetype=file.content_type,
                filesize=filesize,
                status=status
            )
            db.session.add(new_history)
            db.session.commit()



        return jsonify(result)
    except Exception as e:
        logging.error(f"File scan error: {str(e)}")
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"})
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/image_scan', methods=['POST'])
def image_scan():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file provided"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"})

    temp_dir = os.path.join("temp", "uploads")
    clean_dir = os.path.join("temp", "clean_images")
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(clean_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        result = file_scanner.scan_file(file_path)
        if result.get("pdf_path"):
            result["pdf_url"] = f"/download_pdf/{os.path.basename(result['pdf_path'])}"
        cleaned_file_path = file_scanner.clear_hidden_data(file_path)
        if cleaned_file_path:
            cleaned_filename = os.path.basename(cleaned_file_path)
            result["clean_image_url"] = f"/download_clean_image/{cleaned_filename}"
        return jsonify(result)
    except Exception as e:
        logging.error(f"Image scan error: {str(e)}")
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"})
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/download_pdf/<filename>', methods=['GET'])
def download_pdf(filename):
    pdf_path = os.path.join("temp", "uploads", filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    return jsonify({"status": "error", "message": "PDF not found"}), 404

@app.route('/download_clean_image/<filename>', methods=['GET'])
def download_clean_image(filename):
    clean_image_path = os.path.join("temp", "clean_images", filename)
    if os.path.exists(clean_image_path):
        return send_file(clean_image_path, as_attachment=True)
    return jsonify({"status": "error", "message": "Clean image not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
