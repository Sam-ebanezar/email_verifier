import os
import csv
import io
import re
import time
import uuid
import dns.resolver
import smtplib
from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, flash, session, g, Response
)
from flask_cors import CORS
from tempfile import NamedTemporaryFile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
import openpyxl  # For reading xlsx files

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key')
CORS(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

users_db = {}

class User(UserMixin):
    def __init__(self, id_, username, password_hash):
        self.id = id_
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    user = users_db.get(user_id)
    if user:
        return user
    return None

print("\U0001F525 VERIFIER RUNNING - Visit AlexBerman.com/Mastermind \U0001F525")

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.net",
    "dispostable.com", "maildrop.cc", "fakeinbox.com", "trashmail.com", "yopmail.com",
    "guerrillamailblock.com", "spam4.me", "mailcatch.com", "inboxbear.com"
}
ROLE_BASED_PREFIXES = {"info", "support", "admin", "sales", "contact", "help", "marketing"}

verification_cache = {}
user_jobs = {}

def calculate_confidence(status, reason, smtp_code=None):
    if status == 'valid':
        return 95
    if status == 'risky':
        risk_scores = {
            'domain_accepts_all': 60,
            'smtp_timeout': 50,
            'smtp_soft_fail_421': 55,
            'smtp_soft_fail_450': 55,
            'smtp_soft_fail_451': 55,
            'smtp_soft_fail_452': 55,
            'smtp_soft_fail_503': 55
        }
        return risk_scores.get(reason, 50)
    if status == 'invalid':
        return 10
    return 30

def check_email(email):
    if not EMAIL_REGEX.match(email):
        return "invalid", "bad_syntax", None

    domain = email.split('@')[1].lower()
    local = email.split('@')[0].lower()

    if domain in DISPOSABLE_DOMAINS:
        return "invalid", "disposable_domain", None
    if local in ROLE_BASED_PREFIXES:
        return "invalid", "role_based", None

    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(r.exchange) for r in records]
        mx_record = mx_records[0] if mx_records else None
        if not mx_record:
            return "invalid", "no_mx", None
    except Exception:
        return "invalid", "no_mx", None

    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo("example.com")
        server.mail("probe@example.com")
        code_all, _ = server.rcpt(f"doesnotexist123@{domain}")
        if code_all == 250:
            server.quit()
            return "risky", "domain_accepts_all", code_all
        server.quit()
    except Exception:
        pass

    def smtp_check(mail):
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_record)
            server.helo("example.com")
            server.mail("verifier@example.com")
            code, _ = server.rcpt(mail)
            server.quit()
            return code
        except Exception:
            return None

    code = smtp_check(email)
    if code in [421, 450, 451, 452, 503]:
        for attempt in range(3):
            time.sleep(2 * (attempt + 1))
            code = smtp_check(email)
            if code not in [421, 450, 451, 452, 503]:
                break

    if code == 250:
        status = "valid"
        reason = "smtp_ok"
    elif code is None:
        status = "risky"
        reason = "smtp_timeout"
    elif code in [421, 450, 451, 452, 503]:
        status = "risky"
        reason = f"smtp_soft_fail_{code}"
    elif code == 550:
        status = "invalid"
        reason = "smtp_reject"
    else:
        status = "invalid"
        reason = f"smtp_{code}"

    return status, reason, code

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'txt', 'xls', 'xlsx'}

@app.before_request
def load_logged_in_user():
    g.user = current_user if current_user.is_authenticated else None

@app.route('/')
@login_required
def index():
    return render_template('index.html', jobs=user_jobs.get(g.user.id, {}))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password required", "error")
            return render_template('register.html')
        if any(u.username == username for u in users_db.values()):
            flash("Username already taken", "error")
            return render_template('register.html')
        user_id = str(uuid.uuid4())
        pw_hash = generate_password_hash(password)
        user = User(user_id, username, pw_hash)
        users_db[user_id] = user
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = next((u for u in users_db.values() if u.username == username), None)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/verify', methods=['POST'])
@login_required
def verify():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type"}), 400

    job_id = str(uuid.uuid4())
    ext = file.filename.rsplit('.', 1)[1].lower()

    if ext == 'csv':
        content = file.read().decode('utf-8')
        reader = list(csv.DictReader(io.StringIO(content)))
        email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None) if reader else None
    elif ext == 'txt':
        content = file.read().decode('utf-8')
        lines = content.splitlines()
        reader = [{'email': line.strip()} for line in lines if line.strip()]
        email_field = 'email'
    elif ext in ('xls', 'xlsx'):
        file.seek(0)
        workbook = openpyxl.load_workbook(file, read_only=True)
        sheet = workbook.active
        rows = list(sheet.rows)
        headers = [cell.value for cell in rows[0]]
        email_idx = None
        for idx, h in enumerate(headers):
            if h and str(h).strip().lower() == 'email':
                email_idx = idx
                break
        reader = []
        if email_idx is not None:
            for row in rows[1:]:
                cell_val = row[email_idx].value
                reader.append({'email': str(cell_val).strip() if cell_val else ''})
            email_field = 'email'
        else:
            return jsonify({"error": "No 'email' column found in Excel file"}), 400
    else:
        return jsonify({"error": "Unsupported file type"}), 400

    total = len(reader)
    output = io.StringIO()
    fieldnames = list(reader[0].keys()) + ['status', 'reason', 'confidence'] if reader else ['email', 'status', 'reason', 'confidence']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    user_id = g.user.id
    user_jobs.setdefault(user_id, {})
    user_jobs[user_id][job_id] = {
        "progress": 0,
        "row": 0,
        "total": total,
        "log": "",
        "cancel": False,
        "output": output,
        "writer": writer,
        "records": reader,
        "email_field": email_field,
        "filename": file.filename
    }

    def calculate_confidence(status, reason, smtp_code=None):
        if status == 'valid':
            return 95
        if status == 'risky':
            risk_scores = {
                'domain_accepts_all': 60,
                'smtp_timeout': 50,
                'smtp_soft_fail_421': 55,
                'smtp_soft_fail_450': 55,
                'smtp_soft_fail_451': 55,
                'smtp_soft_fail_452': 55,
                'smtp_soft_fail_503': 55
            }
            return risk_scores.get(reason, 50)
        if status == 'invalid':
            return 10
        return 30

    def worker(idx, row):
        if user_jobs[user_id][job_id]['cancel']:
            return (idx, None)  # indicate cancellation
        email = (row.get(email_field) or '').strip()
        cache = verification_cache.setdefault(user_id, {})
        if email in cache:
            status, reason, code = cache[email]
        elif not email:
            status, reason, code = 'invalid', 'empty_email', None
        else:
            status, reason, code = check_email(email)
            cache[email] = (status, reason, code)
        confidence = calculate_confidence(status, reason, code)
        row['status'] = status
        row['reason'] = reason
        row['confidence'] = confidence
        return (idx, row)

    def run():
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(worker, i, row): i for i, row in enumerate(reader)}
            completed = 0
            for future in as_completed(futures):
                idx = futures[future]
                result = future.result()
                if result is None or result[1] is None:
                    user_jobs[user_id][job_id]['log'] = f"\u274c Canceled job {job_id}"
                    break
                _, res_row = result
                user_jobs[user_id][job_id]['writer'].writerow(res_row)
                completed += 1
                percent = int((completed / total) * 100)
                user_jobs[user_id][job_id].update({
                    "progress": percent,
                    "row": completed,
                    "log": f"\u2705 {res_row.get(email_field, '')} → {res_row['status']} ({res_row['reason']}), confidence {res_row['confidence']}%"
                })
        output = user_jobs[user_id][job_id]['output']
        output.seek(0)
        temp = NamedTemporaryFile(delete=False, suffix=".csv", mode='w+')
        temp.write(output.read())
        temp.flush()
        temp.seek(0)
        user_jobs[user_id][job_id]['file_path'] = temp.name

    threading.Thread(target=run).start()

    return jsonify({"job_id": job_id})

@app.route('/progress')
@login_required
def progress():
    user_id = g.user.id
    job_id = request.args.get("job_id")
    d = user_jobs.get(user_id, {}).get(job_id, {})
    return jsonify({
        "percent": d.get("progress", 0),
        "row": d.get("row", 0),
        "total": d.get("total", 0)
    })

@app.route('/log')
@login_required
def log():
    user_id = g.user.id
    job_id = request.args.get("job_id")
    return Response(user_jobs.get(user_id, {}).get(job_id, {}).get("log", ""), mimetype='text/plain')

@app.route('/cancel', methods=['POST'])
@login_required
def cancel():
    user_id = g.user.id
    job_id = request.args.get("job_id")
    if job_id in user_jobs.get(user_id, {}):
        user_jobs[user_id][job_id]['cancel'] = True
    return '', 204

@app.route('/download')
@login_required
def download():
    user_id = g.user.id
    job_id = request.args.get("job_id")
    filter_type = request.args.get("type", "all")
    job = user_jobs.get(user_id, {}).get(job_id)
    if not job:
        return "Invalid job ID", 404

    job['output'].seek(0)
    reader = list(csv.DictReader(job['output']))

    if filter_type == "valid":
        filtered = [row for row in reader if row['status'] == 'valid']
    elif filter_type == "risky":
        filtered = [row for row in reader if row['status'] == 'risky']
    elif filter_type == "risky_invalid":
        filtered = [row for row in reader if row['status'] in ('risky', 'invalid')]
    else:
        filtered = reader

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=reader[0].keys())
    writer.writeheader()
    for row in filtered:
        writer.writerow(row)

    output.seek(0)
    download_name = f"{filter_type}-galadon-{job['filename']}"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={download_name}"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5050)
