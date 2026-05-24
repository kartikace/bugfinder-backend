from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
import json, os, threading, jwt, time, secrets
from collections import defaultdict

app = Flask(__name__)

# Enforce secure random SECRET_KEY generation in production if not set (B-04)
secret_key = os.environ.get('SECRET_KEY')
is_prod = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER') == 'true'
if not secret_key:
    if is_prod:
        # Production: generate a secure cryptographically random key on startup
        secret_key = secrets.token_hex(32)
    else:
        # Local development
        secret_key = 'dev-secret-change-in-production'
app.config['SECRET_KEY'] = secret_key

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///bugfinder.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Lock down CORS origins in production and support cross-site credentials (B-02 / B-13)
allowed_origins = ["http://localhost:5173", "http://localhost:3000"]
frontend_url = os.environ.get('FRONTEND_URL')
if frontend_url:
    allowed_origins.append(frontend_url.rstrip('/'))

CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, supports_credentials=True)

# ─── MODELS ───────────────────────────────────────────────
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    scans = db.relationship('Scan', backref='user', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    results = db.Column(db.Text)
    bugs_found = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.String(20), default='Unknown')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pdf_path = db.Column(db.String(500))

# ─── RATE LIMITER (B-08) ──────────────────────────────────
login_attempts = defaultdict(list)

def rate_limit_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Read IP address safely (handles standard load balancer headers)
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
            
        now = time.time()
        # Clean records older than 60 seconds
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
        
        # Limit to 5 requests per minute
        if len(login_attempts[ip]) >= 5:
            return jsonify({'error': 'Too many login attempts. Please try again in 60 seconds.'}), 429
            
        login_attempts[ip].append(now)
        return f(*args, **kwargs)
    return decorated

# ─── JWT HELPERS (B-13) ───────────────────────────────────
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # 1. Try reading HTTP-Only cookie first (XSS defense)
        token = request.cookies.get('token')
        
        # 2. Fallback to Authorization Header (Bearer token)
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]
                
        # 3. Fallback to Query String (used for programmatic file downloads)
        if not token:
            token = request.args.get('token', '')
            
        if not token:
            return jsonify({'error': 'Authorization token missing'}), 401
            
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 401
            request.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# ─── AUTH ROUTES ──────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
@rate_limit_login
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
        
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
        
    token = generate_token(user.id)
    resp = jsonify({
        'token': token,
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    })
    
    # Set HTTP-Only Secure Cookie
    resp.set_cookie(
        'token',
        token,
        httponly=True,
        secure=is_prod,
        samesite='None' if is_prod else 'Lax',
        max_age=7*24*60*60 # 7 days
    )
    return resp

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400
        
    # Enforce minimum 8-character password length (B-15)
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
        
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password)
    )
    db.session.add(user)
    db.session.commit()
    token = generate_token(user.id)
    
    resp = jsonify({
        'token': token,
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    })
    
    # Set HTTP-Only Secure Cookie
    resp.set_cookie(
        'token',
        token,
        httponly=True,
        secure=is_prod,
        samesite='None' if is_prod else 'Lax',
        max_age=7*24*60*60 # 7 days
    )
    return resp, 201

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    resp = jsonify({'message': 'Logged out successfully'})
    resp.delete_cookie(
        'token',
        httponly=True,
        secure=is_prod,
        samesite='None' if is_prod else 'Lax'
    )
    return resp

@app.route('/api/auth/me', methods=['GET'])
@jwt_required
def me():
    u = request.current_user
    return jsonify({'id': u.id, 'username': u.username, 'email': u.email})

# ─── SCAN ROUTES ──────────────────────────────────────────
@app.route('/api/scans', methods=['GET'])
@jwt_required
def list_scans():
    user = request.current_user
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).all()
    
    # Exclude internal scan errors / info alerts when calculating stats (B-12)
    total_bugs = sum(s.bugs_found or 0 for s in scans if s.status == 'done')
    done_count = len([s for s in scans if s.status == 'done'])
    return jsonify({
        'stats': {
            'total': len(scans),
            'done': done_count,
            'total_bugs': total_bugs
        },
        'scans': [serialize_scan(s) for s in scans]
    })

@app.route('/api/scans', methods=['POST'])
@jwt_required
def create_scan():
    user = request.current_user
    data = request.get_json()
    if not data or not data.get('target_url'):
        return jsonify({'error': 'target_url is required'}), 400
        
    url = data['target_url'].strip()
    
    # Basic backend URL format validation
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url.startswith(('http://', 'https://')) and url or 'https://' + url)
        if not parsed.hostname or '.' not in parsed.hostname:
            return jsonify({'error': 'Invalid target URL format'}), 400
    except:
        return jsonify({'error': 'Invalid target URL format'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    scan = Scan(target_url=url, user_id=user.id, status='running')
    db.session.add(scan)
    db.session.commit()
    thread = threading.Thread(target=run_scan_bg, args=(app, scan.id))
    thread.daemon = True
    thread.start()
    return jsonify(serialize_scan(scan)), 201

@app.route('/api/scans/<int:scan_id>', methods=['GET'])
@jwt_required
def get_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != request.current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    data = serialize_scan(scan)
    if scan.results:
        data['results'] = json.loads(scan.results)
    return jsonify(data)

@app.route('/api/scans/<int:scan_id>/status', methods=['GET'])
@jwt_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != request.current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    return jsonify({'status': scan.status, 'bugs': scan.bugs_found, 'risk': scan.risk_score})

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@jwt_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != request.current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan deleted'})

@app.route('/api/scans/<int:scan_id>/download', methods=['GET'])
@jwt_required
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != request.current_user.id:
        return jsonify({'error': 'Access denied'}), 403
        
    # Programmatic re-generation on the fly if file is deleted / missing (B-05 / B-07)
    pdf_abs_path = os.path.abspath(scan.pdf_path) if scan.pdf_path else None
    
    if not pdf_abs_path or not os.path.exists(pdf_abs_path):
        if scan.results:
            os.makedirs('reports', exist_ok=True)
            pdf_path = f"reports/report_{scan_id}.pdf"
            pdf_abs_path = os.path.abspath(pdf_path)
            from report_gen import generate_pdf_report
            try:
                generate_pdf_report(json.loads(scan.results), scan.target_url, pdf_abs_path)
                scan.pdf_path = pdf_path
                db.session.commit()
            except Exception as e:
                return jsonify({'error': f'Failed to re-generate report: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Report PDF not generated yet'}), 404
            
    # Clean target URL for safe headers filename
    safe_name = scan.target_url.replace('https://','').replace('http://','')[:30]
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in ('._-')).rstrip()
    
    return send_file(
        pdf_abs_path,
        as_attachment=True,
        download_name=f"BugReport_{safe_name}_{scan_id}.pdf"
    )

# ─── BACKGROUND SCAN ──────────────────────────────────────
def run_scan_bg(app, scan_id):
    from scanner import run_full_scan
    from report_gen import generate_pdf_report
    with app.app_context():
        scan = Scan.query.get(scan_id)
        try:
            results = run_full_scan(scan.target_url)
            
            # Exclude scan errors / info elements (B-12)
            def is_real_vulnerability(bug):
                if not bug or 'error' in bug:
                    return False
                if bug.get('title') == 'Scan Error':
                    return False
                if bug.get('severity') == 'INFO':
                    return False
                return True
                
            bugs = sum(1 for v in results.get('vulnerabilities', {}).values() for bug in v if is_real_vulnerability(bug))
            scan.results = json.dumps(results)
            scan.bugs_found = bugs
            scan.risk_score = results.get('risk_score', 'Unknown')
            scan.status = 'done'
            scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            
            os.makedirs('reports', exist_ok=True)
            pdf_path = f"reports/report_{scan_id}.pdf"
            generate_pdf_report(results, scan.target_url, os.path.abspath(pdf_path))
            scan.pdf_path = pdf_path
        except Exception as e:
            scan.status = 'error'
            scan.results = json.dumps({'error': str(e)})
        db.session.commit()

# ─── HELPERS ──────────────────────────────────────────────
def serialize_scan(s):
    return {
        'id': s.id,
        'target_url': s.target_url,
        'status': s.status,
        'bugs_found': s.bugs_found or 0,
        'risk_score': s.risk_score,
        'pdf_ready': bool(s.pdf_path),
        'created_at': s.created_at.isoformat() if s.created_at else None,
        'completed_at': s.completed_at.isoformat() if s.completed_at else None,
    }

with app.app_context():
    os.makedirs(app.instance_path, exist_ok=True)
    db.create_all()
    from werkzeug.security import generate_password_hash as gph
    
    # Secure default credentials from environment (B-01)
    admin_user = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
    admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    if is_prod and admin_user == 'admin' and admin_pass == 'admin123':
        print("⚠️  SECURITY WARNING: Using hardcoded default credentials in production! Please set DEFAULT_ADMIN_USERNAME and DEFAULT_ADMIN_PASSWORD environment variables.")
        
    if not User.query.filter_by(username=admin_user).first():
        db.session.add(User(
            username=admin_user,
            email='admin@bugfinder.local',
            password_hash=gph(admin_pass)
        ))
        db.session.commit()
        print(f"Default admin user seeded successfully: {admin_user}")

if __name__ == '__main__':
    # Disable debug in production via environment configuration (B-06)
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1']
    print(f"Backend API running on http://localhost:5000 (Debug: {debug_mode})")
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
