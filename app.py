from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
import json, os, threading, jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///bugfinder.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Allow requests from the React dev server and production frontend
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://localhost:3000", "*"]}})

# ─── MODELS ───────────────────────────────────────────────
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    results = db.Column(db.Text)
    bugs_found = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.String(20), default='Unknown')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pdf_path = db.Column(db.String(500))

# ─── JWT HELPERS ──────────────────────────────────────────
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token missing'}), 401
        token = auth_header.split(' ', 1)[1]
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
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    token = generate_token(user.id)
    return jsonify({
        'token': token,
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    })

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
    return jsonify({
        'token': token,
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    }), 201

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
    total_bugs = sum(s.bugs_found or 0 for s in scans)
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
    if scan.user_id != request.current_user.id or not scan.pdf_path:
        return jsonify({'error': 'Not found'}), 404
    safe_name = scan.target_url.replace('https://','').replace('http://','')[:30]
    return send_file(
        scan.pdf_path,
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
            bugs = sum(len(v) for v in results.get('vulnerabilities', {}).values())
            scan.results = json.dumps(results)
            scan.bugs_found = bugs
            scan.risk_score = results.get('risk_score', 'Unknown')
            scan.status = 'done'
            scan.completed_at = datetime.utcnow()
            os.makedirs('reports', exist_ok=True)
            pdf_path = f"reports/report_{scan_id}.pdf"
            generate_pdf_report(results, scan.target_url, pdf_path)
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
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(
            username='admin',
            email='admin@bugfinder.local',
            password_hash=gph('admin123')
        ))
        db.session.commit()
        print("Default user created: admin / admin123")

if __name__ == '__main__':
    print("Backend API running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
