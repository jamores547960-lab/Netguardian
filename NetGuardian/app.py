import sqlite3
import os
import csv
import io
import re
import smtplib
import random
import time
import base64
import subprocess
import socket
import concurrent.futures
from email.message import EmailMessage
from email.mime.text import MIMEText
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from werkzeug.security import check_password_hash, generate_password_hash
try:
    import requests as _requests
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request as _GoogleRequest
    _GMAIL_API_AVAILABLE = True
except ImportError:
    _GMAIL_API_AVAILABLE = False

def load_env_file():
    """Load configuration from local .env file if present."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        key = key.strip()
                        val = val.strip().strip('"\'')
                        if key and val:
                            os.environ[key] = val
        except Exception as e:
            print(f'[NetGuardian] Error reading .env file: {e}')

load_env_file()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('NETGUARDIAN_SECRET_KEY', 'dev-secret-change-me'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('NETGUARDIAN_SECURE_COOKIES', 'false').lower() == 'true',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=False,
)

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300
FAILED_LOGIN_ATTEMPTS = {}


def get_login_attempt_key(username):
    return (username or '').strip().lower()


def is_login_locked(username):
    key = get_login_attempt_key(username)
    if not key:
        return False, 0

    attempts = FAILED_LOGIN_ATTEMPTS.get(key)
    if not attempts:
        return False, 0

    now = time.time()
    lockout_until = attempts.get('locked_until', 0)
    if lockout_until and now < lockout_until:
        return True, max(0, int(lockout_until - now))

    if lockout_until and now >= lockout_until:
        FAILED_LOGIN_ATTEMPTS.pop(key, None)
    return False, 0


def record_failed_login(username):
    key = get_login_attempt_key(username)
    if not key:
        return False

    attempts = FAILED_LOGIN_ATTEMPTS.get(key, {'count': 0, 'locked_until': 0})
    attempts['count'] += 1
    if attempts['count'] >= MAX_LOGIN_ATTEMPTS:
        attempts['locked_until'] = time.time() + LOGIN_LOCKOUT_SECONDS
        FAILED_LOGIN_ATTEMPTS[key] = attempts
        return True

    FAILED_LOGIN_ATTEMPTS[key] = attempts
    return False


def clear_failed_login_attempts(username):
    FAILED_LOGIN_ATTEMPTS.pop(get_login_attempt_key(username), None)


def log_login_activity(username, action, notes):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (username or 'Unknown User', action, notes)
    )
    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    sync_real_network_devices(reset_mock_data=True)


def ensure_user_email_column():
    conn = get_db_connection()
    columns = conn.execute('PRAGMA table_info(users)').fetchall()
    existing = [column[1] for column in columns]
    if 'email' not in existing:
        conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
    # Provide defaults only if user email is completely empty
    conn.execute("UPDATE users SET email = 'janjerick3002@gmail.com' WHERE username = 'manager' AND (email IS NULL OR email = '')")
    conn.execute("UPDATE users SET email = 'janjerick3002@gmail.com' WHERE username = 'staff' AND (email IS NULL OR email = '')")
    conn.commit()
    conn.close()


def discover_real_network_devices():
    """
    Discovers 100% real active network devices from the host operating system:
    1. Active local network interface IPv4 and MAC address (Host PC).
    2. Default Gateway router IPv4 and MAC address.
    3. Active LAN devices discovered via full multi-threaded subnet ping sweep & Windows ARP table (arp -a).
    4. Detects real ARP spoofing if any device impersonates the Default Gateway MAC.
    """
    devices = []
    seen_ips = set()
    hostname = socket.gethostname()
    host_ip = None
    host_mac = None
    host_desc = 'Host Network Adapter'
    gateway_ip = None
    gateway_mac = None
    subnet_prefix = "192.168.1"

    # 1. Parse ipconfig for active interface and default gateway
    try:
        ipconfig_out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore')
        sections = re.split(r'\n(?=[A-Za-z0-9].*?:)', ipconfig_out)
        for sec in sections:
            if 'Media disconnected' in sec:
                continue
            ip_match = re.search(r'IPv4 Address[ .:]+:\s*([0-9.]+)', sec)
            mac_match = re.search(r'Physical Address[ .:]+:\s*([0-9A-Fa-f-]+)', sec)
            gw_match = re.search(r'Default Gateway[ .:]+:\s*([0-9.]+)', sec)
            desc_match = re.search(r'Description[ .:]+:\s*([^\r\n]+)', sec)

            if ip_match and mac_match:
                ip = ip_match.group(1).replace('(Preferred)', '').strip()
                mac = mac_match.group(1).replace('-', ':').upper()
                desc = desc_match.group(1).strip() if desc_match else 'Network Adapter'

                if not ip.startswith('127.'):
                    host_ip = ip
                    host_mac = mac
                    host_desc = desc
                    parts = ip.split('.')
                    if len(parts) == 4:
                        subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"

                    if gw_match:
                        gw = gw_match.group(1).strip()
                        if gw and not gw.startswith('127.'):
                            gateway_ip = gw
    except Exception as e:
        print(f'[NetGuardian] Error parsing ipconfig: {e}')

    # 2. Fast multi-threaded ping sweep across full subnet (1-254) to refresh ARP table
    def quick_ping(target):
        try:
            subprocess.run(['ping', '-n', '1', '-w', '120', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    ping_targets = [f'{subnet_prefix}.{i}' for i in range(1, 255)]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
            list(executor.map(quick_ping, ping_targets))
    except Exception as e:
        print(f'[NetGuardian] Subnet ping sweep error: {e}')

    # 3. Read ARP cache to collect all live network devices
    try:
        arp_out = subprocess.check_output(['arp', '-a'], text=True, errors='ignore')

        # First find the gateway's real MAC
        if gateway_ip:
            for line in arp_out.splitlines():
                match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                if match:
                    ip, mac = match.groups()
                    if ip == gateway_ip:
                        gateway_mac = mac.replace('-', ':').upper()
                        break

        # Register Host PC first
        if host_ip and host_mac:
            devices.append({
                'ip_address': host_ip,
                'mac_address': host_mac,
                'device_name': f'{hostname} (Host PC - {host_desc})',
                'status': 'green',
                'is_blocked': 0
            })
            seen_ips.add(host_ip)

        for line in arp_out.splitlines():
            line = line.strip()
            match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})\s+(\w+)', line)
            if match:
                ip, mac, arp_type = match.groups()
                mac = mac.replace('-', ':').upper()

                # Ignore multicast, broadcast, non-subnet, and already seen addresses
                if (ip.startswith('224.') or ip.startswith('239.') or 
                    ip.endswith('.255') or mac == 'FF:FF:FF:FF:FF:FF' or 
                    not ip.startswith(subnet_prefix + '.') or
                    ip in seen_ips):
                    continue

                seen_ips.add(ip)

                if gateway_ip and ip == gateway_ip:
                    dev_name = 'Real Wi-Fi Router (Default Gateway)'
                    status = 'green'
                elif gateway_mac and mac == gateway_mac:
                    dev_name = f'Rogue Attacker / Gateway MAC Impersonator ({ip})'
                    status = 'red'
                else:
                    dev_name = f'Connected LAN Device ({ip})'
                    status = 'green' if arp_type.lower() == 'dynamic' else 'yellow'

                devices.append({
                    'ip_address': ip,
                    'mac_address': mac,
                    'device_name': dev_name,
                    'status': status,
                    'is_blocked': 0
                })
    except Exception as e:
        print(f'[NetGuardian] ARP discovery error: {e}')

    # Sort devices numerically by IP
    def ip_key(d):
        try:
            return [int(x) for x in d['ip_address'].split('.')]
        except Exception:
            return [0, 0, 0, 0]

    devices.sort(key=ip_key)
    return devices


def sync_real_network_devices(reset_mock_data=True):
    """
    Synchronizes real local network devices into SQLite database.
    Clears out any synthetic mock devices and inactive subnets.
    """
    discovered = discover_real_network_devices()
    conn = get_db_connection()
    
    if reset_mock_data and discovered:
        host_entry = next((d for d in discovered if 'Host' in d['device_name']), discovered[0])
        host_ip = host_entry['ip_address']
        parts = host_ip.split('.')
        current_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else "192.168.1."

        # Clean out mock IPs, inactive subnets, and old synthetic sample devices
        conn.execute("DELETE FROM devices WHERE ip_address IN ('8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '93.184.216.34', '142.250.190.78', '198.51.100.5')")
        conn.execute("DELETE FROM devices WHERE ip_address NOT LIKE ?", (f'{current_prefix}%',))
        conn.execute("DELETE FROM devices WHERE device_name IN ('Office Network Printer (HP LaserJet)', 'Smart TV / IoT Hub', 'Unregistered Guest Smartphone', 'Rogue Attacker (ARP Poisoning Detected)', 'Office Network Printer', 'Unregistered Guest Device')")

        # Keep only devices that are in discovered list or were explicitly flagged as threat
        discovered_ips = [d['ip_address'] for d in discovered]
        placeholders = ','.join(['?'] * len(discovered_ips))
        conn.execute(f"DELETE FROM devices WHERE ip_address NOT IN ({placeholders}) AND status != 'red'", discovered_ips)

    for dev in discovered:
        existing = conn.execute('SELECT id, is_blocked, status FROM devices WHERE ip_address = ?', (dev['ip_address'],)).fetchone()
        if existing:
            conn.execute(
                'UPDATE devices SET mac_address = ?, device_name = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (dev['mac_address'], dev['device_name'], existing['id'])
            )
        else:
            conn.execute(
                'INSERT INTO devices (ip_address, mac_address, device_name, status, is_blocked) VALUES (?, ?, ?, ?, ?)',
                (dev['ip_address'], dev['mac_address'], dev['device_name'], dev['status'], dev['is_blocked'])
            )
    conn.commit()
    conn.close()
    return discovered



def is_valid_username(value):
    return bool(value) and re.fullmatch(r'[A-Za-z0-9_.-]{3,50}', value.strip()) is not None


def is_valid_password(value):
    return bool(value) and len(value.strip()) >= 8


def is_valid_email(value):
    return bool(value) and re.fullmatch(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', value.strip()) is not None


def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                flash('You do not have permission to perform this action.', 'warning')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def api_require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                return jsonify({'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def generate_otp():
    return str(random.randint(100000, 999999))


def get_user_email_address(user):
    if user is not None:
        email = None
        if isinstance(user, dict):
            email = user.get('email')
        elif 'email' in user.keys():
            email = user['email']
        if email:
            return email
    configured = os.environ.get('NETGUARDIAN_EMAIL') or os.environ.get('NETGUARDIAN_GMAIL')
    if configured:
        return configured
    return 'janjerick3002@gmail.com'


def send_otp_email(email_address, otp_code):
    """
    Sends OTP email using Gmail REST API over HTTPS (port 443) first,
    then falls back to SMTP if REST API credentials are not configured.
    Returns tuple: (status, error_message)
      status: 'smtp' (success via REST API or SMTP) | 'failed'
    """
    load_env_file()
    gmail_user = (os.environ.get('NETGUARDIAN_EMAIL_USER') or os.environ.get('NETGUARDIAN_GMAIL_USER') or '').strip()

    body_text = (
        f"Hello,\n\n"
        f"Your NetGuardian login verification code is: {otp_code}\n\n"
        f"This code will expire in 5 minutes.\n\n"
        f"If you did not request this verification code, please disregard this message.\n\n"
        f"— NetGuardian On-Site Spoofing Detection"
    )

    # ── Path 1: Gmail REST API (HTTPS port 443 — works on restricted networks) ──
    client_id     = os.environ.get('NETGUARDIAN_GMAIL_CLIENT_ID', '').strip()
    client_secret = os.environ.get('NETGUARDIAN_GMAIL_CLIENT_SECRET', '').strip()
    refresh_token = os.environ.get('NETGUARDIAN_GMAIL_REFRESH_TOKEN', '').strip()

    if _GMAIL_API_AVAILABLE and client_id and client_secret and refresh_token and gmail_user:
        try:
            creds = Credentials(
                token=None,
                refresh_token=refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=client_id,
                client_secret=client_secret,
            )
            creds.refresh(_GoogleRequest())

            mime_msg = MIMEText(body_text)
            mime_msg['Subject'] = 'NetGuardian - Login Verification Code'
            mime_msg['From']    = f'NetGuardian Security <{gmail_user}>'
            mime_msg['To']      = email_address
            raw = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode()

            resp = _requests.post(
                f'https://gmail.googleapis.com/gmail/v1/users/{gmail_user}/messages/send',
                headers={'Authorization': f'Bearer {creds.token}', 'Content-Type': 'application/json'},
                json={'raw': raw},
                timeout=30,
            )
            if resp.status_code == 200:
                print(f'[NetGuardian] OTP sent via Gmail REST API to {email_address}')
                return 'smtp', None
            else:
                print(f'[NetGuardian] Gmail REST API returned {resp.status_code}: {resp.text}')
                # Fall through to SMTP attempt
        except Exception as exc:
            print(f'[NetGuardian] Gmail REST API error: {exc}')
            # Fall through to SMTP attempt

    # ── Path 2: Gmail SMTP fallback (may be blocked on restricted networks) ──
    gmail_password = (os.environ.get('NETGUARDIAN_EMAIL_PASSWORD') or os.environ.get('NETGUARDIAN_GMAIL_PASSWORD') or '').strip()
    if gmail_password:
        gmail_password = gmail_password.replace(' ', '')

    if not gmail_user or not gmail_password:
        print(f'[NetGuardian] No email credentials configured. OTP not sent to {email_address}.')
        return 'failed', 'No Gmail credentials configured (neither REST API nor App Password).'

    msg = EmailMessage()
    msg['Subject'] = 'NetGuardian - Login Verification Code'
    msg['From']    = f'NetGuardian Security <{gmail_user}>'
    msg['To']      = email_address
    msg.set_content(body_text)

    last_error = None
    for port, use_ssl in [(465, True), (587, False)]:
        try:
            if use_ssl:
                with smtplib.SMTP_SSL('smtp.gmail.com', port, timeout=30) as server:
                    server.login(gmail_user, gmail_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP('smtp.gmail.com', port, timeout=30) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(gmail_user, gmail_password)
                    server.send_message(msg)
            print(f'[NetGuardian] OTP sent via Gmail SMTP port {port} to {email_address}')
            return 'smtp', None
        except Exception as exc:
            last_error = exc
            print(f'[NetGuardian] Gmail SMTP port {port} failed: {exc}')

    print(f'[NetGuardian] All delivery methods failed: {last_error}')
    return 'failed', str(last_error) if last_error else 'Unknown error'


@app.route('/overview')
@login_required
def overview():
    """High-level landing page for the NetGuardian console."""
    conn = get_db_connection()
    device_rows = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    recent_logs = conn.execute('SELECT * FROM shift_logs ORDER BY timestamp DESC LIMIT 5').fetchall()
    conn.close()
    active_threats = [device for device in device_rows if device['status'] == 'red' and not device['is_blocked']]
    return render_template(
        'overview.html', devices=device_rows, recent_logs=recent_logs,
        total_devices=len(device_rows), active_threats=len(active_threats),
        blocked_count=sum(1 for device in device_rows if device['is_blocked']),
        review_count=sum(1 for device in device_rows if device['status'] == 'yellow')
    )

def device_to_dict(device):
    return {
        'id': device['id'],
        'ip_address': device['ip_address'],
        'mac_address': device['mac_address'],
        'device_name': device['device_name'],
        'status': device['status'],
        'is_blocked': bool(device['is_blocked']),
        'last_seen': device['last_seen']
    }

def log_to_dict(log):
    return {
        'id': log['id'],
        'timestamp': log['timestamp'],
        'handled_by': log['handled_by'],
        'action_taken': log['action_taken'],
        'notes': log['notes']
    }

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username', '') or '').strip()
        email = (request.form.get('email', '') or '').strip()
        password = request.form.get('password', '')
        role = (request.form.get('role', 'Shift Monitor') or 'Shift Monitor').strip()

        if not is_valid_username(username):
            flash('Username must be 3-50 characters and contain only letters, numbers, underscores, dots, or dashes.', 'danger')
            return render_template('register.html')

        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('register.html')

        if not is_valid_password(password):
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        if role not in ('Whitelist Manager', 'Shift Monitor'):
            flash('Please choose a valid account role.', 'danger')
            return render_template('register.html')

        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE LOWER(TRIM(username)) = LOWER(?) OR LOWER(TRIM(email)) = LOWER(?)',
            (username, email)
        ).fetchone()

        if existing_user:
            conn.close()
            flash('An account with that username or email already exists.', 'danger')
            return render_template('register.html')

        conn.execute(
            'INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
            (username, generate_password_hash(password), email, role)
        )
        conn.commit()
        conn.close()

        log_login_activity(username, 'Account created', f'New {role} account created for {email}.')
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username', '') or '').strip()
        email = (request.form.get('email', '') or '').strip()
        password = request.form.get('password', '')

        if not is_valid_username(username):
            flash('Username must be 3-50 characters and contain only letters, numbers, underscores, dots, or dashes.', 'danger')
            return render_template('login.html')

        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('login.html')

        if not is_valid_password(password):
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('login.html')

        locked, remaining_seconds = is_login_locked(username)
        if locked:
            minutes, seconds = divmod(remaining_seconds, 60)
            log_login_activity(username, 'Login blocked', f'Account locked for {minutes}m {seconds}s after 5 failed attempts.')
            flash(f'Too many failed login attempts. Please try again in {minutes}m {seconds}s.', 'danger')
            return render_template('login.html')

        conn = get_db_connection()
        # Find user by username (case-insensitive)
        user = conn.execute(
            'SELECT * FROM users WHERE LOWER(TRIM(username)) = LOWER(?)', 
            (username,)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            prior_failures = FAILED_LOGIN_ATTEMPTS.get(get_login_attempt_key(username), {}).get('count', 0)
            clear_failed_login_attempts(username)
            # Sync user's email if provided
            if email and (not user['email'] or user['email'].lower() != email.lower()):
                conn.execute('UPDATE users SET email = ? WHERE id = ?', (email, user['id']))
                conn.commit()
            conn.close()

            otp_code = generate_otp()
            recipient_email = email if email else get_user_email_address(user)
            log_login_activity(username, 'Login request approved', f'OTP sent to {recipient_email}. Prior failed attempts: {prior_failures}.')
            session.clear()
            session.permanent = True
            session['pending_user_id'] = user['id']
            session['pending_username'] = user['username']
            session['pending_role'] = user['role']
            session['pending_email'] = recipient_email
            session['pending_otp'] = otp_code
            session['pending_otp_expires'] = time.time() + 300
            session['pending_otp_debug'] = None

            delivery_mode, error_detail = send_otp_email(recipient_email, otp_code)
            if delivery_mode == 'smtp':
                flash(f'A verification code was sent to {recipient_email}. Please check your inbox.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                session.pop('pending_otp_debug', None)
                flash(f'Unable to send the verification code to Gmail. Please check your Gmail App Password and network access. {error_detail}', 'danger')
                return render_template('login.html')
        else:
            conn.close()
            locked_now = record_failed_login(username)
            attempts = FAILED_LOGIN_ATTEMPTS.get(get_login_attempt_key(username), {}).get('count', 0)
            if locked_now:
                log_login_activity(username, 'Failed login attempt', f'User hit the 5-attempt lockout. Account locked for {LOGIN_LOCKOUT_SECONDS // 60} minutes.')
                flash(f'Too many failed login attempts. This account has been temporarily locked for {LOGIN_LOCKOUT_SECONDS // 60} minutes.', 'danger')
            else:
                remaining = max(0, MAX_LOGIN_ATTEMPTS - attempts)
                log_login_activity(username, 'Failed login attempt', f'Invalid username or password. Attempt {attempts}/{MAX_LOGIN_ATTEMPTS}. Remaining before lockout: {remaining}.')
                flash(f'Invalid username or password. {remaining} attempt(s) remaining before lockout.', 'danger')

    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user_id' not in session:
        flash('Please log in before verifying your account.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        submitted_otp = (request.form.get('otp', '') or '').strip()
        expires_at = float(session.get('pending_otp_expires', 0))

        if time.time() > expires_at:
            username = session.get('pending_username')
            log_login_activity(username, 'OTP verification failed', 'Verification code expired before login was confirmed.')
            flash('Your verification code has expired. Please sign in again or request a new code.', 'warning')
            return redirect(url_for('login'))

        if not submitted_otp.isdigit() or len(submitted_otp) != 6:
            username = session.get('pending_username')
            log_login_activity(username, 'OTP verification failed', 'User entered a malformed 6-digit verification code.')
            flash('Enter the 6-digit verification code.', 'danger')
            return render_template('verify_otp.html', email=session.get('pending_email'))

        if submitted_otp != session.get('pending_otp'):
            username = session.get('pending_username')
            log_login_activity(username, 'OTP verification failed', 'Incorrect verification code entered during login.')
            flash('Incorrect verification code. Please try again.', 'danger')
            return render_template('verify_otp.html', email=session.get('pending_email'))

        user_id = session.get('pending_user_id')
        username = session.get('pending_username')
        role = session.get('pending_role')

        log_login_activity(username, 'User logged in successfully', 'OTP verification passed and user authenticated.')
        session.clear()
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = role
        flash(f'Welcome back, {username}! Email verification successful.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('verify_otp.html', email=session.get('pending_email'))


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'pending_user_id' not in session:
        flash('Please log in before requesting a verification code.', 'warning')
        return redirect(url_for('login'))

    recipient_email = session.get('pending_email')
    otp_code = generate_otp()
    session['pending_otp'] = otp_code
    session['pending_otp_expires'] = time.time() + 300
    session['pending_otp_debug'] = None

    delivery_mode, error_detail = send_otp_email(recipient_email, otp_code)
    if delivery_mode == 'smtp':
        flash(f'A fresh verification code was sent to {recipient_email}.', 'info')
    elif delivery_mode == 'console':
        session['pending_otp_debug'] = otp_code
        flash(f'Gmail SMTP not configured. New code: {otp_code}', 'warning')
    else:
        session['pending_otp_debug'] = otp_code
        flash(f'Could not reach Gmail SMTP ({error_detail}). New code: {otp_code}', 'warning')

    return redirect(url_for('verify_otp'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices ORDER BY status DESC').fetchall()
    logs = conn.execute('SELECT * FROM shift_logs ORDER BY timestamp DESC LIMIT 10').fetchall()
    conn.close()

    spoofed_count = sum(1 for d in devices if d['status'] == 'red')
    unknown_count = sum(1 for d in devices if d['status'] == 'yellow')
    trusted_count = sum(1 for d in devices if d['status'] == 'green')
    active_threats = sum(1 for d in devices if d['status'] == 'red' and not d['is_blocked'])
    blocked_count = sum(1 for d in devices if d['is_blocked'])
    review_count = sum(1 for d in devices if d['status'] == 'yellow')
    threats = spoofed_count

    # Adapt the existing device records into monitoring events for the dashboard.
    event_details = {
        'red': ('ARP Spoofing', 'Gateway identity conflict detected', 'Critical'),
        'yellow': ('Unknown Device', 'Unapproved device requires review', 'Medium'),
        'green': ('Verified Device', 'Known device activity detected', 'Low')
    }
    events = []
    for device in devices:
        attack_type, activity, risk_level = event_details[device['status']]
        events.append({
            'timestamp': device['last_seen'],
            'ip_address': device['ip_address'],
            'username': device['device_name'],
            'attack_type': attack_type,
            'activity': activity,
            'risk_level': risk_level,
            'status': 'Blocked' if device['is_blocked'] else 'Detected'
        })

    detections = [
        {'name': 'ARP Spoofing Detection', 'description': 'Detects conflicting MAC address claims and gateway impersonation.', 'icon': 'fa-shield-halved', 'status': 'Monitoring'},
        {'name': 'Unknown Device Detection', 'description': 'Flags devices that have not yet been approved for this network.', 'icon': 'fa-wifi', 'status': 'Monitoring'},
        {'name': 'Access Control Monitoring', 'description': 'Tracks block and unblock actions performed by security staff.', 'icon': 'fa-ban', 'status': 'Monitoring'}
    ]

    total_devices = len(devices)
    security_score = 100
    if total_devices > 0:
        penalty = (active_threats * 40) + (review_count * 10) + (blocked_count * 5)
        security_score = max(5, min(100, 100 - penalty))

    subnet_utilization = round((total_devices / 254.0) * 100, 1)
    mitigation_rate = 100 if threats == 0 else round((blocked_count / float(threats)) * 100, 1)

    octet_buckets = {'1-50': 0, '51-100': 0, '101-150': 0, '151-200': 0, '201-254': 0}
    for d in devices:
        try:
            last_octet = int(d['ip_address'].split('.')[-1])
            if 1 <= last_octet <= 50:
                octet_buckets['1-50'] += 1
            elif 51 <= last_octet <= 100:
                octet_buckets['51-100'] += 1
            elif 101 <= last_octet <= 150:
                octet_buckets['101-150'] += 1
            elif 151 <= last_octet <= 200:
                octet_buckets['151-200'] += 1
            elif 201 <= last_octet <= 254:
                octet_buckets['201-254'] += 1
        except Exception:
            pass

    actions_by_type = {'Threats Flagged': 0, 'Device Blocks': 0, 'Restorations': 0, 'Network Scans': 0, 'Auth & Access': 0}
    for log in logs:
        act = (log['action_taken'] or '').lower()
        if 'threat' in act or 'spoof' in act:
            actions_by_type['Threats Flagged'] += 1
        elif 'blocked device' in act:
            actions_by_type['Device Blocks'] += 1
        elif 'unblock' in act or 'whitelist' in act:
            actions_by_type['Restorations'] += 1
        elif 'scan' in act:
            actions_by_type['Network Scans'] += 1
        else:
            actions_by_type['Auth & Access'] += 1

    log_timeline_labels = []
    log_timeline_threats = []
    log_timeline_responses = []
    recent_logs = logs[-10:] if len(logs) >= 10 else logs
    if not recent_logs:
        log_timeline_labels = ['Initial', 'Current']
        log_timeline_threats = [0, 0]
        log_timeline_responses = [0, 0]
    else:
        for idx, l in enumerate(recent_logs):
            ts = str(l['timestamp'])
            time_label = ts.split(' ')[-1][:5] if ' ' in ts else f"Event #{idx+1}"
            log_timeline_labels.append(time_label)
            is_threat = 1 if ('threat' in (l['action_taken'] or '').lower() or 'spoof' in (l['action_taken'] or '').lower()) else 0
            is_resp = 1 if ('block' in (l['action_taken'] or '').lower() or 'scan' in (l['action_taken'] or '').lower() or 'whitelist' in (l['action_taken'] or '').lower()) else 0
            log_timeline_threats.append(is_threat)
            log_timeline_responses.append(is_resp)

    threat_devices = [d for d in devices if d['status'] == 'red' or d['is_blocked']]

    return render_template(
        'dashboard.html',
        devices=devices,
        logs=logs,
        spoofed_count=spoofed_count,
        unknown_count=unknown_count,
        trusted_count=trusted_count,
        events=events,
        detections=detections,
        total_events=len(events),
        unique_ips=len({device['ip_address'] for device in devices}),
        high_risk_events=sum(1 for event in events if event['risk_level'] in ('High', 'Critical')),
        critical_events=sum(1 for event in events if event['risk_level'] == 'Critical'),
        trusted=trusted_count,
        review=review_count,
        threats=threats,
        blocked=blocked_count,
        active_threats=active_threats,
        security_score=security_score,
        subnet_utilization=subnet_utilization,
        mitigation_rate=mitigation_rate,
        total_actions=len(logs),
        octet_labels=list(octet_buckets.keys()),
        octet_counts=list(octet_buckets.values()),
        action_type_labels=list(actions_by_type.keys()),
        action_type_counts=list(actions_by_type.values()),
        timeline_labels=log_timeline_labels,
        timeline_threats=log_timeline_threats,
        timeline_responses=log_timeline_responses,
        threat_devices=threat_devices,
        total_devices=total_devices,
        review_count=review_count,
        blocked_count=blocked_count
    )


@app.route('/alerts')
@login_required
def alerts():
    """Show active ARP-spoofing alerts recorded by the detection service."""
    conn = get_db_connection()
    alert_devices = conn.execute(
        'SELECT * FROM devices WHERE status = "red" ORDER BY last_seen DESC'
    ).fetchall()
    recent_actions = conn.execute(
        "SELECT * FROM shift_logs WHERE action_taken LIKE '%Blocked Device%' "
        "OR action_taken LIKE '%Unblocked Device%' ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()
    conn.close()

    alert_devices_with_risk = []
    for device in alert_devices:
        device_dict = dict(device)
        base_score = 94
        if device['is_blocked']:
            base_score -= 12
        risk_score = min(max(base_score, 68), 99)
        device_dict['risk_score'] = risk_score
        alert_devices_with_risk.append(device_dict)

    highest_risk_score = max((device['risk_score'] for device in alert_devices_with_risk), default=0)

    return render_template(
        'alerts.html',
        alert_devices=alert_devices_with_risk,
        recent_actions=recent_actions,
        active_alerts=sum(1 for device in alert_devices_with_risk if not device['is_blocked']),
        highest_risk_score=highest_risk_score
    )


@app.route('/devices')
@login_required
def devices():
    """Show the current network device inventory and its security state."""
    conn = get_db_connection()
    device_rows = conn.execute(
        'SELECT * FROM devices ORDER BY CASE status WHEN "red" THEN 1 WHEN "yellow" THEN 2 ELSE 3 END, last_seen DESC'
    ).fetchall()
    conn.close()
    return render_template(
        'devices.html',
        devices=device_rows,
        trusted_count=sum(1 for device in device_rows if device['status'] == 'green'),
        review_count=sum(1 for device in device_rows if device['status'] == 'yellow'),
        threat_count=sum(1 for device in device_rows if device['status'] == 'red'),
        blocked_count=sum(1 for device in device_rows if device['is_blocked'])
    )


@app.route('/logs')
@login_required
def logs():
    conn = get_db_connection()
    activity_logs = conn.execute('SELECT * FROM shift_logs ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('logs.html', logs=activity_logs)


@app.route('/analytics')
@login_required
def analytics():
    conn = get_db_connection()
    device_rows = conn.execute('SELECT * FROM devices ORDER BY status DESC, id ASC').fetchall()
    shift_logs = conn.execute('SELECT * FROM shift_logs ORDER BY timestamp ASC').fetchall()
    conn.close()

    total_devices = len(device_rows)
    trusted = sum(1 for device in device_rows if device['status'] == 'green')
    review = sum(1 for device in device_rows if device['status'] == 'yellow')
    threats = sum(1 for device in device_rows if device['status'] == 'red')
    blocked = sum(1 for device in device_rows if device['is_blocked'])
    active_threats = sum(1 for device in device_rows if device['status'] == 'red' and not device['is_blocked'])

    # Calculate real security posture score (0 to 100)
    security_score = 100
    if total_devices > 0:
        penalty = (active_threats * 40) + (review * 10) + (blocked * 5)
        security_score = max(5, min(100, 100 - penalty))

    subnet_utilization = round((total_devices / 254.0) * 100, 1)
    mitigation_rate = 100 if threats == 0 else round((blocked / float(threats)) * 100, 1)

    # Subnet IP octet distribution (1-50, 51-100, 101-150, 151-200, 201-254)
    octet_buckets = {'1-50': 0, '51-100': 0, '101-150': 0, '151-200': 0, '201-254': 0}
    for d in device_rows:
        try:
            last_octet = int(d['ip_address'].split('.')[-1])
            if 1 <= last_octet <= 50:
                octet_buckets['1-50'] += 1
            elif 51 <= last_octet <= 100:
                octet_buckets['51-100'] += 1
            elif 101 <= last_octet <= 150:
                octet_buckets['101-150'] += 1
            elif 151 <= last_octet <= 200:
                octet_buckets['151-200'] += 1
            elif 201 <= last_octet <= 254:
                octet_buckets['201-254'] += 1
        except Exception:
            pass

    # Operator / Entity Breakdown
    operators = {}
    actions_by_type = {'Threats Flagged': 0, 'Device Blocks': 0, 'Restorations': 0, 'Network Scans': 0, 'Auth & Access': 0}

    for log in shift_logs:
        handler = log['handled_by'] or 'System Sensor'
        operators[handler] = operators.get(handler, 0) + 1

        act = (log['action_taken'] or '').lower()
        if 'threat' in act or 'spoof' in act:
            actions_by_type['Threats Flagged'] += 1
        elif 'blocked device' in act:
            actions_by_type['Device Blocks'] += 1
        elif 'unblock' in act or 'whitelist' in act:
            actions_by_type['Restorations'] += 1
        elif 'scan' in act:
            actions_by_type['Network Scans'] += 1
        else:
            actions_by_type['Auth & Access'] += 1

    # Time-series log activity for timeline chart
    log_timeline_labels = []
    log_timeline_threats = []
    log_timeline_responses = []

    recent_logs = shift_logs[-10:] if len(shift_logs) >= 10 else shift_logs
    if not recent_logs:
        # Fallback labels if logs are empty
        log_timeline_labels = ['Initial', 'Current']
        log_timeline_threats = [0, 0]
        log_timeline_responses = [0, 0]
    else:
        for idx, l in enumerate(recent_logs):
            ts = str(l['timestamp'])
            time_label = ts.split(' ')[-1][:5] if ' ' in ts else f"Event #{idx+1}"
            log_timeline_labels.append(time_label)
            is_threat = 1 if ('threat' in (l['action_taken'] or '').lower() or 'spoof' in (l['action_taken'] or '').lower()) else 0
            is_resp = 1 if ('block' in (l['action_taken'] or '').lower() or 'scan' in (l['action_taken'] or '').lower() or 'whitelist' in (l['action_taken'] or '').lower()) else 0
            log_timeline_threats.append(is_threat)
            log_timeline_responses.append(is_resp)

    threat_devices = [d for d in device_rows if d['status'] == 'red' or d['is_blocked']]

    return render_template(
        'analytics.html',
        total_devices=total_devices,
        trusted=trusted,
        review=review,
        threats=threats,
        blocked=blocked,
        active_threats=active_threats,
        security_score=security_score,
        subnet_utilization=subnet_utilization,
        mitigation_rate=mitigation_rate,
        total_actions=len(shift_logs),
        octet_labels=list(octet_buckets.keys()),
        octet_counts=list(octet_buckets.values()),
        operator_labels=list(operators.keys()) if operators else ['NetGuardian Sensor'],
        operator_counts=list(operators.values()) if operators else [1],
        action_type_labels=list(actions_by_type.keys()),
        action_type_counts=list(actions_by_type.values()),
        timeline_labels=log_timeline_labels,
        timeline_threats=log_timeline_threats,
        timeline_responses=log_timeline_responses,
        threat_devices=threat_devices,
        devices=device_rows
    )


@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')


@app.route('/reports/devices.csv')
@login_required
def download_device_report():
    conn = get_db_connection()
    device_rows = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP Address', 'MAC Address', 'Device Name', 'Security Status', 'Blocked', 'Last Seen'])
    for device in device_rows:
        writer.writerow([device['ip_address'], device['mac_address'], device['device_name'], device['status'], 'Yes' if device['is_blocked'] else 'No', device['last_seen']])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguardian-devices.csv'})


@app.route('/reports/actions.csv')
@login_required
def download_action_report():
    conn = get_db_connection()
    activity_logs = conn.execute('SELECT * FROM shift_logs ORDER BY timestamp DESC').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Handled By', 'Action Taken', 'Notes'])
    for log in activity_logs:
        writer.writerow([log['timestamp'], log['handled_by'], log['action_taken'], log['notes']])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguardian-actions.csv'})

@app.route('/block/<int:device_id>', methods=['POST'])
@login_required
@require_role('Whitelist Manager', 'Shift Monitor')
def block_device(device_id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()

    if device:
        conn.execute('UPDATE devices SET is_blocked = 1 WHERE id = ?', (device_id,))
        conn.execute(
            'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
            (session.get('username', 'Staff'), f'Blocked Device: {device["ip_address"]}', f'MAC: {device["mac_address"]} flagged for spoofing')
        )
        conn.commit()
        flash(f'Device {device["ip_address"]} successfully blocked!', 'danger')

    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/unblock/<int:device_id>', methods=['POST'])
@login_required
@require_role('Whitelist Manager', 'Shift Monitor')
def unblock_device(device_id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()

    if device:
        conn.execute('UPDATE devices SET is_blocked = 0 WHERE id = ?', (device_id,))
        conn.execute(
            'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
            (session.get('username', 'Staff'), f'Unblocked Device: {device["ip_address"]}', f'MAC: {device["mac_address"]} restored to network access')
        )
        conn.commit()
        flash(f'Device {device["ip_address"]} has been unblocked.', 'success')

    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/trust/<int:device_id>', methods=['POST'])
@login_required
@require_role('Whitelist Manager')
def trust_device(device_id):
    if session.get('role') != 'Whitelist Manager':
        flash('Only Whitelist Managers can approve devices.', 'warning')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    conn.execute('UPDATE devices SET status = "green" WHERE id = ?', (device_id,))
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Manager'), 'Whitelisted Device', f'Device ID {device_id} marked as trusted.')
    )
    conn.commit()
    conn.close()
    flash('Device added to whitelist!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/status')
@app.route('/public-status')
def public_status():
    conn = get_db_connection()
    spoofed = conn.execute('SELECT COUNT(*) FROM devices WHERE status = "red" AND is_blocked = 0').fetchone()[0]
    conn.close()

    is_safe = spoofed == 0
    return render_template('public_status.html', is_safe=is_safe)


@app.route('/api/devices', methods=['GET'])
@api_login_required
def api_list_devices():
    conn = get_db_connection()
    status_filter = request.args.get('status')

    if status_filter in ('green', 'yellow', 'red'):
        devices = conn.execute(
            'SELECT * FROM devices WHERE status = ? ORDER BY status DESC', (status_filter,)
        ).fetchall()
    else:
        devices = conn.execute('SELECT * FROM devices ORDER BY status DESC').fetchall()
    conn.close()

    return jsonify({'devices': [device_to_dict(d) for d in devices]})


@app.route('/api/devices/<int:device_id>', methods=['GET'])
@api_login_required
def api_get_device(device_id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()

    if device is None:
        return jsonify({'error': 'Device not found'}), 404

    return jsonify(device_to_dict(device))


@app.route('/api/devices/<int:device_id>/block', methods=['POST'])
@api_login_required
@api_require_role('Whitelist Manager', 'Shift Monitor')
def api_block_device(device_id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()

    if device is None:
        conn.close()
        return jsonify({'error': 'Device not found'}), 404

    conn.execute('UPDATE devices SET is_blocked = 1 WHERE id = ?', (device_id,))
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Staff'), f'Blocked Device: {device["ip_address"]}', f'MAC: {device["mac_address"]} flagged for spoofing')
    )
    conn.commit()

    updated = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()

    return jsonify({'message': 'Device blocked', 'device': device_to_dict(updated)})


@app.route('/api/devices/<int:device_id>/unblock', methods=['POST'])
@api_login_required
@api_require_role('Whitelist Manager', 'Shift Monitor')
def api_unblock_device(device_id):
    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()

    if device is None:
        conn.close()
        return jsonify({'error': 'Device not found'}), 404

    conn.execute('UPDATE devices SET is_blocked = 0 WHERE id = ?', (device_id,))
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Staff'), f'Unblocked Device: {device["ip_address"]}', f'MAC: {device["mac_address"]} restored to network access')
    )
    conn.commit()

    updated = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()

    return jsonify({'message': 'Device unblocked', 'device': device_to_dict(updated)})


@app.route('/api/devices/<int:device_id>/trust', methods=['POST'])
@api_login_required
@api_require_role('Whitelist Manager')
def api_trust_device(device_id):
    if session.get('role') != 'Whitelist Manager':
        return jsonify({'error': 'Only Whitelist Managers can approve devices'}), 403

    conn = get_db_connection()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()

    if device is None:
        conn.close()
        return jsonify({'error': 'Device not found'}), 404

    conn.execute('UPDATE devices SET status = "green" WHERE id = ?', (device_id,))
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Manager'), 'Whitelisted Device', f'Device ID {device_id} marked as trusted.')
    )
    conn.commit()

    updated = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()

    return jsonify({'message': 'Device whitelisted', 'device': device_to_dict(updated)})


@app.route('/api/logs', methods=['GET'])
@api_login_required
def api_list_logs():
    limit = request.args.get('limit', default=10, type=int)
    conn = get_db_connection()
    logs = conn.execute(
        'SELECT * FROM shift_logs ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()

    return jsonify({'logs': [log_to_dict(l) for l in logs]})


@app.route('/scan-network', methods=['GET', 'POST'])
@login_required
def scan_network():
    """Trigger a real-time scan of the local network interface and ARP table."""
    discovered = sync_real_network_devices(reset_mock_data=True)
    host_entry = next((d for d in discovered if 'Host' in d['device_name']), None)
    host_ip = host_entry['ip_address'] if host_entry else '192.168.x.x'

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Staff'), 'Live Network Scan', f'Scanned subnet via local interface {host_ip}. Discovered {len(discovered)} active devices.')
    )
    conn.commit()
    conn.close()

    flash(f'Real network scan complete! Synchronized {len(discovered)} active devices from interface {host_ip}.', 'success')
    referrer = request.referrer
    if referrer and any(p in referrer for p in ('/devices', '/overview', '/alerts', '/dashboard')):
        return redirect(referrer)
    return redirect(url_for('dashboard'))


@app.route('/add-device', methods=['POST'])
@login_required
@require_role('Whitelist Manager')
def add_device():
    ip = (request.form.get('ip_address') or '').strip()
    mac = (request.form.get('mac_address') or '').strip().upper()
    name = (request.form.get('device_name') or 'Custom Network Device').strip()
    status = request.form.get('status', 'green')

    if not ip or not re.fullmatch(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
        flash('Please enter a valid IPv4 address (e.g., 192.168.1.50).', 'danger')
        return redirect(request.referrer or url_for('devices'))

    if mac and not re.fullmatch(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
        flash('Please enter a valid MAC address (e.g., 00:1A:2B:3C:4D:5E).', 'danger')
        return redirect(request.referrer or url_for('devices'))

    if not mac:
        mac = '02:' + ':'.join(['{:02X}'.format(random.randint(0, 255)) for _ in range(5)])

    conn = get_db_connection()
    existing = conn.execute('SELECT id FROM devices WHERE ip_address = ?', (ip,)).fetchone()
    if existing:
        conn.execute(
            'UPDATE devices SET mac_address = ?, device_name = ?, status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (mac, name, status, existing['id'])
        )
        flash(f'Updated device with IP {ip}.', 'info')
    else:
        conn.execute(
            'INSERT INTO devices (ip_address, mac_address, device_name, status, is_blocked) VALUES (?, ?, ?, ?, 0)',
            (ip, mac, name, status)
        )
        flash(f'Added device {ip} ({name}) to inventory.', 'success')

    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        (session.get('username', 'Manager'), f'Device Registered: {ip}', f'MAC: {mac}, Name: {name}')
    )
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('devices'))


@app.route('/simulate-threat', methods=['POST'])
@login_required
def simulate_threat():
    """Simulate an ARP spoofing threat on the real local subnet."""
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices').fetchall()
    host_ip = None
    for d in devices:
        if 'Host' in d['device_name']:
            host_ip = d['ip_address']
            break

    prefix = '192.168.1'
    if host_ip:
        prefix = '.'.join(host_ip.split('.')[:3])

    rogue_ip = f'{prefix}.{random.randint(210, 245)}'
    rogue_mac = 'E4:1F:13:24:6D:A8'
    conn.execute(
        'INSERT INTO devices (ip_address, mac_address, device_name, status, is_blocked) VALUES (?, ?, ?, "red", 0)',
        (rogue_ip, rogue_mac, 'Suspicious Rogue ARP Spoofer (Gateway MAC Conflict)')
    )
    conn.execute(
        'INSERT INTO shift_logs (handled_by, action_taken, notes) VALUES (?, ?, ?)',
        ('NetGuardian Sensor', f'ARP Threat Flagged: {rogue_ip}', f'Conflicting MAC address {rogue_mac} detected on subnet.')
    )
    conn.commit()
    conn.close()
    flash(f'Simulated ARP spoofing attack detected from real-subnet IP {rogue_ip}!', 'danger')
    return redirect(request.referrer or url_for('alerts'))


@app.route('/api/scan-network', methods=['GET', 'POST'])
@api_login_required
def api_scan_network():
    discovered = sync_real_network_devices(reset_mock_data=True)
    return jsonify({
        'status': 'success',
        'count': len(discovered),
        'devices': discovered
    })


@app.route('/api/status', methods=['GET'])
def api_public_status():
    conn = get_db_connection()
    spoofed = conn.execute(
        'SELECT COUNT(*) FROM devices WHERE status = "red" AND is_blocked = 0'
    ).fetchone()[0]
    conn.close()

    return jsonify({'is_safe': spoofed == 0, 'active_spoofing_alerts': spoofed})


if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    ensure_user_email_column()
    sync_real_network_devices(reset_mock_data=True)
    app.run(debug=os.environ.get('NETGUARDIAN_DEBUG', 'false').lower() == 'true', host='0.0.0.0', port=5000)

