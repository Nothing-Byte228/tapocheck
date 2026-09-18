import os
import time
import sqlite3
import json
import datetime
import logging
from typing import Optional, Dict, List, Any, Tuple
from pathlib import Path

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from bleach import clean

from config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
env = os.environ.get('FLASK_ENV', 'development')
app = Flask(__name__)
app.config.from_object(config[env])

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter (only for sensitive endpoints)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]  # No default limits
)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- DATABASE FUNCTIONS ---

def get_db_connection(db_name: str) -> sqlite3.Connection:
    """Get database connection with row factory."""
    conn = sqlite3.connect(db_name, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def init_dbs() -> None:
    """Initialize database schemas."""
    try:
        # Users and Profiles database
        with get_db_connection(app.config['DB_USERS']) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    displayname TEXT,
                    password TEXT NOT NULL,
                    avatar TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    is_admin INTEGER DEFAULT 0,
                    is_banned INTEGER DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')
            conn.commit()
        
        # Chats, DMs and messages database
        with get_db_connection(app.config['DB_CHATS']) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    text TEXT,
                    type TEXT NOT NULL,
                    url TEXT,
                    raw_content TEXT,
                    reply_to TEXT,
                    is_edited INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            ''')
            conn.commit()
            
        logger.info("Databases initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise

init_dbs()

# --- HELPER FUNCTIONS ---

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def determine_msg_type(filename: str) -> str:
    """Determine message type based on file extension."""
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in {'png', 'jpg', 'jpeg', 'gif'}: return 'image'
    if ext in {'mp4', 'avi', 'mov'}: return 'video'
    if ext in {'py', 'cs', 'pas', 'txt'}: return 'code'
    return 'file'

def get_dm_id(user1: str, user2: str) -> str:
    """Generate unique DM ID for two users."""
    sorted_users = sorted([user1, user2])
    return f"{sorted_users[0]}_dm_{sorted_users[1]}"

def sanitize_html(text: str) -> str:
    """Sanitize HTML to prevent XSS attacks."""
    return clean(text, tags=[], attributes={}, strip=True)

def validate_file_size(file) -> bool:
    """Validate file size against max content length."""
    return len(file.read()) <= app.config['MAX_CONTENT_LENGTH']

# In-memory typing status (consider Redis for production)
typing_users: Dict[str, float] = {}

# --- SOCKET.IO EVENT HANDLERS ---

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    if 'username' in session:
        logger.info(f"User {session['username']} connected via WebSocket")
        emit('connected', {'username': session['username']})
    else:
        return False  # Reject connection if not authenticated

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    if 'username' in session:
        username = session['username']
        typing_users.pop(username, None)
        logger.info(f"User {username} disconnected via WebSocket")

@socketio.on('join_room')
def handle_join_room(data):
    """Handle user joining a chat room."""
    if 'username' not in session:
        return
    
    room = data.get('room', 'general')
    join_room(room)
    logger.info(f"User {session['username']} joined room {room}")
    emit('user_joined', {'username': session['username']}, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    """Handle user leaving a chat room."""
    if 'username' not in session:
        return
    
    room = data.get('room', 'general')
    leave_room(room)
    logger.info(f"User {session['username']} left room {room}")
    emit('user_left', {'username': session['username']}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    """Handle message sending via WebSocket."""
    if 'username' not in session:
        return
    
    try:
        username = session['username']
        text = sanitize_html(data.get('text', '').strip())
        reply_to_json = data.get('reply_to_json', '')
        chat_type = data.get('chat_type', 'group')
        target_id = data.get('target_id', 'general').lower()

        if chat_type == 'dm':
            target_id = get_dm_id(username, target_id)

        msg_type = 'text'
        url = ''
        raw_content = ''

        if not text:
            emit('error', {'message': 'Текст сообщения обязателен'})
            return

        conn = get_db_connection(app.config['DB_CHATS'])
        conn.execute('''
            INSERT INTO messages (chat_type, target_id, username, text, type, url, raw_content, reply_to, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chat_type, target_id, username, text, msg_type, url, raw_content, reply_to_json or None, time.time()))
        conn.commit()
        
        # Get the inserted message
        msg = conn.execute('SELECT * FROM messages WHERE id = last_insert_rowid()').fetchone()
        conn.close()

        # Prepare message data for WebSocket
        reply_to_data = None
        if msg['reply_to']:
            try:
                reply_to_data = json.loads(msg['reply_to'])
            except json.JSONDecodeError:
                pass

        # Get user metadata
        conn_u = get_db_connection(app.config['DB_USERS'])
        user_meta = conn_u.execute(
            'SELECT displayname, avatar FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn_u.close()

        message_data = {
            'id': msg['id'],
            'username': msg['username'],
            'displayname': user_meta['displayname'] if user_meta else username,
            'avatar': user_meta['avatar'] if user_meta else '',
            'text': msg['text'],
            'type': msg['type'],
            'url': msg['url'],
            'raw_content': msg['raw_content'],
            'reply_to': reply_to_data,
            'is_edited': bool(msg['is_edited']),
            'time': datetime.datetime.fromtimestamp(msg['timestamp']).strftime('%H:%M')
        }

        # Emit to room
        room = target_id if chat_type == 'dm' else f"{chat_type}_{target_id}"
        emit('new_message', message_data, room=room)
        
        typing_users.pop(username, None)
        logger.info(f"Message sent via WebSocket by {username} in {chat_type}/{target_id}")
        
    except sqlite3.Error as e:
        logger.error(f"Database error in WebSocket message: {e}")
        emit('error', {'message': 'Database error'})
    except Exception as e:
        logger.error(f"Error in WebSocket message: {e}")
        emit('error', {'message': 'Server error'})

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator via WebSocket."""
    if 'username' not in session:
        return
    
    username = session['username']
    typing_users[username] = time.time()
    
    chat_type = data.get('chat_type', 'group')
    target_id = data.get('target_id', 'general').lower()
    
    if chat_type == 'dm':
        target_id = get_dm_id(username, target_id)
    
    room = target_id if chat_type == 'dm' else f"{chat_type}_{target_id}"
    emit('user_typing', {'username': username}, room=room, include_self=False)

# --- AUTHENTICATION ROUTES ---

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Keep rate limiting for login
def login():
    """Handle user login."""
    if 'username' in session:
        return redirect(url_for('chat_page'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if username and password:
            try:
                conn = get_db_connection(app.config['DB_USERS'])
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                conn.close()

                if user:
                    if user['is_banned']:
                        error = "Вы забанены в системе TapoCheck."
                        logger.warning(f"Login attempt by banned user: {username}")
                    elif check_password_hash(user['password'], password):
                        session['username'] = user['username']
                        session.permanent = True
                        logger.info(f"User logged in: {username}")
                        return redirect(url_for('chat_page'))
                    else:
                        error = "Неверный пароль."
                        logger.warning(f"Failed login attempt for: {username}")
                else:
                    error = "Пользователь не найден. Зарегистрируйтесь."
            except sqlite3.Error as e:
                logger.error(f"Database error during login: {e}")
                error = "Ошибка сервера. Попробуйте позже."

    return render_template('auth.html', action='login', error=error)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Keep rate limiting for registration
def register():
    """Handle user registration."""
    if 'username' in session:
        return redirect(url_for('chat_page'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        displayname = request.form.get('displayname', '').strip() or username
        password = request.form.get('password', '')

        if username and password:
            if len(password) < 8:
                error = "Пароль должен быть минимум 8 символов."
            else:
                try:
                    hashed_password = generate_password_hash(password, method='scrypt')
                    conn = get_db_connection(app.config['DB_USERS'])
                    try:
                        conn.execute(
                            'INSERT INTO users (username, displayname, password) VALUES (?, ?, ?)',
                            (username, displayname, hashed_password)
                        )
                        conn.commit()
                        session['username'] = username
                        session.permanent = True
                        logger.info(f"New user registered: {username}")
                        return redirect(url_for('chat_page'))
                    except sqlite3.IntegrityError:
                        error = "Этот логин уже занят."
                    finally:
                        conn.close()
                except sqlite3.Error as e:
                    logger.error(f"Database error during registration: {e}")
                    error = "Ошибка сервера. Попробуйте позже."

    return render_template('auth.html', action='register', error=error)

@app.route('/logout')
def logout():
    """Handle user logout."""
    username = session.get('username', '')
    if username:
        typing_users.pop(username, None)
        logger.info(f"User logged out: {username}")
    session.clear()
    return redirect(url_for('login'))

# --- PROFILE AND ADMIN ROUTES ---

@app.route('/get_profile')
def get_profile():
    """Get current user profile."""
    if 'username' not in session:
        return jsonify({}), 403
    
    try:
        conn = get_db_connection(app.config['DB_USERS'])
        user = conn.execute(
            'SELECT username, displayname, avatar, status, is_admin FROM users WHERE username = ?',
            (session['username'],)
        ).fetchone()
        conn.close()
        return jsonify(dict(user) if user else {})
    except sqlite3.Error as e:
        logger.error(f"Database error getting profile: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update user profile."""
    if 'username' not in session:
        return jsonify({'status': 'error'}), 403
    
    try:
        displayname = sanitize_html(request.form.get('displayname', '').strip())
        status = sanitize_html(request.form.get('status', '').strip())
        password = request.form.get('password', '')

        conn = get_db_connection(app.config['DB_USERS'])
        
        if displayname:
            conn.execute('UPDATE users SET displayname = ? WHERE username = ?', 
                        (displayname, session['username']))
        
        conn.execute('UPDATE users SET status = ? WHERE username = ?', 
                    (status, session['username']))

        if password:
            if len(password) < 8:
                conn.close()
                return jsonify({'status': 'error', 'message': 'Пароль минимум 8 символов'}), 400
            hashed = generate_password_hash(password, method='scrypt')
            conn.execute('UPDATE users SET password = ? WHERE username = ?', 
                        (hashed, session['username']))

        if 'avatar' in request.files and request.files['avatar'].filename != '':
            file = request.files['avatar']
            if allowed_file(file.filename):
                file.seek(0)  # Reset file pointer after size check
                if validate_file_size(file):
                    file.seek(0)  # Reset again for reading
                    filename = f"avatar_{int(time.time())}_{secure_filename(file.filename)}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    conn.execute('UPDATE users SET avatar = ? WHERE username = ?', 
                                (f"/static/uploads/{filename}", session['username']))
                else:
                    conn.close()
                    return jsonify({'status': 'error', 'message': 'Файл слишком большой'}), 400

        conn.commit()
        conn.close()
        logger.info(f"Profile updated for user: {session['username']}")
        return jsonify({'status': 'ok'})
        
    except sqlite3.Error as e:
        logger.error(f"Database error updating profile: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({'status': 'error', 'message': 'Server error'}), 500

@app.route('/admin/users', methods=['GET'])
def admin_get_users():
    """Get all users (admin only)."""
    if 'username' not in session:
        return jsonify([]), 403
    
    try:
        conn = get_db_connection(app.config['DB_USERS'])
        current = conn.execute(
            'SELECT is_admin FROM users WHERE username = ?',
            (session['username'],)
        ).fetchone()
        
        if not current or not current['is_admin']:
            conn.close()
            return jsonify({'status': 'error', 'message': 'No access'}), 403

        users = conn.execute(
            'SELECT id, username, displayname, is_banned, is_admin FROM users'
        ).fetchall()
        conn.close()
        return jsonify([dict(u) for u in users])
    except sqlite3.Error as e:
        logger.error(f"Database error getting admin users: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

@app.route('/admin/toggle_ban/<int:user_id>', methods=['POST'])
def admin_toggle_ban(user_id: int):
    """Toggle user ban status (admin only)."""
    if 'username' not in session:
        return jsonify({'status': 'error'}), 403
    
    try:
        conn = get_db_connection(app.config['DB_USERS'])
        current = conn.execute(
            'SELECT is_admin FROM users WHERE username = ?',
            (session['username'],)
        ).fetchone()
        
        if not current or not current['is_admin']:
            conn.close()
            return jsonify({'status': 'error'}), 403

        user = conn.execute(
            'SELECT is_banned FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        
        if user:
            new_ban = 0 if user['is_banned'] else 1
            conn.execute('UPDATE users SET is_banned = ? WHERE id = ?', (new_ban, user_id))
            conn.commit()
            logger.info(f"User {user_id} ban status toggled to {new_ban} by {session['username']}")
        
        conn.close()
        return jsonify({'status': 'ok'})
    except sqlite3.Error as e:
        logger.error(f"Database error toggling ban: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

# --- CHAT AND MESSAGE ROUTES ---

@app.route('/chat')
def chat_page():
    """Render chat page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection(app.config['DB_USERS'])
        user = conn.execute(
            'SELECT is_banned FROM users WHERE username = ?',
            (session['username'],)
        ).fetchone()
        conn.close()
        
        if user and user['is_banned']:
            session.clear()
            return redirect(url_for('login'))
            
        return render_template('chat.html', username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error checking ban status: {e}")
        return redirect(url_for('login'))

@app.route('/get_active_users')
def get_active_users():
    """Get list of active users."""
    try:
        conn = get_db_connection(app.config['DB_USERS'])
        users = conn.execute(
            'SELECT username, displayname, avatar, status FROM users WHERE username != ?',
            (session.get('username', ''),)
        ).fetchall()
        conn.close()
        return jsonify([dict(u) for u in users])
    except sqlite3.Error as e:
        logger.error(f"Database error getting active users: {e}")
        return jsonify([]), 500

@app.route('/get_messages')
def get_messages():
    """Get messages for a chat."""
    if 'username' not in session:
        return jsonify([]), 403
    
    try:
        chat_type = request.args.get('type', 'group')
        target_id = request.args.get('target', 'general').lower()

        if chat_type == 'dm':
            target_id = get_dm_id(session['username'], target_id)

        conn = get_db_connection(app.config['DB_CHATS'])
        db_msgs = conn.execute('''
            SELECT * FROM messages
            WHERE chat_type = ? AND target_id = ?
            ORDER BY timestamp ASC
        ''', (chat_type, target_id)).fetchall()
        conn.close()

        # Get user metadata for display names and avatars
        conn_u = get_db_connection(app.config['DB_USERS'])
        user_meta = {
            u['username']: {'displayname': u['displayname'], 'avatar': u['avatar']} 
            for u in conn_u.execute('SELECT username, displayname, avatar FROM users').fetchall()
        }
        conn_u.close()

        result = []
        for m in db_msgs:
            meta = user_meta.get(m['username'], {'displayname': m['username'], 'avatar': ''})
            formatted_time = datetime.datetime.fromtimestamp(m['timestamp']).strftime('%H:%M')

            reply_to_data = None
            if m['reply_to']:
                try:
                    reply_to_data = json.loads(m['reply_to'])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid reply_to JSON for message {m['id']}")

            result.append({
                'id': m['id'],
                'username': m['username'],
                'displayname': meta['displayname'],
                'avatar': meta['avatar'],
                'text': sanitize_html(m['text']) if m['text'] else '',
                'type': m['type'],
                'url': m['url'],
                'raw_content': m['raw_content'],
                'reply_to': reply_to_data,
                'is_edited': bool(m['is_edited']),
                'time': formatted_time
            })
        return jsonify(result)
    except sqlite3.Error as e:
        logger.error(f"Database error getting messages: {e}")
        return jsonify([]), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    """Send a new message."""
    if 'username' not in session:
        return jsonify({'status': 'error'}), 403

    try:
        username = session['username']
        text = sanitize_html(request.form.get('text', '').strip())
        reply_to_json = request.form.get('reply_to_json', '')
        chat_type = request.form.get('chat_type', 'group')
        target_id = request.form.get('target_id', 'general').lower()

        if chat_type == 'dm':
            target_id = get_dm_id(username, target_id)

        msg_type = 'text'
        url = ''
        raw_content = ''

        if 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            if file and allowed_file(file.filename):
                if validate_file_size(file):
                    file.seek(0)  # Reset file pointer
                    filename = f"{int(time.time())}_{secure_filename(file.filename)}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)

                    msg_type = determine_msg_type(filename)
                    url = f"/static/uploads/{filename}"
                    text = sanitize_html(file.filename)

                    if msg_type == 'code':
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                raw_content = f.read()
                        except IOError as e:
                            logger.error(f"Error reading code file: {e}")
                            raw_content = "Ошибка чтения файла."
                else:
                    return jsonify({'status': 'error', 'message': 'Файл слишком большой'}), 400
            else:
                return jsonify({'status': 'error', 'message': 'Недопустимый тип файла'}), 400
        else:
            if not text:
                return jsonify({'status': 'error', 'message': 'Текст сообщения обязателен'}), 400

        conn = get_db_connection(app.config['DB_CHATS'])
        conn.execute('''
            INSERT INTO messages (chat_type, target_id, username, text, type, url, raw_content, reply_to, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chat_type, target_id, username, text, msg_type, url, raw_content, reply_to_json or None, time.time()))
        conn.commit()
        conn.close()

        typing_users.pop(username, None)
        logger.info(f"Message sent by {username} in {chat_type}/{target_id}")
        return jsonify({'status': 'ok'})
        
    except sqlite3.Error as e:
        logger.error(f"Database error sending message: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return jsonify({'status': 'error', 'message': 'Server error'}), 500

@app.route('/edit/<int:msg_id>', methods=['POST'])
def edit_message(msg_id: int):
    """Edit an existing message."""
    if 'username' not in session:
        return jsonify({'status': 'error'}), 403
    
    try:
        new_text = sanitize_html(request.form.get('text', '').strip())
        if not new_text:
            return jsonify({'status': 'error', 'message': 'Текст обязателен'}), 400

        conn = get_db_connection(app.config['DB_CHATS'])
        msg = conn.execute(
            'SELECT username FROM messages WHERE id = ?',
            (msg_id,)
        ).fetchone()
        
        if msg and msg['username'] == session['username']:
            conn.execute(
                'UPDATE messages SET text = ?, is_edited = 1 WHERE id = ?',
                (new_text, msg_id)
            )
            conn.commit()
            conn.close()
            logger.info(f"Message {msg_id} edited by {session['username']}")
            return jsonify({'status': 'ok'})
        
        conn.close()
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    except sqlite3.Error as e:
        logger.error(f"Database error editing message: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

@app.route('/delete/<int:msg_id>', methods=['POST'])
def delete_message(msg_id: int):
    """Delete a message."""
    if 'username' not in session:
        return jsonify({'status': 'error'}), 403
    
    try:
        conn = get_db_connection(app.config['DB_CHATS'])
        msg = conn.execute(
            'SELECT username FROM messages WHERE id = ?',
            (msg_id,)
        ).fetchone()
        
        if msg and msg['username'] == session['username']:
            conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
            conn.commit()
            conn.close()
            logger.info(f"Message {msg_id} deleted by {session['username']}")
            return jsonify({'status': 'ok'})
        
        conn.close()
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    except sqlite3.Error as e:
        logger.error(f"Database error deleting message: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500

@app.route('/typing_status', methods=['POST'])
def typing_status():
    """Update typing status."""
    if 'username' in session:
        typing_users[session['username']] = time.time()
    return jsonify({'status': 'ok'})

@app.route('/get_typing', methods=['GET'])
def get_typing():
    """Get typing users for current chat."""
    now = time.time()
    chat_type = request.args.get('type', 'group')
    target_id = request.args.get('target', 'general').lower()

    if chat_type == 'dm':
        target_id = get_dm_id(session.get('username', ''), target_id)

    active_typers = []
    for user, last_time in list(typing_users.items()):
        if now - last_time < app.config['TYPING_TIMEOUT']:
            if chat_type == 'group' and user != session.get('username'):
                active_typers.append(user)
            elif chat_type == 'dm' and user == request.args.get('target'):
                active_typers.append(user)
        else:
            typing_users.pop(user, None)
    
    return jsonify({'users': active_typers})

# --- ERROR HANDLERS ---

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logger.warning(f"404 error: {request.url}")
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"500 error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors."""
    logger.warning(f"Rate limit exceeded for {request.remote_addr}")
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    logger.info(f"Starting TapoCheck in {env} mode with WebSocket support")
    socketio.run(
        app,
        debug=app.config['DEBUG'],
        host='0.0.0.0',
        port=5000,
        use_reloader=False  # Disabled for Python 3.13 Windows compatibility
    )
