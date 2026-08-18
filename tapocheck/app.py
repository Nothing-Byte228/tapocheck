import os
import time
import sqlite3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'tapocheck_ultra_secret_key_1337'

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'txt', 'py', 'cs', 'pas'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- РАБОТА С ДВУМЯ БАЗАМИ ДАННЫХ ---
DB_USERS = 'users.db'
DB_CHATS = 'chats.db'

def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def init_dbs():
    # БД 1: Пользователи и Профили
    with get_db_connection(DB_USERS) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                displayname TEXT,
                password TEXT NOT NULL,
                avatar TEXT DEFAULT '',
                status TEXT DEFAULT '',
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0
            )
        ''')
    # БД 2: Чаты, ЛС и сообщения
    with get_db_connection(DB_CHATS) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_type TEXT NOT NULL, -- 'group' или 'dm'
                target_id TEXT NOT NULL,  -- Имя комнаты (например, 'general', 'python') или имя юзера для ЛС
                username TEXT NOT NULL,
                text TEXT,
                type TEXT NOT NULL,
                url TEXT,
                raw_content TEXT,
                reply_to TEXT,          -- JSON-строка или ID родителя
                is_edited INTEGER DEFAULT 0,
                timestamp REAL NOT NULL
            )
        ''')
init_dbs()

typing_users = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def determine_msg_type(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in {'png', 'jpg', 'jpeg', 'gif'}: return 'image'
    if ext in {'mp4', 'avi', 'mov'}: return 'video'
    if ext in {'py', 'cs', 'pas', 'txt'}: return 'code'
    return 'file'

# --- МАРШРУТЫ АВТОРИЗАЦИИ С ХЕШИРОВАНИЕМ ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('chat_page'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if username and password:
            conn = get_db_connection(DB_USERS)
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            if user:
                if user['is_banned']:
                    error = "Вы забанены в системе TapoCheck."
                elif check_password_hash(user['password'], password):
                    session['username'] = user['username']
                    return redirect(url_for('chat_page'))
                else:
                    error = "Неверный пароль."
            else:
                error = "Пользователь не найден. Зарегистрируйтесь."

    return render_template('auth.html', action='login', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('chat_page'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        displayname = request.form.get('displayname', '').strip() or username
        password = request.form.get('password', '')

        if username and password:
            hashed_password = generate_password_hash(password, method='scrypt')
            conn = get_db_connection(DB_USERS)
            try:
                conn.execute(
                    'INSERT INTO users (username, displayname, password) VALUES (?, ?, ?)',
                    (username, displayname, hashed_password)
                )
                conn.commit()
                session['username'] = username
                return redirect(url_for('chat_page'))
            except sqlite3.IntegrityError:
                error = "Этот логин уже занят."
            finally:
                conn.close()
    return render_template('auth.html', action='register', error=error)

@app.route('/logout')
def logout():
    typing_users.pop(session.get('username', ''), None)
    session.pop('username', None)
    return redirect(url_for('login'))

# --- ПРОФИЛЬ И АДМИНКА ---

@app.route('/get_profile')
def get_profile():
    if 'username' not in session: return jsonify({}), 403
    conn = get_db_connection(DB_USERS)
    user = conn.execute('SELECT username, displayname, avatar, status, is_admin FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()
    return jsonify(dict(user) if user else {})

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session: return jsonify({'status':'error'}), 403
    displayname = request.form.get('displayname', '').strip()
    status = request.form.get('status', '').strip()
    password = request.form.get('password', '')

    conn = get_db_connection(DB_USERS)
    if displayname:
        conn.execute('UPDATE users SET displayname = ? WHERE username = ?', (displayname, session['username']))
    conn.execute('UPDATE users SET status = ? WHERE username = ?', (status, session['username']))

    if password:
        hashed = generate_password_hash(password, method='scrypt')
        conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed, session['username']))

    if 'avatar' in request.files and request.files['avatar'].filename != '':
        file = request.files['avatar']
        if allowed_file(file.filename):
            filename = f"avatar_{int(time.time())}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            conn.execute('UPDATE users SET avatar = ? WHERE username = ?', (f"/static/uploads/{filename}", session['username']))

    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

# API для Админ-панели (проверяет is_admin из БД)
@app.route('/admin/users', methods=['GET'])
def admin_get_users():
    if 'username' not in session: return jsonify([]), 403
    conn = get_db_connection(DB_USERS)
    current = conn.execute('SELECT is_admin FROM users WHERE username = ?', (session['username'],)).fetchone()
    if not current or not current['is_admin']:
        conn.close()
        return jsonify({'status':'error', 'message':'No access'}), 403

    users = conn.execute('SELECT id, username, displayname, is_banned, is_admin FROM users').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/admin/toggle_ban/<int:user_id>', methods=['POST'])
def admin_toggle_ban(user_id):
    if 'username' not in session: return jsonify({'status':'error'}), 403
    conn = get_db_connection(DB_USERS)
    current = conn.execute('SELECT is_admin FROM users WHERE username = ?', (session['username'],)).fetchone()
    if not current or not current['is_admin']:
        conn.close()
        return jsonify({'status':'error'}), 403

    user = conn.execute('SELECT is_banned FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_ban = 0 if user['is_banned'] else 1
        conn.execute('UPDATE users SET is_banned = ? WHERE id = ?', (new_ban, user_id))
        conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

# --- ЛОГИКА СООБЩЕНИЙ, ЧАТОВ И ЛС ---

@app.route('/chat')
def chat_page():
    if 'username' not in session: return redirect(url_for('login'))
    # Проверка на бан прямо при обновлении
    conn = get_db_connection(DB_USERS)
    user = conn.execute('SELECT is_banned FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()
    if user and user['is_banned']:
        session.clear()
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

@app.route('/get_active_users')
def get_active_users():
    conn = get_db_connection(DB_USERS)
    users = conn.execute('SELECT username, displayname, avatar, status FROM users WHERE username != ?', (session.get('username',''),)).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/get_messages')
def get_messages():
    if 'username' not in session: return jsonify([]), 403
    chat_type = request.args.get('type', 'group')
    target_id = request.args.get('target', 'general').lower()

    # Багфикс ЛС: Сортировка имен для создания уникального ID диалога между двумя юзерами
    if chat_type == 'dm':
        sorted_users = sorted([session['username'], target_id])
        target_id = f"{sorted_users[0]}_dm_{sorted_users[1]}"

    conn = get_db_connection(DB_CHATS)
    db_msgs = conn.execute('''
        SELECT * FROM messages
        WHERE chat_type = ? AND target_id = ?
        ORDER BY timestamp ASC
    ''', (chat_type, target_id)).fetchall()
    conn.close()

    # Подтягиваем актуальные отображаемые имена и аватарки из DB_USERS для багфиксов отображения
    conn_u = get_db_connection(DB_USERS)
    user_meta = {u['username']: {'displayname': u['displayname'], 'avatar': u['avatar']} for u in conn_u.execute('SELECT username, displayname, avatar FROM users').fetchall()}
    conn_u.close()

    result = []
    import json
    for m in db_msgs:
        meta = user_meta.get(m['username'], {'displayname': m['username'], 'avatar': ''})
        import datetime
        formatted_time = datetime.datetime.fromtimestamp(m['timestamp']).strftime('%H:%M')

        reply_to_data = None
        if m['reply_to']:
            try: reply_to_data = json.loads(m['reply_to'])
            except: pass

        result.append({
            'id': m['id'],
            'username': m['username'],
            'displayname': meta['displayname'],
            'avatar': meta['avatar'],
            'text': m['text'],
            'type': m['type'],
            'url': m['url'],
            'raw_content': m['raw_content'],
            'reply_to': reply_to_data,
            'is_edited': bool(m['is_edited']),
            'time': formatted_time
        })
    return jsonify(result)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session: return jsonify({'status': 'error'}), 403

    username = session['username']
    text = request.form.get('text', '').strip()
    reply_to_json = request.form.get('reply_to_json', '') # Передаем цитату сериализованной
    chat_type = request.form.get('chat_type', 'group')
    target_id = request.form.get('target_id', 'general').lower()

    if chat_type == 'dm':
        sorted_users = sorted([username, target_id])
        target_id = f"{sorted_users[0]}_dm_{sorted_users[1]}"

    msg_type = 'text'
    url = ''
    raw_content = ''

    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = f"{int(time.time())}_{secure_filename(file.filename)}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            msg_type = determine_msg_type(filename)
            url = f"/static/uploads/{filename}"
            text = file.filename

            if msg_type == 'code':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_content = f.read()
                except: raw_content = "Ошибка чтения файла."
        else: return jsonify({'status': 'error'}), 400
    else:
        if not text: return jsonify({'status': 'error'}), 400

    conn = get_db_connection(DB_CHATS)
    conn.execute('''
        INSERT INTO messages (chat_type, target_id, username, text, type, url, raw_content, reply_to, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (chat_type, target_id, username, text, msg_type, url, raw_content, reply_to_json or None, time.time()))
    conn.commit()
    conn.close()

    typing_users.pop(username, None)
    return jsonify({'status': 'ok'})

@app.route('/edit/<int:msg_id>', methods=['POST'])
def edit_message(msg_id):
    if 'username' not in session: return jsonify({'status': 'error'}), 403
    new_text = request.form.get('text', '').strip()
    if not new_text: return jsonify({'status': 'error'}), 400

    conn = get_db_connection(DB_CHATS)
    msg = conn.execute('SELECT username FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if msg and msg['username'] == session['username']:
        conn.execute('UPDATE messages SET text = ?, is_edited = 1 WHERE id = ?', (new_text, msg_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})
    conn.close()
    return jsonify({'status': 'error'}), 403

@app.route('/delete/<int:msg_id>', methods=['POST'])
def delete_message(msg_id):
    if 'username' not in session: return jsonify({'status': 'error'}), 403
    conn = get_db_connection(DB_CHATS)
    msg = conn.execute('SELECT username FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if msg and msg['username'] == session['username']:
        conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})
    conn.close()
    return jsonify({'status': 'error'}), 403

@app.route('/typing_status', methods=['POST'])
def typing_status():
    if 'username' in session: typing_users[session['username']] = time.time()
    return jsonify({'status': 'ok'})

@app.route('/get_typing', methods=['GET'])
def get_typing():
    now = time.time()
    chat_type = request.args.get('type', 'group')
    target_id = request.args.get('target', 'general').lower()

    if chat_type == 'dm':
        sorted_users = sorted([session.get('username',''), target_id])
        target_id = f"{sorted_users[0]}_dm_{sorted_users[1]}"

    active_typers = []
    for user, last_time in list(typing_users.items()):
        if now - last_time < 4:
            if chat_type == 'group' and user != session.get('username'):
                active_typers.append(user)
            elif chat_type == 'dm' and user == request.args.get('target'):
                active_typers.append(user)
        else: typing_users.pop(user, None)
    return jsonify({'users': active_typers})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)