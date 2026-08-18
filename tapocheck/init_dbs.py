import sqlite3

def init_databases():
    # 1. Создаем базу данных пользователей
    conn_users = sqlite3.connect('users.db')
    cursor_users = conn_users.cursor()
    cursor_users.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Добавим тестового пользователя, если таблица пустая
    try:
        cursor_users.execute("INSERT INTO user (username, password) VALUES ('Admin', 'admin123')")
    except sqlite3.IntegrityError:
        pass
    conn_users.commit()
    conn_users.close()

    # 2. Создаем базу данных чатов и сообщений
    conn_chats = sqlite3.connect('chats.db')
    cursor_chats = conn_chats.cursor()

    # Таблица комнат (чатов)
    cursor_chats.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator_username TEXT NOT NULL
        )
    ''')

    # Таблица сообщений
    cursor_chats.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    ''')

    # Создадим один чат по умолчанию
    cursor_chats.execute("SELECT COUNT(*) FROM rooms")
    if cursor_chats.fetchone()[0] == 0:
        cursor_chats.execute("INSERT INTO rooms (name, creator_username) VALUES ('Общий чат', 'Admin')")

    conn_chats.commit()
    conn_chats.close()
    print("Базы данных успешно инициализированы!")

if __name__ == '__main__':
    init_databases()
