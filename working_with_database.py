# Імпорт необхідних модулей.
import sqlite3

# Визначення імені файлу бази даних.
db_file = 'database_collected_indicators.db'

def create_table_in_db():
    try:
        # Створення з'єднання з базою даних.
        with sqlite3.connect(db_file) as con:
            # Створення курсору.
            cursor = con.cursor()
            # Перевірка та створення таблиці бази даних.
            cursor.execute('''
                            CREATE TABLE IF NOT EXISTS indicators (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            time TEXT,
                            source TEXT,
                            destination TEXT,
                            protocol TEXT,
                            info TEXT
                            )
                            ''')
    except sqlite3.Error as e:
        # Повідомлення про помилку при роботі з базою даних.
        print(f"Виникла помилка - {e}")

def write_indicators_in_db(time, source, destination, protocol, info):
    try:
        # Створення з'єднання з базою даних.
        with sqlite3.connect(db_file) as con:
            # Створення курсору.
            cursor = con.cursor()
            # Додавання показників до таблиці бази даних.
            cursor.execute("INSERT INTO indicators (source, destination, protocol, length, time) VALUES (?, ?, ?, ?, ?)",
                           (f"{time}", f"{source}", f"{destination}", f"{protocol}", f"{info}))
    except sqlite3.Error as e:
        # Повідомлення про помилку при роботі з базою даних.
        print(f"Виникла помилка - {e}")
