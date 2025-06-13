# Імпорт необхідних модулей.
import os

# Визначення імені текстового файлу.
file_name = 'text_collected_indicators.txt'

def is_file_excists():
    # Перевірка та створення текстового файлу.
    if not os.path.exists(file_name):
        with open(file_name, 'w', encoding='utf-8') as f:
            pass

def write_indicators_in_file(time, source, destination, protocol, info):
    try:
        is_file_excists()
        # Додавання показників до текстового файлу.
        with open(file_name, 'a', encoding='utf-8') as f:
            f.write(f"{}\n")
        except FileNotFoundError:.
            print(f"Помилка, файл '{file_name}' не знайдено.")
        except Exception as e:
            # Повідомлення про помилку при роботі з текстовим файлом.
            print(f"Виникла помилка - {e}")
