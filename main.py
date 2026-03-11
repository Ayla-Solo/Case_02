import re
import base64
import codecs
from datetime import datetime


# ============================================================
# РОЛЬ 1: Финансовый аналитик - поиск и валидация кредитных карт
# ============================================================

def luhn_check(card_number: str) -> bool:
    """
    Проверка номера карты по алгоритму Луна
    """
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = 0
    reverse_digits = digits[::-1]

    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def find_and_validate_credit_cards(text):
    """
    Ищет и проверяет номера кредитных карт в тексте
    Возвращает {'valid': [], 'invalid': []}
    """
    pattern = r'\b(?:\d[ -]?){13,19}\b'
    matches = re.findall(pattern, text)

    valid_cards = []
    invalid_cards = []

    for match in matches:
        clean_number = re.sub(r'\D', '', match)

        if 13 <= len(clean_number) <= 19 and luhn_check(clean_number):
            valid_cards.append(clean_number)
        else:
            invalid_cards.append(clean_number)

    return {"valid": valid_cards, "invalid": invalid_cards}


# ============================================================
# РОЛЬ 2: Специалист по секретам - поиск ключей и паролей
# ============================================================

PATTERNS = {
    'Generic Secret (Key/Pass)': r'(?i)(api_key|secret|password|token|auth|pwd)[\s:="\' ]+([a-zA-Z0-9_\-\.]{12,})',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Private Key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    'High Entropy String (Potential Key)': r'[a-zA-Z0-9/\+=]{32,}'
}


def find_secrets(text):
    """
    Ищет в тексте потенциальные секретные ключи и пароли
    Возвращает список найденных секретов
    """
    secrets = []

    for name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            if name == 'Generic Secret (Key/Pass)' and len(match.groups()) >= 2:
                secret_value = match.group(2)
                secrets.append(secret_value)
            else:
                val = match.group(0)
                secrets.append(val[:100])  # Обрезаем слишком длинные

    return list(dict.fromkeys(secrets))  # Удаляем дубликаты


# ============================================================
# РОЛЬ 3: Системный аналитик - поиск IP, файлов, email
# ============================================================

def find_system_info(text):
    """
    Находит IP-адреса, имена файлов и email'ы в тексте
    Возвращает словарь с найденными артефактами
    """
    num = r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    ip_pattern = r'\b(' + num + r'\.' + num + r'\.' + num + r'\.' + num + r')\b'
    email_pattern = r'\b[a-zA-Z0-9]+([._+%-][a-zA-Z0-9]+)*@[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}\b'
    file_pattern = r'\b[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\b'

    found_ip = [match.group(0) for match in re.finditer(ip_pattern, text)]
    found_file = re.findall(file_pattern, text)
    found_email = [match.group(0) for match in re.finditer(email_pattern, text)]

    return {
        'ip': list(dict.fromkeys(found_ip)),
        'file': list(dict.fromkeys(found_file)),
        'email': list(dict.fromkeys(found_email))
    }


# ============================================================
# РОЛЬ 4: Криптоаналитик - декодирование base64/hex/rot13
# ============================================================

def decode_messages(text):
    """
    Находит и расшифровывает закодированные сообщения
    Возвращает {'base64': [], 'hex': [], 'rot13': []}
    """
    result = {'base64': [], 'hex': [], 'rot13': []}

    # Base64
    words = re.findall(r'\S+', text)
    for word in words:
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', word) and len(word) > 10:
            try:
                decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                if all(ord(c) < 128 for c in decoded):
                    result['base64'].append(decoded)
            except:
                pass

    # HEX
    hex_pattern1 = r'0x[0-9A-Fa-f]+'
    hex_pattern2 = r'(?:\\x[0-9A-Fa-f]{2})+'
    hex_matches = re.findall(hex_pattern1, text) + re.findall(hex_pattern2, text)

    for encoded in hex_matches:
        try:
            if encoded.startswith('0x'):
                hex_str = encoded[2:]
                if len(hex_str) % 2 == 0:
                    byte_data = bytes.fromhex(hex_str)
                    decoded = byte_data.decode('utf-8', errors='ignore')
                    result['hex'].append(decoded)
            elif encoded.startswith('\\x'):
                hex_parts = encoded.split('\\x')[1:]
                byte_data = bytes([int(part, 16) for part in hex_parts])
                decoded = byte_data.decode('utf-8', errors='ignore')
                result['hex'].append(decoded)
        except:
            pass

    # ROT13
    words_rot13 = re.findall(r'[A-Za-z]{4,}', text)
    for word in words_rot13:
        try:
            decoded = codecs.decode(word, 'rot_13')
            if re.search(r'[AEIOUaeiou]', decoded):
                result['rot13'].append(decoded)
        except:
            pass

    # Удаляем дубликаты
    result['base64'] = list(dict.fromkeys(result['base64']))
    result['hex'] = list(dict.fromkeys(result['hex']))
    result['rot13'] = list(dict.fromkeys(result['rot13']))

    return result


# ============================================================
# РОЛЬ 5: Аналитик безопасности - анализ логов на угрозы
# ============================================================

def analyze_logs(text):
    """
    Анализирует логи на признаки атак
    Возвращает словарь с найденными угрозами
    """
    results = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    patterns = {
        'sql_injections': r"(?i)(UNION\s+SELECT|SELECT.*FROM|OR\s+1=1|DROP\s+TABLE|--|')",
        'xss_attempts': r"(?i)(<script|alert\(|onload=|javascript:)",
        'suspicious_user_agents': r"(?i)(sqlmap|nmap|nikto|acunetix|gobuster|python-requests)",
        'failed_logins': r"(?i)(failed login|authentication failure|invalid password|401)"
    }

    for line in text.split('\n'):
        for category, pattern in patterns.items():
            if re.search(pattern, line):
                results[category].append(line.strip())

    return results


# ============================================================
# ДОПОЛНИТЕЛЬНАЯ ФУНКЦИЯ: Нормализация и валидация данных
# ============================================================

def validate_inn(inn):
    """Полная валидация ИНН по ГОСТ 28147-89"""
    if not inn.isdigit():
        return False

    if len(inn) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(inn[i]) * weights[i] for i in range(9)) % 11 % 10
        return checksum == int(inn[9])

    elif len(inn) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(int(inn[i]) * weights1[i] for i in range(10)) % 11 % 10
        if checksum1 != int(inn[10]):
            return False

        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(int(inn[i]) * weights2[i] for i in range(11)) % 11 % 10
        return checksum2 == int(inn[11])

    return False


def normalize_and_validate(text):
    """
    Приводит данные к единому формату и проверяет их на корректность.
    """
    results = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    text_lower = text.lower()

    # Телефоны
    phone_patterns = [
        r'(\+?7|8|7)[\s\-\.]?(\(?\d{3}\)?)[\s\-\.]?(\d{3})[\s\-\.]?(\d{2})[\s\-\.]?(\d{2})',
        r'(\+?7|8|7)[\s\-\.]?(\d{3})[\s\-\.]?(\d{3})[\s\-\.]?(\d{4})',
        r'(\+?7|8|7)(\d{10})',
        r'\+?(\d{10,15})'
    ]

    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            phone_digits = ''.join(filter(str.isdigit, ''.join(match)))

            if len(phone_digits) in [10, 11] and phone_digits[:2] in ['7', '8']:
                if len(phone_digits) == 10:
                    phone_digits = '7' + phone_digits
                elif phone_digits.startswith('8'):
                    phone_digits = phone_digits.replace('8', '7', 1)

                normalized_phone = '+' + phone_digits
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)

            elif 10 <= len(phone_digits) <= 15 and not phone_digits.startswith('7'):
                normalized_phone = '+' + phone_digits[:15]
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)
            else:
                invalid_phone = ''.join(match)
                if invalid_phone not in results['phones']['invalid']:
                    results['phones']['invalid'].append(invalid_phone)

    # Даты
    date_patterns = [
        r'(\d{1,2})\.(\d{1,2})\.(\d{4})',
        r'(\d{1,2})/(\d{1,2})/(\d{4})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})',
        r'(\d{4})/(\d{1,2})/(\d{1,2})',
        r'(\d{2})\.(\d{2})\.(\d{2})',
        r'(\d{1,2})\s*(янв|фев|мар|апр|май|июн|июл|авг|сен|окт|ноя|дек)\s*(\d{4})'
    ]

    month_map = {
        'янв': 1, 'фев': 2, 'мар': 3, 'апр': 4, 'май': 5, 'июн': 6,
        'июл': 7, 'авг': 8, 'сен': 9, 'окт': 10, 'ноя': 11, 'дек': 12
    }

    for pattern in date_patterns:
        matches = re.findall(pattern, text_lower)
        for match in matches:
            try:
                if len(match) == 3 and isinstance(match[2], str) and len(match[2]) == 2:
                    day, month, year = int(match[0]), int(match[1]), 2000 + int(match[2])
                elif len(match) == 3 and match[2] in month_map:
                    day, month, year = int(match[0]), month_map[match[2]], int(match[-1])
                else:
                    day, month, year = map(int, match[:3])

                dt = datetime(year, month, day)
                normalized = dt.strftime('%Y-%m-%d')

                if normalized not in results['dates']['normalized']:
                    results['dates']['normalized'].append(normalized)

            except (ValueError, IndexError):
                invalid_date = '.'.join([str(x) for x in match])
                if invalid_date not in results['dates']['invalid']:
                    results['dates']['invalid'].append(invalid_date)

    # ИНН
    inn_pattern = r'\b(\d{10}|\d{12})\b'
    raw_inns = re.findall(inn_pattern, text)

    for inn in raw_inns:
        if validate_inn(inn):
            if inn not in results['inn']['valid']:
                results['inn']['valid'].append(inn)
        else:
            if inn not in results['inn']['invalid']:
                results['inn']['invalid'].append(inn)

    # Карты
    card_pattern = r'\b(?:\d[ -]?){13,19}\b'
    raw_cards = re.findall(card_pattern, text)

    for card in raw_cards:
        digits_only = ''.join(filter(str.isdigit, card))
        if 13 <= len(digits_only) <= 19 and luhn_check(digits_only):
            results['cards']['valid'].append(digits_only)
        else:
            results['cards']['invalid'].append(digits_only)

    return results


# ============================================================
# ГЛАВНАЯ ФУНКЦИЯ: generate_comprehensive_report
# ============================================================

def generate_comprehensive_report(main_text, log_text, messy_data):
    """
    Генерирует полный отчет о расследовании
    """
    report = {
        'financial_data': find_and_validate_credit_cards(main_text),
        'secrets': find_secrets(main_text),
        'system_info': find_system_info(main_text),
        'encoded_messages': decode_messages(main_text),
        'security_threats': analyze_logs(log_text),
        'normalized_data': normalize_and_validate(messy_data)
    }
    return report


def print_report(report):
    """Красиво выводит отчет"""
    print("=" * 60)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'".center(60))
    print("=" * 60)

    sections = [
        ("ФИНАНСОВЫЕ ДАННЫЕ (карты)", report['financial_data']),
        ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
        ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
        ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
        ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
        ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data'])
    ]

    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 40)

        if isinstance(data, dict):
            for key, value in data.items():
                if value:
                    if isinstance(value, list):
                        print(f"  {key}: {len(value)} найдено")
                        for item in value[:5]:  # Показываем первые 5
                            print(f"    - {item}")
                    else:
                        print(f"  {key}: {value}")
        elif isinstance(data, list):
            if data:
                for item in data[:5]:
                    print(f"  - {item}")
            else:
                print("  Ничего не найдено")
        else:
            print(f"  {data}")

# __________data comparison________________
def compare_files(file1, file2):  # сравнение файлов
    with open(file1, "r", encoding="utf-8") as f1:
        set1 = {line.strip() for line in f1}

    with open(file2, "r", encoding="utf-8") as f2:
        set2 = {line.strip() for line in f2}

    only_in_file1 = set1 - set2
    only_in_file2 = set2 - set1

    if not only_in_file1 and not only_in_file2:
        print("Файлы совпадают по содержимому")
        return

    if only_in_file1:
        print("Есть только в result11.txt:")
        for line in only_in_file1:
            print(line)

    if only_in_file2:
        print("Есть только во втором файле:")
        for line in only_in_file2:
            print(line)

if __name__ == "__main__":
    # Чтение файлов с данными
    try:
        with open('666.txt', 'r', encoding='utf-8') as f:
            main_text = f.read()

        # Запуск расследования
        report = generate_comprehensive_report(main_text, main_text, main_text)

        # Вывод отчета
        #print_report(report)

        # Сохраняем все артефакты в один файл
        with open('result11.txt', 'w', encoding='utf-8') as f:
            # Финансовые данные
            for card in report['financial_data']['valid']:
                f.write(card + '\n')

            # Секреты
            for secret in report['secrets']:
                f.write(secret + '\n')

            # Системная информация
            for ip in report['system_info']['ip']:
                f.write(ip + '\n')
            for file in report['system_info']['file']:
                f.write(file + '\n')
            for email in report['system_info']['email']:
                f.write(email + '\n')

            # Декодированные сообщения
            for msg in report['encoded_messages']['base64']:
                f.write(msg + '\n')
            for msg in report['encoded_messages']['hex']:
                f.write(msg + '\n')
            for msg in report['encoded_messages']['rot13']:
                f.write(msg + '\n')

            # Нормализованные данные
            for phone in report['normalized_data']['phones']['valid']:
                f.write(phone + '\n')
            for date in report['normalized_data']['dates']['normalized']:
                f.write(date + '\n')
            for inn in report['normalized_data']['inn']['valid']:
                f.write(inn + '\n')
            for card in report['normalized_data']['cards']['valid']:
                f.write(card + '\n')

        # Эта часть уже выполнена выше, поэтому просто вызываем сравнение
        # Сравнение файлов (только это выводится в консоль)
        for i in range(1, 2):
            file1 = "result11.txt"
            file2 = "result" + str(i) + ".txt"
            compare_files(file1, file2)

    except FileNotFoundError as e:
        print(f"Ошибка: не найден файл {e.filename}")
        print("Убедитесь, что все файлы существуют:")
        print("- 666.txt")


