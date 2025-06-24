import smtplib
import dns.resolver
import sys
import time

SMTP_PORT = 25  # Можно попробовать 587 или 465 при необходимости
SENDER_EMAIL = "test@example.com"  # Отправитель, можно указать любой существующий email
RETRY_LIMIT = 3  # Количество попыток при ошибке сети
RETRY_DELAY = 30  # Задержка перед повторной попыткой (в секундах)
CHECK_DELAY = 2  # Задержка между проверками email'ов (в секундах)

def get_mx_record(domain):
    """Получает MX-запись домена"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return sorted(mx_records, key=lambda record: record.preference)[0].exchange.to_text()
    except Exception as e:
        print(f"Ошибка получения MX-записи для {domain}: {e}")
        return None

def check_email(email, smtp_server, method):
    """Проверяет существование email через SMTP (VRFY, EXPN, RCPT TO) с повторными попытками при ошибке"""
    attempts = 0
    while attempts < RETRY_LIMIT:
        try:
            server = smtplib.SMTP(smtp_server, SMTP_PORT, timeout=10)
            server.helo()
            server.mail(SENDER_EMAIL)

            if method == "VRFY":
                code, _ = server.verify(email)
            elif method == "EXPN":
                code, _ = server.expn(email)
            else:
                code, _ = server.rcpt(email)

            server.quit()

            if code == 250:
                print(f"[+] {email} существует")
                return True
            else:
                print(f"[-] {email} не существует")
                return False
        except OSError as e:
            if "Network is unreachable" in str(e):
                attempts += 1
                print(f"[!] Ошибка сети при проверке {email}, попытка {attempts}/{RETRY_LIMIT}. Ждем {RETRY_DELAY} секунд...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"Ошибка при проверке {email}: {e}")
                return False

    print(f"[X] Не удалось проверить {email} после {RETRY_LIMIT} попыток.")
    return False

def main():
    if len(sys.argv) != 4:
        print("Использование: python script.py <файл_почт> <smtp_сервер> <метод>")
        sys.exit(1)

    email_list_file = sys.argv[1]
    smtp_server = sys.argv[2]
    method = sys.argv[3].upper()

    if method not in ["VRFY", "EXPN", "RCPT"]:
        print("Метод должен быть VRFY, EXPN или RCPT")
        sys.exit(1)

    try:
        with open(email_list_file, "r") as file:
            emails = [line.strip() for line in file if line.strip()]

        for email in emails:
            check_email(email, smtp_server, method)
            time.sleep(CHECK_DELAY)  # Задержка между проверками
    except FileNotFoundError:
        print("Файл с email-адресами не найден.")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()