import requests
from concurrent.futures import ThreadPoolExecutor
import argparse

def analyze_url(url, cookies, headers, output_file=None):
    try:
        response = requests.options(url, headers=headers, cookies=cookies)
        
        directory = response.headers.get("Location") or response.headers.get("Content-Location", "N/A")
        
        allowed_methods = response.headers.get("Allow", "N/A")
        
        result = (
            f"URL: {url}\n"
            f"Directory: {directory}\n"
            f"Allowed Methods: {allowed_methods}\n"
            "-----------------------------\n"
        )
        
        print(result, end="")
        
        if output_file:
            with open(output_file, "a") as file:
                file.write(result)
    except requests.RequestException as e:
        error_message = f"Error analyzing {url}: {e}\n"
        print(error_message, end="")
        if output_file:
            with open(output_file, "a") as file:
                file.write(error_message)

def load_cookies_from_file(file_path):
    cookies = {}
    with open(file_path, "r") as file:
        for line in file:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                cookies[key] = value
    return cookies

def load_headers_from_file(file_path):
    headers = {}
    with open(file_path, "r") as file:
        for line in file:
            if ":" in line:
                key, value = line.strip().split(":", 1)
                headers[key.strip()] = value.strip()
    return headers

def main():
    parser = argparse.ArgumentParser(description="Analyze URLs with OPTIONS method.")
    parser.add_argument("urls_file", type=str, help="Path to a file containing URLs (one URL per line)")
    parser.add_argument("--cookies", type=str, help="Cookie string in format 'key1=value1; key2=value2'")
    parser.add_argument("--cookies-file", type=str, help="Path to a file containing cookies (one 'key=value' per line)")
    parser.add_argument("--headers", type=str, help="Headers string in format 'key1:value1; key2:value2'")
    parser.add_argument("--headers-file", type=str, help="Path to a file containing headers (one 'key:value' per line)")
    parser.add_argument("--output", type=str, help="Path to the output file to save results")
    args = parser.parse_args()

    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies[key] = value
    elif args.cookies_file:
        cookies = load_cookies_from_file(args.cookies_file)

    headers = {}
    if args.headers:
        for header in args.headers.split(";"):
            if ":" in header:
                key, value = header.strip().split(":", 1)
                headers[key.strip()] = value.strip()
    elif args.headers_file:
        headers = load_headers_from_file(args.headers_file)

    with open(args.urls_file, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    if args.output:
        open(args.output, "w").close()

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda url: analyze_url(url, cookies, headers, args.output), urls)

if __name__ == "__main__":
    main()
