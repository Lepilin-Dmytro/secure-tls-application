import os
import ssl
import json
import hmac
import hashlib
import secrets
import logging
import socketserver
import bcrypt
from datetime import datetime, timezone

HOST = "127.0.0.1"
PORT = 8443

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "certs", "server.crt")
KEY_FILE = os.path.join(BASE_DIR, "certs", "server.key")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "server.log")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def log_event(event, **details):
    logging.info("%s %s", event, json.dumps(details))


def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


class TLSRequestHandler(socketserver.StreamRequestHandler):
    def send_json(self, data):
        message = json.dumps(data).encode("utf-8") + b"\n"
        self.wfile.write(message)
        self.wfile.flush()

    def read_json(self):
        line = self.rfile.readline(65536)
        if not line:
            return None
        return json.loads(line.decode("utf-8"))

    def handle(self):
        peer = self.client_address[0]
        session_key = None

        try:
            request = self.read_json()

            if not request or request.get("action") != "login":
                self.send_json({"status": "error", "message": "Authentication required"})
                log_event("AUTH_REQUIRED", ip=peer)
                return

            username = str(request.get("username", ""))
            password = str(request.get("password", ""))

            users = load_users()
            password_hash = users.get(username)

            if not password_hash or not bcrypt.checkpw(
                password.encode("utf-8"),
                password_hash.encode("utf-8")
            ):
                self.send_json({"status": "error", "message": "Invalid credentials"})
                log_event("AUTH_FAILED", ip=peer, username=username)
                return

            session_key = secrets.token_bytes(32)

            self.send_json({
                "status": "ok",
                "message": "Authentication successful",
                "session_key": session_key.hex()
            })

            log_event("AUTH_SUCCESS", ip=peer, username=username)

            while True:
                request = self.read_json()
                if request is None:
                    break

                if request.get("action") == "logout":
                    self.send_json({"status": "ok", "message": "Logged out"})
                    break

                if request.get("action") != "message":
                    self.send_json({"status": "error", "message": "Unknown action"})
                    continue

                data = request.get("data", "")
                received_mac = request.get("hmac", "")

                expected_mac = hmac.new(
                    session_key,
                    data.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(received_mac, expected_mac):
                    self.send_json({"status": "error", "message": "Integrity check failed"})
                    log_event("INTEGRITY_FAILED", ip=peer, username=username)
                    continue

                self.send_json({
                    "status": "ok",
                    "message": "Data received",
                    "received": data
                })

                log_event(
                    "MESSAGE_RECEIVED",
                    ip=peer,
                    username=username,
                    length=len(data)
                )

        except (json.JSONDecodeError, UnicodeDecodeError):
            log_event("INVALID_REQUEST", ip=peer)
            try:
                self.send_json({"status": "error", "message": "Invalid request"})
            except OSError:
                pass

        except Exception as error:
            log_event("SERVER_ERROR", ip=peer, error=type(error).__name__)

        finally:
            log_event("CONNECTION_CLOSED", ip=peer)


class ThreadedTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)

    class TLSWrappedServer(ThreadedTLSServer):
        def get_request(self):
            sock, address = super().get_request()
            try:
                tls_sock = context.wrap_socket(sock, server_side=True)
                log_event(
                    "TLS_CONNECTED",
                    ip=address[0],
                    protocol=tls_sock.version(),
                    cipher=tls_sock.cipher()[0]
                )
                return tls_sock, address
            except ssl.SSLError as error:
                log_event("TLS_FAILED", ip=address[0], error=str(error))
                sock.close()
                raise

    with TLSWrappedServer((HOST, PORT), TLSRequestHandler) as server:
        print(f"TLS server listening on {HOST}:{PORT}")
        print("Minimum TLS version:", context.minimum_version.name)
        server.serve_forever()


if __name__ == "__main__":
    main()
