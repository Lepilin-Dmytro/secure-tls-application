import json
import socket
import ssl
import hmac
import hashlib


def test_valid_message_integrity(tls_server):
    host, port, ca_file = tls_server
    context = ssl.create_default_context(cafile=ca_file)

    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            reader = tls.makefile("r", encoding="utf-8")

            login = {
                "action": "login",
                "username": "alice",
                "password": "SecurePass123!"
            }
            tls.sendall(json.dumps(login).encode() + b"\n")

            auth_response = json.loads(reader.readline())
            assert auth_response["status"] == "ok"

            session_key = bytes.fromhex(auth_response["session_key"])
            message = "Integrity test message"

            mac = hmac.new(
                session_key,
                message.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            request = {
                "action": "message",
                "data": message,
                "hmac": mac
            }
            tls.sendall(json.dumps(request).encode() + b"\n")

            response = json.loads(reader.readline())

            assert response["status"] == "ok"
            assert response["received"] == message

            reader.close()


def test_tampered_message_rejected(tls_server):
    host, port, ca_file = tls_server
    context = ssl.create_default_context(cafile=ca_file)

    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            reader = tls.makefile("r", encoding="utf-8")

            login = {
                "action": "login",
                "username": "alice",
                "password": "SecurePass123!"
            }
            tls.sendall(json.dumps(login).encode() + b"\n")

            auth_response = json.loads(reader.readline())
            session_key = bytes.fromhex(auth_response["session_key"])

            message = "Original message"
            mac = hmac.new(
                session_key,
                message.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            request = {
                "action": "message",
                "data": "Modified message",
                "hmac": mac
            }
            tls.sendall(json.dumps(request).encode() + b"\n")

            response = json.loads(reader.readline())

            assert response["status"] == "error"
            assert response["message"] == "Integrity check failed"

            reader.close()
