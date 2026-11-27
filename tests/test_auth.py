import json
import socket
import ssl


def connect(tls_server):
    host, port, ca_file = tls_server
    context = ssl.create_default_context(cafile=ca_file)

    raw = socket.create_connection((host, port), timeout=5)
    tls = context.wrap_socket(raw, server_hostname="localhost")
    reader = tls.makefile("r", encoding="utf-8")
    return tls, reader


def test_successful_authentication(tls_server):
    tls, reader = connect(tls_server)

    try:
        request = {
            "action": "login",
            "username": "alice",
            "password": "SecurePass123!"
        }
        tls.sendall(json.dumps(request).encode() + b"\n")

        response = json.loads(reader.readline())

        assert response["status"] == "ok"
        assert response["message"] == "Authentication successful"
        assert len(response["session_key"]) == 64
    finally:
        reader.close()
        tls.close()


def test_failed_authentication(tls_server):
    tls, reader = connect(tls_server)

    try:
        request = {
            "action": "login",
            "username": "alice",
            "password": "WrongPassword"
        }
        tls.sendall(json.dumps(request).encode() + b"\n")

        response = json.loads(reader.readline())

        assert response["status"] == "error"
        assert response["message"] == "Invalid credentials"
    finally:
        reader.close()
        tls.close()
