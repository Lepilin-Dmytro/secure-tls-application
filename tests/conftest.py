import json
import os
import ssl
import threading
import socketserver
import pytest
import bcrypt

import server as app


@pytest.fixture
def tls_server(tmp_path, monkeypatch):
    cert_dir = os.path.join(os.path.dirname(app.__file__), "certs")
    ca_file = os.path.join(cert_dir, "ca.crt")
    cert_file = os.path.join(cert_dir, "server.crt")
    key_file = os.path.join(cert_dir, "server.key")

    users_file = tmp_path / "users.json"
    password_hash = bcrypt.hashpw(
        b"SecurePass123!",
        bcrypt.gensalt()
    ).decode("utf-8")

    users_file.write_text(
        json.dumps({"alice": password_hash}),
        encoding="utf-8"
    )

    monkeypatch.setattr(app, "USERS_FILE", str(users_file))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)

    class TestServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

        def get_request(self):
            sock, address = super().get_request()
            tls_sock = context.wrap_socket(sock, server_side=True)
            return tls_sock, address

    test_server = TestServer(("127.0.0.1", 0), app.TLSRequestHandler)

    thread = threading.Thread(
        target=test_server.serve_forever,
        daemon=True
    )
    thread.start()

    host, port = test_server.server_address

    yield host, port, ca_file

    test_server.shutdown()
    test_server.server_close()
    thread.join(timeout=2)
