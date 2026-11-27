import socket
import ssl


def test_tls_connection_and_certificate(tls_server):
    host, port, ca_file = tls_server

    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=ca_file
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            assert tls.cipher() is not None
            assert tls.getpeercert()
