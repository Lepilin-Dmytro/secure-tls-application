import ssl
import json
import hmac
import hashlib
import socket
import getpass
import os

HOST = "localhost"
PORT = 8443

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_FILE = os.path.join(BASE_DIR, "certs", "ca.crt")


def send_json(sock, data):
    message = json.dumps(data).encode("utf-8") + b"\n"
    sock.sendall(message)


def receive_json(file):
    line = file.readline(65536)
    if not line:
        raise ConnectionError("Server disconnected")
    return json.loads(line)


def main():
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA_FILE
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    print("Connecting to secure TLS server...")

    try:
        with socket.create_connection((HOST, PORT), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=HOST) as tls_socket:
                print("TLS connection established")
                print("Protocol:", tls_socket.version())
                print("Cipher:", tls_socket.cipher()[0])
                print("Certificate verification: successful")

                with tls_socket.makefile("r", encoding="utf-8") as server_file:
                    username = input("Username: ")
                    password = getpass.getpass("Password: ")

                    send_json(tls_socket, {
                        "action": "login",
                        "username": username,
                        "password": password
                    })

                    response = receive_json(server_file)
                    print("Server:", response.get("message"))

                    if response.get("status") != "ok":
                        return

                    session_key = bytes.fromhex(response["session_key"])

                    print("\nAuthentication successful.")
                    print("Enter messages. Type /exit to disconnect.\n")

                    while True:
                        message = input("Message: ")

                        if message == "/exit":
                            send_json(tls_socket, {"action": "logout"})
                            print("Server:", receive_json(server_file).get("message"))
                            break

                        mac = hmac.new(
                            session_key,
                            message.encode("utf-8"),
                            hashlib.sha256
                        ).hexdigest()

                        send_json(tls_socket, {
                            "action": "message",
                            "data": message,
                            "hmac": mac
                        })

                        response = receive_json(server_file)
                        print("Server:", response)

    except ssl.SSLCertVerificationError:
        print("ERROR: Server certificate verification failed.")
    except (ConnectionError, ConnectionRefusedError, TimeoutError, OSError) as error:
        print("Connection error:", error)


if __name__ == "__main__":
    main()
