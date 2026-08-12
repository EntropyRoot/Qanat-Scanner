#!/usr/bin/env python3
import json
import os
import socket
import ssl
import stat
import sys
import time


def recv_exact(connection, length):
    output = bytearray()
    while len(output) < length:
        chunk = connection.recv(length - len(output))
        if not chunk:
            return None
        output.extend(chunk)
    return bytes(output)


def config_path(arguments):
    try:
        index = arguments.index("-c")
    except ValueError:
        return None
    if index + 1 >= len(arguments):
        return None
    return arguments[index + 1]


def read_config(path):
    if not path or stat.S_IMODE(os.stat(path).st_mode) != 0o600:
        raise ValueError("config mode")
    with open(path, "r", encoding="utf-8") as source:
        config = json.load(source)
    inbound = config["inbounds"][0]
    if inbound["listen"] != "127.0.0.1" or inbound["protocol"] != "socks":
        raise ValueError("inbound")
    return int(inbound["port"])


def read_connect(connection):
    header = recv_exact(connection, 4)
    if not header or header != b"\x05\x01\x00\x03":
        return False
    length = recv_exact(connection, 1)
    if not length or length[0] == 0:
        return False
    return recv_exact(connection, length[0] + 2) is not None


def send_fragmented(connection, payload):
    for byte in payload:
        connection.sendall(bytes((byte,)))
        time.sleep(0.001)


def serve_tls(connection, mode):
    certificate = os.environ["QN_FAKE_XRAY_CERT"]
    key = os.environ["QN_FAKE_XRAY_KEY"]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(["http/1.1"])
    with context.wrap_socket(connection, server_side=True) as secure:
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) <= 32768:
            chunk = secure.recv(4096)
            if not chunk:
                return
            request.extend(chunk)
        if b"GET /cdn-cgi/trace " not in request:
            return
        if mode == "no-marker":
            body = b"fl=test\nip=127.0.0.1\ntls=TLSv1.3\n"
        else:
            body = b"fl=test\nip=127.0.0.1\ncolo=TST\ntls=TLSv1.3\n"
        head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" +
                b"Connection: close\r\nContent-Length: " +
                str(len(body)).encode("ascii") + b"\r\n\r\n")
        secure.sendall(head)
        send_fragmented(secure, body)


def serve(port, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(4)
        while True:
            connection, _ = listener.accept()
            with connection:
                greeting = recv_exact(connection, 3)
                if greeting is None:
                    continue
                if greeting != b"\x05\x01\x00":
                    return 2
                if mode == "socks-auth":
                    connection.sendall(b"\x05\x02")
                    return 0
                connection.sendall(b"\x05\x00")
                if not read_connect(connection):
                    return 3
                send_fragmented(
                    connection,
                    b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb",
                )
                serve_tls(connection, mode)
                return 0


def main():
    path = config_path(sys.argv[1:])
    try:
        port = read_config(path)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return 1
    if "-test" in sys.argv[1:]:
        return 0
    return serve(port, os.environ.get("QN_FAKE_XRAY_MODE", "success"))


if __name__ == "__main__":
    sys.exit(main())
