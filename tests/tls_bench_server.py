import argparse
import socket
import ssl


def serve(cert, key, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    body = b"fl=bench\ncolo=SJC\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"CF-Ray: 0123456789abcdef-SJC\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )

    with socket.create_server(("127.0.0.1", port), reuse_port=False) as listener:
        while True:
            raw, _ = listener.accept()
            try:
                with context.wrap_socket(raw, server_side=True) as peer:
                    request = b""
                    while b"\r\n\r\n" not in request and len(request) < 16384:
                        chunk = peer.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    if request:
                        peer.sendall(response)
            except (ConnectionError, ssl.SSLError):
                raw.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=9443)
    args = parser.parse_args()
    serve(args.cert, args.key, args.port)


if __name__ == "__main__":
    main()
