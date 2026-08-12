#!/usr/bin/env python3

import argparse
import json
import socket
import subprocess
import time


SAFE_HEADERS = {
    "accept", "accept-encoding", "accept-language", "connection", "host",
    "priority", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "te", "upgrade-insecure-requests", "user-agent",
}


def adb(path, *args):
    return subprocess.run([path, *args], check=True, capture_output=True, text=True)


def capture(path, package, port):
    adb(path, "reverse", f"tcp:{port}", f"tcp:{port}")
    adb(path, "shell", "am", "force-stop", package)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    listener.settimeout(20)
    url = f"http://localhost:{port}/qanat-profile"
    adb(path, "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW",
        "-d", url, package)
    raw = b""
    deadline = time.monotonic() + 20
    while not raw.startswith((b"GET ", b"HEAD ")):
        listener.settimeout(max(0.1, deadline - time.monotonic()))
        conn, _ = listener.accept()
        conn.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
        if raw.startswith((b"GET ", b"HEAD ")):
            conn.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        conn.close()
    listener.close()
    adb(path, "reverse", "--remove", f"tcp:{port}")
    lines = raw.split(b"\r\n")
    headers = []
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.decode("ascii", "strict").lower()
        if key in SAFE_HEADERS:
            headers.append({"name": key, "value": value.strip().decode("latin1")})
    return {
        "package": package,
        "request_line": lines[0].decode("ascii", "replace"),
        "headers": headers,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    packages = ["com.android.chrome", "org.mozilla.firefox", "com.brave.browser"]
    result = {
        "schema": 1,
        "captured_at": time.strftime("%Y-%m-%d"),
        "scope": "localhost navigation; allowlisted headers only",
        "samples": [capture(args.adb, package, 18770 + i)
                    for i, package in enumerate(packages)],
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
