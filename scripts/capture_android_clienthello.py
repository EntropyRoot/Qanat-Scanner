#!/usr/bin/env python3

import argparse
import json
import socket
import subprocess
import time


SAFE_BODY_TYPES = {
    5, 10, 11, 13, 16, 18, 23, 27, 28, 34, 43, 45, 0x44CD, 0xFF01,
}
SECRET_BODY_TYPES = {0, 35, 41, 44, 51, 0xFE0D}


def adb(path, *args):
    return subprocess.run([path, *args], check=True, capture_output=True, text=True)


def u16(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def u24(data, offset):
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def grease(value):
    return value >> 8 == value & 0xff and value & 0x0f == 0x0a


def vector16(data, prefix):
    size = data[0] if prefix == 1 else u16(data, 0)
    start = prefix
    if size != len(data) - start or size % 2:
        return []
    return [u16(data, pos) for pos in range(start, len(data), 2)
            if not grease(u16(data, pos))]


def key_shares(data):
    if len(data) < 2 or u16(data, 0) != len(data) - 2:
        return []
    result = []
    pos = 2
    while pos + 4 <= len(data):
        group = u16(data, pos)
        size = u16(data, pos + 2)
        pos += 4
        if size > len(data) - pos:
            return []
        if not grease(group):
            result.append({"group": group, "length": size})
        pos += size
    return result if pos == len(data) else []


def ech_shape(data):
    variants = [("outer", 1), ("legacy", 0)]
    for name, start in variants:
        if start and (not data or data[0] != 0):
            continue
        if len(data) < start + 41 or u16(data, start) == 0:
            continue
        enc_size = u16(data, start + 5)
        payload_at = start + 7 + enc_size
        if payload_at + 2 > len(data):
            continue
        payload_size = u16(data, payload_at)
        if payload_at + 2 + payload_size == len(data):
            return {
                "encoding": name,
                "kdf": u16(data, start),
                "aead": u16(data, start + 2),
                "enc_length": enc_size,
                "payload_length": payload_size,
            }
    return {"encoding": "unrecognized"}


def parse(record):
    if len(record) < 9 or record[0] != 22 or u16(record, 3) != len(record) - 5:
        raise ValueError("not one complete TLS handshake record")
    hello = record[5:]
    if hello[0] != 1 or u24(hello, 1) != len(hello) - 4:
        raise ValueError("not one complete ClientHello")
    pos = 4 + 2 + 32
    pos += 1 + hello[pos]
    cipher_size = u16(hello, pos)
    pos += 2
    ciphers = [u16(hello, i) for i in range(pos, pos + cipher_size, 2)
               if not grease(u16(hello, i))]
    pos += cipher_size
    pos += 1 + hello[pos]
    ext_size = u16(hello, pos)
    pos += 2
    if ext_size != len(hello) - pos:
        raise ValueError("bad extension vector")
    extensions = []
    groups = []
    shares = []
    sigalgs = []
    versions = []
    ech = None
    while pos < len(hello):
        ext_type = u16(hello, pos)
        size = u16(hello, pos + 2)
        pos += 4
        body = hello[pos:pos + size]
        pos += size
        if grease(ext_type):
            continue
        item = {"type": ext_type, "length": size}
        if ext_type in SAFE_BODY_TYPES and ext_type not in SECRET_BODY_TYPES:
            item["body_hex"] = body.hex()
        extensions.append(item)
        if ext_type == 10:
            groups = vector16(body, 2)
        elif ext_type == 13:
            sigalgs = vector16(body, 2)
        elif ext_type == 43:
            versions = vector16(body, 1)
        elif ext_type == 51:
            shares = key_shares(body)
        elif ext_type == 0xFE0D:
            ech = ech_shape(body)
    return {
        "record_length": len(record),
        "cipher_suites": ciphers,
        "extensions": extensions,
        "supported_groups": groups,
        "key_shares": shares,
        "signature_algorithms": sigalgs,
        "supported_versions": versions,
        "ech": ech,
    }


def recv_record(conn):
    data = b""
    while len(data) < 5:
        chunk = conn.recv(5 - len(data))
        if not chunk:
            return b""
        data += chunk
    wanted = 5 + u16(data, 3)
    while len(data) < wanted:
        chunk = conn.recv(wanted - len(data))
        if not chunk:
            break
        data += chunk
    return data


def capture(path, package, port):
    adb(path, "reverse", f"tcp:{port}", f"tcp:{port}")
    listener = socket.socket()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)
        listener.settimeout(20)
        adb(path, "shell", "am", "force-stop", package)
        adb(path, "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW",
            "-d", f"https://localhost:{port}/qanat-profile", package)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            conn, _ = listener.accept()
            try:
                conn.settimeout(5)
                record = recv_record(conn)
                if record.startswith(b"\x16"):
                    result = parse(record)
                    result["package"] = package
                    return result
            finally:
                conn.close()
        raise TimeoutError(f"no ClientHello from {package}")
    finally:
        listener.close()
        adb(path, "reverse", "--remove", f"tcp:{port}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--package", action="append")
    args = parser.parse_args()
    packages = args.package or ["com.android.chrome", "org.mozilla.firefox"]
    result = {
        "schema": 1,
        "captured_at": time.strftime("%Y-%m-%d"),
        "scope": "localhost ClientHello; random, session, SNI and key bytes removed",
        "samples": [capture(args.adb, package, 18780 + i)
                    for i, package in enumerate(packages)],
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
