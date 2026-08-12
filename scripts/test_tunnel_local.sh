#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-"$ROOT/build/test_tunnel_runtime"}
TMP=$(mktemp -d)

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

command -v python3 >/dev/null
command -v openssl >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 1 \
    -subj "/CN=www.cloudflare.com" >/dev/null 2>&1
cp "$ROOT/tests/fake_xray.py" "$TMP/xray"
chmod 700 "$TMP/xray"

QN_TUNNEL_LIVE_FIXTURE="$TMP/xray" \
QN_FAKE_XRAY_CERT="$TMP/cert.pem" \
QN_FAKE_XRAY_KEY="$TMP/key.pem" \
"$BIN"
