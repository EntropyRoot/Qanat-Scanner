#!/bin/sh
# Runs the handshake against a local OpenSSL server. No network needed.
set -eu

CC=${CC:-cc}
BUILD=${BUILD:-build-tlstest}
PORT=${PORT:-14433}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
PIDS=""

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

command -v openssl >/dev/null || { echo "SKIP: openssl not installed"; exit 0; }

mkdir -p "$ROOT/$BUILD"
$CC -std=c11 -D_GNU_SOURCE -I"$ROOT/include" -O1 -g -pthread \
    -o "$ROOT/$BUILD/tls_probe" \
    "$ROOT/tests/tls_probe.c" \
    "$ROOT/src/net/tls13.c" "$ROOT/src/net/tls12.c" "$ROOT/src/net/profile.c" \
    "$ROOT/src/net/tls_capability.c" "$ROOT/src/net/tls_hello.c" \
    "$ROOT/src/net/tls_fp.c" "$ROOT/src/net/tls_cert.c" \
    "$ROOT/src/crypto/"*.c "$ROOT/src/crypto/arm64/cpufeat.c" \
    "$ROOT/src/core/perm.c" "$ROOT/src/core/util.c" ${EXTRA_CFLAGS:-}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/k.pem" -out "$TMP/c.pem" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

# A two-certificate 4096-bit chain outgrows the 2 KiB parse buffer, so the
# streaming Certificate framing check is exercised against real OpenSSL output.
big_chain=0
if openssl req -x509 -newkey rsa:4096 -nodes -keyout "$TMP/ca.key" \
        -out "$TMP/ca.pem" -days 1 -subj "/CN=Qanat Test CA" >/dev/null 2>&1 &&
   openssl req -newkey rsa:4096 -nodes -keyout "$TMP/leaf.key" \
        -out "$TMP/leaf.csr" -subj "/CN=localhost" >/dev/null 2>&1 &&
   openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
        -set_serial 1 -days 1 -out "$TMP/leaf.pem" >/dev/null 2>&1; then
    cat "$TMP/leaf.pem" "$TMP/ca.pem" > "$TMP/chain.pem"
    big_chain=1
fi

fail=0
CERT="$TMP/c.pem"
KEY="$TMP/k.pem"

run_case() {
    label=$1
    mode=$2
    shift 2

    for fp in chrome firefox safari; do
        openssl s_server -quiet -www -cert "$CERT" -key "$KEY" \
            -accept "$PORT" "$@" >/dev/null 2>&1 &
        sp=$!
        PIDS="$PIDS $sp"

        ok=0
        i=0
        while [ $i -lt 50 ]; do
            if "$ROOT/$BUILD/tls_probe" 127.0.0.1 "$PORT" localhost "$fp" "$mode" \
                >"$TMP/out" 2>"$TMP/err"; then
                ok=1; break
            fi
            grep -q "connect failed" "$TMP/err" || break
            i=$((i + 1))
            sleep 0.1
        done

        if [ $ok -eq 1 ]; then
            printf '  ok   %-28s %-8s %s\n' "$label" "$fp" \
                "$(sed -n 's/^handshake: ok //p' "$TMP/out")"
        else
            printf '  FAIL %-28s %-8s\n' "$label" "$fp"
            sed 's/^/       /' "$TMP/err"
            fail=1
        fi

        kill "$sp" 2>/dev/null || true
        wait "$sp" 2>/dev/null || true
        PORT=$((PORT + 1))
    done
}

for cs in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    run_case "$cs" tls13 -tls1_3 -ciphersuites "$cs"
done

for c in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 \
         ECDHE-RSA-CHACHA20-POLY1305; do
    run_case "$c" tls12 -tls1_2 -cipher "$c"
done

if [ $big_chain -eq 1 ]; then
    CERT="$TMP/chain.pem"
    KEY="$TMP/leaf.key"
    run_case "ECDHE-RSA-AES128 4096 chain" tls12 -tls1_2 \
        -cipher ECDHE-RSA-AES128-GCM-SHA256
    run_case "TLS_AES_128_GCM 4096 chain" tls13 -tls1_3 \
        -ciphersuites TLS_AES_128_GCM_SHA256
    CERT="$TMP/c.pem"
    KEY="$TMP/k.pem"
else
    echo "  skip large-chain cases: could not build a test CA"
fi

[ $fail -eq 0 ] && echo "tls handshake tests: ok"
exit $fail
