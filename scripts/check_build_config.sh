#!/bin/sh
# P0-6 regression: a change of compiler flags must rebuild, not reuse objects.
# Objects carry no record of their flags, so only the config stamp can catch it.
set -u

CC_BIN=${CC:-cc}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
D=${TMPDIR:-/tmp}/qn-build-config-$$
B=$D/b
BASEF="-std=c11 -D_GNU_SOURCE -Iinclude -pthread -MMD -MP"
fail=0
ok=0

cleanup() { rm -rf "$D"; }
trap cleanup EXIT INT TERM
mkdir -p "$D" || exit 1
cd "$ROOT" || exit 1

# One object is enough and keeps the check fast.
OBJ=$B/src/net/engine.o

build() {
    make -s CC="$CC_BIN" BUILD="$B" LTO= CFLAGS="$BASEF $1" \
         LDFLAGS="-pthread $2" "$OBJ" >/dev/null 2>&1
}

stamp() { stat -c %Y%n "$OBJ" 2>/dev/null || stat -f %m "$OBJ"; }
digest() { md5sum "$OBJ" | cut -d' ' -f1; }

pass() { echo "  ok    $1"; ok=$((ok + 1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail + 1)); }

# The compiler must run again; identical bytes are fine when a define is unused.
rebuilt() {
    if [ "$2" != "$3" ]; then pass "$1"; else bad "$1 (object was reused)"; fi
}

build "-O0" "" || { echo "  FAIL  baseline build"; exit 1; }
t0=$(stamp); h0=$(digest)
sleep 1

build "-O2 -DNDEBUG" "" || { echo "  FAIL  -O2 build"; exit 1; }
t1=$(stamp); h1=$(digest)
rebuilt "optimisation level change recompiles" "$t0" "$t1"
if [ "$h0" != "$h1" ]; then
    pass "the rebuilt object really used the new flags"
else
    bad "-O0 and -O2 produced the same object"
fi
sleep 1

build "-O2 -DNDEBUG -DQN_CONFIG_PROBE=1" "" || { echo "  FAIL  define build"; exit 1; }
t2=$(stamp)
rebuilt "preprocessor define change recompiles" "$t1" "$t2"
sleep 1

build "-O1 -g -fsanitize=address" "-fsanitize=address" || { echo "  FAIL  asan build"; exit 1; }
t3=$(stamp); h3=$(digest)
rebuilt "sanitizer change recompiles" "$t2" "$t3"
if nm "$OBJ" 2>/dev/null | grep -qi asan; then
    pass "the sanitized object contains ASan instrumentation"
else
    bad "the sanitized object has no ASan instrumentation"
fi
sleep 1

# The same configuration twice must not rebuild, or the stamp is a false trigger.
build "-O1 -g -fsanitize=address" "-fsanitize=address"
t4=$(stamp)
if [ "$t3" = "$t4" ]; then
    pass "an unchanged configuration does not rebuild"
else
    bad "an unchanged configuration rebuilt anyway"
fi

echo "build-config checks: $ok ok, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
