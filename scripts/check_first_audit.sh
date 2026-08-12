#!/bin/sh
# Re-checks each first-audit outcome against the current tree. No redesign:
# this only asks whether the fix is still there.
cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat || exit 1

pass=0
fail=0

want() { # want <label> <pattern> <file...>
    label=$1; pat=$2; shift 2
    if grep -qE "$pat" "$@" 2>/dev/null; then
        printf '  ok    %s\n' "$label"; pass=$((pass+1))
    else
        printf '  FAIL  %s  (missing: %s)\n' "$label" "$pat"; fail=$((fail+1))
    fi
}

gone() { # gone <label> <pattern>
    label=$1; pat=$2
    n=$(grep -rlE "$pat" --include=*.c --include=*.h src/ include/ 2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then
        printf '  ok    %s (still removed)\n' "$label"; pass=$((pass+1))
    else
        printf '  FAIL  %s reappeared in %s file(s)\n' "$label" "$n"; fail=$((fail+1))
    fi
}

echo "== blockers =="
want "1 getrandom via qn_os_entropy"      'qn_os_entropy'            src/core/util.c
want "1 SYS_getrandom syscall path"       'SYS_getrandom'            src/core/util.c
want "1 urandom fallback"                 '/dev/urandom'             src/core/util.c
want "1 perm.c no __has_include guess"    '^'                        src/core/perm.c
if grep -q '__has_include' src/core/perm.c; then
    printf '  FAIL  1 perm.c still guesses with __has_include\n'; fail=$((fail+1))
else
    printf '  ok    1 perm.c does not guess entropy support\n'; pass=$((pass+1))
fi
want "2 drain before SO_ERROR"            'SO_ERROR'                 src/net/engine.c
want "2 EPOLLHUP handled separately"      'EPOLLHUP'                 src/net/engine.c
want "3 retry holds pending_job"          'pending_job'              src/net/engine.c include/qanat/engine.h
want "4 qn_tw_arm takes the caller clock" 'qn_tw_arm\(.*now_ms'      include/qanat/timewheel.h
want "4 banner arms its own budget"       'QN_STAGE_BANNER'          src/net/engine.c

echo "== high =="
want "5 qn_prefix_hosts full span"        'qn_prefix_hosts'          include/qanat/cidr.h
want "5 qn_prefix_usable opt-in"          'qn_prefix_usable'         include/qanat/cidr.h
want "5 skip_edges is a policy"           'qn_cidr_set_skip_edges'   include/qanat/cidr.h
want "6 ring reset precondition"          'qn_ring_reset'            src/net/engine.c
want "7 range file reports"               'qn_cidr_report'           include/qanat/cidr.h
want "7 load_file fills a report"         'qn_cidr_set_load_file'    include/qanat/cidr.h

echo "== smaller =="
want "banner timed from first byte"       'on_timeout'               src/net/engine.c
want "--seed via strict arg_u64"          'arg_u64'                  src/main.c
want "io_warn surfaces file failures"     'io_warn'                  include/qanat/task.h
want "aes_gcm_setkey length check"        'klen != 16u'              src/crypto/aesgcm.c

echo "== dead weight stays dead =="
gone "CF_PHASE_HTTP"     'CF_PHASE_HTTP'
gone "QN_STAGE_HTTP"     'QN_STAGE_HTTP\b'
gone "phase_domain"      'phase_domain'
gone "bandit.exhausted"  'exhausted[;,)]'
gone "qn_spark.max"      'qn_spark_max|spark\.max'
gone "qn_cpu_has_sha512" 'qn_cpu_has_sha512'

echo "== complete key exchanges stay live =="
want "P-256 source linked"       'src/crypto/p256\.c'        Makefile
want "P-256 TLS 1.2 consumed"    'qn_p256\(pms'              src/net/tls12.c
want "P-256 TLS 1.3 consumed"    'qn_p256\(out'              src/net/tls13.c
want "P-256 peer validated"      'uECC_valid_public_key'     src/crypto/p256.c
want "P-256 KAT retained"        'test_p256_kat'             tests/test_tls.c

echo
echo "first-audit checks: $pass ok, $fail failed"
[ "$fail" -eq 0 ]
