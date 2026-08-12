#include "qanat/util.h"
#include "qanat/verify.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_SAMPLES 101u
#define WARMUPS     3u

static uint64_t clock_ns(clockid_t id)
{
    struct timespec ts;

    if (clock_gettime(id, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y ? 1 : 0;
}

static uint64_t median(uint64_t *v, size_t n)
{
    qsort(v, n, sizeof *v, cmp_u64);
    return v[n / 2u];
}

static double mad_percent(const uint64_t *v, size_t n, uint64_t med)
{
    uint64_t deviation[MAX_SAMPLES];
    size_t   i;

    if (med == 0u)
        return 0.0;
    for (i = 0; i < n; i++)
        deviation[i] = v[i] > med ? v[i] - med : med - v[i];
    return (double)median(deviation, n) * 100.0 / (double)med;
}

static bool parse_uint(const char *s, unsigned min, unsigned max, unsigned *out)
{
    char         *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || !s[0] || *end || v < min || v > max)
        return false;
    *out = (unsigned)v;
    return true;
}

int main(int argc, char **argv)
{
    qn_verify_cfg cfg;
    qn_addr       addr;
    uint64_t      wall[MAX_SAMPLES], cpu[MAX_SAMPLES], handshake[MAX_SAMPLES];
    const char   *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned      port = 9443u, samples = 31u;
    unsigned      run;

    if ((argc > 2 && !parse_uint(argv[2], 1u, 65535u, &port)) ||
        (argc > 3 && !parse_uint(argv[3], 3u, MAX_SAMPLES, &samples)) || argc > 4 ||
        !qn_addr_parse(host, &addr)) {
        fprintf(stderr, "usage: %s [numeric-host] [port] [samples]\n", argv[0]);
        return 2;
    }

    qn_verify_defaults(&cfg);
    cfg.sni           = "bench.qanat.test";
    cfg.port          = (uint16_t)port;
    cfg.concurrency   = 1u;
    cfg.timeout_ms    = 2000u;
    cfg.idle_ms       = 0u;
    cfg.want_bytes    = 0u;
    cfg.allow_tls12   = false;
    cfg.deterministic = true;
    cfg.seed          = UINT64_C(0x514e544c5342454e);

    for (run = 0; run < WARMUPS + samples; run++) {
        qn_verify_result result;
        qn_verify_status status;
        uint64_t         wall0, cpu0, wall1, cpu1;

        memset(&result, 0, sizeof result);
        wall0 = clock_ns(CLOCK_MONOTONIC_RAW);
        cpu0  = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        status = qn_verify_run(&cfg, &addr, 1u, &result);
        cpu1  = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        wall1 = clock_ns(CLOCK_MONOTONIC_RAW);
        if (status.state != QN_VERIFY_COMPLETE || status.handshakes != 1u ||
            status.completed != 1u || !result.observation.completed ||
            result.observation.tls.handshake_us == 0u) {
            fprintf(stderr,
                    "session %u failed: state=%u completed=%u handshakes=%u verdict=%s "
                    "reason=%s errno=%d\n",
                    run, (unsigned)status.state, status.completed, status.handshakes,
                    qn_classification_str(result.classification),
                    result.observation.terminal.reason,
                    result.observation.terminal.sys_errno);
            return 1;
        }
        if (run >= WARMUPS) {
            size_t i = run - WARMUPS;

            wall[i]      = wall1 - wall0;
            cpu[i]       = cpu1 - cpu0;
            handshake[i] = (uint64_t)result.observation.tls.handshake_us * 1000u;
        }
    }

    {
        uint64_t med_wall = median(wall, samples);
        uint64_t med_cpu  = median(cpu, samples);
        uint64_t med_hs   = median(handshake, samples);
        double   var_wall = mad_percent(wall, samples, med_wall);
        double   var_cpu  = mad_percent(cpu, samples, med_cpu);
        double   var_hs   = mad_percent(handshake, samples, med_hs);

        printf("qanat TLS verifier benchmark\n");
        printf("  target=%s:%u samples=%u warmups=%u\n", host, port, samples, WARMUPS);
        printf("  handshake median=%" PRIu64 " ns %.1f handshakes/s mad=%.1f%%\n",
               med_hs, med_hs != 0u ? 1e9 / (double)med_hs : 0.0, var_hs);
        printf("  verifier session wall median=%" PRIu64 " ns mad=%.1f%%\n",
               med_wall, var_wall);
        printf("  verifier session thread-CPU median=%" PRIu64 " ns mad=%.1f%%\n",
               med_cpu, var_cpu);
    }
    return 0;
}
