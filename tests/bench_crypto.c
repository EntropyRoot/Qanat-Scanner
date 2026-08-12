/* Reproducible short-record and throughput benchmarks for Qanat crypto. */

#include "aead_impl.h"
#include "qanat/crypto.h"

#if !defined(QN_BENCH_BASELINE)
#include "arm64/backend.h"
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LEN       (UINT32_C(1) << 20)
#define SAMPLE_COUNT  7u
#define TARGET_NS     UINT64_C(25000000)
#define MAX_ITER      (UINT64_C(1) << 30)

static const size_t bench_lengths[] = { 64u, 128u, 256u, 1024u, 4096u, 16384u, 1048576u };

static volatile uint8_t benchmark_sink;

#if defined(__GNUC__) || defined(__clang__)
extern bool        qn_cpu_has_pmull(void) __attribute__((weak));
extern const char *qn_crypto_backend_control_error(void) __attribute__((weak));
extern void        qn_chacha20_xor_c(const uint8_t key[32], uint32_t counter,
                                     const uint8_t nonce[12], const uint8_t *in,
                                     uint8_t *out, size_t len) __attribute__((weak));
#endif

#if defined(__aarch64__)
void qn_aes_ctr_ce(const uint32_t *rk, unsigned nr, uint8_t ctr[16], const uint8_t *in,
                   uint8_t *out, size_t len);
void qn_aes_encrypt_ce(const uint32_t *rk, unsigned nr, const uint8_t in[16], uint8_t out[16]);
void qn_ghash_ce(uint8_t acc[16], const uint8_t hp[64], const uint8_t *data, size_t blocks);
void qn_chacha20_4x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t groups);
#if defined(__GNUC__) || defined(__clang__)
void qn_chacha20_1x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len) __attribute__((weak));
void qn_ghash_gcm_ce(uint8_t out[16], const uint8_t hp[64], const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t ctlen) __attribute__((weak));
#endif
#endif

typedef void (*bench_call)(void *opaque);

typedef struct {
    uint64_t iterations;
    uint64_t median_ns;
    uint64_t min_ns;
    uint64_t max_ns;
} bench_result;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t timed_calls(bench_call call, void *opaque, uint64_t iterations)
{
    uint64_t start = now_ns();
    uint64_t i;

    for (i = 0; i < iterations; i++)
        call(opaque);
    return now_ns() - start;
}

static void sort_u64(uint64_t *v, unsigned n)
{
    unsigned i;

    for (i = 1; i < n; i++) {
        uint64_t x = v[i];
        unsigned j = i;

        while (j && v[j - 1u] > x) {
            v[j] = v[j - 1u];
            j--;
        }
        v[j] = x;
    }
}

static bench_result measure(bench_call call, void *opaque)
{
    uint64_t samples[SAMPLE_COUNT];
    uint64_t iterations = 1u;
    uint64_t elapsed;
    unsigned i;
    bench_result result;

    call(opaque);
    for (;;) {
        elapsed = timed_calls(call, opaque, iterations);
        if (elapsed >= TARGET_NS / 4u || iterations >= MAX_ITER)
            break;
        if (!elapsed)
            iterations *= 16u;
        else {
            uint64_t scale = (TARGET_NS / 2u) / elapsed;
            if (scale < 2u)
                scale = 2u;
            if (scale > 16u)
                scale = 16u;
            if (iterations > MAX_ITER / scale)
                iterations = MAX_ITER;
            else
                iterations *= scale;
        }
    }
    if (elapsed < TARGET_NS && iterations < MAX_ITER) {
        uint64_t scale = TARGET_NS / (elapsed ? elapsed : 1u);
        if (scale < 1u)
            scale = 1u;
        if (scale > 8u)
            scale = 8u;
        if (iterations <= MAX_ITER / scale)
            iterations *= scale;
    }

    for (i = 0; i < SAMPLE_COUNT; i++)
        samples[i] = timed_calls(call, opaque, iterations);
    sort_u64(samples, SAMPLE_COUNT);
    result.iterations = iterations;
    result.min_ns      = samples[0];
    result.median_ns   = samples[SAMPLE_COUNT / 2u];
    result.max_ns      = samples[SAMPLE_COUNT - 1u];
    return result;
}

static void report(const char *name, size_t len, bench_result r)
{
    double ns_op = (double)r.median_ns / (double)r.iterations;
    double min_op = (double)r.min_ns / (double)r.iterations;
    double max_op = (double)r.max_ns / (double)r.iterations;
    double variation = ns_op != 0.0 ? (max_op - min_op) * 100.0 / ns_op : 0.0;
    double mib_s = ns_op != 0.0
                       ? ((double)len / 1048576.0) / (ns_op / 1e9)
                       : 0.0;

    if (len < 4096u)
        printf("  %-26s %7zu B  %10.1f ns/op  var %5.1f%%\n", name, len, ns_op,
               variation);
    else
        printf("  %-26s %7zu B  %9.1f MiB/s  %10.1f ns/op  var %5.1f%%\n", name,
               len, mib_s, ns_op, variation);
}

typedef struct {
    qn_aead aead;
    uint8_t iv[QN_AEAD_IV_LEN];
    uint8_t aad[13];
    uint8_t *input;
    uint8_t *output;
    size_t len;
} aead_bench;

static void call_aead_seal(void *opaque)
{
    aead_bench *b = (aead_bench *)opaque;
    if (!qn_aead_seal(&b->aead, b->iv, b->aad, sizeof b->aad, b->input, b->len, b->output))
        abort();
    benchmark_sink ^= b->output[b->len];
}

static void call_aead_open(void *opaque)
{
    aead_bench *b = (aead_bench *)opaque;
    if (!qn_aead_open(&b->aead, b->iv, b->aad, sizeof b->aad, b->input,
                      b->len + QN_AEAD_TAG_LEN, b->output))
        abort();
    if (b->len)
        benchmark_sink ^= b->output[b->len - 1u];
}

static void bench_aead_pair(qn_aead_id id, const char *seal_name, const char *open_name,
                            size_t len, uint8_t *plain, uint8_t *sealed, uint8_t *opened)
{
    uint8_t    key[QN_AEAD_KEY_MAX];
    aead_bench b;

    memset(key, 0x2b, sizeof key);
    memset(&b, 0, sizeof b);
    memset(b.iv, 0x7c, sizeof b.iv);
    memset(b.aad, 0x11, sizeof b.aad);
    b.len = len;
    if (!qn_aead_init(&b.aead, id, key)) {
        printf("  %-26s unavailable\n", seal_name);
        return;
    }

    b.input  = plain;
    b.output = sealed;
    report(seal_name, len, measure(call_aead_seal, &b));

    if (!qn_aead_seal(&b.aead, b.iv, b.aad, sizeof b.aad, plain, len, sealed))
        abort();
    b.input  = sealed;
    b.output = opened;
    report(open_name, len, measure(call_aead_open, &b));
}

typedef struct {
    qn_hash_id id;
    uint8_t   *input;
    size_t     len;
    uint8_t    output[QN_HASH_MAX];
} hash_bench;

static void call_hash(void *opaque)
{
    hash_bench *b = (hash_bench *)opaque;
    qn_hash h;
    qn_hash_init(&h, b->id);
    qn_hash_update(&h, b->input, b->len);
    qn_hash_final(&h, b->output);
    benchmark_sink ^= b->output[0];
}

typedef struct {
    uint8_t *input;
    size_t len;
    uint8_t output[QN_SHA512_LEN];
} sha512_bench;

static void call_sha512(void *opaque)
{
    sha512_bench *b = (sha512_bench *)opaque;
    qn_sha512 h;
    qn_sha512_init(&h, QN_SHA512_LEN);
    qn_sha512_update(&h, b->input, b->len);
    qn_sha512_final(&h, b->output);
    benchmark_sink ^= b->output[0];
}

typedef struct {
    uint8_t key[32];
    uint8_t *input;
    size_t len;
    uint8_t tag[16];
} poly_bench;

static void call_poly1305(void *opaque)
{
    poly_bench *b = (poly_bench *)opaque;
    qn_poly1305 st;
    qn_poly1305_init(&st, b->key);
    qn_poly1305_update(&st, b->input, b->len);
    qn_poly1305_final(&st, b->tag);
    benchmark_sink ^= b->tag[0];
}

typedef struct {
    uint8_t sk[32];
    uint8_t point[32];
    uint8_t out[32];
} x25519_bench;

static void call_x25519(void *opaque)
{
    x25519_bench *b = (x25519_bench *)opaque;
    if (!qn_x25519(b->out, b->sk, b->point))
        abort();
    benchmark_sink ^= b->out[0];
}

#if defined(__aarch64__)
typedef struct {
    qn_aes_gcm gcm;
    uint8_t ctr[16];
    uint8_t *input;
    uint8_t *output;
    size_t len;
} aes_ctr_bench;

static void call_aes_ctr(void *opaque)
{
    aes_ctr_bench *b = (aes_ctr_bench *)opaque;
    uint8_t ctr[16];
    memcpy(ctr, b->ctr, sizeof ctr);
    qn_aes_ctr_ce(b->gcm.rk, b->gcm.nr, ctr, b->input, b->output, b->len);
    benchmark_sink ^= b->output[0];
}

static void call_aes_block(void *opaque)
{
    aes_ctr_bench *b = (aes_ctr_bench *)opaque;
    qn_aes_encrypt_ce(b->gcm.rk, b->gcm.nr, b->input, b->output);
    benchmark_sink ^= b->output[0];
}

typedef struct {
    qn_aes_gcm gcm;
    uint8_t acc[16];
    uint8_t *input;
    size_t len;
} ghash_bench;

#if defined(QN_BENCH_BASELINE)
#define GCM_HP(g) ((g).h)
#else
#define GCM_HP(g) (&(g).hp[0][0])
#endif

static void call_ghash(void *opaque)
{
    ghash_bench *b = (ghash_bench *)opaque;
    qn_ghash_ce(b->acc, GCM_HP(b->gcm), b->input, b->len / 16u);
    benchmark_sink ^= b->acc[0];
}

static void call_ghash_gcm(void *opaque)
{
    ghash_bench *b = (ghash_bench *)opaque;
    qn_ghash_gcm_ce(b->acc, GCM_HP(b->gcm), b->input, 13u, b->input, b->len);
    benchmark_sink ^= b->acc[0];
}

typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t *input;
    uint8_t *output;
    size_t len;
} chacha_bench;

static void call_chacha_1x(void *opaque)
{
    chacha_bench *b = (chacha_bench *)opaque;
    qn_chacha20_1x_neon(b->key, 1u, b->nonce, b->input, b->output, b->len);
    benchmark_sink ^= b->output[0];
}

static void call_chacha_4x(void *opaque)
{
    chacha_bench *b = (chacha_bench *)opaque;
    qn_chacha20_4x_neon(b->key, 1u, b->nonce, b->input, b->output, b->len / 256u);
    benchmark_sink ^= b->output[0];
}

#if defined(QN_BENCH_TEST_HOOKS)
static void call_chacha_scalar(void *opaque)
{
    chacha_bench *b = (chacha_bench *)opaque;
    qn_chacha20_xor_c(b->key, 1u, b->nonce, b->input, b->output, b->len);
    benchmark_sink ^= b->output[0];
}
#endif
#endif

static void bench_hashes(size_t len, uint8_t *input)
{
    hash_bench h;
    sha512_bench h512;

    memset(&h, 0, sizeof h);
    h.input = input;
    h.len   = len;
    h.id    = QN_HASH_SHA256;
    report("sha-256", len, measure(call_hash, &h));
    h.id = QN_HASH_SHA384;
    report("sha-384", len, measure(call_hash, &h));

    memset(&h512, 0, sizeof h512);
    h512.input = input;
    h512.len   = len;
    report("sha-512", len, measure(call_sha512, &h512));
}

static void bench_poly(size_t len, uint8_t *input)
{
    poly_bench p;
    memset(&p, 0x31, sizeof p);
    p.input = input;
    p.len   = len;
    report("poly1305", len, measure(call_poly1305, &p));
}

#if defined(__aarch64__)
static void bench_arm64_raw(size_t len, uint8_t *input, uint8_t *output)
{
    uint8_t       key[32];
    aes_ctr_bench aes;
    ghash_bench   gh;
    chacha_bench  ch;

    memset(key, 0x2b, sizeof key);
    memset(&aes, 0, sizeof aes);
    aes.input  = input;
    aes.output = output;
    aes.len    = len;
    aes.ctr[15] = 2u;
    if (qn_cpu_has_aes() && qn_aes_gcm_setkey(&aes.gcm, key, 16u)) {
        report("aes-128-ctr-ce", len, measure(call_aes_ctr, &aes));
        if (len == 64u)
            report("aes-128-block-ce", 16u, measure(call_aes_block, &aes));
    }

    memset(&gh, 0, sizeof gh);
    gh.input = input;
    gh.len   = len;
    if (qn_aes_gcm_setkey(&gh.gcm, key, 16u) &&
        (qn_cpu_has_pmull ? qn_cpu_has_pmull() : qn_cpu_has_aes())) {
        report("ghash-pmull", len, measure(call_ghash, &gh));
        if (qn_ghash_gcm_ce)
            report("ghash-gcm-coarse", len, measure(call_ghash_gcm, &gh));
    }

    memset(&ch, 0x19, sizeof ch);
    ch.input  = input;
    ch.output = output;
    ch.len    = len;
    if (qn_cpu_has_neon() && qn_chacha20_1x_neon)
        report("chacha20-1x-neon", len, measure(call_chacha_1x, &ch));
    if (qn_cpu_has_neon() && (len % 256u) == 0u)
        report("chacha20-4x-neon", len, measure(call_chacha_4x, &ch));
#if defined(QN_BENCH_TEST_HOOKS)
    if (qn_chacha20_xor_c)
        report("chacha20-scalar", len, measure(call_chacha_scalar, &ch));
#endif
}
#endif

static void bench_x25519_once(void)
{
    x25519_bench x;
    bench_result r;
    double ns_op;
    double ops;

    memset(&x, 0, sizeof x);
    memset(x.sk, 0x42, sizeof x.sk);
    x.point[0] = 9u;
    r     = measure(call_x25519, &x);
    ns_op = (double)r.median_ns / (double)r.iterations;
    ops   = ns_op != 0.0 ? 1e9 / ns_op : 0.0;
    printf("  %-26s %10.1f ns/op  %10.0f op/s  var %5.1f%%\n", "x25519", ns_op,
           ops, ns_op != 0.0
                    ? ((double)(r.max_ns - r.min_ns) / (double)r.iterations) *
                          100.0 / ns_op
                    : 0.0);
}

int main(int argc, char **argv)
{
    uint8_t *plain  = (uint8_t *)malloc(MAX_LEN + QN_AEAD_TAG_LEN);
    uint8_t *sealed = (uint8_t *)malloc(MAX_LEN + QN_AEAD_TAG_LEN);
    uint8_t *opened = (uint8_t *)malloc(MAX_LEN + QN_AEAD_TAG_LEN);
    const char *only = getenv("QN_BENCH_ONLY");
    bool all = !only || !*only;
#if defined(QN_BENCH_BASELINE)
    const char *fused_state = "n/a", *poly_state = "n/a";
#else
    const char *fused_state = qn_crypto_backend_enabled(QN_BACKEND_AES_GCM_FUSED)
                                  ? "on"
                                  : "off";
    const char *poly_state = qn_crypto_backend_enabled(QN_BACKEND_POLY1305_ASM)
                                 ? "on"
                                 : "off";
#endif
    size_t i;

    if (!plain || !sealed || !opened)
        return 1;
    if (!all && strcmp(only, "aead") != 0 && strcmp(only, "raw") != 0 &&
        strcmp(only, "poly1305") != 0 && strcmp(only, "hashes") != 0 &&
        strcmp(only, "x25519") != 0) {
        fprintf(stderr, "QN_BENCH_ONLY must be aead, raw, poly1305, hashes, or x25519\n");
        free(plain);
        free(sealed);
        free(opened);
        return 2;
    }
#if defined(__GNUC__) || defined(__clang__)
    if (qn_crypto_backend_control_error) {
        const char *error = qn_crypto_backend_control_error();
        if (error) {
            fprintf(stderr, "crypto backend control error: %s\n", error);
            free(plain);
            free(sealed);
            free(opened);
            return 2;
        }
    }
#endif
    for (i = 0; i < MAX_LEN + QN_AEAD_TAG_LEN; i++)
        plain[i] = (uint8_t)(i * 131u + 17u);

    printf("qanat crypto benchmark v2\n");
    printf("  dispatch: aes-ce=%s pmull=%s fused=%s sha256-ce=%s "
           "chacha-neon=%s poly1305-asm=%s\n",
           qn_cpu_has_aes() ? "on" : "off",
           (qn_cpu_has_pmull ? qn_cpu_has_pmull() : qn_cpu_has_aes()) ? "on" : "off",
           fused_state,
           qn_cpu_has_sha2() ? "on" : "off", qn_cpu_has_neon() ? "on" : "off",
           poly_state);
    if (argc == 2 && strcmp(argv[1], "--dispatch-only") == 0) {
        free(plain);
        free(sealed);
        free(opened);
        return 0;
    }
    printf("  samples=%u target=%" PRIu64 "ns per sample\n", SAMPLE_COUNT, TARGET_NS);

    for (i = 0; i < sizeof bench_lengths / sizeof bench_lengths[0]; i++) {
        size_t len = bench_lengths[i];

        printf("\n[length %zu]\n", len);
        if (all || strcmp(only, "aead") == 0) {
            bench_aead_pair(QN_AEAD_AES128GCM, "aes-128-gcm-seal", "aes-128-gcm-open",
                            len, plain, sealed, opened);
            bench_aead_pair(QN_AEAD_AES256GCM, "aes-256-gcm-seal", "aes-256-gcm-open",
                            len, plain, sealed, opened);
            bench_aead_pair(QN_AEAD_CHACHA20POLY1305, "chacha20-poly1305-seal",
                            "chacha20-poly1305-open", len, plain, sealed, opened);
        }
#if defined(__aarch64__)
        if (all || strcmp(only, "raw") == 0)
            bench_arm64_raw(len, plain, opened);
#endif
        if (all || strcmp(only, "poly1305") == 0)
            bench_poly(len, plain);
        if (all || strcmp(only, "hashes") == 0)
            bench_hashes(len, plain);
    }
    if (all || strcmp(only, "x25519") == 0) {
        printf("\n[operation]\n");
        bench_x25519_once();
    }
    printf("  sink=%u\n", (unsigned)benchmark_sink);

    free(plain);
    free(sealed);
    free(opened);
    return 0;
}
