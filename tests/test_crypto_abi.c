#include "aead_impl.h"
#include "arm64/backend.h"
#include "qanat/crypto.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__)

int main(void)
{
    puts("crypto ABI tests: skipped (not AArch64)");
    return 0;
}

#else

typedef struct {
    uint64_t  x[11];
    uint64_t  d[8];
    uintptr_t sp_before;
    uintptr_t sp_after;
} qn_abi_snapshot;

typedef void (*abi_fn)(void);

void qn_test_abi_probe(abi_fn fn, const uint64_t args[8], qn_abi_snapshot *snapshot);
void qn_aes_ctr_ce(const uint32_t *rk, unsigned nr, uint8_t ctr[16], const uint8_t *in,
                   uint8_t *out, size_t len);
void qn_aes_encrypt_ce(const uint32_t *rk, unsigned nr, const uint8_t in[16], uint8_t out[16]);
void qn_aes_gcm_encrypt_ghash_ce(const uint32_t *rk, unsigned nr, const uint8_t hp[64],
                                 uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t len,
                                 uint8_t acc[16]);
void qn_ghash_ce(uint8_t acc[16], const uint8_t hp[64], const uint8_t *data, size_t blocks);
void qn_ghash_gcm_ce(uint8_t out[16], const uint8_t hp[64], const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t ctlen);
void qn_sha256_blocks_ce(uint32_t state[8], const uint8_t *data, size_t blocks);
void qn_chacha20_1x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len);
void qn_chacha20_4x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t groups);
void qn_poly1305_blocks_aarch64(qn_poly1305 *st, const uint8_t *m, size_t blocks,
                                 uint64_t full);

static const uint64_t x_pattern[10] = {
    UINT64_C(0x1919191919191919), UINT64_C(0x2020202020202020),
    UINT64_C(0x2121212121212121), UINT64_C(0x2222222222222222),
    UINT64_C(0x2323232323232323), UINT64_C(0x2424242424242424),
    UINT64_C(0x2525252525252525), UINT64_C(0x2626262626262626),
    UINT64_C(0x2727272727272727), UINT64_C(0x2828282828282828),
};

static const uint64_t d_pattern[8] = {
    UINT64_C(0xd8d8d8d8d8d8d8d8), UINT64_C(0xd9d9d9d9d9d9d9d9),
    UINT64_C(0xdadadadadadadada), UINT64_C(0xdbdbdbdbdbdbdbdb),
    UINT64_C(0xdcdcdcdcdcdcdcdc), UINT64_C(0xdddddddddddddddd),
    UINT64_C(0xdededededededede), UINT64_C(0xdfdfdfdfdfdfdfdf),
};

static int failures;

static void check_call(const char *name, abi_fn fn, const uint64_t args[8])
{
    qn_abi_snapshot got;
    unsigned        i;

    memset(&got, 0, sizeof got);
    qn_test_abi_probe(fn, args, &got);

    for (i = 0; i < 10; i++) {
        if (got.x[i] != x_pattern[i]) {
            fprintf(stderr, "FAIL %-28s x%u: got %016" PRIx64 " want %016" PRIx64 "\n",
                    name, i + 19u, got.x[i], x_pattern[i]);
            failures++;
        }
    }
    if (got.x[10] != got.sp_before) {
        fprintf(stderr, "FAIL %-28s x29: got %016" PRIx64 " want call SP %016" PRIxPTR
                        "\n",
                name, got.x[10], got.sp_before);
        failures++;
    }
    for (i = 0; i < 8; i++) {
        if (got.d[i] != d_pattern[i]) {
            fprintf(stderr, "FAIL %-28s d%u: got %016" PRIx64 " want %016" PRIx64 "\n",
                    name, i + 8u, got.d[i], d_pattern[i]);
            failures++;
        }
    }
    if ((got.sp_before & 15u) != 0u || got.sp_after != got.sp_before) {
        fprintf(stderr, "FAIL %-28s SP: before %016" PRIxPTR " after %016" PRIxPTR "\n",
                name, got.sp_before, got.sp_after);
        failures++;
    }
}

#define FN_CAST(fn) ((abi_fn)(fn))
#define PTR_ARG(p)  ((uint64_t)(uintptr_t)(p))

static void test_aes_abi(void)
{
    qn_aes_gcm g128, g256;
    uint8_t    key[32], ctr[16], in[80], out[80];
    uint64_t   args[8] = { 0 };
    static const size_t lengths[] = { 0u, 1u, 16u, 64u, 65u };
    unsigned            key_case;
    size_t              i;

    if (!qn_cpu_has_aes()) {
        puts("crypto ABI tests: AES CE skipped (feature unavailable)");
        return;
    }
    memset(key, 0x5a, sizeof key);
    if (!qn_aes_gcm_setkey(&g128, key, 16u) || !qn_aes_gcm_setkey(&g256, key, 32u)) {
        fputs("FAIL AES setup\n", stderr);
        failures++;
        return;
    }

    for (key_case = 0; key_case < 2u; key_case++) {
        qn_aes_gcm *g = key_case ? &g256 : &g128;
        char        name[64];

        for (i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
            memset(ctr, 0, sizeof ctr);
            memset(in, 0xa5, sizeof in);
            memset(out, 0, sizeof out);
            args[0] = PTR_ARG(g->rk);
            args[1] = g->nr;
            args[2] = PTR_ARG(ctr);
            args[3] = PTR_ARG(in);
            args[4] = PTR_ARG(out);
            args[5] = lengths[i];
            (void)snprintf(name, sizeof name, "aes-%u-ctr-len-%zu", key_case ? 256u : 128u,
                           lengths[i]);
            check_call(name, FN_CAST(qn_aes_ctr_ce), args);
        }

        if (qn_cpu_has_pmull()) {
            for (i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
                uint8_t acc[16] = { 0 };

                memset(ctr, 0, sizeof ctr);
                memset(in, 0xa5, sizeof in);
                memset(out, 0, sizeof out);
                args[0] = PTR_ARG(g->rk);
                args[1] = g->nr;
                args[2] = PTR_ARG(&g->hp[0][0]);
                args[3] = PTR_ARG(ctr);
                args[4] = PTR_ARG(in);
                args[5] = PTR_ARG(out);
                args[6] = lengths[i];
                args[7] = PTR_ARG(acc);
                (void)snprintf(name, sizeof name, "aes-%u-fused-len-%zu",
                               key_case ? 256u : 128u, lengths[i]);
                check_call(name, FN_CAST(qn_aes_gcm_encrypt_ghash_ce), args);
            }
        }

        args[0] = PTR_ARG(g->rk);
        args[1] = g->nr;
        args[2] = PTR_ARG(in + 1);
        args[3] = PTR_ARG(out + 1);
        (void)snprintf(name, sizeof name, "aes-%u-encrypt-block", key_case ? 256u : 128u);
        check_call(name, FN_CAST(qn_aes_encrypt_ce), args);
    }
}

static void test_ghash_abi(void)
{
    uint8_t  acc[16], hp[64], data[64];
    uint64_t args[8] = { 0 };
    size_t   blocks;
    char     name[48];

    if (!qn_cpu_has_pmull()) {
        puts("crypto ABI tests: GHASH CE skipped (feature unavailable)");
        return;
    }
    memset(hp, 0x66, sizeof hp);
    memset(data, 0x99, sizeof data);
    for (blocks = 0; blocks <= 4u; blocks = blocks ? 4u : 1u) {
        memset(acc, 0, sizeof acc);
        args[0] = PTR_ARG(acc);
        args[1] = PTR_ARG(hp);
        args[2] = PTR_ARG(data);
        args[3] = blocks;
        (void)snprintf(name, sizeof name, "ghash-blocks-%zu", blocks);
        check_call(name, FN_CAST(qn_ghash_ce), args);
        if (blocks == 4u)
            break;
    }

    for (blocks = 0; blocks <= 2u; blocks++) {
        static const size_t lengths[] = { 0u, 1u, 16u, 17u, 64u };
        size_t              i;

        for (i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
            size_t aadlen = blocks ? lengths[i] : 0u;
            size_t ctlen  = blocks == 2u ? lengths[i] : 0u;

            memset(acc, 0, sizeof acc);
            args[0] = PTR_ARG(acc);
            args[1] = PTR_ARG(hp);
            args[2] = PTR_ARG(data);
            args[3] = aadlen;
            args[4] = PTR_ARG(data);
            args[5] = ctlen;
            (void)snprintf(name, sizeof name, "ghash-gcm-a%zu-c%zu", aadlen, ctlen);
            check_call(name, FN_CAST(qn_ghash_gcm_ce), args);
        }
    }
}

static void test_sha256_abi(void)
{
    uint32_t state[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    uint8_t  data[256];
    uint64_t args[8] = { 0 };
    size_t   blocks;
    char     name[48];

    if (!qn_cpu_has_sha2()) {
        puts("crypto ABI tests: SHA-256 CE skipped (feature unavailable)");
        return;
    }
    memset(data, 0x3c, sizeof data);
    for (blocks = 0; blocks <= 4u; blocks = blocks ? 4u : 1u) {
        args[0] = PTR_ARG(state);
        args[1] = PTR_ARG(data);
        args[2] = blocks;
        (void)snprintf(name, sizeof name, "sha256-blocks-%zu", blocks);
        check_call(name, FN_CAST(qn_sha256_blocks_ce), args);
        if (blocks == 4u)
            break;
    }
}

static void test_chacha_abi(void)
{
    uint8_t  key[32], nonce[12], in[512], out[512];
    uint64_t args[8] = { 0 };
    size_t   groups;
    char     name[48];

    if (!qn_cpu_has_neon()) {
        puts("crypto ABI tests: ChaCha NEON skipped (feature unavailable)");
        return;
    }
    memset(key, 0x17, sizeof key);
    memset(nonce, 0x42, sizeof nonce);
    memset(in, 0xa6, sizeof in);
    memset(out, 0, sizeof out);
    for (groups = 0; groups < 6u; groups++) {
        static const size_t lengths[] = { 0u, 1u, 63u, 64u, 65u, 257u };

        args[0] = PTR_ARG(key);
        args[1] = UINT32_C(0xfffffff7);
        args[2] = PTR_ARG(nonce);
        args[3] = PTR_ARG(in);
        args[4] = PTR_ARG(out);
        args[5] = lengths[groups];
        (void)snprintf(name, sizeof name, "chacha20-1x-len-%zu", lengths[groups]);
        check_call(name, FN_CAST(qn_chacha20_1x_neon), args);
    }
    for (groups = 0; groups <= 2u; groups++) {
        args[0] = PTR_ARG(key);
        args[1] = UINT32_C(0xfffffff7);
        args[2] = PTR_ARG(nonce);
        args[3] = PTR_ARG(in);
        args[4] = PTR_ARG(out);
        args[5] = groups;
        (void)snprintf(name, sizeof name, "chacha20-4x-groups-%zu", groups);
        check_call(name, FN_CAST(qn_chacha20_4x_neon), args);
    }
}

static void test_poly1305_abi(void)
{
    qn_poly1305 st;
    uint8_t key[32], data[64];
    uint64_t args[8] = { 0 };
    size_t blocks;
    char name[48];

    if (!qn_crypto_backend_available(QN_BACKEND_POLY1305_ASM)) {
        puts("crypto ABI tests: Poly1305 skipped (backend unavailable)");
        return;
    }
    memset(key, 0x51, sizeof key);
    memset(data, 0xa9, sizeof data);
    for (blocks = 0; blocks <= 4u; blocks = blocks ? 4u : 1u) {
        qn_poly1305_init(&st, key);
        args[0] = PTR_ARG(&st);
        args[1] = PTR_ARG(data);
        args[2] = blocks;
        args[3] = 1u;
        (void)snprintf(name, sizeof name, "poly1305-blocks-%zu", blocks);
        check_call(name, FN_CAST(qn_poly1305_blocks_aarch64), args);
        if (blocks == 4u)
            break;
    }
}

int main(void)
{
    test_aes_abi();
    test_ghash_abi();
    test_sha256_abi();
    test_chacha_abi();
    test_poly1305_abi();

    if (failures) {
        fprintf(stderr, "crypto ABI tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("crypto ABI tests: ok");
    return 0;
}

#endif /* __aarch64__ */
