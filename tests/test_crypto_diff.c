#include "aead_impl.h"
#include "arm64/backend.h"
#include "qanat/crypto.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__)
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
#endif

#define MAX_TEST_LEN (UINT32_C(1) << 20)
#define GUARD_BYTE   UINT8_C(0xa7)

static const size_t lengths[] = { 0u,   1u,   15u,  16u,  17u,   31u,   32u,
                                  33u,  63u,  64u,  65u,  127u,  128u,  129u,
                                  255u, 256u, 257u, 1024u, 4096u, 16384u, 1048576u };

static int      failures;
static uint64_t random_state = UINT64_C(0x6a09e667f3bcc909);

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static uint64_t random64(void)
{
    uint64_t x = random_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    random_state = x;
    return x;
}

static void random_bytes(uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (uint8_t)random64();
}

static void set_counter(uint8_t ctr[16], uint32_t value)
{
    random_bytes(ctr, 12u);
    ctr[12] = (uint8_t)(value >> 24);
    ctr[13] = (uint8_t)(value >> 16);
    ctr[14] = (uint8_t)(value >> 8);
    ctr[15] = (uint8_t)value;
}

static void guarded_reset(uint8_t *base, size_t cap)
{
    memset(base, GUARD_BYTE, cap);
}

static bool guards_ok(const uint8_t *base, size_t offset, size_t len, size_t cap)
{
    size_t i;
    size_t end = offset + len;

    for (i = 0; i < offset; i++)
        if (base[i] != GUARD_BYTE)
            return false;
    for (i = end; i < end + 16u && i < cap; i++)
        if (base[i] != GUARD_BYTE)
            return false;
    return true;
}

static bool equal_bytes(const char *what, size_t len, unsigned src_off, unsigned dst_off,
                        const uint8_t *got, const uint8_t *want)
{
    if (memcmp(got, want, len) == 0)
        return true;
    fprintf(stderr, "FAIL %-18s len=%zu src+%u dst+%u\n", what, len, src_off, dst_off);
    failures++;
    return false;
}

static void test_aes_key_policy(void)
{
    qn_aes_gcm g;
    uint8_t    key[40];

    random_bytes(key, sizeof key);
    CHECK(qn_aes_gcm_setkey(&g, key + 1, 16u));
    CHECK(!qn_aes_gcm_setkey(&g, key + 1, 24u));
    CHECK(qn_aes_gcm_setkey(&g, key + 1, 32u));
    CHECK(!qn_aes_gcm_setkey(&g, key + 1, 0u));
    CHECK(!qn_aes_gcm_setkey(&g, key + 1, 31u));
}

#if defined(__aarch64__)
static void test_aes_block(void)
{
    uint8_t    keybuf[48], inbuf[48], outbuf[48], inplace[48], want[16];
    qn_aes_gcm g;
    size_t     klen;
    unsigned   key_off, src_off, dst_off;

    if (!qn_crypto_backend_enabled(QN_BACKEND_AES_CE)) {
        puts("crypto differential: AES CE skipped");
        return;
    }
    random_bytes(keybuf, sizeof keybuf);
    random_bytes(inbuf, sizeof inbuf);
    for (klen = 16u; klen <= 32u; klen += 16u) {
        for (key_off = 0; key_off < 16u; key_off++) {
            CHECK(qn_aes_gcm_setkey(&g, keybuf + key_off, klen));
            for (src_off = 0; src_off < 16u; src_off++) {
                qn_aes_encrypt_block_c(&g, inbuf + src_off, want);
                for (dst_off = 0; dst_off < 16u; dst_off++) {
                    memset(outbuf, GUARD_BYTE, sizeof outbuf);
                    qn_aes_encrypt_ce(g.rk, g.nr, inbuf + src_off, outbuf + dst_off);
                    (void)equal_bytes("aes-block", 16u, src_off, dst_off, outbuf + dst_off,
                                      want);
                }
                memcpy(inplace + src_off, inbuf + src_off, 16u);
                qn_aes_encrypt_ce(g.rk, g.nr, inplace + src_off, inplace + src_off);
                (void)equal_bytes("aes-block-inplace", 16u, src_off, src_off,
                                  inplace + src_off, want);
            }
        }
    }
}

static void test_aes_ctr(void)
{
    const size_t cap = MAX_TEST_LEN + 64u;
    uint8_t     *src_base = (uint8_t *)malloc(cap);
    uint8_t     *dst_base = (uint8_t *)malloc(cap);
    uint8_t     *inplace  = (uint8_t *)malloc(cap);
    uint8_t     *want     = (uint8_t *)malloc(MAX_TEST_LEN + 16u);
    uint8_t      key[32], ctr0[16], ctr_ref[16], ctr_got[16];
    qn_aes_gcm   g;
    size_t       klen, li;
    unsigned     src_off, dst_off;

    CHECK(src_base && dst_base && inplace && want);
    if (!src_base || !dst_base || !inplace || !want)
        goto done;
    if (!qn_crypto_backend_enabled(QN_BACKEND_AES_CE))
        goto done;
    random_bytes(src_base, cap);
    random_bytes(key, sizeof key);
    for (klen = 16u; klen <= 32u; klen += 16u) {
        CHECK(qn_aes_gcm_setkey(&g, key, klen));
        for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
            size_t len = lengths[li];

            for (src_off = 0; src_off < 16u; src_off++) {
                set_counter(ctr0, UINT32_C(0x10203040));
                memcpy(ctr_ref, ctr0, 16u);
                qn_aes_ctr_c(&g, ctr_ref, src_base + src_off, want, len);
                for (dst_off = 0; dst_off < 16u; dst_off++) {
                    size_t out_off = 16u + dst_off;

                    guarded_reset(dst_base, cap);
                    memcpy(ctr_got, ctr0, 16u);
                    qn_aes_ctr_ce(g.rk, g.nr, ctr_got, src_base + src_off,
                                  dst_base + out_off, len);
                    (void)equal_bytes("aes-ctr", len, src_off, dst_off,
                                      dst_base + out_off, want);
                    CHECK(memcmp(ctr_got, ctr_ref, 16u) == 0);
                    CHECK(guards_ok(dst_base, out_off, len, cap));
                }

                guarded_reset(inplace, cap);
                memcpy(inplace + 16u + src_off, src_base + src_off, len);
                memcpy(ctr_got, ctr0, 16u);
                qn_aes_ctr_ce(g.rk, g.nr, ctr_got, inplace + 16u + src_off,
                              inplace + 16u + src_off, len);
                (void)equal_bytes("aes-ctr-inplace", len, src_off, src_off,
                                  inplace + 16u + src_off, want);
                CHECK(guards_ok(inplace, 16u + src_off, len, cap));
            }
        }
    }

done:
    free(src_base);
    free(dst_base);
    free(inplace);
    free(want);
}

static void ghash_cipher_c(const qn_aes_gcm *g, uint8_t acc[16], const uint8_t *ct, size_t len)
{
    size_t blocks = len / 16u;

    if (blocks)
        qn_ghash_blocks_c(g, acc, ct, blocks);
    if ((len & 15u) != 0u) {
        uint8_t last[16] = { 0 };

        memcpy(last, ct + blocks * 16u, len & 15u);
        qn_ghash_blocks_c(g, acc, last, 1u);
    }
}

static void test_aes_gcm_fused(void)
{
    const size_t cap = MAX_TEST_LEN + 64u;
    uint8_t     *src_base = (uint8_t *)malloc(cap);
    uint8_t     *dst_base = (uint8_t *)malloc(cap);
    uint8_t     *inplace  = (uint8_t *)malloc(cap);
    uint8_t     *want     = (uint8_t *)malloc(MAX_TEST_LEN + 16u);
    uint8_t      key[32], ctr0[16], ctr_ref[16], ctr_got[16];
    uint8_t      initial[16], acc_ref[16], acc_got[16];
    qn_aes_gcm   g;
    size_t       klen, li;
    unsigned     src_off, dst_off;

    CHECK(src_base && dst_base && inplace && want);
    if (!src_base || !dst_base || !inplace || !want)
        goto done;
    if (!qn_crypto_backend_available(QN_BACKEND_AES_GCM_FUSED))
        goto done;
    random_bytes(src_base, cap);
    random_bytes(key, sizeof key);
    for (klen = 16u; klen <= 32u; klen += 16u) {
        CHECK(qn_aes_gcm_setkey(&g, key, klen));
        for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
            size_t len = lengths[li];

            for (src_off = 0; src_off < 16u; src_off++) {
                set_counter(ctr0, UINT32_C(0x10203040));
                random_bytes(initial, sizeof initial);
                memcpy(ctr_ref, ctr0, sizeof ctr_ref);
                memcpy(acc_ref, initial, sizeof acc_ref);
                qn_aes_ctr_c(&g, ctr_ref, src_base + src_off, want, len);
                ghash_cipher_c(&g, acc_ref, want, len);
                for (dst_off = 0; dst_off < 16u; dst_off++) {
                    size_t out_off = 16u + dst_off;

                    guarded_reset(dst_base, cap);
                    memcpy(ctr_got, ctr0, sizeof ctr_got);
                    memcpy(acc_got, initial, sizeof acc_got);
                    qn_aes_gcm_encrypt_ghash_ce(g.rk, g.nr, &g.hp[0][0], ctr_got,
                                                src_base + src_off, dst_base + out_off, len,
                                                acc_got);
                    (void)equal_bytes("aes-gcm-fused", len, src_off, dst_off,
                                      dst_base + out_off, want);
                    CHECK(memcmp(ctr_got, ctr_ref, sizeof ctr_got) == 0);
                    CHECK(memcmp(acc_got, acc_ref, sizeof acc_got) == 0);
                    CHECK(guards_ok(dst_base, out_off, len, cap));
                }

                guarded_reset(inplace, cap);
                memcpy(inplace + 16u + src_off, src_base + src_off, len);
                memcpy(ctr_got, ctr0, sizeof ctr_got);
                memcpy(acc_got, initial, sizeof acc_got);
                qn_aes_gcm_encrypt_ghash_ce(g.rk, g.nr, &g.hp[0][0], ctr_got,
                                            inplace + 16u + src_off,
                                            inplace + 16u + src_off, len, acc_got);
                (void)equal_bytes("aes-gcm-fused-inplace", len, src_off, src_off,
                                  inplace + 16u + src_off, want);
                CHECK(memcmp(ctr_got, ctr_ref, sizeof ctr_got) == 0);
                CHECK(memcmp(acc_got, acc_ref, sizeof acc_got) == 0);
                CHECK(guards_ok(inplace, 16u + src_off, len, cap));
            }
        }
    }

done:
    free(src_base);
    free(dst_base);
    free(inplace);
    free(want);
}

static void test_ghash(void)
{
    const size_t cap = MAX_TEST_LEN + 64u;
    uint8_t     *data = (uint8_t *)malloc(cap);
    uint8_t     *out  = (uint8_t *)malloc(64u);
    uint8_t      key[16], want[16], initial[16];
    qn_aes_gcm   g;
    size_t       li;
    unsigned     src_off, dst_off;

    CHECK(data && out);
    if (!data || !out)
        goto done;
    if (!qn_crypto_backend_enabled(QN_BACKEND_GHASH_CE))
        goto done;
    random_bytes(data, cap);
    random_bytes(key, sizeof key);
    random_bytes(initial, sizeof initial);
    CHECK(qn_aes_gcm_setkey(&g, key, sizeof key));

    for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t blocks = lengths[li] / 16u;
        size_t bytes  = blocks * 16u;

        for (src_off = 0; src_off < 16u; src_off++) {
            memcpy(want, initial, sizeof want);
            qn_ghash_blocks_c(&g, want, data + src_off, blocks);
            for (dst_off = 0; dst_off < 16u; dst_off++) {
                memset(out, GUARD_BYTE, 64u);
                memcpy(out + dst_off, initial, sizeof initial);
                qn_ghash_ce(out + dst_off, &g.hp[0][0], data + src_off, blocks);
                (void)equal_bytes("ghash-blocks", sizeof want, src_off, dst_off,
                                  out + dst_off, want);
                CHECK(guards_ok(out, dst_off, 16u, 64u));
            }
        }

        /* Cover all alignments without multiplying scalar work by 256. */
        for (src_off = 0; src_off < 16u; src_off++) {
            size_t aadlen = lengths[li];
            size_t ctlen  = lengths[(li * 7u + 3u) % (sizeof lengths / sizeof lengths[0])];
            unsigned ct_off = (src_off * 5u + 1u) & 15u;

            qn_ghash_gcm_c(&g, want, data + src_off, aadlen, data + ct_off, ctlen);
            for (dst_off = 0; dst_off < 16u; dst_off++) {
                memset(out, GUARD_BYTE, 64u);
                qn_ghash_gcm_ce(out + dst_off, &g.hp[0][0], data + src_off, aadlen,
                                data + ct_off, ctlen);
                (void)equal_bytes("ghash-gcm", 16u, src_off, dst_off,
                                  out + dst_off, want);
                CHECK(guards_ok(out, dst_off, 16u, 64u));
            }
        }
        (void)bytes;
    }

done:
    free(data);
    free(out);
}

static void test_sha256_blocks(void)
{
    const size_t cap = MAX_TEST_LEN + 64u;
    uint8_t     *data = (uint8_t *)malloc(cap);
    static const uint32_t iv[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                     0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                     0x1f83d9abu, 0x5be0cd19u };
    uint32_t     want[8], got[8];
    size_t       li;
    unsigned     src_off;

    CHECK(data != NULL);
    if (!data)
        return;
    if (!qn_crypto_backend_enabled(QN_BACKEND_SHA256_CE)) {
        free(data);
        return;
    }
    random_bytes(data, cap);
    for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t blocks = lengths[li] / 64u;

        for (src_off = 0; src_off < 16u; src_off++) {
            memcpy(want, iv, sizeof want);
            memcpy(got, iv, sizeof got);
            qn_sha256_blocks_c(want, data + src_off, blocks);
            qn_sha256_blocks_ce(got, data + src_off, blocks);
            if (memcmp(got, want, sizeof got) != 0) {
                fprintf(stderr, "FAIL sha256-blocks blocks=%zu src+%u\n", blocks, src_off);
                failures++;
            }
        }
    }
    free(data);
}

static void test_chacha(void)
{
    const size_t cap = MAX_TEST_LEN + 64u;
    uint8_t     *src_base = (uint8_t *)malloc(cap);
    uint8_t     *dst_base = (uint8_t *)malloc(cap);
    uint8_t     *inplace  = (uint8_t *)malloc(cap);
    uint8_t     *want     = (uint8_t *)malloc(MAX_TEST_LEN + 16u);
    uint8_t      key[32], nonce[12];
    size_t       li;
    unsigned     src_off, dst_off;

    CHECK(src_base && dst_base && inplace && want);
    if (!src_base || !dst_base || !inplace || !want)
        goto done;
    if (!qn_crypto_backend_enabled(QN_BACKEND_CHACHA_NEON))
        goto done;
    random_bytes(src_base, cap);
    random_bytes(key, sizeof key);
    random_bytes(nonce, sizeof nonce);
    for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t len = lengths[li];

        for (src_off = 0; src_off < 16u; src_off++) {
            qn_chacha20_xor_c(key, 7u, nonce, src_base + src_off, want, len);
            for (dst_off = 0; dst_off < 16u; dst_off++) {
                size_t out_off = 16u + dst_off;

                guarded_reset(dst_base, cap);
                qn_chacha20_1x_neon(key, 7u, nonce, src_base + src_off,
                                    dst_base + out_off, len);
                (void)equal_bytes("chacha-1x", len, src_off, dst_off,
                                  dst_base + out_off, want);
                CHECK(guards_ok(dst_base, out_off, len, cap));

                if (len >= 256u) {
                    size_t whole = len & ~(size_t)255u;

                    guarded_reset(dst_base, cap);
                    qn_chacha20_4x_neon(key, 7u, nonce, src_base + src_off,
                                        dst_base + out_off, whole / 256u);
                    (void)equal_bytes("chacha-4x", whole, src_off, dst_off,
                                      dst_base + out_off, want);
                    CHECK(guards_ok(dst_base, out_off, whole, cap));
                }
            }

            guarded_reset(inplace, cap);
            memcpy(inplace + 16u + src_off, src_base + src_off, len);
            qn_chacha20_1x_neon(key, 7u, nonce, inplace + 16u + src_off,
                                inplace + 16u + src_off, len);
            (void)equal_bytes("chacha-inplace", len, src_off, src_off,
                              inplace + 16u + src_off, want);
            CHECK(guards_ok(inplace, 16u + src_off, len, cap));
        }
    }

    /* Four blocks ending exactly at UINT32_MAX must not wrap internally. */
    qn_chacha20_xor_c(key, UINT32_MAX - 3u, nonce, src_base, want, 256u);
    qn_chacha20_4x_neon(key, UINT32_MAX - 3u, nonce, src_base, dst_base, 1u);
    (void)equal_bytes("chacha-counter-boundary", 256u, 0u, 0u, dst_base, want);

done:
    free(src_base);
    free(dst_base);
    free(inplace);
    free(want);
}

static void test_poly1305_blocks(void)
{
    const size_t cap = MAX_TEST_LEN + 32u;
    uint8_t *data = (uint8_t *)malloc(cap);
    uint8_t key[32];
    size_t li;
    unsigned src_off;

    CHECK(data != NULL);
    if (!data)
        return;
    if (!qn_crypto_backend_available(QN_BACKEND_POLY1305_ASM)) {
        free(data);
        return;
    }
    random_bytes(data, cap);
    random_bytes(key, sizeof key);
    for (li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t blocks = lengths[li] / 16u;

        for (src_off = 0; src_off < 16u; src_off++) {
            qn_poly1305 c, a;

            memset(&c, 0, sizeof c);
            memset(&a, 0, sizeof a);
            qn_poly1305_init(&c, key);
            qn_poly1305_init(&a, key);
            qn_poly1305_blocks_c(&c, data + src_off, blocks, 1u);
            qn_poly1305_blocks_aarch64(&a, data + src_off, blocks, 1u);
            if (memcmp(&a, &c, sizeof a) != 0) {
                fprintf(stderr, "FAIL poly1305-blocks blocks=%zu src+%u\n", blocks,
                        src_off);
                failures++;
            }
        }
    }
    for (src_off = 0; src_off < 16u; src_off++) {
        qn_poly1305 c, a;

        memset(&c, 0, sizeof c);
        memset(&a, 0, sizeof a);
        qn_poly1305_init(&c, key);
        qn_poly1305_init(&a, key);
        qn_poly1305_blocks_c(&c, data + src_off, 1u, 0u);
        qn_poly1305_blocks_aarch64(&a, data + src_off, 1u, 0u);
        CHECK(memcmp(&a, &c, sizeof a) == 0);
    }
    free(data);
}
#endif /* __aarch64__ */

static void test_poly1305_kat(void)
{
    static const uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe,
        0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    static const uint8_t msg[] = "Cryptographic Forum Research Group";
    static const uint8_t want[16] = { 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                                      0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 };
    qn_poly1305 st;
    uint8_t     got[16];

    qn_poly1305_init(&st, key);
    qn_poly1305_update(&st, msg, sizeof msg - 1u);
    qn_poly1305_final(&st, got);
    CHECK(memcmp(got, want, sizeof got) == 0);

    qn_poly1305_init(&st, key);
    for (size_t i = 0; i < sizeof msg - 1u; i++)
        qn_poly1305_update(&st, msg + i, 1u);
    qn_poly1305_final(&st, got);
    CHECK(memcmp(got, want, sizeof got) == 0);
}

static void test_x25519_alias_alignment(void)
{
    uint8_t skbuf[64], pointbuf[64], outbuf[64], sk[32], point[32], aligned[32];
    unsigned i, so, po, oo;

    for (i = 0; i < 32u; i++) {
        random_bytes(sk, sizeof sk);
        memset(point, 0, sizeof point);
        point[0] = 9u;
        CHECK(qn_x25519(aligned, sk, point));
        so = i & 15u;
        po = (i * 5u + 1u) & 15u;
        oo = (i * 7u + 3u) & 15u;
        memcpy(skbuf + so, sk, 32u);
        memcpy(pointbuf + po, point, 32u);
        CHECK(qn_x25519(outbuf + oo, skbuf + so, pointbuf + po));
        CHECK(memcmp(outbuf + oo, aligned, 32u) == 0);

        memcpy(outbuf + oo, skbuf + so, 32u);
        CHECK(qn_x25519(outbuf + oo, outbuf + oo, pointbuf + po));
        CHECK(memcmp(outbuf + oo, aligned, 32u) == 0);

        memcpy(outbuf + oo, pointbuf + po, 32u);
        CHECK(qn_x25519(outbuf + oo, skbuf + so, outbuf + oo));
        CHECK(memcmp(outbuf + oo, aligned, 32u) == 0);
    }
    memset(pointbuf, 0, 32u);
    CHECK(!qn_x25519(outbuf, skbuf, pointbuf));
    memset(pointbuf, 0, 32u);
    pointbuf[0] = 1u;
    CHECK(!qn_x25519(outbuf, skbuf, pointbuf));
}

int main(void)
{
    const char *control_error = qn_crypto_backend_control_error();

    if (control_error) {
        fprintf(stderr, "crypto backend control error: %s\n", control_error);
        return 2;
    }
    test_aes_key_policy();
#if defined(__aarch64__)
    test_aes_block();
    test_aes_ctr();
    test_aes_gcm_fused();
    test_ghash();
    test_sha256_blocks();
    test_chacha();
    test_poly1305_blocks();
#endif
    test_poly1305_kat();
    test_x25519_alias_alignment();

    if (failures) {
        fprintf(stderr, "crypto differential tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("crypto differential tests: ok");
    return 0;
}
