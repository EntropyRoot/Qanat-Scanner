/* ChaCha20, Poly1305 and the combined AEAD, RFC 8439. */

#include "aead_impl.h"

#if defined(__aarch64__)
#include "arm64/backend.h"
#endif

#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32u - (n))))

static uint32_t ld32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void st32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void st64le(uint8_t *p, uint64_t v)
{
    st32le(p, (uint32_t)v);
    st32le(p + 4, (uint32_t)(v >> 32));
}

#define QR(a, b, c, d)                                                                       \
    do {                                                                                     \
        a += b;                                                                              \
        d ^= a;                                                                              \
        d = ROL32(d, 16);                                                                    \
        c += d;                                                                              \
        b ^= c;                                                                              \
        b = ROL32(b, 12);                                                                    \
        a += b;                                                                              \
        d ^= a;                                                                              \
        d = ROL32(d, 8);                                                                     \
        c += d;                                                                              \
        b ^= c;                                                                              \
        b = ROL32(b, 7);                                                                     \
    } while (0)

static void chacha_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         uint8_t out[64])
{
    uint32_t x[16], s[16];
    unsigned i;

    s[0]  = 0x61707865u;
    s[1]  = 0x3320646eu;
    s[2]  = 0x79622d32u;
    s[3]  = 0x6b206574u;
    for (i = 0; i < 8; i++)
        s[4 + i] = ld32le(key + 4u * i);
    s[12] = counter;
    for (i = 0; i < 3; i++)
        s[13 + i] = ld32le(nonce + 4u * i);

    memcpy(x, s, sizeof x);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++)
        st32le(out + 4u * i, x[i] + s[i]);

    qn_wipe(x, sizeof x);
    qn_wipe(s, sizeof s);
}

#if defined(__aarch64__)
void qn_chacha20_1x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len);
void qn_chacha20_4x_neon(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t groups);
#endif

static void chacha20_xor_scalar(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                                const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[64];
    size_t  off = 0;

    while (off < len) {
        size_t take = len - off < 64u ? len - off : 64u;
        size_t i;
        chacha_block(key, counter, nonce, ks);
        for (i = 0; i < take; i++)
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        off += take;
        counter++;
    }
    qn_wipe(ks, sizeof ks);
}

static void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len)
{
#if defined(__aarch64__)
    if (qn_cpu_has_neon()) {
        bool force_short = qn_crypto_backend_forced(QN_BACKEND_CHACHA_NEON);

        if (len >= 256u) {
            size_t groups = len / 256u;
            qn_chacha20_4x_neon(key, counter, nonce, in, out, groups);
            counter += (uint32_t)(groups * 4u);
            in += groups * 256u;
            out += groups * 256u;
            len -= groups * 256u;
        }
        /* Keep one-lane NEON force-only until it beats scalar on target CPUs. */
        if (force_short && len) {
            qn_chacha20_1x_neon(key, counter, nonce, in, out, len);
            return;
        }
    }
#endif
    chacha20_xor_scalar(key, counter, nonce, in, out, len);
}

static void poly_pad16(qn_poly1305 *st, size_t len)
{
    static const uint8_t z[16] = { 0 };
    size_t               rem   = len & 15u;
    if (rem)
        qn_poly1305_update(st, z, 16u - rem);
}

static void chacha_tag(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                       size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t tag[16])
{
    uint8_t  block[64], lens[16];
    qn_poly1305 st;

    chacha_block(key, 0, nonce, block);
    qn_poly1305_init(&st, block);

    if (aadlen)
        qn_poly1305_update(&st, aad, aadlen);
    poly_pad16(&st, aadlen);
    if (ctlen)
        qn_poly1305_update(&st, ct, ctlen);
    poly_pad16(&st, ctlen);

    st64le(lens, (uint64_t)aadlen);
    st64le(lens + 8, (uint64_t)ctlen);
    qn_poly1305_update(&st, lens, sizeof lens);

    qn_poly1305_final(&st, tag);
    qn_wipe(block, sizeof block);
}

static bool chacha_counter_ok(uint32_t counter, size_t len)
{
    uint64_t blocks;
    uint64_t available;

    if (!len)
        return true;
    blocks    = ((uint64_t)len - 1u) / 64u + 1u;
    available = (uint64_t)UINT32_MAX - counter + 1u;
    return blocks <= available;
}

bool qn_chacha20poly1305_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                              size_t aadlen, const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    if (!chacha_counter_ok(1u, ptlen))
        return false;
    chacha20_xor(key, 1, nonce, pt, out, ptlen);
    chacha_tag(key, nonce, aad, aadlen, out, ptlen, out + ptlen);
    return true;
}

bool qn_chacha20poly1305_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                              size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    uint8_t tag[16];
    size_t  ptlen;

    if (ctlen < QN_AEAD_TAG_LEN)
        return false;
    ptlen = ctlen - QN_AEAD_TAG_LEN;
    if (!chacha_counter_ok(1u, ptlen))
        return false;

    chacha_tag(key, nonce, aad, aadlen, ct, ptlen, tag);
    if (!qn_ct_eq(tag, ct + ptlen, QN_AEAD_TAG_LEN))
        return false;

    chacha20_xor(key, 1, nonce, ct, out, ptlen);
    return true;
}

#if defined(QN_CRYPTO_TESTING)
void qn_chacha20_xor_c(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    chacha20_xor_scalar(key, counter, nonce, in, out, len);
}
#endif
