/* AES-128/256 and GCM, FIPS 197 and SP 800-38D, with a 4-bit GHASH table. */

#include "aead_impl.h"

#if defined(__aarch64__)
#include "arm64/backend.h"
#endif

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

static bool aes_ce_ok(void)
{
    return qn_cpu_has_aes();
}

static bool ghash_ce_ok(void)
{
    return qn_cpu_has_pmull();
}
#endif

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16
};

static const uint32_t RCON[10] = { 0x01000000u, 0x02000000u, 0x04000000u, 0x08000000u,
                                   0x10000000u, 0x20000000u, 0x40000000u, 0x80000000u,
                                   0x1b000000u, 0x36000000u };

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint64_t be64(const uint8_t *p)
{
    unsigned i;
    uint64_t v = 0;
    for (i = 0; i < 8; i++)
        v = (v << 8) | (uint64_t)p[i];
    return v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56u - 8u * i));
}

static uint32_t subword(uint32_t w)
{
    return ((uint32_t)SBOX[(w >> 24) & 0xFFu] << 24) | ((uint32_t)SBOX[(w >> 16) & 0xFFu] << 16) |
           ((uint32_t)SBOX[(w >> 8) & 0xFFu] << 8) | (uint32_t)SBOX[w & 0xFFu];
}

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((uint8_t)(x << 1) ^ (uint8_t)(((x >> 7) & 1u) * 0x1bu));
}

static void aes_expand(uint32_t *rk, uint32_t *nr_out, const uint8_t *key, size_t klen)
{
    uint32_t nk = (uint32_t)(klen / 4u);
    uint32_t nr = nk + 6u;
    uint32_t i;

    for (i = 0; i < nk; i++)
        rk[i] = be32(key + 4u * i);

    for (i = nk; i < 4u * (nr + 1u); i++) {
        uint32_t t = rk[i - 1u];
        if (i % nk == 0)
            t = subword((t << 8) | (t >> 24)) ^ RCON[i / nk - 1u];
        else if (nk > 6u && i % nk == 4u)
            t = subword(t);
        rk[i] = rk[i - nk] ^ t;
    }
    *nr_out = nr;
}

static void add_rk(uint8_t s[16], const uint32_t *rk)
{
    unsigned c;
    for (c = 0; c < 4; c++) {
        s[4u * c + 0u] ^= (uint8_t)(rk[c] >> 24);
        s[4u * c + 1u] ^= (uint8_t)(rk[c] >> 16);
        s[4u * c + 2u] ^= (uint8_t)(rk[c] >> 8);
        s[4u * c + 3u] ^= (uint8_t)rk[c];
    }
}

static void aes_encrypt(const uint32_t *rk, uint32_t nr, const uint8_t in[16], uint8_t out[16])
{
    uint8_t  s[16], t[16];
    uint32_t r;
    unsigned i, c;

    memcpy(s, in, 16);
    add_rk(s, rk);

    for (r = 1; r <= nr; r++) {
        for (i = 0; i < 16; i++)
            t[i] = SBOX[s[i]];

        /* ShiftRows: row j rotates left by j. */
        s[0]  = t[0];
        s[4]  = t[4];
        s[8]  = t[8];
        s[12] = t[12];
        s[1]  = t[5];
        s[5]  = t[9];
        s[9]  = t[13];
        s[13] = t[1];
        s[2]  = t[10];
        s[6]  = t[14];
        s[10] = t[2];
        s[14] = t[6];
        s[3]  = t[15];
        s[7]  = t[3];
        s[11] = t[7];
        s[15] = t[11];

        if (r != nr) {
            for (c = 0; c < 4; c++) {
                uint8_t *p  = s + 4u * c;
                uint8_t  a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                uint8_t  x  = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                p[0] = (uint8_t)(a0 ^ x ^ xtime((uint8_t)(a0 ^ a1)));
                p[1] = (uint8_t)(a1 ^ x ^ xtime((uint8_t)(a1 ^ a2)));
                p[2] = (uint8_t)(a2 ^ x ^ xtime((uint8_t)(a2 ^ a3)));
                p[3] = (uint8_t)(a3 ^ x ^ xtime((uint8_t)(a3 ^ a0)));
            }
        }
        add_rk(s, rk + 4u * r);
    }

    memcpy(out, s, 16);
    qn_wipe(s, sizeof s);
    qn_wipe(t, sizeof t);
}

static void aes_encrypt_dispatch(const uint32_t *rk, uint32_t nr, const uint8_t in[16],
                                 uint8_t out[16])
{
#if defined(__aarch64__)
    if (aes_ce_ok()) {
        qn_aes_encrypt_ce(rk, nr, in, out);
        return;
    }
#endif
    aes_encrypt(rk, nr, in, out);
}

static const uint64_t LAST4[16] = { 0x0000u, 0x1c20u, 0x3840u, 0x2460u, 0x7080u, 0x6ca0u,
                                    0x48c0u, 0x54e0u, 0xe100u, 0xfd20u, 0xd940u, 0xc560u,
                                    0x9180u, 0x8da0u, 0xa9c0u, 0xb5e0u };

static void ghash_mul(const qn_aes_gcm *g, uint8_t x[16]);

bool qn_aes_gcm_setkey(qn_aes_gcm *g, const uint8_t *key, size_t klen)
{
    uint8_t  h[16], zero[16];
    uint64_t vh, vl;
    unsigned i, j;

    /* AES-192 is unsupported because CE implements only 10 or 14 rounds. */
    if (klen != 16u && klen != 32u)
        return false;

    memset(zero, 0, sizeof zero);
    aes_expand(g->rk, &g->nr, key, klen);
    aes_encrypt_dispatch(g->rk, g->nr, zero, h);
    memcpy(g->hp[0], h, sizeof g->hp[0]);

    vh = be64(h);
    vl = be64(h + 8);

    g->hh[0][0] = 0;
    g->hh[0][1] = 0;
    g->hh[8][0] = vh;
    g->hh[8][1] = vl;

    for (i = 4; i > 0; i >>= 1) {
        uint32_t t = (uint32_t)(vl & 1u) * 0xe1000000u;
        vl         = (vh << 63) | (vl >> 1);
        vh         = (vh >> 1) ^ ((uint64_t)t << 32);
        g->hh[i][0] = vh;
        g->hh[i][1] = vl;
    }
    for (i = 2; i <= 8; i *= 2) {
        vh = g->hh[i][0];
        vl = g->hh[i][1];
        for (j = 1; j < i; j++) {
            g->hh[i + j][0] = vh ^ g->hh[j][0];
            g->hh[i + j][1] = vl ^ g->hh[j][1];
        }
    }

    memcpy(g->hp[1], g->hp[0], sizeof g->hp[1]);
    ghash_mul(g, g->hp[1]);
    memcpy(g->hp[2], g->hp[1], sizeof g->hp[2]);
    ghash_mul(g, g->hp[2]);
    memcpy(g->hp[3], g->hp[2], sizeof g->hp[3]);
    ghash_mul(g, g->hp[3]);

    qn_wipe(h, sizeof h);
    return true;
}

static void ghash_mul(const qn_aes_gcm *g, uint8_t x[16])
{
    uint64_t zh, zl;
    unsigned i;
    uint8_t  lo, hi, rem;

    lo = (uint8_t)(x[15] & 0x0fu);
    zh = g->hh[lo][0];
    zl = g->hh[lo][1];

    for (i = 16; i-- > 0;) {
        lo = (uint8_t)(x[i] & 0x0fu);
        hi = (uint8_t)((x[i] >> 4) & 0x0fu);

        if (i != 15) {
            rem = (uint8_t)(zl & 0x0fu);
            zl  = (zh << 60) | (zl >> 4);
            zh  = zh >> 4;
            zh ^= LAST4[rem] << 48;
            zh ^= g->hh[lo][0];
            zl ^= g->hh[lo][1];
        }

        rem = (uint8_t)(zl & 0x0fu);
        zl  = (zh << 60) | (zl >> 4);
        zh  = zh >> 4;
        zh ^= LAST4[rem] << 48;
        zh ^= g->hh[hi][0];
        zl ^= g->hh[hi][1];
    }

    put_be64(x, zh);
    put_be64(x + 8, zl);
}

static void ghash_bytes_scalar(const qn_aes_gcm *g, uint8_t acc[16], const uint8_t *p, size_t n)
{
    while (n) {
        size_t   take = n < 16u ? n : 16u;
        unsigned i;
        for (i = 0; i < take; i++)
            acc[i] ^= p[i];
        ghash_mul(g, acc);
        p += take;
        n -= take;
    }
}

static void gctr_scalar(const qn_aes_gcm *g, uint8_t ctr[16], const uint8_t *in, uint8_t *out,
                        size_t n)
{
    uint8_t ks[16];

    while (n) {
        size_t   take = n < 16u ? n : 16u;
        unsigned i;
        uint32_t c;

        aes_encrypt(g->rk, g->nr, ctr, ks);
        for (i = 0; i < take; i++)
            *out++ = (uint8_t)(*in++ ^ ks[i]);
        n -= take;

        c = be32(ctr + 12) + 1u;
        ctr[12] = (uint8_t)(c >> 24);
        ctr[13] = (uint8_t)(c >> 16);
        ctr[14] = (uint8_t)(c >> 8);
        ctr[15] = (uint8_t)c;
    }
    qn_wipe(ks, sizeof ks);
}

static void gctr(const qn_aes_gcm *g, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t n)
{
#if defined(__aarch64__)
    if (aes_ce_ok()) {
        qn_aes_ctr_ce(g->rk, g->nr, ctr, in, out, n);
        return;
    }
#endif
    gctr_scalar(g, ctr, in, out, n);
}

static void gcm_j0(const uint8_t iv[QN_AEAD_IV_LEN], uint8_t j0[16])
{
    memcpy(j0, iv, QN_AEAD_IV_LEN);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
}

static bool gcm_lengths_ok(size_t aadlen, size_t textlen)
{
    const uint64_t max_text = (UINT64_C(0xfffffffe) * 16u);

    return (uint64_t)aadlen <= UINT64_MAX / 8u && (uint64_t)textlen <= max_text;
}

/* GHASH is always taken over the ciphertext, never the plaintext. */
static void gcm_tag(const qn_aes_gcm *g, const uint8_t j0[16], const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen, uint8_t tag[16])
{
    uint8_t  acc[16], lens[16], ek[16];
    unsigned i;

    memset(acc, 0, sizeof acc);
#if defined(__aarch64__)
    if (ghash_ce_ok()) {
        qn_ghash_gcm_ce(acc, (const uint8_t *)g->hp, aad, aadlen, ct, ctlen);
    } else
#endif
    {
        ghash_bytes_scalar(g, acc, aad, aadlen);
        ghash_bytes_scalar(g, acc, ct, ctlen);

        put_be64(lens, (uint64_t)aadlen << 3);
        put_be64(lens + 8, (uint64_t)ctlen << 3);
        ghash_bytes_scalar(g, acc, lens, sizeof lens);
    }

    aes_encrypt_dispatch(g->rk, g->nr, j0, ek);
    for (i = 0; i < 16; i++)
        tag[i] = (uint8_t)(acc[i] ^ ek[i]);

    qn_wipe(ek, sizeof ek);
    qn_wipe(acc, sizeof acc);
}

#if defined(__aarch64__)
static void ghash_update_ce(const qn_aes_gcm *g, uint8_t acc[16], const uint8_t *p, size_t n)
{
    size_t whole = n & ~(size_t)15u;

    if (whole)
        qn_ghash_ce(acc, (const uint8_t *)g->hp, p, whole / 16u);
    if (n != whole) {
        uint8_t last[16] = { 0 };

        memcpy(last, p + whole, n - whole);
        qn_ghash_ce(acc, (const uint8_t *)g->hp, last, 1u);
    }
}

static void gcm_seal_fused(const qn_aes_gcm *g, const uint8_t j0[16], uint8_t ctr[16],
                           const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t ptlen,
                           uint8_t *out)
{
    uint8_t acc[16] = { 0 };
    uint8_t lens[16], ek[16];
    unsigned i;

    ghash_update_ce(g, acc, aad, aadlen);
    qn_aes_gcm_encrypt_ghash_ce(g->rk, g->nr, (const uint8_t *)g->hp, ctr, pt, out, ptlen,
                                acc);
    put_be64(lens, (uint64_t)aadlen << 3);
    put_be64(lens + 8, (uint64_t)ptlen << 3);
    qn_ghash_ce(acc, (const uint8_t *)g->hp, lens, 1u);
    aes_encrypt_dispatch(g->rk, g->nr, j0, ek);
    for (i = 0; i < 16u; i++)
        out[ptlen + i] = (uint8_t)(acc[i] ^ ek[i]);
    qn_wipe(ek, sizeof ek);
    qn_wipe(acc, sizeof acc);
}
#endif

bool qn_aes_gcm_seal(const qn_aes_gcm *g, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                     size_t aadlen, const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    uint8_t j0[16], ctr[16];

    if (!gcm_lengths_ok(aadlen, ptlen))
        return false;
    gcm_j0(iv, j0);
    memcpy(ctr, j0, 16);
    ctr[15] = 2;
#if defined(__aarch64__)
    if (ptlen && aes_ce_ok() && ghash_ce_ok() &&
        qn_crypto_backend_enabled(QN_BACKEND_AES_GCM_FUSED)) {
        gcm_seal_fused(g, j0, ctr, aad, aadlen, pt, ptlen, out);
        return true;
    }
#endif
    if (ptlen)
        gctr(g, ctr, pt, out, ptlen);
    gcm_tag(g, j0, aad, aadlen, out, ptlen, out + ptlen);
    return true;
}

bool qn_aes_gcm_open(const qn_aes_gcm *g, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                     size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    uint8_t j0[16], ctr[16], tag[16];
    size_t  ptlen;

    if (ctlen < QN_AEAD_TAG_LEN)
        return false;
    ptlen = ctlen - QN_AEAD_TAG_LEN;
    if (!gcm_lengths_ok(aadlen, ptlen))
        return false;

    gcm_j0(iv, j0);
    gcm_tag(g, j0, aad, aadlen, ct, ptlen, tag);
    if (!qn_ct_eq(tag, ct + ptlen, QN_AEAD_TAG_LEN))
        return false;

    memcpy(ctr, j0, 16);
    ctr[15] = 2;
    if (ptlen)
        gctr(g, ctr, ct, out, ptlen);
    return true;
}

#if defined(QN_CRYPTO_TESTING)
void qn_aes_encrypt_block_c(const qn_aes_gcm *g, const uint8_t in[16], uint8_t out[16])
{
    aes_encrypt(g->rk, g->nr, in, out);
}

void qn_aes_ctr_c(const qn_aes_gcm *g, uint8_t ctr[16], const uint8_t *in, uint8_t *out,
                  size_t len)
{
    gctr_scalar(g, ctr, in, out, len);
}

void qn_ghash_blocks_c(const qn_aes_gcm *g, uint8_t acc[16], const uint8_t *data,
                       size_t blocks)
{
    ghash_bytes_scalar(g, acc, data, blocks * 16u);
}

void qn_ghash_gcm_c(const qn_aes_gcm *g, uint8_t out[16], const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen)
{
    uint8_t lens[16];

    memset(out, 0, 16u);
    ghash_bytes_scalar(g, out, aad, aadlen);
    ghash_bytes_scalar(g, out, ct, ctlen);
    put_be64(lens, (uint64_t)aadlen << 3);
    put_be64(lens + 8, (uint64_t)ctlen << 3);
    ghash_bytes_scalar(g, out, lens, sizeof lens);
}
#endif
