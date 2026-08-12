/* SHA-256 and SHA-384/512, FIPS 180-4. */

#include "qanat/crypto.h"

#include "arm64/backend.h"

#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32u - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64u - (n))))

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u
};

static uint32_t ld32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_block(uint32_t h[8], const uint8_t *b)
{
    uint32_t w[64], a, bb, c, d, e, f, g, hh, t1, t2;
    unsigned i;

    for (i = 0; i < 16; i++)
        w[i] = ld32(b + 4u * i);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i]        = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a  = h[0];
    bb = h[1];
    c  = h[2];
    d  = h[3];
    e  = h[4];
    f  = h[5];
    g  = h[6];
    hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1  = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch  = (e & f) ^ (~e & g);
        uint32_t S0  = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
        t1           = hh + S1 + ch + K256[i] + w[i];
        t2           = S0 + maj;
        hh           = g;
        g            = f;
        f            = e;
        e            = d + t1;
        d            = c;
        c            = bb;
        bb           = a;
        a            = t1 + t2;
    }

    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;

    qn_wipe(w, sizeof w);
}

void qn_sha256_init(qn_sha256 *s)
{
    static const uint32_t iv[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    memcpy(s->h, iv, sizeof iv);
    s->len = 0;
    s->n   = 0;
}

#if defined(__aarch64__)
void qn_sha256_blocks_ce(uint32_t state[8], const uint8_t *data, size_t blocks);
void qn_sha512_blocks_ce(uint64_t state[8], const uint8_t *data, size_t blocks);

static bool sha_ce_ok(void)
{
    return qn_cpu_has_sha2();
}
#endif

static void sha256_blocks(uint32_t h[8], const uint8_t *p, size_t blocks)
{
#if defined(__aarch64__)
    if (sha_ce_ok()) {
        qn_sha256_blocks_ce(h, p, blocks);
        return;
    }
#endif
    while (blocks--) {
        sha256_block(h, p);
        p += 64;
    }
}

#if defined(QN_CRYPTO_TESTING)
void qn_sha256_blocks_c(uint32_t h[8], const uint8_t *p, size_t blocks)
{
    while (blocks--) {
        sha256_block(h, p);
        p += 64u;
    }
}
#endif

void qn_sha256_update(qn_sha256 *s, const void *p, size_t n)
{
    const uint8_t *d = (const uint8_t *)p;

    s->len += (uint64_t)n;

    if (s->n) {
        size_t take = 64u - s->n;
        if (take > n)
            take = n;
        memcpy(s->buf + s->n, d, take);
        s->n += (uint32_t)take;
        d += take;
        n -= take;
        if (s->n < 64u)
            return;
        sha256_blocks(s->h, s->buf, 1);
        s->n = 0;
    }

    if (n >= 64u) {
        size_t blocks = n / 64u;
        sha256_blocks(s->h, d, blocks);
        d += blocks * 64u;
        n -= blocks * 64u;
    }

    if (n) {
        memcpy(s->buf, d, n);
        s->n = (uint32_t)n;
    }
}

void qn_sha256_final(const qn_sha256 *cs, uint8_t out[QN_SHA256_LEN])
{
    qn_sha256 s = *cs;
    uint8_t   tail[8];
    uint64_t  bits = s.len << 3;
    unsigned  i;

    for (i = 0; i < 8; i++)
        tail[i] = (uint8_t)(bits >> (56u - 8u * i));

    s.buf[s.n++] = 0x80u;
    if (s.n > 56u) {
        memset(s.buf + s.n, 0, 64u - s.n);
        sha256_blocks(s.h, s.buf, 1);
        s.n = 0;
    }
    memset(s.buf + s.n, 0, 56u - s.n);
    memcpy(s.buf + 56, tail, 8);
    sha256_blocks(s.h, s.buf, 1);

    for (i = 0; i < 8; i++)
        st32(out + 4u * i, s.h[i]);

    qn_wipe(&s, sizeof s);
}

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static uint64_t ld64(const uint8_t *p)
{
    unsigned i;
    uint64_t v = 0;
    for (i = 0; i < 8; i++)
        v = (v << 8) | (uint64_t)p[i];
    return v;
}

static void st64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56u - 8u * i));
}

static void sha512_block_c(uint64_t h[8], const uint8_t *b)
{
    uint64_t w[16], a, bb, c, d, e, f, g, hh, t1, t2;
    unsigned i;

    for (i = 0; i < 16; i++)
        w[i] = ld64(b + 8u * i);

    a  = h[0];
    bb = h[1];
    c  = h[2];
    d  = h[3];
    e  = h[4];
    f  = h[5];
    g  = h[6];
    hh = h[7];

    for (i = 0; i < 80; i++) {
        unsigned j = i & 15u;

        if (i >= 16u) {
            uint64_t x0 = w[(j + 1u) & 15u];
            uint64_t x1 = w[(j + 14u) & 15u];
            uint64_t s0 = ROR64(x0, 1) ^ ROR64(x0, 8) ^ (x0 >> 7);
            uint64_t s1 = ROR64(x1, 19) ^ ROR64(x1, 61) ^ (x1 >> 6);

            w[j] += s0 + w[(j + 9u) & 15u] + s1;
        }
        uint64_t S1  = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
        uint64_t ch  = (e & f) ^ (~e & g);
        uint64_t S0  = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
        uint64_t maj = (a & bb) ^ (a & c) ^ (bb & c);
        t1           = hh + S1 + ch + K512[i] + w[j];
        t2           = S0 + maj;
        hh           = g;
        g            = f;
        f            = e;
        e            = d + t1;
        d            = c;
        c            = bb;
        bb           = a;
        a            = t1 + t2;
    }

    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;

    qn_wipe(w, sizeof w);
}

/* One block, on the SHA-512 instructions where the core has them. */
static void sha512_block(uint64_t h[8], const uint8_t *b)
{
#if defined(__aarch64__)
    if (qn_crypto_backend_enabled(QN_BACKEND_SHA512_CE)) {
        qn_sha512_blocks_ce(h, b, 1u);
        return;
    }
#endif
    sha512_block_c(h, b);
}

void qn_sha512_init(qn_sha512 *s, uint32_t outlen)
{
    static const uint64_t iv512[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
                                       0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                                       0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                       0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    static const uint64_t iv384[8] = { 0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
                                       0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
                                       0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
                                       0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull };

    memcpy(s->h, outlen == QN_SHA384_LEN ? iv384 : iv512, sizeof s->h);
    s->len_lo = 0;
    s->len_hi = 0;
    s->n      = 0;
    s->outlen = outlen == QN_SHA384_LEN ? QN_SHA384_LEN : QN_SHA512_LEN;
}

void qn_sha512_update(qn_sha512 *s, const void *p, size_t n)
{
    const uint8_t *d   = (const uint8_t *)p;
    uint64_t       old = s->len_lo;

    s->len_lo += (uint64_t)n;
    if (s->len_lo < old)
        s->len_hi++;

    while (n) {
        size_t take = 128u - s->n;
        if (take > n)
            take = n;
        memcpy(s->buf + s->n, d, take);
        s->n += (uint32_t)take;
        d += take;
        n -= take;
        if (s->n == 128u) {
            sha512_block(s->h, s->buf);
            s->n = 0;
        }
    }
}

void qn_sha512_final(const qn_sha512 *cs, uint8_t *out)
{
    qn_sha512 s = *cs;
    uint8_t   tail[16];
    uint64_t  lo = s.len_lo << 3;
    uint64_t  hi = (s.len_hi << 3) | (s.len_lo >> 61);
    unsigned  i;

    st64(tail, hi);
    st64(tail + 8, lo);

    s.buf[s.n++] = 0x80u;
    if (s.n > 112u) {
        memset(s.buf + s.n, 0, 128u - s.n);
        sha512_block(s.h, s.buf);
        s.n = 0;
    }
    memset(s.buf + s.n, 0, 112u - s.n);
    memcpy(s.buf + 112, tail, 16);
    sha512_block(s.h, s.buf);

    for (i = 0; i < s.outlen / 8u; i++)
        st64(out + 8u * i, s.h[i]);

    qn_wipe(&s, sizeof s);
}

size_t qn_hash_len(qn_hash_id id)
{
    return id == QN_HASH_SHA384 ? QN_SHA384_LEN : QN_SHA256_LEN;
}

size_t qn_hash_block(qn_hash_id id)
{
    return id == QN_HASH_SHA384 ? 128u : 64u;
}

void qn_hash_init(qn_hash *h, qn_hash_id id)
{
    h->id = id;
    if (id == QN_HASH_SHA384)
        qn_sha512_init(&h->u.s384, QN_SHA384_LEN);
    else
        qn_sha256_init(&h->u.s256);
}

void qn_hash_update(qn_hash *h, const void *p, size_t n)
{
    if (h->id == QN_HASH_SHA384)
        qn_sha512_update(&h->u.s384, p, n);
    else
        qn_sha256_update(&h->u.s256, p, n);
}

void qn_hash_final(const qn_hash *h, uint8_t *out)
{
    if (h->id == QN_HASH_SHA384)
        qn_sha512_final(&h->u.s384, out);
    else
        qn_sha256_final(&h->u.s256, out);
}
