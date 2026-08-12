/* X25519 (RFC 7748). Radix 2^51 where 128-bit products exist, else 2^16. */

#include "qanat/crypto.h"

#include <string.h>

/* QN_NO_INT128 forces the portable path so it stays tested. */
#if defined(__SIZEOF_INT128__) && !defined(QN_NO_INT128)

typedef uint64_t fe[5];
typedef unsigned __int128 u128;

#define MASK51 0x7ffffffffffffull

/* Padding keeps subtraction positive without a conditional. */
#define TWO54M152 (((uint64_t)1 << 54) - 152)
#define TWO54M8   (((uint64_t)1 << 54) - 8)

static const fe C121665 = { 121665, 0, 0, 0, 0 };

static void fe_copy(fe o, const fe a)
{
    memcpy(o, a, sizeof(fe));
}

static void fe_add(fe o, const fe a, const fe b)
{
    unsigned i;
    for (i = 0; i < 5; i++)
        o[i] = a[i] + b[i];
}

static void fe_sub(fe o, const fe a, const fe b)
{
    unsigned i;
    o[0] = a[0] + TWO54M152 - b[0];
    for (i = 1; i < 5; i++)
        o[i] = a[i] + TWO54M8 - b[i];
}

static void fe_mul(fe o, const fe a, const fe b)
{
    uint64_t b1 = b[1] * 19u, b2 = b[2] * 19u, b3 = b[3] * 19u, b4 = b[4] * 19u;
    u128     t0, t1, t2, t3, t4;
    uint64_t c;

    t0 = (u128)a[0] * b[0] + (u128)a[1] * b4 + (u128)a[2] * b3 + (u128)a[3] * b2 +
         (u128)a[4] * b1;
    t1 = (u128)a[0] * b[1] + (u128)a[1] * b[0] + (u128)a[2] * b4 + (u128)a[3] * b3 +
         (u128)a[4] * b2;
    t2 = (u128)a[0] * b[2] + (u128)a[1] * b[1] + (u128)a[2] * b[0] + (u128)a[3] * b4 +
         (u128)a[4] * b3;
    t3 = (u128)a[0] * b[3] + (u128)a[1] * b[2] + (u128)a[2] * b[1] + (u128)a[3] * b[0] +
         (u128)a[4] * b4;
    t4 = (u128)a[0] * b[4] + (u128)a[1] * b[3] + (u128)a[2] * b[2] + (u128)a[3] * b[1] +
         (u128)a[4] * b[0];

    c = (uint64_t)(t0 >> 51);
    o[0] = (uint64_t)t0 & MASK51;
    t1 += c;
    c = (uint64_t)(t1 >> 51);
    o[1] = (uint64_t)t1 & MASK51;
    t2 += c;
    c = (uint64_t)(t2 >> 51);
    o[2] = (uint64_t)t2 & MASK51;
    t3 += c;
    c = (uint64_t)(t3 >> 51);
    o[3] = (uint64_t)t3 & MASK51;
    t4 += c;
    c = (uint64_t)(t4 >> 51);
    o[4] = (uint64_t)t4 & MASK51;
    o[0] += c * 19u;
    c = o[0] >> 51;
    o[0] &= MASK51;
    o[1] += c;
}

static void fe_sq(fe o, const fe a)
{
    fe_mul(o, a, a);
}

static void fe_cswap(fe p, fe q, uint64_t bit)
{
    uint64_t mask = ~(bit - 1u);
    unsigned i;
    for (i = 0; i < 5; i++) {
        uint64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_frombytes(fe o, const uint8_t *b)
{
    uint64_t x0 = 0, x1 = 0, x2 = 0, x3 = 0;
    unsigned i;

    for (i = 0; i < 8; i++) {
        x0 |= (uint64_t)b[i] << (8u * i);
        x1 |= (uint64_t)b[8 + i] << (8u * i);
        x2 |= (uint64_t)b[16 + i] << (8u * i);
        x3 |= (uint64_t)b[24 + i] << (8u * i);
    }
    x3 &= 0x7fffffffffffffffull;

    o[0] = x0 & MASK51;
    o[1] = ((x0 >> 51) | (x1 << 13)) & MASK51;
    o[2] = ((x1 >> 38) | (x2 << 26)) & MASK51;
    o[3] = ((x2 >> 25) | (x3 << 39)) & MASK51;
    o[4] = (x3 >> 12) & MASK51;
}

static void fe_tobytes(uint8_t *o, const fe n)
{
    fe       t;
    uint64_t c, x0, x1, x2, x3;
    unsigned i;

    fe_copy(t, n);

    for (i = 0; i < 3; i++) {
        c = t[0] >> 51;
        t[0] &= MASK51;
        t[1] += c;
        c = t[1] >> 51;
        t[1] &= MASK51;
        t[2] += c;
        c = t[2] >> 51;
        t[2] &= MASK51;
        t[3] += c;
        c = t[3] >> 51;
        t[3] &= MASK51;
        t[4] += c;
        c = t[4] >> 51;
        t[4] &= MASK51;
        t[0] += c * 19u;
    }

    /* Now t < 2^255; fold the one remaining 2^255-19 if it is still there. */
    c = (t[0] + 19u) >> 51;
    c = (t[1] + c) >> 51;
    c = (t[2] + c) >> 51;
    c = (t[3] + c) >> 51;
    c = (t[4] + c) >> 51;
    t[0] += 19u * c;
    c = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c;
    t[4] &= MASK51;

    x0 = t[0] | (t[1] << 51);
    x1 = (t[1] >> 13) | (t[2] << 38);
    x2 = (t[2] >> 26) | (t[3] << 25);
    x3 = (t[3] >> 39) | (t[4] << 12);

    for (i = 0; i < 8; i++) {
        o[i]      = (uint8_t)(x0 >> (8u * i));
        o[8 + i]  = (uint8_t)(x1 >> (8u * i));
        o[16 + i] = (uint8_t)(x2 >> (8u * i));
        o[24 + i] = (uint8_t)(x3 >> (8u * i));
    }
}

#else

typedef int64_t fe[16];

static const fe C121665 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static void fe_copy(fe o, const fe a)
{
    unsigned i;
    for (i = 0; i < 16; i++)
        o[i] = a[i];
}

static void fe_add(fe o, const fe a, const fe b)
{
    unsigned i;
    for (i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void fe_sub(fe o, const fe a, const fe b)
{
    unsigned i;
    for (i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void fe_carry(fe o)
{
    unsigned i;
    int64_t  c;

    for (i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        c = o[i] >> 16;
        if (i < 15)
            o[i + 1] += c - 1;
        else
            o[0] += 38 * (c - 1);
        o[i] -= c * 65536; /* not c << 16: c is often negative */
    }
}

static void fe_mul(fe o, const fe a, const fe b)
{
    int64_t  t[31];
    unsigned i, j;

    for (i = 0; i < 31; i++)
        t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++)
        o[i] = t[i];

    fe_carry(o);
    fe_carry(o);
}

static void fe_sq(fe o, const fe a)
{
    fe_mul(o, a, a);
}

static void fe_cswap(fe p, fe q, int64_t bit)
{
    unsigned i;
    int64_t  mask = ~(bit - 1);

    for (i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_frombytes(fe o, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)b[2u * i] + ((int64_t)b[2u * i + 1u] << 8);
    o[15] &= 0x7fff;
}

static void fe_tobytes(uint8_t *o, const fe n)
{
    fe       t, m;
    unsigned i, j;
    int64_t  b;

    fe_copy(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);

    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b     = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_cswap(t, m, 1 - b);
    }

    for (i = 0; i < 16; i++) {
        o[2u * i]      = (uint8_t)(t[i] & 0xff);
        o[2u * i + 1u] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

#endif

static void fe_inv(fe o, const fe a)
{
    fe  c;
    int i;

    fe_copy(c, a);
    for (i = 253; i >= 0; i--) {
        fe_sq(c, c);
        if (i != 2 && i != 4)
            fe_mul(c, c, a);
    }
    fe_copy(o, c);
}

static void scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t z[32];
    fe      x, a, b, c, d, e, f;
    int     i;

    memcpy(z, scalar, 32);
    z[0] &= 248u;
    z[31] = (uint8_t)((z[31] & 127u) | 64u);

    fe_frombytes(x, point);
    fe_copy(b, x);
    memset(a, 0, sizeof a);
    memset(c, 0, sizeof c);
    memset(d, 0, sizeof d);
    a[0] = 1;
    d[0] = 1;

    for (i = 254; i >= 0; i--) {
        uint64_t bit = (uint64_t)((z[i >> 3] >> (i & 7)) & 1);

        fe_cswap(a, b, bit);
        fe_cswap(c, d, bit);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_add(c, b, d);
        fe_sub(b, b, d);
        fe_sq(d, e);
        fe_sq(f, a);
        fe_mul(a, c, a);
        fe_mul(c, b, e);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_sq(b, a);
        fe_sub(c, d, f);
        fe_mul(a, c, C121665);
        fe_add(a, a, d);
        fe_mul(c, c, a);
        fe_mul(a, d, f);
        fe_mul(d, b, x);
        fe_sq(b, e);
        fe_cswap(a, b, bit);
        fe_cswap(c, d, bit);
    }

    fe_inv(c, c);
    fe_mul(a, a, c);
    fe_tobytes(out, a);

    qn_wipe(z, sizeof z);
    qn_wipe(a, sizeof a);
    qn_wipe(c, sizeof c);
    qn_wipe(d, sizeof d);
}

void qn_x25519_base(uint8_t pk[QN_X25519_LEN], const uint8_t sk[QN_X25519_LEN])
{
    uint8_t nine[32] = { 9 };
    scalarmult(pk, sk, nine);
}

bool qn_x25519(uint8_t out[QN_X25519_LEN], const uint8_t sk[QN_X25519_LEN],
               const uint8_t peer[QN_X25519_LEN])
{
    uint8_t zero[QN_X25519_LEN] = { 0 };

    scalarmult(out, sk, peer);
    return !qn_ct_eq(out, zero, sizeof zero);
}

bool qn_x25519_keypair(uint8_t sk[QN_X25519_LEN], uint8_t pk[QN_X25519_LEN], qn_rng *rng)
{
    if (rng)
        qn_rng_bytes(rng, sk, QN_X25519_LEN);
    else if (!qn_random_secure(sk, QN_X25519_LEN))
        return false;

    sk[0] &= 248u;
    sk[31] = (uint8_t)((sk[31] & 127u) | 64u);
    qn_x25519_base(pk, sk);
    return true;
}
