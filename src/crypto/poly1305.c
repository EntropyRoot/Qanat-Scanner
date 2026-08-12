/* Poly1305, RFC 8439. 3x44-bit limbs where 128-bit products exist, else 5x26. */

#include "aead_impl.h"

#if defined(__aarch64__)
#include "arm64/backend.h"
#endif

#include <stddef.h>
#include <string.h>

static uint64_t ld64le(const uint8_t *p)
{
    unsigned i;
    uint64_t v = 0;
    for (i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static void st64le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8u * i));
}

#if defined(__SIZEOF_INT128__) && !defined(QN_NO_INT128)

#define M44 0xfffffffffffull
#define M42 0x3ffffffffffull

typedef struct {
    uint64_t r[3], h[3], pad[2];
    uint8_t  buf[16];
    size_t   n;
} poly;

#if defined(__aarch64__)
_Static_assert(offsetof(poly, r) == 0u, "Poly1305 assembly r offset");
_Static_assert(offsetof(poly, h) == 24u, "Poly1305 assembly h offset");
#endif

static void poly_setup(poly *st, const uint8_t key[32])
{
    uint64_t t0 = ld64le(key), t1 = ld64le(key + 8);

    st->r[0] = t0 & 0xffc0fffffffull;
    st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffull;
    st->r[2] = (t1 >> 24) & 0x00ffffffc0full;

    memset(st->h, 0, sizeof st->h);
    st->pad[0] = ld64le(key + 16);
    st->pad[1] = ld64le(key + 24);
    st->n      = 0;
}

static void poly_run_c(poly *st, const uint8_t *m, size_t bytes, uint64_t full)
{
    uint64_t hibit = full ? ((uint64_t)1 << 40) : 0; /* limb 2 starts at bit 88 */
    uint64_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2];
    uint64_t s1 = r1 * 20u, s2 = r2 * 20u;
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];

    while (bytes >= 16u) {
        unsigned __int128 d0, d1, d2;
        uint64_t          c, t0 = ld64le(m), t1 = ld64le(m + 8);

        h0 += t0 & M44;
        h1 += ((t0 >> 44) | (t1 << 20)) & M44;
        h2 += (((t1 >> 24) & M42) | hibit);

        d0 = (unsigned __int128)h0 * r0 + (unsigned __int128)h1 * s2 +
             (unsigned __int128)h2 * s1;
        d1 = (unsigned __int128)h0 * r1 + (unsigned __int128)h1 * r0 +
             (unsigned __int128)h2 * s2;
        d2 = (unsigned __int128)h0 * r2 + (unsigned __int128)h1 * r1 +
             (unsigned __int128)h2 * r0;

        c  = (uint64_t)(d0 >> 44);
        h0 = (uint64_t)d0 & M44;
        d1 += c;
        c  = (uint64_t)(d1 >> 44);
        h1 = (uint64_t)d1 & M44;
        d2 += c;
        c  = (uint64_t)(d2 >> 42);
        h2 = (uint64_t)d2 & M42;
        h0 += c * 5u;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;

        m += 16;
        bytes -= 16u;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
}

static void poly_done(poly *st, uint8_t tag[16])
{
    uint64_t h0, h1, h2, c, g0, g1, g2, t0, t1;

    if (st->n) {
        st->buf[st->n++] = 1u;
        memset(st->buf + st->n, 0, 16u - st->n);
        poly_run_c(st, st->buf, 16u, 0);
    }

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5u;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5u;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;

    g0 = h0 + 5u;
    c  = g0 >> 44;
    g0 &= M44;
    g1 = h1 + c;
    c  = g1 >> 44;
    g1 &= M44;
    g2 = h2 + c - ((uint64_t)1 << 42);

    c = (g2 >> 63) - 1u;
    g0 &= c;
    g1 &= c;
    g2 &= c;
    c  = ~c;
    h0 = (h0 & c) | g0;
    h1 = (h1 & c) | g1;
    h2 = (h2 & c) | g2;

    t0 = st->pad[0];
    t1 = st->pad[1];
    h0 += t0 & M44;
    c = h0 >> 44;
    h0 &= M44;
    h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c;
    c = h1 >> 44;
    h1 &= M44;
    h2 += ((t1 >> 24) & M42) + c;
    h2 &= M42;

    st64le(tag, h0 | (h1 << 44));
    st64le(tag + 8, (h1 >> 20) | (h2 << 24));

    qn_wipe(st, sizeof *st);
}

#else

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   n;
} poly;

static uint32_t ld32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void poly_setup(poly *st, const uint8_t key[32])
{
    st->r[0] = ld32le(key + 0) & 0x03ffffffu;
    st->r[1] = (ld32le(key + 3) >> 2) & 0x03ffff03u;
    st->r[2] = (ld32le(key + 6) >> 4) & 0x03ffc0ffu;
    st->r[3] = (ld32le(key + 9) >> 6) & 0x03f03fffu;
    st->r[4] = (ld32le(key + 12) >> 8) & 0x000fffffu;

    memset(st->h, 0, sizeof st->h);
    st->pad[0] = ld32le(key + 16);
    st->pad[1] = ld32le(key + 20);
    st->pad[2] = ld32le(key + 24);
    st->pad[3] = ld32le(key + 28);
    st->n      = 0;
}

static void poly_run_c(poly *st, const uint8_t *m, size_t bytes, uint64_t hibit_in)
{
    uint32_t hibit = (uint32_t)(hibit_in ? (1u << 24) : 0u);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16u) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += ld32le(m + 0) & 0x03ffffffu;
        h1 += (ld32le(m + 3) >> 2) & 0x03ffffffu;
        h2 += (ld32le(m + 6) >> 4) & 0x03ffffffu;
        h3 += (ld32le(m + 9) >> 6) & 0x03ffffffu;
        h4 += (ld32le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
             (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
             (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
             (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
             (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
             (uint64_t)h4 * r0;

        c  = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & 0x03ffffffu;
        d1 += c;
        c  = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & 0x03ffffffu;
        d2 += c;
        c  = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & 0x03ffffffu;
        d3 += c;
        c  = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & 0x03ffffffu;
        d4 += c;
        c  = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & 0x03ffffffu;
        h0 += c * 5u;
        c = h0 >> 26;
        h0 &= 0x03ffffffu;
        h1 += c;

        m += 16;
        bytes -= 16u;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly_done(poly *st, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t f;

    if (st->n) {
        st->buf[st->n++] = 1u;
        memset(st->buf + st->n, 0, 16u - st->n);
        poly_run_c(st, st->buf, 16u, 0);
    }

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    c = h1 >> 26;
    h1 &= 0x03ffffffu;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ffffffu;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ffffffu;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ffffffu;
    h0 += c * 5u;
    c = h0 >> 26;
    h0 &= 0x03ffffffu;
    h1 += c;

    g0 = h0 + 5u;
    c  = g0 >> 26;
    g0 &= 0x03ffffffu;
    g1 = h1 + c;
    c  = g1 >> 26;
    g1 &= 0x03ffffffu;
    g2 = h2 + c;
    c  = g2 >> 26;
    g2 &= 0x03ffffffu;
    g3 = h3 + c;
    c  = g3 >> 26;
    g3 &= 0x03ffffffu;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1u;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0   = (h0 & mask) | g0;
    h1   = (h1 & mask) | g1;
    h2   = (h2 & mask) | g2;
    h3   = (h3 & mask) | g3;
    h4   = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffffu;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

    f  = (uint64_t)h0 + st->pad[0];
    h0 = (uint32_t)f;
    f  = (uint64_t)h1 + st->pad[1] + (f >> 32);
    h1 = (uint32_t)f;
    f  = (uint64_t)h2 + st->pad[2] + (f >> 32);
    h2 = (uint32_t)f;
    f  = (uint64_t)h3 + st->pad[3] + (f >> 32);
    h3 = (uint32_t)f;

    st64le(tag, (uint64_t)h0 | ((uint64_t)h1 << 32));
    st64le(tag + 8, (uint64_t)h2 | ((uint64_t)h3 << 32));

    qn_wipe(st, sizeof *st);
}

#endif

#if defined(__aarch64__) && defined(__SIZEOF_INT128__) && !defined(QN_NO_INT128)
void qn_poly1305_blocks_aarch64(qn_poly1305 *st, const uint8_t *m, size_t blocks,
                                 uint64_t full);
#endif

static void poly_run(poly *st, const uint8_t *m, size_t bytes, uint64_t full)
{
#if defined(__aarch64__) && defined(__SIZEOF_INT128__) && !defined(QN_NO_INT128)
    if (qn_crypto_backend_enabled(QN_BACKEND_POLY1305_ASM)) {
        qn_poly1305_blocks_aarch64((qn_poly1305 *)st, m, bytes / 16u,
                                   full != 0u ? 1u : 0u);
        return;
    }
#endif
    poly_run_c(st, m, bytes, full);
}

_Static_assert(sizeof(poly) <= sizeof(qn_poly1305), "poly1305 state does not fit");

void qn_poly1305_init(qn_poly1305 *o, const uint8_t key[32])
{
    poly_setup((poly *)o, key);
}

void qn_poly1305_update(qn_poly1305 *o, const uint8_t *m, size_t n)
{
    poly *st = (poly *)o;

    if (st->n) {
        size_t take = 16u - st->n;
        if (take > n)
            take = n;
        memcpy(st->buf + st->n, m, take);
        st->n += take;
        m += take;
        n -= take;
        if (st->n == 16u) {
            poly_run(st, st->buf, 16u, 1u);
            st->n = 0;
        }
    }
    if (n >= 16u) {
        size_t whole = n & ~(size_t)15u;
        poly_run(st, m, whole, 1u);
        m += whole;
        n -= whole;
    }
    if (n) {
        memcpy(st->buf, m, n);
        st->n = n;
    }
}

void qn_poly1305_final(qn_poly1305 *o, uint8_t tag[16])
{
    poly_done((poly *)o, tag);
}

#if defined(QN_CRYPTO_TESTING)
void qn_poly1305_blocks_c(qn_poly1305 *o, const uint8_t *m, size_t blocks, uint64_t full)
{
    poly_run_c((poly *)o, m, blocks * 16u, full);
}
#endif
