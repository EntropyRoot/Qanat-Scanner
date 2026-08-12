#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/perm.h"

#include <string.h>
#include <unistd.h>

static inline uint64_t rotl(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

void qn_rng_seed(qn_rng *r, uint64_t seed)
{
    for (int i = 0; i < 4; i++) {
        seed += 0x9E3779B97F4A7C15ull;
        r->s[i] = mix64(seed);
    }
    if (!(r->s[0] | r->s[1] | r->s[2] | r->s[3]))
        r->s[0] = 0x2545F4914F6CDD1Dull;
}

uint64_t qn_rng_next(qn_rng *r)
{
    uint64_t res = rotl(r->s[0] + r->s[3], 23) + r->s[0];
    uint64_t t   = r->s[1] << 17;

    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl(r->s[3], 45);
    return res;
}

/* Lemire multiply-shift with rejection. */
uint32_t qn_rng_below(qn_rng *r, uint32_t bound)
{
    uint64_t m;
    uint32_t l;

    if (bound < 2)
        return 0;

    m = (uint64_t)(uint32_t)qn_rng_next(r) * bound;
    l = (uint32_t)m;
    if (QN_UNLIKELY(l < bound)) {
        uint32_t t = (uint32_t)(0u - bound) % bound;
        while (l < t) {
            m = (uint64_t)(uint32_t)qn_rng_next(r) * bound;
            l = (uint32_t)m;
        }
    }
    return (uint32_t)(m >> 32);
}

void qn_rng_bytes(qn_rng *r, uint8_t *dst, size_t n)
{
    while (n >= 8) {
        uint64_t v = qn_rng_next(r);
        memcpy(dst, &v, 8);
        dst += 8;
        n -= 8;
    }
    if (n) {
        uint64_t v = qn_rng_next(r);
        memcpy(dst, &v, n);
    }
}

uint64_t qn_rng_entropy(void)
{
    uint64_t v = 0;

    if (qn_os_entropy(&v, sizeof v) && v)
        return v;
    v = mix64(qn_now_ns() ^ ((uint64_t)getpid() << 32));
    return v ? v : 0xA0761D6478BD642Full;
}

uint64_t qn_seed_derive(uint64_t master, uint64_t domain)
{
    return mix64(master ^ mix64(domain + 0xD1B54A32D192ED03ull));
}

void qn_perm_init(qn_perm *p, uint64_t domain, uint64_t seed)
{
    uint32_t bits = 2;

    memset(p, 0, sizeof *p);
    p->domain = domain;

    /* Rounding a 1-address range up to 2 would hand the caller index 1. */
    if (domain < 2)
        return;

    while (bits < 64 && ((uint64_t)1u << bits) < domain)
        bits += 2;

    p->half   = bits / 2;
    p->hmask  = (p->half >= 32) ? 0xFFFFFFFFu : ((1u << p->half) - 1u);
    p->mask   = (bits >= 64) ? ~0ull : (((uint64_t)1u << bits) - 1u);

    for (int i = 0; i < 4; i++) {
        seed = mix64(seed + 0xA24BAED4963EE407ull);
        p->key[i] = seed;
    }
}

/* Four-round Feistel, cycle-walked to the exact domain. */
uint64_t qn_perm_apply(const qn_perm *p, uint64_t i)
{
    uint64_t x = i;

    if (QN_UNLIKELY(p->domain < 2))
        return 0;
    if (QN_UNLIKELY(x >= p->domain))
        x %= p->domain;

    for (;;) {
        uint32_t l = (uint32_t)((x >> p->half) & p->hmask);
        uint32_t r = (uint32_t)(x & p->hmask);

        for (int k = 0; k < 4; k++) {
            uint32_t prev = r;
            uint32_t f    = (uint32_t)(mix64(((uint64_t)r << 24) ^ p->key[k]) & p->hmask);
            r = l ^ f;
            l = prev;
        }

        x = (((uint64_t)l << p->half) | r) & p->mask;
        if (QN_LIKELY(x < p->domain))
            return x;
    }
}
