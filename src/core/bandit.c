/* Beta-Bernoulli bandit over address blocks, sampled Thompson-style. */

#include "qanat/bandit.h"

#include <string.h>

#define Q 16u
#define ONE (1u << Q)
#define QN_BANDIT_MAX_BLOCKS 65536u

static bool bandit_shape(uint64_t total, uint32_t requested_span,
                         uint32_t *span, uint32_t *blocks)
{
    uint64_t need_span, count;

    if (!total || !requested_span || !span || !blocks)
        return false;
    need_span = total / QN_BANDIT_MAX_BLOCKS;
    if (total % QN_BANDIT_MAX_BLOCKS)
        need_span++;
    if (need_span > UINT32_MAX)
        return false;
    *span = QN_MAX(requested_span, (uint32_t)need_span);
    count = total / *span + (total % *span != 0u);
    if (!count || count > QN_BANDIT_MAX_BLOCKS)
        return false;
    *blocks = (uint32_t)count;
    return true;
}

uint32_t qn_bandit_block_count(uint64_t total, uint32_t span)
{
    uint32_t actual_span, blocks;

    return bandit_shape(total, span, &actual_span, &blocks) ? blocks : 0u;
}

static uint64_t mix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

static uint32_t gcd32(uint32_t a, uint32_t b)
{
    while (b) {
        uint32_t r = a % b;
        a = b;
        b = r;
    }
    return a;
}

/* A coprime affine map permutes every offset even in a short final block. */
static uint32_t block_perm(uint32_t c, uint32_t span, uint64_t key)
{
    uint32_t a, b;

    if (span < 2u)
        return 0u;
    a = (uint32_t)(mix64(key ^ 0xA24BAED4963EE407ull) % span);
    if (!a)
        a = 1u;
    while (gcd32(a, span) != 1u) {
        a++;
        if (a == span)
            a = 1u;
    }
    b = (uint32_t)(mix64(key ^ 0x9FB21C651E98DF25ull) % span);
    return (uint32_t)(((uint64_t)a * c + b) % span);
}

static uint32_t isqrt32(uint32_t v)
{
    uint32_t r = 0, bit = 1u << 30;

    while (bit > v)
        bit >>= 2;
    while (bit) {
        if (v >= r + bit) {
            v -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    return r;
}

/* Beta as a moment-matched normal, normal as an Irwin-Hall sum: no libm. */
static int32_t thompson_score(uint32_t a, uint32_t b, uint64_t *rng)
{
    uint64_t n  = (uint64_t)a + b;
    uint32_t mu = (uint32_t)(((uint64_t)a << Q) / n);
    uint32_t var, sigma;
    int32_t  z = 0;
    unsigned i;

    var = (uint32_t)(((uint64_t)mu * (ONE - mu)) >> Q);
    var = (uint32_t)(var / (n + 1u));
    sigma = isqrt32(var << Q);

    for (i = 0; i < 12u; i++) {
        *rng = mix64(*rng);
        z += (int32_t)(*rng & 0xFFFFu);
    }
    z -= 12 * 32768;

    return (int32_t)mu + (int32_t)(((int64_t)sigma * z) >> Q);
}

bool qn_bandit_init(qn_bandit *t, qn_arena *a, uint64_t total, uint32_t span, uint32_t explore,
                    uint64_t seed)
{
    uint32_t actual_span, blocks;
    uint32_t i;

    memset(t, 0, sizeof *t);
    if (!bandit_shape(total, span, &actual_span, &blocks))
        return false;

    t->total   = total;
    t->span    = actual_span;
    t->seed    = seed; /* an explicit all-zero master seed is valid */
    t->explore = explore ? explore : 2u;
    t->probe   = 48u;
    t->n       = blocks;
    qn_perm_init(&t->block_order, t->n, mix64(t->seed ^ 0xA5A5ull));

    t->b = QN_ARENA_ARRAY(a, qn_block, t->n);
    if (!t->b)
        return false;

    for (i = 0; i < t->n; i++) {
        atomic_store_explicit(&t->b[i].alpha, 1u, memory_order_relaxed);
        atomic_store_explicit(&t->b[i].beta, 1u, memory_order_relaxed);
        atomic_store_explicit(&t->b[i].drawn, 0u, memory_order_relaxed);
    }
    return true;
}

static uint32_t block_span(const qn_bandit *t, uint32_t blk)
{
    uint64_t base = (uint64_t)blk * t->span;
    uint64_t left = t->total - base;
    return left < t->span ? (uint32_t)left : t->span;
}

static bool mul_div_floor(uint64_t a, uint64_t b, uint64_t d, uint64_t *out)
{
    uint64_t q = 0u, r = 0u;

    if (!out || !d || a > d || b > d)
        return false;
    for (unsigned bit = 64u; bit-- > 0u;) {
        if (q > UINT64_MAX / 2u)
            return false;
        q *= 2u;
        if (r >= d - r) {
            r -= d - r;
            q++;
        } else {
            r *= 2u;
        }
        if ((b >> bit) & 1u) {
            if (r >= d - a) {
                r -= d - a;
                if (q == UINT64_MAX)
                    return false;
                q++;
            } else {
                r += a;
            }
        }
    }
    *out = q;
    return true;
}

static uint64_t block_capacity_prefix(const qn_bandit *t, uint32_t blocks)
{
    uint64_t capacity;

    if (!blocks)
        return 0u;
    capacity = (uint64_t)blocks * t->span;
    return capacity < t->total ? capacity : t->total;
}

static bool explore_quota_prefix(const qn_bandit *t, uint32_t blocks,
                                 uint64_t *quota)
{
    uint64_t capacity = block_capacity_prefix(t, blocks);
    uint64_t apportioned;

    if (!blocks) {
        *quota = 0u;
        return true;
    }
    if (blocks >= t->n) {
        *quota = t->explore_total;
        return true;
    }
    if (t->explore_total >= t->n) {
        uint64_t remainder_budget = t->explore_total - t->n;
        uint64_t remainder_total = t->total - t->n;
        uint64_t remainder_capacity = capacity - blocks;

        if (!remainder_total) {
            *quota = blocks;
            return true;
        }
        if (!mul_div_floor(remainder_budget, remainder_capacity,
                           remainder_total, &apportioned))
            return false;
        *quota = blocks + apportioned;
        return true;
    }
    if (!mul_div_floor(t->explore_total, capacity, t->total, &apportioned))
        return false;
    *quota = apportioned;
    return true;
}

bool qn_bandit_set_explore_total(qn_bandit *t, uint64_t explore_total)
{
    uint64_t previous = 0u;

    if (!t || !t->b || explore_total > t->total ||
        atomic_load_explicit(&t->issued, memory_order_relaxed) != 0u)
        return false;
    t->explore_total = explore_total;
    t->exact_explore = true;
    qn_perm_init(&t->explore_order, explore_total,
                 mix64(t->seed ^ UINT64_C(0x5354524154494659)));
    for (uint32_t block = 0u; block < t->n; block++) {
        uint64_t cumulative;

        if (!explore_quota_prefix(t, block + 1u, &cumulative) ||
            cumulative < previous || cumulative - previous > block_span(t, block))
            return false;
        atomic_store_explicit(&t->b[block].drawn,
                              (uint32_t)(cumulative - previous),
                              memory_order_relaxed);
        previous = cumulative;
    }
    return previous == explore_total;
}

static bool exact_explore_next(qn_bandit *t, uint64_t step, uint64_t *out)
{
    uint64_t mapped = qn_perm_apply(&t->explore_order, step);
    uint32_t lo = 0u, hi = t->n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        uint64_t cumulative;

        if (!explore_quota_prefix(t, mid + 1u, &cumulative))
            return false;
        if (mapped < cumulative)
            hi = mid;
        else
            lo = mid + 1u;
    }
    if (lo >= t->n)
        return false;
    {
        uint64_t previous;
        uint64_t local;
        uint32_t span = block_span(t, lo);

        if (!explore_quota_prefix(t, lo, &previous))
            return false;
        local = mapped - previous;
        if (local >= span)
            return false;
        *out = (uint64_t)lo * t->span +
               block_perm((uint32_t)local, span, mix64(t->seed ^ lo));
    }
    return true;
}

/* Claims one unused offset in blk, or reports the block full. */
static bool take(qn_bandit *t, uint32_t blk, uint64_t *out)
{
    uint32_t span = block_span(t, blk);
    uint32_t c    = atomic_fetch_add_explicit(&t->b[blk].drawn, 1u, memory_order_relaxed);

    if (c >= span) {
        atomic_fetch_sub_explicit(&t->b[blk].drawn, 1u, memory_order_relaxed);
        return false;
    }
    *out = (uint64_t)blk * t->span + block_perm(c, span, mix64(t->seed ^ blk));
    return true;
}

bool qn_bandit_next(qn_bandit *t, uint64_t step, uint64_t *index_out)
{
    uint64_t explore_total = (uint64_t)t->n * t->explore;
    uint64_t rng           = mix64(t->seed ^ (step * 0x2545F4914F6CDD1Dull));
    unsigned attempt;

    if (atomic_load_explicit(&t->issued, memory_order_relaxed) >= t->total)
        return false;

    if (t->exact_explore && step < t->explore_total) {
        if (!exact_explore_next(t, step, index_out))
            return false;
        atomic_fetch_add_explicit(&t->issued, 1u, memory_order_relaxed);
        return true;
    }

    /* Permuted exploration samples every block before exploitation favours one. */
    if (!t->exact_explore && step < explore_total) {
        uint32_t blk = (uint32_t)qn_perm_apply(&t->block_order, step % t->n);
        if (take(t, blk, index_out)) {
            atomic_fetch_add_explicit(&t->issued, 1u, memory_order_relaxed);
            return true;
        }
    }

    for (attempt = 0; attempt < 4u; attempt++) {
        uint32_t best = 0;
        int32_t  bestv = -0x7FFFFFFF;
        unsigned i;

        for (i = 0; i < t->probe; i++) {
            uint32_t blk;
            int32_t  v;

            rng = mix64(rng);
            blk = (uint32_t)(rng % t->n);
            if (atomic_load_explicit(&t->b[blk].drawn, memory_order_relaxed) >= block_span(t, blk))
                continue;

            v = thompson_score(atomic_load_explicit(&t->b[blk].alpha, memory_order_relaxed),
                               atomic_load_explicit(&t->b[blk].beta, memory_order_relaxed), &rng);
            if (v > bestv) {
                bestv = v;
                best  = blk;
            }
        }

        if (bestv > -0x7FFFFFFF && take(t, best, index_out)) {
            atomic_fetch_add_explicit(&t->issued, 1u, memory_order_relaxed);
            return true;
        }
    }

    /* Sampling kept landing on full blocks; fall back to a linear search. */
    {
        uint32_t blk;
        for (blk = 0; blk < t->n; blk++) {
            if (take(t, blk, index_out)) {
                atomic_fetch_add_explicit(&t->issued, 1u, memory_order_relaxed);
                return true;
            }
        }
    }
    return false;
}

void qn_bandit_report(qn_bandit *t, uint64_t index, bool good)
{
    uint32_t blk;

    if (index >= t->total)
        return;
    blk = (uint32_t)(index / t->span);
    if (blk >= t->n)
        return;

    if (good)
        atomic_fetch_add_explicit(&t->b[blk].alpha, 1u, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&t->b[blk].beta, 1u, memory_order_relaxed);
}

uint32_t qn_bandit_live_blocks(const qn_bandit *t)
{
    uint32_t i, live = 0;

    for (i = 0; i < t->n; i++)
        if (atomic_load_explicit(&t->b[i].alpha, memory_order_relaxed) > 1u)
            live++;
    return live;
}
