#include "qanat/ring.h"

#include <string.h>

static bool pow2_ceil(uint32_t value, uint32_t *result)
{
    uint32_t v = value;

    if (!result || !v || v > (UINT32_C(1) << 31))
        return false;
    if (v < 2u) {
        *result = 2u;
        return true;
    }
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    *result = v + 1u;
    return true;
}

bool qn_ring_init(qn_ring *r, qn_arena *a, uint32_t cap, uint32_t esz)
{
    size_t bytes;

    if (!r || !a || !esz || !pow2_ceil(cap, &cap) ||
        !qn_size_mul((size_t)cap, (size_t)esz, &bytes))
        return false;
    r->buf = (uint8_t *)qn_arena_alloc(a, bytes, QN_CACHELINE);
    if (!r->buf)
        return false;

    r->mask       = cap - 1;
    r->esz        = esz;
    r->tail_cache = 0;
    r->head_cache = 0;
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->dropped, 0, memory_order_relaxed);
    return true;
}

/* Only between runs, with the producer joined: there is no ABA-safe reset. */
void qn_ring_reset(qn_ring *r)
{
    r->tail_cache = 0;
    r->head_cache = 0;
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->dropped, 0, memory_order_relaxed);
}

bool qn_ring_push(qn_ring *r, const void *item)
{
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);

    /* Read the consumer line only when the ring looks full. */
    if (QN_UNLIKELY(tail - r->tail_cache > r->mask)) {
        r->tail_cache = atomic_load_explicit(&r->head, memory_order_acquire);
        if (tail - r->tail_cache > r->mask) {
            atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
            return false;
        }
    }

    memcpy(r->buf + (size_t)(tail & r->mask) * r->esz, item, r->esz);
    /* Release: the payload store must be visible before the index. */
    atomic_store_explicit(&r->tail, tail + 1, memory_order_release);
    return true;
}

uint32_t qn_ring_pop_batch(qn_ring *r, void *dst, uint32_t max)
{
    uint32_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t n;

    if (head == r->head_cache) {
        r->head_cache = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (head == r->head_cache)
            return 0;
    }

    n = r->head_cache - head;
    if (n > max)
        n = max;

    for (uint32_t i = 0; i < n; i++)
        memcpy((uint8_t *)dst + (size_t)i * r->esz,
               r->buf + (size_t)((head + i) & r->mask) * r->esz, r->esz);

    atomic_store_explicit(&r->head, head + n, memory_order_release);
    return n;
}
