#ifndef QANAT_RING_H
#define QANAT_RING_H

#include <stdatomic.h>

#include "qanat/arena.h"
#include "qanat/util.h"

/* Per-worker SPSC ring; release/acquire is required on ARM64. */
typedef struct {
    _Atomic uint32_t tail QN_ALIGNED(QN_CACHELINE);
    uint32_t              tail_cache;

    _Atomic uint32_t head QN_ALIGNED(QN_CACHELINE);
    uint32_t              head_cache;

    uint8_t *buf QN_ALIGNED(QN_CACHELINE);
    uint32_t         mask;
    uint32_t         esz;
    _Atomic uint64_t dropped;
} qn_ring;

bool     qn_ring_init(qn_ring *r, qn_arena *a, uint32_t cap, uint32_t esz);
void     qn_ring_reset(qn_ring *r);
bool     qn_ring_push(qn_ring *r, const void *item);
uint32_t qn_ring_pop_batch(qn_ring *r, void *dst, uint32_t max);

static inline uint32_t qn_ring_len(const qn_ring *r)
{
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    return t - h;
}

#endif /* QANAT_RING_H */
