#ifndef QANAT_TOPK_H
#define QANAT_TOPK_H

#include "qanat/arena.h"

/* Fixed-memory best-K, so a sweep runs to completion instead of filling up. */

/* Returns >0 when a is better than b, <0 when worse, 0 when equal. */
typedef int (*qn_topk_cmp)(const void *a, const void *b);

typedef struct {
    uint8_t    *slot; /* min-heap on "better": slot[0] is the worst kept */
    uint32_t    esz;
    uint32_t    cap;
    uint32_t    n;
    uint64_t    offered;
    uint64_t    evicted;
    qn_topk_cmp cmp;
} qn_topk;

bool qn_topk_init(qn_topk *h, qn_arena *a, uint32_t cap, uint32_t esz, qn_topk_cmp cmp);

/* Same, over storage the caller already owns. */
bool qn_topk_attach(qn_topk *h, void *storage, uint32_t cap, uint32_t esz, qn_topk_cmp cmp);

/* True when the item was kept, which may have evicted the previous worst. */
bool qn_topk_offer(qn_topk *h, const void *item);

/* Writes the kept items best-first into dst and empties the heap. */
uint32_t qn_topk_drain(qn_topk *h, void *dst);

static inline bool qn_topk_full(const qn_topk *h)
{
    return h->n >= h->cap;
}

#endif /* QANAT_TOPK_H */
