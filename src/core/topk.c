/* Fixed-memory best-K over a stream. */

#include "qanat/topk.h"

#include <string.h>

static uint8_t *at(const qn_topk *h, uint32_t i)
{
    return h->slot + (size_t)i * h->esz;
}

static void swap(qn_topk *h, uint32_t i, uint32_t j)
{
    uint8_t  tmp[256];
    uint8_t *a = at(h, i);
    uint8_t *b = at(h, j);
    uint32_t left = h->esz;

    while (left) {
        uint32_t chunk = left < sizeof tmp ? left : (uint32_t)sizeof tmp;
        memcpy(tmp, a, chunk);
        memcpy(a, b, chunk);
        memcpy(b, tmp, chunk);
        a += chunk;
        b += chunk;
        left -= chunk;
    }
}

bool qn_topk_init(qn_topk *h, qn_arena *a, uint32_t cap, uint32_t esz, qn_topk_cmp cmp)
{
    size_t bytes;

    memset(h, 0, sizeof *h);
    if (!cap || !esz || !cmp || !qn_size_mul((size_t)cap, (size_t)esz, &bytes))
        return false;

    h->slot = (uint8_t *)qn_arena_alloc(a, bytes, 16u);
    if (!h->slot)
        return false;

    h->esz = esz;
    h->cap = cap;
    h->cmp = cmp;
    return true;
}

bool qn_topk_attach(qn_topk *h, void *storage, uint32_t cap, uint32_t esz, qn_topk_cmp cmp)
{
    memset(h, 0, sizeof *h);
    if (!storage || !cap || !esz || !cmp)
        return false;

    h->slot = (uint8_t *)storage;
    h->esz  = esz;
    h->cap  = cap;
    h->cmp  = cmp;
    return true;
}

static void sift_up(qn_topk *h, uint32_t i)
{
    while (i) {
        uint32_t p = (i - 1u) / 2u;
        if (h->cmp(at(h, i), at(h, p)) >= 0)
            break;
        swap(h, i, p);
        i = p;
    }
}

static void sift_down(qn_topk *h, uint32_t i)
{
    for (;;) {
        uint32_t l = 2u * i + 1u;
        uint32_t r = l + 1u;
        uint32_t m = i;

        if (l < h->n && h->cmp(at(h, l), at(h, m)) < 0)
            m = l;
        if (r < h->n && h->cmp(at(h, r), at(h, m)) < 0)
            m = r;
        if (m == i)
            return;
        swap(h, i, m);
        i = m;
    }
}

bool qn_topk_offer(qn_topk *h, const void *item)
{
    h->offered++;

    if (h->n < h->cap) {
        memcpy(at(h, h->n), item, h->esz);
        sift_up(h, h->n);
        h->n++;
        return true;
    }

    if (h->cmp(item, at(h, 0)) <= 0)
        return false;

    memcpy(at(h, 0), item, h->esz);
    sift_down(h, 0);
    h->evicted++;
    return true;
}

uint32_t qn_topk_drain(qn_topk *h, void *dst)
{
    uint32_t n = h->n;
    uint32_t i;

    /* extract-min yields worst-first, so fill back to front */
    for (i = n; i-- > 0;) {
        memcpy((uint8_t *)dst + (size_t)i * h->esz, at(h, 0), h->esz);
        h->n--;
        if (h->n) {
            memcpy(at(h, 0), at(h, h->n), h->esz);
            sift_down(h, 0);
        }
    }
    return n;
}
