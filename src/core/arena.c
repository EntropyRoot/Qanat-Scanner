#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/arena.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool qn_arena_init(qn_arena *a, size_t cap)
{
    long   pg = sysconf(_SC_PAGESIZE);
    size_t page = pg > 0 ? (size_t)pg : 4096u;
    void  *p;

    if (!a || !cap || cap > SIZE_MAX - (page - 1u))
        return false;
    memset(a, 0, sizeof *a);
    cap = (cap + page - 1) & ~(page - 1);
    p   = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return false;

    a->base = (uint8_t *)p;
    a->cap  = cap;
    a->used = 0;
    a->peak = 0;
    return true;
}

void qn_arena_free(qn_arena *a)
{
    if (a->base) {
        munmap(a->base, a->cap);
        a->base = NULL;
        a->cap = a->used = a->peak = 0;
    }
}

/* Pre-fault without changing live arena bytes. */
void qn_arena_prefault(qn_arena *a)
{
    long   pg   = sysconf(_SC_PAGESIZE);
    size_t page = pg > 0 ? (size_t)pg : 4096u;

    if (!a->base)
        return;
#ifdef MADV_WILLNEED
    madvise(a->base, a->cap, MADV_WILLNEED);
#endif
    for (size_t i = 0; i < a->cap; i += page) {
        volatile uint8_t *p = (volatile uint8_t *)a->base + i;
        uint8_t value = *p;
        *p = value;
    }
}

void qn_arena_reset(qn_arena *a)
{
    if (a->used > a->peak)
        a->peak = a->used;
    a->used = 0;
}

void *qn_arena_alloc(qn_arena *a, size_t n, size_t align)
{
    size_t off;

    if (!a || !a->base || !n || !align || (align & (align - 1u)) != 0u ||
        a->used > SIZE_MAX - (align - 1u))
        return NULL;
    off = (a->used + align - 1) & ~(align - 1);
    if (QN_UNLIKELY(off > a->cap || n > a->cap - off))
        return NULL;

    a->used = off + n;
    if (a->used > a->peak)
        a->peak = a->used;
    memset(a->base + off, 0, n);
    return a->base + off;
}

void *qn_arena_array(qn_arena *a, size_t item_size, size_t count, size_t align)
{
    if (!item_size || !count || item_size > SIZE_MAX / count)
        return NULL;
    return qn_arena_alloc(a, item_size * count, align);
}
