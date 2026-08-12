#ifndef QANAT_ARENA_H
#define QANAT_ARENA_H

#include "qanat/util.h"

typedef struct {
    uint8_t *base;
    size_t   cap;
    size_t   used;
    size_t   peak;
} qn_arena;

bool  qn_arena_init(qn_arena *a, size_t cap);
void  qn_arena_free(qn_arena *a);
void  qn_arena_prefault(qn_arena *a);
void  qn_arena_reset(qn_arena *a);
void *qn_arena_alloc(qn_arena *a, size_t n, size_t align);
void *qn_arena_array(qn_arena *a, size_t item_size, size_t count, size_t align);

#define QN_ARENA_NEW(a, T)      ((T *)qn_arena_alloc((a), sizeof(T), _Alignof(T)))
#define QN_ARENA_ARRAY(a, T, n) \
    ((T *)qn_arena_array((a), sizeof(T), (size_t)(n), _Alignof(T)))
#define QN_ARENA_LINE(a, T, n) \
    ((T *)qn_arena_array((a), sizeof(T), (size_t)(n), QN_CACHELINE))

#endif /* QANAT_ARENA_H */
