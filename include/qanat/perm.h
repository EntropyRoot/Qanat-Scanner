#ifndef QANAT_PERM_H
#define QANAT_PERM_H

#include "qanat/util.h"

typedef struct {
    uint64_t s[4];
} qn_rng;

void     qn_rng_seed(qn_rng *r, uint64_t seed);
uint64_t qn_rng_next(qn_rng *r);
uint32_t qn_rng_below(qn_rng *r, uint32_t bound);
void     qn_rng_bytes(qn_rng *r, uint8_t *dst, size_t n);
uint64_t qn_rng_entropy(void);
uint64_t qn_seed_derive(uint64_t master, uint64_t domain);

/* O(1)-memory Feistel permutation with cycle walking. */
typedef struct {
    uint64_t domain;
    uint64_t mask;
    uint32_t half;
    uint32_t hmask;
    uint64_t key[4];
} qn_perm;

void     qn_perm_init(qn_perm *p, uint64_t domain, uint64_t seed);
uint64_t qn_perm_apply(const qn_perm *p, uint64_t i);

#endif /* QANAT_PERM_H */
