#ifndef QANAT_BANDIT_H
#define QANAT_BANDIT_H

#include <stdatomic.h>

#include "qanat/arena.h"
#include "qanat/perm.h"

/* Thompson sampling over address blocks: budget follows what answers. */

typedef struct {
    _Atomic uint32_t alpha; /* successes, offset by one */
    _Atomic uint32_t beta;  /* failures, offset by one */
    _Atomic uint32_t drawn;
} qn_block;

typedef struct {
    qn_block *b;
    uint32_t  n;
    uint32_t  span; /* addresses per block */
    uint64_t  total;
    uint64_t  seed;
    qn_perm   block_order;
    qn_perm   explore_order;
    uint32_t  explore; /* draws per block before exploitation starts */
    uint32_t  probe;   /* blocks sampled per exploit draw */
    uint64_t  explore_total;
    bool      exact_explore;

    _Atomic uint64_t issued;
} qn_bandit;

bool qn_bandit_init(qn_bandit *t, qn_arena *a, uint64_t total, uint32_t span, uint32_t explore,
                    uint64_t seed);
uint32_t qn_bandit_block_count(uint64_t total, uint32_t span);

bool qn_bandit_set_explore_total(qn_bandit *t, uint64_t explore_total);

/* Concurrently maps each monotonic draw to one address until the space is exhausted. */
bool qn_bandit_next(qn_bandit *t, uint64_t step, uint64_t *index_out);

void qn_bandit_report(qn_bandit *t, uint64_t index, bool good);

/* Blocks that have produced at least one success. */
uint32_t qn_bandit_live_blocks(const qn_bandit *t);

#endif /* QANAT_BANDIT_H */
