#ifndef QANAT_TIMEWHEEL_H
#define QANAT_TIMEWHEEL_H

#include "qanat/arena.h"
#include "qanat/util.h"

#define QN_TW_SLOTS   1024u
#define QN_TW_TICK_MS 8u

/* O(1) deadline arm, disarm and expiry. */
typedef struct qn_tw_node {
    struct qn_tw_node *prev, *next;
    uint64_t           deadline_ms;
    uint32_t           slot;
    uint32_t           armed;
} qn_tw_node;

/* cursor_tick is absolute, not modulo: a whole revolution must stay visible. */
typedef struct {
    qn_tw_node *slot[QN_TW_SLOTS];
    uint64_t    now_ms;
    uint64_t    cursor_tick;
    uint32_t    armed;
} qn_timewheel;

void qn_tw_init(qn_timewheel *w, uint64_t now_ms);

/* Advancing from caller-supplied now_ms prevents stale clocks shortening budgets. */
void qn_tw_arm(qn_timewheel *w, qn_tw_node *n, uint64_t now_ms, uint32_t after_ms);
void qn_tw_disarm(qn_timewheel *w, qn_tw_node *n);

/* Pops one expired node, or NULL when caught up. */
qn_tw_node *qn_tw_expire(qn_timewheel *w, uint64_t now_ms);

/* Milliseconds until the next possible expiry; clamps to `cap`. */
uint32_t qn_tw_next_timeout(const qn_timewheel *w, uint64_t now_ms, uint32_t cap);

#endif /* QANAT_TIMEWHEEL_H */
