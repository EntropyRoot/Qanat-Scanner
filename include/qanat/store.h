#ifndef QANAT_STORE_H
#define QANAT_STORE_H

#include "qanat/arena.h"
#include "qanat/netinfo.h"
#include "qanat/qanat.h"

/* Repeated observations across paths outweigh one moment, and old evidence decays. */

#define QN_STORE_HALFLIFE_SEC (3u * 86400u)

/* Bump when a column changes meaning; the loader refuses what it cannot read. */
#define QN_STORE_SCHEMA 2u

typedef struct {
    qn_addr  addr;
    uint64_t last_seen;
    uint32_t runs;
    uint32_t score_q10;  /* decayed successes */
    uint32_t weight_q10; /* decayed observations */
    uint32_t oper_mask;  /* one bit per distinct path tag */
    /* A full TLS handshake, never a round trip: v1 wrote this under an rtt name. */
    uint32_t handshake_us;
} qn_store_entry;

typedef struct {
    qn_store_entry *e;
    uint32_t        n, cap;
} qn_store;

bool qn_store_init(qn_store *s, qn_arena *a, uint32_t cap);
bool qn_store_load(qn_store *s, const char *path);
bool qn_store_save(const qn_store *s, const char *path);

void qn_store_observe(qn_store *s, const qn_addr *a, const char *oper, bool good,
                      uint32_t handshake_us, uint64_t now);

/* Confidence 0..1000 blends decayed success with distinct paths and runs. */
uint32_t qn_store_confidence(const qn_store *s, const qn_addr *a, uint64_t now);

const qn_store_entry *qn_store_find(const qn_store *s, const qn_addr *a);

#endif /* QANAT_STORE_H */
