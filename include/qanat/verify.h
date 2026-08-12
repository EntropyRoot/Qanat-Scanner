#ifndef QANAT_VERIFY_H
#define QANAT_VERIFY_H

#include <stdatomic.h>

#include "qanat/observation.h"
#include "qanat/outcome.h"
#include "qanat/profile.h"
#include "qanat/tls.h"
#include "qanat/tunnel.h"

/* Full TLS sessions use a separate bounded verifier over the finalist set. */

typedef struct {
    qn_addr           addr;
    qn_observation    observation;
    qn_classification classification;
} qn_verify_result;

typedef enum {
    QN_VERIFY_COMPLETE = 0,
    QN_VERIFY_PARTIAL,
    QN_VERIFY_CANCELLED,
    QN_VERIFY_INFRA_FAILURE
} qn_verify_state;

/* attempted + unattempted == n, and completed + cancelled == attempted. */
typedef struct {
    qn_verify_state state;
    uint32_t        attempted;
    uint32_t        completed;
    uint32_t        cancelled;
    uint32_t        unattempted;
    uint32_t        handshakes;
    uint32_t        active_limit;
    uint32_t        stability_limit;
    uint32_t        peak_active;
    uint32_t        peak_stability;
    int             fatal_errno;
} qn_verify_status;

typedef struct {
    uint32_t active;
    uint32_t stability;
    uint32_t total;
} qn_verify_pool_plan;

typedef struct {
    const qn_profile_instance *profile;
    const char *sni;
    const char *trace_path;
    const char *flow_path;
    qn_tls_fp   fp;
    bool        allow_tls12;
    /* Refuse a compressed certificate rather than accept it opaquely. */
    bool        cert_strict;
    uint16_t    port;
    bool        socks_enabled;
    qn_addr     socks_address;
    uint16_t    socks_port;
    const char *socks_target_host;
    uint16_t    socks_target_port;
    uint32_t    concurrency;
    uint32_t    stability_concurrency;
    uint32_t    timeout_ms;
    uint32_t    idle_ms;    /* hold after the body to catch a late reset */
    uint32_t    want_bytes; /* bulk sample target; 0 disables the flow stage */
    uint64_t    seed;       /* master seed when deterministic is true */
    bool        deterministic;
    const _Atomic bool *cancel;
    _Atomic size_t     *progress_done;
    _Atomic size_t     *progress_total;
    size_t              progress_base;
    size_t              progress_grand_total;
} qn_verify_cfg;

bool qn_verify_plan_pools(uint32_t active, uint32_t stability,
                          uint32_t idle_ms, size_t candidates,
                          uint32_t fd_budget, qn_verify_pool_plan *out);

size_t qn_verify_slot_bytes(void);
size_t qn_verify_result_bytes(void);
size_t qn_verify_fixed_bytes(void);

void qn_verify_defaults(qn_verify_cfg *c);
qn_run_outcome qn_verify_run_outcome(qn_verify_state state);

/* Peer observations and verifier health are separate contracts. */
qn_verify_status qn_verify_run(const qn_verify_cfg *cfg, const qn_addr *addrs, size_t n,
                               qn_verify_result *out);

/* Reports the fingerprint the pass will present, for --fingerprint output. */
bool qn_verify_fingerprint(const qn_verify_cfg *cfg, char ja3[33], char ja4[40]);

#if defined(QN_VERIFY_TESTING)
typedef enum {
    QN_VERIFY_TEST_NONE = 0,
    QN_VERIFY_TEST_WORK_ALLOC,
    QN_VERIFY_TEST_EPOLL_CREATE,
    QN_VERIFY_TEST_SLOT_ALLOC,
    QN_VERIFY_TEST_INBUF_ALLOC,
    QN_VERIFY_TEST_APPBUF_ALLOC,
    QN_VERIFY_TEST_SOCKET,
    QN_VERIFY_TEST_EPOLL_CTL,
    QN_VERIFY_TEST_EPOLL_WAIT,
    QN_VERIFY_TEST_READ,
    QN_VERIFY_TEST_SHORT_WRITE
} qn_verify_test_fault;

void qn_verify_test_set_fault(qn_verify_test_fault fault);
bool qn_verify_test_short_write_seen(void);
#endif

#endif /* QANAT_VERIFY_H */
