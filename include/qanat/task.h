#ifndef QANAT_TASK_H
#define QANAT_TASK_H

#include <stdatomic.h>

#include "qanat/bandit.h"
#include "qanat/cidr.h"
#include "qanat/engine.h"
#include "qanat/netinfo.h"
#include "qanat/sprt.h"
#include "qanat/stats.h"
#include "qanat/store.h"
#include "qanat/topk.h"

typedef enum {
    CF_PHASE_SWEEP = 0,
    CF_PHASE_TLS,
    CF_PHASE_RTT,
    CF_PHASE_DONE
} cf_phase;

const char *cf_phase_str(cf_phase p);

typedef struct {
    qn_cidr_set set;
    qn_bandit   bandit;
    qn_perm     uniform;
    char        oper[QN_OPERATOR_TAG_LEN];
    qn_store    store;
    qn_arena   *arena;
    qn_arena    candidate_arena;
    bool        candidate_arena_live;
    pthread_mutex_t records_lock;
    bool            records_lock_live;

    cf_record *rec;
    uint32_t   n, cap;
    /* Reachable target clamped to allocated capacity; 0 selects streaming Top-K. */
    uint32_t   limit;
    qn_topk    keep; /* best-K over rec when there is no --limit */
    qn_sprt   *spr;  /* per-record sequential budget gate during measurement */
    uint32_t  *rtt_baseline_us; /* fixed after three successful calibration RTTs */
    uint32_t  *selection_scratch; /* bounded hash workspace for diversity selection */

    uint32_t *finalist; /* calibration order until robust finalist selection completes */
    uint32_t  ncalibration;
    uint32_t  nfinalist;
    uint32_t *active;   /* only unresolved SPRT members */
    uint32_t  nactive;

    cf_phase     phase;
    int          step;
    uint8_t      rtt_round;
    bool         rtt_ready;
    bool         verified;
    bool         history_writable;
    _Atomic bool full;
    uint32_t reached;
    uint64_t candidate_dropped;
    uint64_t candidate_replaced;
    uint64_t late_reachable_discarded;
    bool     candidate_truncated;
    uint32_t input_prefixes;
    uint32_t normalized_prefixes;
    uint64_t input_addresses;
    uint64_t duplicate_addresses;
    uint64_t sweep_completed; /* one terminal event per scheduled address */
    qn_engine_snapshot sweep_stats;
    uint32_t suspected;
    uint32_t inconclusive;
    uint32_t local_errors;
    uint32_t clean;
    uint32_t edges;
    uint32_t verify_attempted;
    uint32_t verify_completed;
    int32_t  verify_errno;
    uint8_t  verify_state;
    _Atomic bool tunnel_active;
    qn_run_outcome tunnel_outcome;
    _Atomic uint32_t tunnel_queued;
    _Atomic uint32_t tunnel_passed;
    _Atomic uint32_t tunnel_failed;
    _Atomic uint32_t tunnel_skipped;

    /* SHA-256 of the range file this run actually parsed. */
    uint8_t  ranges_digest[32];
    uint64_t ranges_bytes;

    /* Set when history or the event log could not be written; the UI shows it. */
    char io_warn[96];

    const qn_config *cfg;
    qn_task          task;
    qn_hist          hist;
    const _Atomic bool *cancel;
    _Atomic size_t     *verify_done;
    _Atomic size_t     *verify_total;
} cf_scan;

bool cf_scan_init(cf_scan *s, qn_arena *a, qn_config *cfg);
bool cf_scan_next_phase(cf_scan *s);
bool cf_scan_verify(cf_scan *s);
qn_run_outcome cf_scan_tunnel(cf_scan *s);
void cf_scan_finish(cf_scan *s);
void cf_scan_destroy(cf_scan *s);
void cf_scan_account_phase(cf_scan *s, const qn_engine_finalization *finalization);

enum {
    PORT_ST_UNKNOWN = 0,
    PORT_ST_OPEN,
    PORT_ST_CLOSED,
    PORT_ST_FILTERED,
    PORT_ST_UNREACHABLE,
    PORT_ST_LOCAL_ERROR,
    PORT_ST_CANCELLED,
    PORT_ST_RESET
};

typedef enum {
    PORT_PHASE_SWEEP = 0,
    PORT_PHASE_RETRY,
    PORT_PHASE_BANNER,
    PORT_PHASE_DONE
} port_phase;

const char *port_phase_str(port_phase p);

typedef struct {
    qn_addr   target;
    char      target_str[QN_ADDRSTRLEN];
    uint16_t *ports;
    uint32_t  nports;
    qn_perm   perm;

    uint8_t  *pstate;
    uint16_t *retry;
    uint32_t  nretry;

    port_record *open;
    uint32_t     nopen, opencap;

    uint32_t scanned;
    uint32_t refused;
    uint32_t filtered;
    uint32_t unreachable;
    uint32_t local_errors;
    uint32_t cancelled;
    uint32_t reset;

    port_phase phase;
    int        step;
    uint32_t   retry_round;

    const qn_config *cfg;
    qn_task          task;
    qn_hist          hist;
} port_scan;

bool port_scan_init(port_scan *s, qn_arena *a, const qn_config *cfg);
bool port_scan_next_phase(port_scan *s);
void port_scan_finish(port_scan *s);
/* "top", "-"/"all", or "22,80,443,8000-8100". */
bool qn_parse_ports(const char *spec, uint16_t *out, uint32_t cap, uint32_t *n);

const char *qn_service_name(uint16_t port);
const uint16_t *qn_top_ports(uint32_t *count);

#define QN_DISCOVER_MAX_HOSTS 65536u

typedef struct {
    qn_prefix prefix;
    char      prefix_str[64];

    host_record *host;
    uint32_t     n, cap;

    uint8_t  *seen;
    uint32_t *slot;
    uint32_t *tcp_host;
    uint32_t  ntcp_host;
    uint64_t *icmp_sent_ns;
    uint32_t  span;
    uint32_t  first_host;
    uint32_t  host_count;

    /* Unpredictable per run: a reply must quote what only our probe carried. */
    uint64_t icmp_nonce;

    uint32_t probed;
    uint32_t total;
    /* Distinct units: probes issued, probes answered, hosts newly found. */
    uint32_t icmp_attempted;
    uint32_t icmp_replied;
    uint32_t icmp_found;
    uint32_t icmp_unsent;
    uint32_t icmp_rejected; /* replies that failed validation */
    uint32_t tcp_attempted;
    uint32_t tcp_completed;
    qn_run_outcome icmp_outcome;
    int            icmp_errno;
    _Atomic bool  *cancel;
    bool     icmp_ok;

    int step;

    const qn_config *cfg;
    qn_task          task;
} host_discover;

bool host_discover_init(host_discover *s, qn_arena *a, const qn_config *cfg);
qn_run_outcome host_discover_icmp(host_discover *s, uint32_t timeout_ms);
bool host_discover_next_phase(host_discover *s);
void host_discover_finish(host_discover *s);
const uint16_t *qn_discover_ports(uint32_t *count);

qn_run_outcome qn_export_json(const char *path, const cf_scan *cf,
                              const port_scan *ps, const host_discover *hd,
                              const qn_netinfo *ni);
bool qn_export_fmt_parse(const char *s, uint8_t *out);
qn_run_outcome qn_export_config(const char *path, uint8_t fmt, const cf_scan *cf);

qn_run_outcome qn_export_csv(const char *path, const cf_scan *cf,
                             const port_scan *ps, const host_discover *hd);

#if defined(QN_EXPORT_TESTING)
typedef enum {
    QN_EXPORT_TEST_NONE = 0,
    QN_EXPORT_TEST_SHORT_WRITE,
    QN_EXPORT_TEST_FSYNC,
    QN_EXPORT_TEST_RENAME
} qn_export_test_fault;

void qn_export_test_set_fault(qn_export_test_fault fault);
#endif

extern const char *const qn_cf_v4[];
extern const uint32_t    qn_cf_v4_n;
extern const char *const qn_cf_updated;

#endif /* QANAT_TASK_H */
