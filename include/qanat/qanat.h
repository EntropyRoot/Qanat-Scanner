#ifndef QANAT_QANAT_H
#define QANAT_QANAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qanat/scan_plan.h"
#include "qanat/tunnel.h"

#define QN_NAME    "qanat"
/* The only place the version is written; the Makefile reads it from here. */
#define QN_VERSION "1.0.0"
#define QN_EXPORT_SCHEMA 7u

/* Names the compiler, target and flags an artifact was actually built with. */
#ifndef QN_BUILD_FINGERPRINT
#define QN_BUILD_FINGERPRINT "unrecorded"
#endif

/* IPv4 uses host order; IPv6 uses network bytes. */
typedef struct {
    uint8_t af;
    uint8_t _pad[3];
    union {
        uint32_t v4;
        uint8_t  v6[16];
    } u;
} qn_addr;

#define QN_ADDRSTRLEN 46

typedef enum {
    QN_R_PENDING = 0,
    QN_R_OPEN,
    QN_R_REFUSED,
    QN_R_TIMEOUT,
    QN_R_UNREACH,
    QN_R_RESET,
    QN_R_ERROR,
    QN_R_CANCELLED
} qn_result;

const char *qn_result_str(qn_result r);

/* Failure origin is evidence; only the higher-level classifier assigns a verdict. */
typedef enum {
    QN_FAIL_NONE = 0,
    QN_FAIL_LOCAL,
    QN_FAIL_PEER,
    QN_FAIL_PATH,
    QN_FAIL_PROTOCOL,
    QN_FAIL_UNSUPPORTED,
    QN_FAIL_CANCELLED
} qn_failure_origin;

const char *qn_failure_origin_str(qn_failure_origin origin);

typedef enum {
    QN_RUNG_NONE = 0,
    QN_RUNG_TCP,
    QN_RUNG_TLS,
    QN_RUNG_HTTP,
    QN_RUNG_EDGE,
    QN_RUNG_FLOWING,
    QN_RUNG_STABLE,
    QN_RUNG_COUNT
} qn_highest_rung;

typedef enum {
    QN_TERM_NONE = 0,
    QN_TERM_SUCCESS,
    QN_TERM_DEAD,
    QN_TERM_LOCAL_ERROR,
    QN_TERM_INCONCLUSIVE,
    QN_TERM_PEER_REJECTED,
    QN_TERM_UNSUPPORTED,
    QN_TERM_PROTOCOL_INVALID,
    QN_TERM_RESET,
    QN_TERM_TIMEOUT,
    QN_TERM_CANCELLED,
    QN_TERM_INTERFERENCE,
    QN_TERM_COUNT
} qn_terminal_outcome;

typedef struct {
    qn_highest_rung     highest_rung_reached;
    qn_terminal_outcome terminal_outcome;
} qn_classification;

const char *qn_highest_rung_str(qn_highest_rung rung);
const char *qn_terminal_outcome_str(qn_terminal_outcome outcome);
const char *qn_classification_str(qn_classification classification);
bool        qn_classification_has_tls(qn_classification classification);
bool        qn_classification_has_marker(qn_classification classification);

#define QN_MAX_SAMPLES 12

typedef struct {
    uint32_t rtt_us[QN_MAX_SAMPLES];
    uint8_t  n;
    uint8_t  lost;
} qn_samples;

typedef struct {
    qn_addr    addr;
    uint32_t   rtt_min_us;
    uint32_t   rtt_med_us;
    uint32_t   rtt_p90_us;
    uint32_t   rtt_ci90_lo_us, rtt_ci90_hi_us;
    uint16_t   confidence; /* 0..1000 from stored history */
    uint32_t   rtt_delta_mean_us;
    uint32_t   score;
    uint16_t   score_version;
    uint16_t   score_edge;
    uint16_t   score_latency;
    uint16_t   score_stability;
    uint16_t   score_confidence;
    uint16_t   score_throughput;
    uint16_t   score_tunnel;
    uint8_t    highest_rung_reached;
    uint8_t    terminal_outcome;
    uint8_t    loss_pct;
    uint16_t   http_status;
    char       colo[4];
    uint16_t   tls_version;
    uint16_t   tls_suite;
    uint32_t   handshake_us;
    uint32_t   ttfb_us;
    uint64_t   bytes;
    uint32_t   kbps;
    uint32_t   idle_held_ms;
    int32_t    sys_errno;
    char       alpn[16];
    char       verify_reason[24];
    uint8_t    failure_origin;
    uint8_t    transport_result;
    uint8_t    tls_outcome;
    uint8_t    verified;
    uint8_t    rtt_ci90_valid;
    uint8_t    tunnel_state;
    uint8_t    tunnel_attempts;
    uint16_t   _tunnel_pad;
    uint32_t   tunnel_ttfb_us;
    uint32_t   tunnel_kbps;
    char       tunnel_reason[32];
    qn_samples samples;
} cf_record;

qn_classification qn_cf_record_classification(const cf_record *record);

typedef struct {
    uint16_t port;
    uint8_t  result;
    uint8_t  banner_len;
    uint32_t rtt_us;
    char     banner[56];
} port_record;

typedef struct {
    qn_addr  addr;
    uint32_t rtt_us;
    uint16_t open_hint;
    uint8_t  alive;
    uint8_t  _pad;
    char     name[64];
} host_record;

typedef enum {
    QN_MODE_NONE = 0,
    QN_MODE_PORTS,
    QN_MODE_CF,
    QN_MODE_DISCOVER,
    QN_MODE_NETINFO
} qn_mode;

typedef enum {
    QN_WARM_AUTO = 0,
    QN_WARM_ON,
    QN_WARM_OFF
} qn_warm_mode;

typedef enum {
    QN_DISCOVER_AUTO = 0,
    QN_DISCOVER_ICMP,
    QN_DISCOVER_TCP,
    QN_DISCOVER_BOTH
} qn_discover_method;

typedef struct {
    qn_mode mode;

    const char *target;
    const char *ranges_file;
    char        managed_ranges[1024];
    /* Interactive input needs stable storage while CLI values continue to reference argv. */
    char        input_host[256];
    char        input_prefix[256];
    char        input_port_spec[512];
    char        input_sni[254];
    const char *port_spec;

    const char *sni;
    const struct qn_profile_instance *profile_instance;
    qn_scan_request scan;
    qn_scan_plan    scan_plan;
    bool            scan_plan_valid;
    uint8_t     samples;
    bool        deep;
    bool        v6;
    uint8_t     fingerprint;
    bool        cert_strict;
    uint32_t    flow_bytes;
    uint32_t    idle_ms;
    uint32_t    verify_concurrency;
    uint32_t    stability_concurrency;
    char        input_tunnel_link[QN_TUNNEL_LINK_MAX + 1u];
    char        input_tunnel_file[1024];
    char        input_xray_path[QN_TUNNEL_XRAY_PATH_MAX + 1u];
    const char *tunnel_link;
    const char *tunnel_link_file;
    const char *xray_path;
    bool        tunnel_confirmed;

    uint32_t workers;     /* 0 = auto from CPU topology */
    uint32_t concurrency; /* 0 = auto from rlimit */
    uint32_t rate;        /* 0 = adaptive */
    uint32_t timeout_ms;
    uint32_t retries;
    bool     no_adaptive;
    bool     no_affinity;
    bool     no_thermal;
    bool     select_backend;
    uint8_t  warm_mode;
    uint8_t  discover_method;

    uint64_t    seed; /* numeric master seed, including a valid explicit zero */
    uint64_t    effective_seed; /* always populated before a run starts */
    bool        seed_explicit;
    const char *event_log;
    const char *history;
    const char *export_file;
    uint8_t     export_fmt;
    bool        export_on;

    const char *out_json;
    const char *out_csv;
    bool        headless;
    bool        no_color;
    bool        quiet;
    bool        update_ranges;
} qn_config;

void qn_config_defaults(qn_config *c);

#endif /* QANAT_QANAT_H */
