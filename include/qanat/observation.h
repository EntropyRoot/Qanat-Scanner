#ifndef QANAT_OBSERVATION_H
#define QANAT_OBSERVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qanat/probe.h"

typedef enum {
    QN_HTTP_PROTOCOL_NONE = 0,
    QN_HTTP_PROTOCOL_1,
    QN_HTTP_PROTOCOL_2
} qn_http_protocol;

enum {
    QN_HTTP_FACT_NONE = 0,
    QN_HTTP_FACT_HEADERS = 1u << 0,
    QN_HTTP_FACT_BODY = 1u << 1,
    QN_HTTP_FACT_DONE = 1u << 2,
    QN_HTTP_FACT_INFORMATIONAL = 1u << 3,
    QN_HTTP_FACT_TRACE_COLO = 1u << 4,
    QN_HTTP_FACT_CF_RAY = 1u << 5,
    QN_HTTP_FACT_SERVER_CLOUDFLARE = 1u << 6,
    QN_HTTP_FACT_RESET = 1u << 7,
    /* A trailing header block carries no status and replaces nothing. */
    QN_HTTP_FACT_TRAILERS = 1u << 8
};

typedef struct {
    uint32_t flags;
    uint32_t stream_id;
    uint32_t response_index;
    uint64_t body_bytes;
    uint16_t status;
    char     colo[4];
} qn_http_event;

typedef struct {
    bool     attempted;
    bool     connected;
    uint8_t  result;
    uint32_t connect_us;
} qn_transport_observation;

typedef struct {
    bool     handshake_complete;
    uint8_t  outcome;
    uint8_t  cert_state;
    uint16_t version;
    uint16_t suite;
    uint32_t handshake_us;
    char     alpn[16];
    char     peer_cn[48];
    char     peer_issuer[48];
} qn_tls_observation;

typedef struct {
    uint8_t  protocol;
    bool     request_queued;
    bool     request_fully_flushed;
    bool     final_headers;
    bool     trailers;
    bool     response_complete;
    bool     cf_ray;
    bool     server_cloudflare;
    bool     trace_colo;
    uint16_t status;
    uint32_t informational_responses;
    uint64_t body_bytes;
    uint32_t app_first_us;
    uint32_t ttfb_us;
    uint32_t trace_body_us;
    char     colo[4];
} qn_http_observation;

typedef struct {
    bool weak_header;
    bool trace_colo;
    bool verified;
    char colo[4];
} qn_edge_observation;

typedef struct {
    bool     request_queued;
    bool     request_fully_flushed;
    uint64_t requested;
    uint64_t received;
    uint32_t kbps;
    uint32_t partial_kbps;
    uint32_t stall_us;
    bool     completed;
} qn_flow_observation;

typedef struct {
    uint32_t requested_ms;
    uint32_t held_ms;
    bool     admitted;
    bool     capacity_limited;
    bool     survived;
} qn_stability_observation;

typedef struct {
    uint8_t origin;
    uint8_t outcome;
    int32_t sys_errno;
    int32_t protocol_code;
    char    reason[24];
} qn_terminal_observation;

typedef struct {
    qn_transport_observation transport;
    qn_tls_observation       tls;
    qn_http_observation      http;
    qn_edge_observation      edge;
    qn_flow_observation      flow;
    qn_stability_observation stability;
    qn_terminal_observation  terminal;
    uint64_t                 bytes;
    bool                     completed;
} qn_observation;

void qn_observation_init(qn_observation *observation);
void qn_observation_apply_http(qn_observation *observation,
                               const qn_http_event *event);
void qn_edge_policy_apply(qn_observation *observation);
void qn_observation_fail(qn_observation *observation,
                         qn_terminal_outcome outcome,
                         qn_failure_origin origin, int sys_errno,
                         int protocol_code, const char *reason);
qn_classification qn_observation_classify(const qn_observation *observation);

#endif /* QANAT_OBSERVATION_H */
