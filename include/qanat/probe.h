#ifndef QANAT_PROBE_H
#define QANAT_PROBE_H

#include "qanat/perm.h"
#include "qanat/tls_hello.h"
#include "qanat/qanat.h"

/* Holds a modern hybrid ClientHello, then reuses the space for the response. */
#define QN_PROBE_BUF  2304
#define QN_EVENT_BODY 48

typedef enum {
    QN_STAGE_TCP = 0, /* handshake only */
    QN_STAGE_TLS,     /* handshake + ClientHello + ServerHello */
    QN_STAGE_RTT,     /* handshake, timed, discarded */
    QN_STAGE_BANNER   /* handshake + passive read */
} qn_stage;

typedef enum {
    QN_TLS_NONE = 0,
    QN_TLS_SERVERHELLO, /* clean answer */
    QN_TLS_ALERT,       /* server refused: not interference */
    QN_TLS_RESET,       /* RST after ClientHello */
    QN_TLS_SILENCE,     /* no answer after ClientHello */
    QN_TLS_GARBAGE      /* answer was not a TLS record */
} qn_tls_outcome;

const char *qn_tls_outcome_str(qn_tls_outcome o);

/* Builds a browser-shaped ClientHello; returns bytes written or -1. */
/* The cheap screen must present the same identity the verifier will. */
int qn_tls_build_hello(uint8_t *buf, size_t cap, const char *sni, qn_rng *rng,
                       qn_tls_fp fp);
int qn_tls_build_hello_instance(uint8_t *buf, size_t cap,
                                const struct qn_profile_instance *profile,
                                qn_rng *rng);

/* Classifies whatever came back on the wire. */
qn_tls_outcome qn_tls_classify(const uint8_t *buf, size_t len);

int qn_http_build_get(uint8_t *buf, size_t cap, const char *host, const char *path);

typedef struct {
    uint16_t status;
    char     colo[4];
    /* Header hints; forgeable, so supporting evidence only. */
    bool     is_cloudflare;
    bool     cf_ray;
    bool     server_cloudflare;
    /* A colo read from a complete, well-formed trace line. */
    bool     colo_verified;
    bool     complete;
} qn_http_reply;

#define QN_TRACE_LINE_MAX 128u

typedef struct {
    char     colo[4];
    qn_addr  ip;
    uint32_t lines;
    bool     have_colo;
    bool     have_ip;
    bool     conflict;
    bool     malformed;
} qn_trace_body;

/* Strict key=value lines; false unless a valid colo was found. */
bool qn_http_trace_parse(const uint8_t *b, size_t len, qn_trace_body *out);

bool qn_http_parse(const uint8_t *buf, size_t len, qn_http_reply *out);

#endif /* QANAT_PROBE_H */
