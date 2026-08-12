#ifndef QANAT_HTTP1_H
#define QANAT_HTTP1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qanat/observation.h"

#define QN_HTTP1_HEAD_MAX 8192u

typedef enum {
    QN_HTTP1_OK = 0,
    QN_HTTP1_PROTOCOL,
    QN_HTTP1_SPACE
} qn_http1_rc;

#define QN_HTTP1_EV_NONE        QN_HTTP_FACT_NONE
#define QN_HTTP1_EV_HEADERS     QN_HTTP_FACT_HEADERS
#define QN_HTTP1_EV_BODY        QN_HTTP_FACT_BODY
#define QN_HTTP1_EV_DONE        QN_HTTP_FACT_DONE
#define QN_HTTP1_EV_EDGE        QN_HTTP_FACT_TRACE_COLO
#define QN_HTTP1_EV_WEAK_MARKER QN_HTTP_FACT_CF_RAY

typedef qn_http_event qn_http1_event;

typedef struct {
    uint8_t  head[QN_HTTP1_HEAD_MAX];
    uint32_t head_n;
    uint64_t left;
    uint64_t current_body;
    uint64_t total_body;
    uint32_t responses;
    uint32_t opened;
    uint16_t status;
    uint8_t  state;
    uint8_t  crlf_n;
    /* One trace line at a time, so a marker must sit on a line of its own. */
    uint8_t  line[QN_TRACE_LINE_MAX];
    uint16_t line_n;
    bool     line_overflow;
} qn_http1;

void qn_http1_init(qn_http1 *h);
bool qn_http1_open_response(qn_http1 *h);
qn_http1_rc qn_http1_feed(qn_http1 *h, const uint8_t *in, size_t inlen,
                          qn_http1_event *ev);
qn_http1_rc qn_http1_eof(qn_http1 *h, qn_http1_event *ev);

#endif /* QANAT_HTTP1_H */
