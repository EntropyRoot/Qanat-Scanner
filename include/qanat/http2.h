#ifndef QANAT_HTTP2_H
#define QANAT_HTTP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qanat/observation.h"
#include "qanat/profile.h"

/* Bounded HTTP/2 subset for deep verification. */

#define QN_H2_HEADER_BLOCK_MAX 8192u

typedef enum {
    QN_H2_OK = 0,
    QN_H2_PROTOCOL,
    QN_H2_SPACE,
    QN_H2_UNSUPPORTED /* well-formed but beyond the bounded parser */
} qn_h2_rc;

/* Peer data on a stream without a sent request is a protocol error, not evidence. */
typedef enum {
    QN_H2_STREAM_IDLE = 0,
    QN_H2_STREAM_OPEN,    /* request sent, response headers not yet valid */
    QN_H2_STREAM_HEADERS, /* one valid informational-free response head seen */
    QN_H2_STREAM_CLOSED
} qn_h2_stream_state;

#define QN_H2_MAX_STREAMS 4u

/* A trace line longer than this is not a trace line. */
#define QN_H2_TRACE_LINE_MAX 64

#define QN_H2_EV_NONE          QN_HTTP_FACT_NONE
#define QN_H2_EV_HEADERS       QN_HTTP_FACT_HEADERS
#define QN_H2_EV_DATA          QN_HTTP_FACT_BODY
#define QN_H2_EV_END_STREAM    QN_HTTP_FACT_DONE
#define QN_H2_EV_EDGE          QN_HTTP_FACT_TRACE_COLO
#define QN_H2_EV_RST           QN_HTTP_FACT_RESET
#define QN_H2_EV_WEAK_MARKER   QN_HTTP_FACT_CF_RAY
#define QN_H2_EV_INFORMATIONAL QN_HTTP_FACT_INFORMATIONAL

#define QN_H2_EV_GOAWAY (1u << 0)

typedef qn_http_event qn_h2_stream_event;

#define QN_H2_EVENT_STREAMS 4u

typedef struct {
    uint32_t           flags; /* connection-scoped events, currently GOAWAY */
    uint8_t            nstreams;
    qn_h2_stream_event stream[QN_H2_EVENT_STREAMS];
} qn_h2_event;

typedef struct {
    uint8_t  hdr[9];
    uint8_t  hdr_n;
    uint8_t  type;
    uint8_t  flags;
    uint32_t frame_len;
    uint32_t frame_got;
    uint32_t stream_id;

    uint8_t  pad_len;
    uint32_t data_start;
    uint32_t data_end;

    uint8_t  control[128];
    uint32_t control_n;
    uint8_t  scratch[64];
    uint8_t  setting[6];
    uint8_t  setting_n;

    uint8_t  hblock[QN_H2_HEADER_BLOCK_MAX];
    uint32_t hblock_n;
    uint32_t hblock_stream;
    bool     hblock_open;
    bool     hblock_end_stream;

    struct {
        uint32_t stream_id;
        uint8_t  line[QN_H2_TRACE_LINE_MAX];
        uint16_t line_n;
        bool     line_overflow;
    } trace[QN_H2_EVENT_STREAMS];

    /* Flow-control credit consumed since the last WINDOW_UPDATE. */
    uint32_t conn_consumed;
    struct {
        uint32_t stream_id;
        uint32_t consumed;
    } flow[QN_H2_EVENT_STREAMS];

    struct {
        uint32_t id;
        uint8_t  state;
        bool     head_done;  /* a valid final response head was parsed */
    } stream[QN_H2_MAX_STREAMS];
    uint8_t nstream;
} qn_h2;

void qn_h2_init(qn_h2 *h);

/* Declares a written request so frames for undeclared streams can be rejected. */
bool qn_h2_open_stream(qn_h2 *h, uint32_t stream_id);

/* True once a complete, valid response head has been observed. */
bool qn_h2_stream_has_head(const qn_h2 *h, uint32_t stream_id);

/* Browser-shaped preface, SETTINGS, and connection window. */
int qn_h2_preface(uint8_t *out, size_t cap);
int qn_h2_preface_profile(const qn_client_profile *profile, uint64_t seed,
                           uint8_t *out, size_t cap);
int qn_h2_preface_instance(const qn_profile_instance *instance,
                           uint8_t *out, size_t cap);

/* stream_id must be non-zero and odd. */
int qn_h2_get(uint32_t stream_id, const char *authority, const char *path,
              uint8_t *out, size_t cap);
int qn_h2_get_profile(const qn_client_profile *profile, uint64_t seed,
                      uint32_t stream_id, const char *authority,
                      const char *path, uint8_t *out, size_t cap);
int qn_h2_get_instance(const qn_profile_instance *instance, uint32_t stream_id,
                       const char *authority, const char *path,
                       uint8_t *out, size_t cap);

/* QN_H2_SPACE retains generated control frames for a later empty-input drain. */
qn_h2_rc qn_h2_feed(qn_h2 *h, const uint8_t *in, size_t inlen,
                    uint8_t *control, size_t control_cap, size_t *control_len,
                    qn_h2_event *ev);

#endif /* QANAT_HTTP2_H */
