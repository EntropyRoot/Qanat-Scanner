/* Bounded HTTP/2 framing (RFC 9113/7541). */

#include "qanat/http2.h"

#include "hpack_huff.h"

#include <string.h>

#define H2_DATA          0x0u
#define H2_HEADERS       0x1u
#define H2_RST_STREAM    0x3u
#define H2_SETTINGS      0x4u
#define H2_PUSH_PROMISE  0x5u
#define H2_PING          0x6u
#define H2_GOAWAY        0x7u
#define H2_WINDOW_UPDATE 0x8u
#define H2_CONTINUATION  0x9u

#define H2_END_STREAM  0x01u
#define H2_ACK         0x01u
#define H2_END_HEADERS 0x04u
#define H2_PADDED      0x08u
#define H2_PRIORITY    0x20u

#define H2_SETTINGS_ENABLE_PUSH          0x2u
#define H2_SETTINGS_INITIAL_WINDOW_SIZE  0x4u
#define H2_SETTINGS_MAX_FRAME_SIZE       0x5u

#define H2_MAX_FRAME_IN (1u << 14) /* our advertised/default receive maximum */
#define H2_WINDOW       (16u << 20)
#define H2_WINDOW_STEP  H2_MAX_FRAME_IN /* publish credit a frame at a time */

/* Decode buffers; a longer field is still validated, just not retained. */
#define QN_HPACK_NAME_MAX  256u
#define QN_HPACK_VALUE_MAX 32u

static uint32_t be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void put24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t frame(uint8_t *out, size_t cap, uint8_t type, uint8_t flags,
                    uint32_t stream, const uint8_t *payload, size_t len)
{
    if (len > 0xFFFFFFu || cap < 9u + len)
        return 0;
    put24(out, (uint32_t)len);
    out[3] = type;
    out[4] = flags;
    put32(out + 5, stream & 0x7FFFFFFFu);
    if (len)
        memcpy(out + 9, payload, len);
    return 9u + len;
}

static bool hpack_uint(uint8_t first, unsigned prefix, uint32_t value,
                       uint8_t *out, size_t cap, size_t *n)
{
    uint32_t mask = (1u << prefix) - 1u;
    size_t   off  = 0;

    if (!cap)
        return false;
    if (value < mask) {
        out[0] = (uint8_t)(first | (uint8_t)value);
        *n = 1;
        return true;
    }

    out[off++] = (uint8_t)(first | (uint8_t)mask);
    value -= mask;
    while (value >= 128u) {
        if (off >= cap)
            return false;
        out[off++] = (uint8_t)((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    if (off >= cap)
        return false;
    out[off++] = (uint8_t)value;
    *n = off;
    return true;
}

static bool hpack_string(const char *s, uint8_t *out, size_t cap, size_t *n)
{
    size_t len = strlen(s), hn;

    if (len > UINT32_MAX || !hpack_uint(0, 7, (uint32_t)len, out, cap, &hn) ||
        cap - hn < len)
        return false;
    memcpy(out + hn, s, len);
    *n = hn + len;
    return true;
}

static bool literal_indexed_name(uint32_t name, const char *value,
                                 uint8_t *out, size_t cap, size_t *n)
{
    size_t a, b;

    /* Literal without indexing. */
    if (!hpack_uint(0, 4, name, out, cap, &a) ||
        !hpack_string(value, out + a, cap - a, &b))
        return false;
    *n = a + b;
    return true;
}

void qn_h2_init(qn_h2 *h)
{
    if (h)
        memset(h, 0, sizeof *h);
}

int qn_h2_preface(uint8_t *out, size_t cap)
{
    return qn_h2_preface_profile(qn_client_profile_get(QN_TLS_FP_CHROME),
                                 0u, out, cap);
}

static int preface_shaped(const qn_h2_setting *setting, size_t nsettings,
                          uint32_t connection_window, uint8_t *out, size_t cap)
{
    static const uint8_t magic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    uint8_t settings[6u * QN_PROFILE_MAX_H2_SETTINGS], update[4];
    size_t  off = 0, n;

    if (!setting || !out || cap < sizeof magic - 1u ||
        nsettings > QN_PROFILE_MAX_H2_SETTINGS)
        return -1;
    memcpy(out, magic, sizeof magic - 1u);
    off = sizeof magic - 1u;

    for (size_t i = 0; i < nsettings; i++) {
        settings[i * 6u] = (uint8_t)(setting[i].id >> 8);
        settings[i * 6u + 1u] = (uint8_t)setting[i].id;
        put32(settings + i * 6u + 2u, setting[i].value);
    }
    n = frame(out + off, cap - off, H2_SETTINGS, 0, 0, settings,
              nsettings * 6u);
    if (!n)
        return -1;
    off += n;

    if (connection_window < 65535u || connection_window > 0x7FFFFFFFu)
        return -1;
    if (connection_window > 65535u) {
        put32(update, connection_window - 65535u);
        n = frame(out + off, cap - off, H2_WINDOW_UPDATE, 0, 0,
                  update, sizeof update);
        if (!n)
            return -1;
        off += n;
    }
    return (int)off;
}

int qn_h2_preface_profile(const qn_client_profile *profile, uint64_t seed,
                          uint8_t *out, size_t cap)
{
    qn_h2_setting setting[QN_PROFILE_MAX_H2_SETTINGS];
    size_t nsettings;
    uint32_t connection_window;

    if (!profile || !qn_profile_h2_shape(profile, seed, setting,
                                          QN_PROFILE_MAX_H2_SETTINGS, &nsettings,
                                          &connection_window))
        return -1;
    return preface_shaped(setting, nsettings, connection_window, out, cap);
}

int qn_h2_preface_instance(const qn_profile_instance *instance,
                           uint8_t *out, size_t cap)
{
    if (!instance || instance->version != QN_PROFILE_INSTANCE_VERSION)
        return -1;
    return preface_shaped(instance->h2_settings, instance->h2_settings_n,
                          instance->h2_connection_window, out, cap);
}

int qn_h2_get(uint32_t stream_id, const char *authority, const char *path,
              uint8_t *out, size_t cap)
{
    return qn_h2_get_profile(qn_client_profile_get(QN_TLS_FP_CHROME),
                             0u, stream_id, authority, path, out, cap);
}

static bool emit_pseudo(uint8_t field, const char *authority, const char *path,
                        uint8_t *out, size_t cap, size_t *n)
{
    switch ((qn_pseudo_header)field) {
    case QN_PSEUDO_METHOD:
        if (!cap)
            return false;
        out[0] = 0x82u;
        *n = 1u;
        return true;
    case QN_PSEUDO_SCHEME:
        if (!cap)
            return false;
        out[0] = 0x87u;
        *n = 1u;
        return true;
    case QN_PSEUDO_AUTHORITY:
        return literal_indexed_name(1u, authority, out, cap, n);
    case QN_PSEUDO_PATH:
        return literal_indexed_name(4u, path, out, cap, n);
    default:
        return false;
    }
}

static bool emit_regular(const qn_http_header_profile *profile, uint8_t field,
                         uint8_t *out, size_t cap, size_t *n)
{
    switch ((qn_regular_header)field) {
    case QN_HEADER_USER_AGENT:
        return literal_indexed_name(58u, profile->user_agent, out, cap, n);
    case QN_HEADER_ACCEPT:
        return literal_indexed_name(19u, profile->accept, out, cap, n);
    case QN_HEADER_ACCEPT_ENCODING:
        return literal_indexed_name(16u, profile->accept_encoding, out, cap, n);
    default:
        return false;
    }
}

static int get_shaped(const qn_client_profile *profile,
                      const uint8_t pseudo_order[4], const uint8_t header_order[3],
                      uint32_t stream_id, const char *authority,
                      const char *path, uint8_t *out, size_t cap)
{
    uint8_t block[1024];
    size_t  off = 0, n;

    if (!profile || !out || !stream_id || !(stream_id & 1u) ||
        !authority || !*authority || !path || path[0] != '/')
        return -1;

    for (size_t i = 0; i < 4u; i++) {
        if (!emit_pseudo(pseudo_order[i], authority, path,
                         block + off, sizeof block - off, &n))
            return -1;
        off += n;
    }
    for (size_t i = 0; i < 3u; i++) {
        if (!emit_regular(&profile->http, header_order[i],
                          block + off, sizeof block - off, &n))
            return -1;
        off += n;
    }

    n = frame(out, cap, H2_HEADERS, H2_END_HEADERS | H2_END_STREAM, stream_id, block, off);
    return n ? (int)n : -1;
}

int qn_h2_get_profile(const qn_client_profile *profile, uint64_t seed,
                      uint32_t stream_id, const char *authority,
                      const char *path, uint8_t *out, size_t cap)
{
    uint8_t pseudo_order[4], header_order[3];

    if (!profile || !qn_profile_http_shape(profile, seed, pseudo_order, header_order))
        return -1;
    return get_shaped(profile, pseudo_order, header_order, stream_id, authority,
                      path, out, cap);
}

int qn_h2_get_instance(const qn_profile_instance *instance, uint32_t stream_id,
                       const char *authority, const char *path,
                       uint8_t *out, size_t cap)
{
    if (!instance || instance->version != QN_PROFILE_INSTANCE_VERSION ||
        !instance->profile)
        return -1;
    return get_shaped(instance->profile, instance->h2_pseudo_order,
                      instance->http1_header_order, stream_id, authority,
                      path, out, cap);
}

static bool pull_hpack_int(const uint8_t *p, size_t len, size_t *off,
                           unsigned prefix, uint32_t *value)
{
    uint32_t mask = (1u << prefix) - 1u;
    uint32_t v, shift = 0;
    uint8_t  b;

    if (*off >= len)
        return false;
    b = p[(*off)++];
    v = b & mask;
    if (v != mask) {
        *value = v;
        return true;
    }

    do {
        if (*off >= len || shift > 28u)
            return false;
        b = p[(*off)++];
        if ((uint32_t)(b & 0x7Fu) > (UINT32_MAX - v) >> shift)
            return false;
        v += (uint32_t)(b & 0x7Fu) << shift;
        shift += 7u;
    } while (b & 0x80u);
    *value = v;
    return true;
}

/* Always plain bytes: a Huffman string is decoded before it is inspected. */
typedef struct {
    const uint8_t *p;
    size_t         n;         /* bytes readable at p */
    size_t         full;      /* complete length, n <= full */
    bool           truncated;
    bool           has_upper; /* holds for the whole string, not just p[0..n) */
} hstr;

static bool pull_hpack_string(const uint8_t *p, size_t len, size_t *off,
                              uint8_t *buf, size_t cap, hstr *s)
{
    size_t   mark = *off;
    uint32_t n;

    if (mark >= len || !pull_hpack_int(p, len, off, 7, &n) || n > len - *off)
        return false;

    if (p[mark] & 0x80u) {
        qn_huff_info info;

        if (!qn_huff_decode(p + *off, n, buf, cap, &info))
            return false;
        s->p         = buf;
        s->full      = info.len;
        s->n         = info.truncated ? cap : info.len;
        s->truncated = info.truncated;
        s->has_upper = info.has_upper;
    } else {
        size_t i;

        s->p         = p + *off;
        s->n         = n;
        s->full      = n;
        s->truncated = false;
        s->has_upper = false;
        for (i = 0; i < n; i++)
            if (s->p[i] >= 'A' && s->p[i] <= 'Z') {
                s->has_upper = true;
                break;
            }
    }
    *off += n;
    return true;
}

static bool eq_ascii_ci(const hstr *s, const char *lit)
{
    size_t n = strlen(lit);

    if (s->truncated || s->full != n)
        return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t a = s->p[i], b = (uint8_t)lit[i];
        if (a >= 'A' && a <= 'Z')
            a = (uint8_t)(a + ('a' - 'A'));
        if (a != b)
            return false;
    }
    return true;
}

static uint16_t static_status(uint32_t index)
{
    static const uint16_t status[] = { 200, 204, 206, 304, 400, 404, 500 };
    return (index >= 8u && index <= 14u) ? status[index - 8u] : 0;
}

/* Of static pseudo-headers 1..14, only :status may appear in a response. */
static bool static_index_is_pseudo(uint32_t idx, bool *is_status)
{
    *is_status = idx >= 8u && idx <= 14u;
    return idx <= 14u;
}

static bool name_is_lowercase(const hstr *s)
{
    return !s->has_upper;
}

/* Fields HTTP/2 forbids outright, whatever their value. */
static bool name_is_forbidden(const hstr *s)
{
    return eq_ascii_ci(s, "connection") || eq_ascii_ci(s, "keep-alive") ||
           eq_ascii_ci(s, "proxy-connection") || eq_ascii_ci(s, "transfer-encoding") ||
           eq_ascii_ci(s, "upgrade");
}

/* Entry 57 is transfer-encoding, the only forbidden name the table can spell. */
static bool static_index_is_forbidden(uint32_t idx)
{
    return idx == 57u;
}

typedef struct {
    uint32_t status_count;
    bool     saw_regular;
} hblock_scan;

static bool status_from_value(const hstr *v, uint16_t *out)
{
    if (v->truncated || v->full != 3u)
        return false;
    if (v->p[0] < '1' || v->p[0] > '5' || v->p[1] < '0' || v->p[1] > '9' ||
        v->p[2] < '0' || v->p[2] > '9')
        return false;
    *out = (uint16_t)((v->p[0] - '0') * 100u + (v->p[1] - '0') * 10u + v->p[2] - '0');
    return true;
}

/* trailers rejects every pseudo-header, per RFC 9113 8.1. */
static bool parse_hpack(const uint8_t *p, size_t len, qn_h2_stream_event *ev, bool trailers,
                        hblock_scan *scan)
{
    size_t off = 0;
    bool   saw_field = false;
    unsigned size_updates = 0;

    while (off < len) {
        uint8_t  b = p[off];
        uint32_t idx;
        bool     is_status = false;

        if (b & 0x80u) { /* indexed field */
            /* HEADER_TABLE_SIZE=0 permits only the 61-entry static table. */
            if (!pull_hpack_int(p, len, &off, 7, &idx) || !idx || idx > 61u)
                return false;
            if (static_index_is_pseudo(idx, &is_status)) {
                if (trailers || !is_status || scan->saw_regular)
                    return false;
                if (++scan->status_count > 1u)
                    return false;
                ev->status = static_status(idx);
            } else {
                if (static_index_is_forbidden(idx))
                    return false;
                scan->saw_regular = true;
            }
            saw_field = true;
            continue;
        }
        if ((b & 0xE0u) == 0x20u) { /* dynamic table size update */
            /* Updates precede fields, respect the zero table cap, and occur at most twice. */
            if (saw_field || ++size_updates > 2u ||
                !pull_hpack_int(p, len, &off, 5, &idx) || idx != 0u)
                return false;
            continue;
        }

        /* Incremental indexing contradicts the advertised zero-sized table. */
        if (b & 0x40u)
            return false;

        {
            uint8_t namebuf[QN_HPACK_NAME_MAX], valbuf[QN_HPACK_VALUE_MAX];
            hstr    name = { 0 }, value = { 0 };
            bool    pseudo, cf_ray = false, server = false;

            if (!pull_hpack_int(p, len, &off, 4, &idx) || idx > 61u)
                return false;
            if (!idx && !pull_hpack_string(p, len, &off, namebuf, sizeof namebuf, &name))
                return false;
            if (!pull_hpack_string(p, len, &off, valbuf, sizeof valbuf, &value))
                return false;

            if (idx) {
                if (static_index_is_forbidden(idx))
                    return false;
                pseudo    = static_index_is_pseudo(idx, &is_status);
                server    = idx == 54u;
            } else {
                if (!name.full || !name_is_lowercase(&name) || name_is_forbidden(&name))
                    return false;
                pseudo    = name.p[0] == ':';
                is_status = eq_ascii_ci(&name, ":status");
                cf_ray    = eq_ascii_ci(&name, "cf-ray");
                server    = eq_ascii_ci(&name, "server");
            }

            if (pseudo) {
                if (trailers || !is_status || scan->saw_regular)
                    return false;
                if (++scan->status_count > 1u)
                    return false;
                if (!status_from_value(&value, &ev->status))
                    return false;
            } else {
                scan->saw_regular = true;
                if (cf_ray)
                    ev->flags |= QN_HTTP_FACT_CF_RAY;
                if (server && eq_ascii_ci(&value, "cloudflare"))
                    ev->flags |= QN_HTTP_FACT_SERVER_CLOUDFLARE;
            }
            saw_field = true;
        }
    }
    return true;
}

static int stream_index(const qn_h2 *h, uint32_t stream_id)
{
    uint8_t i;

    for (i = 0; i < h->nstream; i++)
        if (h->stream[i].id == stream_id)
            return (int)i;
    return -1;
}

bool qn_h2_open_stream(qn_h2 *h, uint32_t stream_id)
{
    if (!h || !stream_id || !(stream_id & 1u) || h->nstream >= QN_H2_MAX_STREAMS)
        return false;
    if (stream_index(h, stream_id) >= 0)
        return false;
    h->stream[h->nstream].id    = stream_id;
    h->stream[h->nstream].state = QN_H2_STREAM_OPEN;
    h->nstream++;
    return true;
}

bool qn_h2_stream_has_head(const qn_h2 *h, uint32_t stream_id)
{
    int i = h ? stream_index(h, stream_id) : -1;

    return i >= 0 && h->stream[i].head_done;
}

static qn_h2_stream_event *stream_event(const qn_h2 *h, qn_h2_event *ev,
                                        uint32_t stream_id)
{
    size_t i;
    int    si;

    for (i = 0; i < ev->nstreams; i++)
        if (ev->stream[i].stream_id == stream_id)
            return &ev->stream[i];
    if (ev->nstreams >= QN_H2_EVENT_STREAMS)
        return NULL;
    si = stream_index(h, stream_id);
    ev->stream[ev->nstreams].stream_id = stream_id;
    if (si >= 0)
        ev->stream[ev->nstreams].response_index = (uint32_t)si + 1u;
    return &ev->stream[ev->nstreams++];
}

static size_t trace_slot(qn_h2 *h, uint32_t stream_id)
{
    size_t i;

    for (i = 0; i < QN_H2_EVENT_STREAMS; i++) {
        if (h->trace[i].stream_id == stream_id)
            return i;
        if (!h->trace[i].stream_id) {
            h->trace[i].stream_id = stream_id;
            return i;
        }
    }
    return QN_H2_EVENT_STREAMS;
}

static size_t flow_slot(qn_h2 *h, uint32_t stream_id)
{
    size_t i;

    for (i = 0; i < QN_H2_EVENT_STREAMS; i++) {
        if (h->flow[i].stream_id == stream_id)
            return i;
        if (!h->flow[i].stream_id) {
            h->flow[i].stream_id = stream_id;
            return i;
        }
    }
    return QN_H2_EVENT_STREAMS;
}

/* A colo is evidence only as a complete trace line, matching the HTTP/1 contract. */
static void take_trace_line(const uint8_t *line, size_t n, qn_h2_stream_event *ev)
{
    uint8_t       buf[QN_H2_TRACE_LINE_MAX + 1u];
    qn_trace_body trace;

    if (n > QN_H2_TRACE_LINE_MAX)
        return;
    memcpy(buf, line, n);
    buf[n++] = '\n';
    if (!qn_http_trace_parse(buf, n, &trace) || !trace.have_colo)
        return;
    memcpy(ev->colo, trace.colo, sizeof ev->colo);
    ev->flags |= QN_HTTP_FACT_TRACE_COLO;
}

static void scan_trace(qn_h2 *h, uint32_t stream_id, const uint8_t *p, size_t n,
                       qn_h2_stream_event *ev)
{
    size_t slot = trace_slot(h, stream_id), i;

    if (slot == QN_H2_EVENT_STREAMS)
        return;

    for (i = 0; i < n; i++) {
        if (p[i] == 0x0Au) {
            if (!h->trace[slot].line_overflow)
                take_trace_line(h->trace[slot].line, h->trace[slot].line_n, ev);
            h->trace[slot].line_n        = 0;
            h->trace[slot].line_overflow = false;
            continue;
        }
        if (h->trace[slot].line_n < QN_H2_TRACE_LINE_MAX)
            h->trace[slot].line[h->trace[slot].line_n++] = p[i];
        else
            h->trace[slot].line_overflow = true;
    }
}

static bool emit_ack(qn_h2 *h, uint8_t type, const uint8_t *payload, size_t len)
{
    size_t n = frame(h->control + h->control_n, sizeof h->control - h->control_n,
                     type, H2_ACK, 0, payload, len);
    if (!n)
        return false;
    h->control_n += (uint32_t)n;
    return true;
}

/* Credit is published at frame granularity or immediately when the caller drains. */
static bool credit_worth_publishing(const qn_h2 *h, bool force)
{
    size_t i;

    if (force)
        return h->conn_consumed || h->flow[0].consumed || h->flow[1].consumed ||
               h->flow[2].consumed || h->flow[3].consumed;
    if (h->conn_consumed >= H2_WINDOW_STEP)
        return true;
    for (i = 0; i < QN_H2_EVENT_STREAMS; i++)
        if (h->flow[i].consumed >= H2_WINDOW_STEP)
            return true;
    return false;
}

static qn_h2_rc replenish_windows(qn_h2 *h, size_t external_cap, bool force)
{
    uint8_t pending[13u * (1u + QN_H2_EVENT_STREAMS)];
    uint8_t payload[4];
    size_t  pending_n = 0;

    if (!credit_worth_publishing(h, force))
        return QN_H2_OK;

    if (h->conn_consumed) {
        size_t n;

        if (h->conn_consumed > 0x7FFFFFFFu)
            return QN_H2_SPACE;
        put32(payload, h->conn_consumed);
        n = frame(pending + pending_n, sizeof pending - pending_n,
                  H2_WINDOW_UPDATE, 0, 0, payload, sizeof payload);
        if (!n)
            return QN_H2_SPACE;
        pending_n += n;
    }
    for (size_t i = 0; i < QN_H2_EVENT_STREAMS; i++) {
        size_t n;

        if (!h->flow[i].consumed)
            continue;
        if (h->flow[i].consumed > 0x7FFFFFFFu)
            return QN_H2_SPACE;
        put32(payload, h->flow[i].consumed);
        n = frame(pending + pending_n, sizeof pending - pending_n,
                  H2_WINDOW_UPDATE, 0, h->flow[i].stream_id, payload, sizeof payload);
        if (!n)
            return QN_H2_SPACE;
        pending_n += n;
    }

    /* Flow-credit publication is all-or-nothing across both output buffers. */
    if (pending_n > sizeof h->control - h->control_n ||
        (size_t)h->control_n > external_cap ||
        pending_n > external_cap - (size_t)h->control_n)
        return QN_H2_SPACE;
    memcpy(h->control + h->control_n, pending, pending_n);
    h->control_n += (uint32_t)pending_n;
    h->conn_consumed = 0;
    for (size_t i = 0; i < QN_H2_EVENT_STREAMS; i++)
        h->flow[i].consumed = 0;
    return QN_H2_OK;
}

static qn_h2_rc begin_frame(qn_h2 *h)
{
    h->frame_len = be24(h->hdr);
    h->type      = h->hdr[3];
    h->flags     = h->hdr[4];
    h->stream_id = be32(h->hdr + 5) & 0x7FFFFFFFu;
    h->frame_got = 0;
    h->pad_len   = 0;
    h->data_start = ((h->type == H2_DATA || h->type == H2_HEADERS ||
                      h->type == H2_PUSH_PROMISE) &&
                     (h->flags & H2_PADDED))
                        ? 1u
                        : 0u;
    if (h->type == H2_HEADERS && (h->flags & H2_PRIORITY))
        h->data_start += 5u;
    if (h->type == H2_PUSH_PROMISE)
        h->data_start += 4u;
    h->data_end = h->frame_len;
    if (h->type == H2_SETTINGS)
        h->setting_n = 0u;

    if (h->frame_len > H2_MAX_FRAME_IN || h->data_start > h->frame_len)
        return QN_H2_PROTOCOL;
    if (h->type == H2_DATA && !h->stream_id)
        return QN_H2_PROTOCOL;
    if (h->hblock_open && h->type != H2_CONTINUATION)
        return QN_H2_PROTOCOL;
    if (h->type == H2_CONTINUATION &&
        (!h->hblock_open || h->stream_id != h->hblock_stream))
        return QN_H2_PROTOCOL;

    /* Unrequested streams cannot deliver data; server push is disabled. */
    if (h->stream_id && (h->type == H2_DATA || h->type == H2_HEADERS ||
                         h->type == H2_CONTINUATION || h->type == H2_RST_STREAM ||
                         h->type == H2_PUSH_PROMISE)) {
        int si = stream_index(h, h->stream_id);

        if (si < 0 || h->stream[si].state == QN_H2_STREAM_IDLE)
            return QN_H2_PROTOCOL;
        if (h->stream[si].state == QN_H2_STREAM_CLOSED)
            return QN_H2_PROTOCOL;
        /* QN2-017: body before a response head is not a body. */
        if (h->type == H2_DATA && !h->stream[si].head_done)
            return QN_H2_PROTOCOL;
    }
    return QN_H2_OK;
}

/* QN2-016: a SETTINGS payload we accept must actually be legal. */
static qn_h2_rc check_setting(const uint8_t setting[6])
{
    uint16_t id = (uint16_t)((uint16_t)setting[0] << 8 | setting[1]);
    uint32_t v = be32(setting + 2u);

    switch (id) {
    case H2_SETTINGS_ENABLE_PUSH:
        if (v > 1u)
            return QN_H2_PROTOCOL;
        break;
    case H2_SETTINGS_INITIAL_WINDOW_SIZE:
        if (v > 0x7FFFFFFFu)
            return QN_H2_PROTOCOL;
        break;
    case H2_SETTINGS_MAX_FRAME_SIZE:
        if (v < 16384u || v > 16777215u)
            return QN_H2_PROTOCOL;
        break;
    default:
        break;
    }
    return QN_H2_OK;
}

static qn_h2_rc consume_payload(qn_h2 *h, const uint8_t *p, size_t n, qn_h2_event *ev)
{
    uint32_t first = h->frame_got;
    uint32_t last;

    if (n > UINT32_MAX - first)
        return QN_H2_PROTOCOL;
    last = first + (uint32_t)n;

    if (h->data_start && (h->flags & H2_PADDED) && first == 0u && n) {
        h->pad_len = p[0];
        if ((uint32_t)h->pad_len > h->frame_len - h->data_start)
            return QN_H2_PROTOCOL;
        h->data_end = h->frame_len - h->pad_len;
    }

    if (h->type == H2_DATA) {
        size_t slot = flow_slot(h, h->stream_id);

        if (slot == QN_H2_EVENT_STREAMS || n > UINT32_MAX - h->conn_consumed ||
            n > UINT32_MAX - h->flow[slot].consumed)
            return QN_H2_SPACE;
        h->conn_consumed += (uint32_t)n;
        h->flow[slot].consumed += (uint32_t)n;

        uint32_t lo = first > h->data_start ? first : h->data_start;
        uint32_t hi = last < h->data_end ? last : h->data_end;
        if (hi > lo) {
            const uint8_t      *d = p + (lo - first);
            size_t              dn = hi - lo;
            qn_h2_stream_event *se = stream_event(h, ev, h->stream_id);
            if (!se)
                return QN_H2_SPACE;
            se->flags |= QN_HTTP_FACT_BODY;
            se->body_bytes += dn;
            scan_trace(h, h->stream_id, d, dn, se);
        }
    } else if (h->type == H2_HEADERS || h->type == H2_CONTINUATION) {
        uint32_t lo = first > h->data_start ? first : h->data_start;
        uint32_t hi = last < h->data_end ? last : h->data_end;
        if (hi > lo) {
            size_t take = hi - lo;
            if (take > sizeof h->hblock - h->hblock_n)
                return QN_H2_SPACE;
            memcpy(h->hblock + h->hblock_n, p + (lo - first), take);
            h->hblock_n += (uint32_t)take;
        }
    } else if (h->type == H2_SETTINGS) {
        size_t i;

        for (i = 0; i < n; i++) {
            h->setting[h->setting_n++] = p[i];
            if (h->setting_n == sizeof h->setting) {
                qn_h2_rc rc = check_setting(h->setting);

                h->setting_n = 0u;
                if (rc != QN_H2_OK)
                    return rc;
            }
        }
    } else if (first < sizeof h->scratch) {
        size_t keep = sizeof h->scratch - first;
        if (keep > n)
            keep = n;
        memcpy(h->scratch + first, p, keep);
    }

    h->frame_got = last;
    return QN_H2_OK;
}

/* A response head has exactly one :status before every regular field. */
static qn_h2_rc complete_hblock(qn_h2 *h, qn_h2_event *ev)
{
    qn_h2_stream_event *se = stream_event(h, ev, h->stream_id);
    hblock_scan         scan;
    int                 si = stream_index(h, h->stream_id);
    bool                trailers;

    if (!se)
        return QN_H2_SPACE;
    if (si < 0)
        return QN_H2_PROTOCOL;

    memset(&scan, 0, sizeof scan);
    trailers = h->stream[si].head_done;
    if (!parse_hpack(h->hblock, h->hblock_n, se, trailers, &scan))
        return QN_H2_PROTOCOL;
    h->hblock_n = 0;

    if (!trailers) {
        /* A response head without exactly one :status is not a response head. */
        if (scan.status_count != 1u)
            return QN_H2_PROTOCOL;
        if (se->status < 200u) {
            if (se->status == 101u || h->hblock_end_stream)
                return QN_H2_PROTOCOL;
            se->flags |= QN_HTTP_FACT_INFORMATIONAL;
            h->hblock_end_stream = false;
            return QN_H2_OK;
        }
        h->stream[si].head_done = true;
        h->stream[si].state     = QN_H2_STREAM_HEADERS;
    }

    /* Three distinct events; only a final head carries a status. */
    se->flags |= trailers ? QN_HTTP_FACT_TRAILERS : QN_HTTP_FACT_HEADERS;
    if (h->hblock_end_stream) {
        se->flags |= QN_HTTP_FACT_DONE;
        h->stream[si].state      = QN_H2_STREAM_CLOSED;
    }
    h->hblock_end_stream = false;
    return QN_H2_OK;
}

static qn_h2_rc finish_frame(qn_h2 *h, qn_h2_event *ev)
{
    qn_h2_stream_event *se;
    qn_h2_rc            rc;

    switch (h->type) {
    case H2_DATA:
        if (h->flags & H2_END_STREAM) {
            int si = stream_index(h, h->stream_id);

            se = stream_event(h, ev, h->stream_id);
            if (!se)
                return QN_H2_SPACE;
            se->flags |= QN_HTTP_FACT_DONE;
            if (si >= 0) {
                h->stream[si].state      = QN_H2_STREAM_CLOSED;
            }
        }
        break;

    case H2_HEADERS:
        if (!h->stream_id)
            return QN_H2_PROTOCOL;
        h->hblock_open   = (h->flags & H2_END_HEADERS) == 0;
        h->hblock_stream = h->stream_id;
        h->hblock_end_stream = (h->flags & H2_END_STREAM) != 0;
        if (!h->hblock_open) {
            rc = complete_hblock(h, ev);
            if (rc != QN_H2_OK)
                return rc;
        }
        break;

    case H2_CONTINUATION:
        if (h->flags & H2_END_HEADERS) {
            h->hblock_open = false;
            rc = complete_hblock(h, ev);
            if (rc != QN_H2_OK)
                return rc;
        }
        break;

    case H2_SETTINGS:
        if (h->stream_id || ((h->flags & H2_ACK) && h->frame_len) ||
            (!(h->flags & H2_ACK) && h->frame_len % 6u))
            return QN_H2_PROTOCOL;
        if (!(h->flags & H2_ACK)) {
            if (h->setting_n)
                return QN_H2_PROTOCOL;
        }
        if (!(h->flags & H2_ACK) && !emit_ack(h, H2_SETTINGS, NULL, 0))
            return QN_H2_SPACE;
        break;

    case H2_PING:
        if (h->stream_id || h->frame_len != 8u)
            return QN_H2_PROTOCOL;
        if (!(h->flags & H2_ACK)) {
            uint8_t ping[8];
            memcpy(ping, h->scratch, sizeof ping);
            if (!emit_ack(h, H2_PING, ping, sizeof ping))
                return QN_H2_SPACE;
        }
        break;

    case H2_RST_STREAM: {
        int si;
        if (!h->stream_id || h->frame_len != 4u)
            return QN_H2_PROTOCOL;
        se = stream_event(h, ev, h->stream_id);
        if (!se)
            return QN_H2_SPACE;
        se->flags |= QN_HTTP_FACT_RESET;
        si = stream_index(h, h->stream_id);
        if (si >= 0)
            h->stream[si].state = QN_H2_STREAM_CLOSED;
    }
        break;

    case H2_GOAWAY:
        if (h->stream_id || h->frame_len < 8u)
            return QN_H2_PROTOCOL;
        ev->flags |= QN_H2_EV_GOAWAY;
        break;

    case H2_WINDOW_UPDATE:
        if (h->frame_len != 4u || !(be32(h->scratch) & 0x7FFFFFFFu))
            return QN_H2_PROTOCOL;
        break;

    case H2_PUSH_PROMISE:
        /* Push is disabled. */
        return QN_H2_PROTOCOL;

    default:
        break;
    }
    return QN_H2_OK;
}

qn_h2_rc qn_h2_feed(qn_h2 *h, const uint8_t *in, size_t inlen,
                    uint8_t *control, size_t control_cap, size_t *control_len,
                    qn_h2_event *ev)
{
    qn_h2_rc rc = QN_H2_OK;
    size_t   emitted = 0;
    bool     drain = inlen == 0u;

    if (!h || !control_len || !ev || (!in && inlen) || (!control && control_cap))
        return QN_H2_PROTOCOL;
    memset(ev, 0, sizeof *ev);
    *control_len = 0;

    /* Preserve control frames across a SPACE return. */
    if (h->control_n) {
        if (!control || h->control_n > control_cap)
            return QN_H2_SPACE;
        memcpy(control, h->control, h->control_n);
        emitted = h->control_n;
        h->control_n = 0;
        *control_len = emitted;
    }

    while (inlen) {
        if (h->hdr_n < sizeof h->hdr) {
            size_t take = sizeof h->hdr - h->hdr_n;
            if (take > inlen)
                take = inlen;
            memcpy(h->hdr + h->hdr_n, in, take);
            h->hdr_n += (uint8_t)take;
            in += take;
            inlen -= take;
            if (h->hdr_n < sizeof h->hdr)
                break;
            rc = begin_frame(h);
            if (rc != QN_H2_OK)
                return rc;
            if (!h->frame_len) {
                rc = finish_frame(h, ev);
                h->hdr_n = 0;
                if (rc != QN_H2_OK)
                    return rc;
                continue;
            }
        }

        {
            size_t take = h->frame_len - h->frame_got;
            if (take > inlen)
                take = inlen;
            rc = consume_payload(h, in, take, ev);
            if (rc != QN_H2_OK)
                return rc;
            in += take;
            inlen -= take;
        }

        if (h->frame_got == h->frame_len) {
            rc = finish_frame(h, ev);
            h->hdr_n = 0;
            if (rc != QN_H2_OK)
                return rc;
        }
    }

    /* Empty feeds and ended streams publish all outstanding flow-control credit. */
    for (uint8_t i = 0; !drain && i < ev->nstreams; i++)
        if (ev->stream[i].flags & (QN_H2_EV_END_STREAM | QN_H2_EV_RST))
            drain = true;
    rc = replenish_windows(h, control_cap - emitted, drain || (ev->flags & QN_H2_EV_GOAWAY));
    if (rc != QN_H2_OK)
        return rc;
    if (h->control_n > control_cap - emitted)
        return QN_H2_SPACE;
    if (h->control_n)
        memcpy(control + emitted, h->control, h->control_n);
    emitted += h->control_n;
    h->control_n = 0;
    *control_len = emitted;
    return QN_H2_OK;
}
