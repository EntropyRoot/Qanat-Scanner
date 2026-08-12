/* Bounded HTTP/1.1 response framing (RFC 9112). */

#include "qanat/http1.h"

#include "qanat/probe.h"

#include <limits.h>
#include <string.h>

enum {
    H1_HEAD = 0,
    H1_FIXED,
    H1_CHUNK_SIZE,
    H1_CHUNK_DATA,
    H1_CHUNK_CRLF,
    H1_TRAILERS,
    H1_EOF_BODY
};

static bool ascii_eq(const uint8_t *p, size_t n, const char *s)
{
    size_t sn = strlen(s);

    if (n != sn)
        return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t a = p[i], b = (uint8_t)s[i];
        if (a >= 'A' && a <= 'Z')
            a = (uint8_t)(a + ('a' - 'A'));
        if (a != b)
            return false;
    }
    return true;
}

static bool tchar(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') || c == '!' || c == '#' || c == '$' ||
           c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
           c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
           c == '|' || c == '~';
}

static bool token(const uint8_t *p, size_t n)
{
    size_t i;

    if (!n)
        return false;
    for (i = 0; i < n; i++)
        if (!tchar(p[i]))
            return false;
    return true;
}


/* Transfer-Encoding lines concatenate in order; the final coding controls framing. */
typedef struct {
    uint32_t codings;
    uint32_t chunked_seen;
    bool     chunked_is_last;
    bool     malformed;
} te_list;

static void te_append(te_list *te, const uint8_t *p, size_t n)
{
    size_t i = 0;
    size_t trimmed = n;

    while (trimmed && (p[trimmed - 1u] == ' ' || p[trimmed - 1u] == '\t'))
        trimmed--;
    if (trimmed && p[trimmed - 1u] == ',')
        te->malformed = true;

    while (i < n) {
        size_t lo, hi;

        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        lo = i;
        while (i < n && p[i] != ',')
            i++;
        hi = i;
        if (i < n)
            i++; /* step over the comma */
        while (hi > lo && (p[hi - 1u] == ' ' || p[hi - 1u] == '\t'))
            hi--;
        if (hi == lo) {
            /* An empty element is only legal as optional whitespace padding. */
            if (lo < n || te->codings)
                te->malformed = true;
            continue;
        }
        if (!token(p + lo, hi - lo)) {
            te->malformed = true;
            continue;
        }
        te->codings++;
        if (ascii_eq(p + lo, hi - lo, "chunked")) {
            te->chunked_seen++;
            te->chunked_is_last = true;
        } else {
            te->chunked_is_last = false;
        }
    }
}

static bool parse_decimal(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    size_t   i = 0;

    while (i < n && (p[i] == ' ' || p[i] == '\t'))
        i++;
    if (i == n)
        return false;
    for (; i < n && p[i] >= '0' && p[i] <= '9'; i++) {
        uint32_t d = p[i] - '0';
        if (v > (UINT64_MAX - d) / 10u)
            return false;
        v = v * 10u + d;
    }
    while (i < n && (p[i] == ' ' || p[i] == '\t'))
        i++;
    if (i != n)
        return false;
    *out = v;
    return true;
}

static bool parse_hex_line(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    size_t   i = 0;
    bool     any = false;

    while (i < n && (p[i] == ' ' || p[i] == '\t'))
        i++;
    for (; i < n; i++) {
        uint8_t  c = p[i];
        uint32_t d;

        if (c == ';' || c == ' ' || c == '\t')
            break;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10u;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10u;
        else
            return false;
        if (v > (UINT64_MAX - d) / 16u)
            return false;
        v = v * 16u + d;
        any = true;
    }
    if (!any)
        return false;
    while (i < n && (p[i] == ' ' || p[i] == '\t'))
        i++;
    while (i < n) {
        size_t lo;

        if (p[i++] != ';')
            return false;
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        lo = i;
        while (i < n && tchar(p[i]))
            i++;
        if (i == lo)
            return false;
        if (i < n && p[i] == '=') {
            i++;
            if (i < n && p[i] == '"') {
                bool closed = false;

                i++;
                while (i < n) {
                    uint8_t c = p[i++];

                    if (c == '"') {
                        closed = true;
                        break;
                    }
                    if (c == '\\') {
                        if (i == n || p[i] < 0x20u || p[i] == 0x7Fu)
                            return false;
                        i++;
                    } else if ((c < 0x20u && c != '\t') || c == 0x7Fu) {
                        return false;
                    }
                }
                if (!closed)
                    return false;
            } else {
                lo = i;
                while (i < n && tchar(p[i]))
                    i++;
                if (i == lo)
                    return false;
            }
        }
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
    }
    *out = v;
    return true;
}

static void event_trace(qn_http1_event *ev, const char colo[4])
{
    ev->flags |= QN_HTTP_FACT_TRACE_COLO;
    if (colo[0])
        memcpy(ev->colo, colo, 4);
}

/* Only a complete trace line is evidence; embedded colo text is not a marker. */
static void scan_line(qn_http1 *h, qn_http1_event *ev)
{
    qn_trace_body tb;
    uint8_t       nl = '\n';
    uint8_t       buf[QN_TRACE_LINE_MAX + 1u];

    if (h->line_overflow || !h->line_n)
        return;
    memcpy(buf, h->line, h->line_n);
    buf[h->line_n] = nl;
    if (qn_http_trace_parse(buf, (size_t)h->line_n + 1u, &tb) && tb.have_colo)
        event_trace(ev, tb.colo);
}

static void scan_trace(qn_http1 *h, const uint8_t *p, size_t n, qn_http1_event *ev)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] == '\n') {
            scan_line(h, ev);
            h->line_n        = 0;
            h->line_overflow = false;
            continue;
        }
        if (p[i] == '\r')
            continue;
        if (h->line_n >= sizeof h->line) {
            h->line_overflow = true;
            continue;
        }
        h->line[h->line_n++] = p[i];
    }
}

static void body(qn_http1 *h, const uint8_t *p, size_t n, qn_http1_event *ev)
{
    h->current_body += n;
    h->total_body += n;
    ev->response_index = h->responses + 1u;
    ev->status = h->status;
    ev->body_bytes += n;
    ev->flags |= QN_HTTP_FACT_BODY;
    scan_trace(h, p, n, ev);
}

static void reset_response(qn_http1 *h)
{
    h->head_n = 0;
    h->left = 0;
    h->current_body = 0;
    h->status = 0;
    h->state = H1_HEAD;
    h->crlf_n = 0;
    h->line_n = 0;
    h->line_overflow = false;
}

static void complete(qn_http1 *h, qn_http1_event *ev)
{
    h->responses++;
    ev->flags |= QN_HTTP_FACT_DONE;
    ev->response_index = h->responses;
    ev->status = h->status;
    reset_response(h);
}

static qn_http1_rc parse_head(qn_http1 *h, qn_http1_event *ev)
{
    qn_http_reply rep;
    size_t        pos = 0;
    bool          have_len = false, have_te = false;
    uint64_t      content_len = 0;
    te_list       te;

    memset(&te, 0, sizeof te);

    if (!qn_http_parse(h->head, h->head_n, &rep) || !rep.complete)
        return QN_HTTP1_PROTOCOL;
    h->status = rep.status;
    ev->status = rep.status;
    ev->response_index = h->responses + 1u;
    if (rep.cf_ray)
        ev->flags |= QN_HTTP_FACT_CF_RAY;
    if (rep.server_cloudflare)
        ev->flags |= QN_HTTP_FACT_SERVER_CLOUDFLARE;

    while (pos + 1u < h->head_n && !(h->head[pos] == '\r' && h->head[pos + 1u] == '\n'))
        pos++;
    if (pos + 1u >= h->head_n)
        return QN_HTTP1_PROTOCOL;
    pos += 2u;

    while (pos + 1u < h->head_n) {
        size_t end = pos, colon;
        while (end + 1u < h->head_n && !(h->head[end] == '\r' && h->head[end + 1u] == '\n'))
            end++;
        if (end + 1u >= h->head_n)
            return QN_HTTP1_PROTOCOL;
        if (end == pos)
            break;
        colon = pos;
        while (colon < end && h->head[colon] != ':')
            colon++;
        if (colon == end)
            return QN_HTTP1_PROTOCOL;
        if (!token(h->head + pos, colon - pos))
            return QN_HTTP1_PROTOCOL;

        {
            size_t value = colon + 1u;
            while (value < end && (h->head[value] == ' ' || h->head[value] == '\t'))
                value++;
            if (ascii_eq(h->head + pos, colon - pos, "content-length")) {
                uint64_t v;
                if (!parse_decimal(h->head + value, end - value, &v) ||
                    (have_len && v != content_len))
                    return QN_HTTP1_PROTOCOL;
                content_len = v;
                have_len = true;
            } else if (ascii_eq(h->head + pos, colon - pos, "transfer-encoding")) {
                have_te = true;
                te_append(&te, h->head + value, end - value);
            }
        }
        pos = end + 2u;
    }
    h->head_n = 0;

    /* An unoffered 101 is a protocol error and cannot be replaced by a later 200. */
    if (h->status == 101u)
        return QN_HTTP1_PROTOCOL;
    if (h->status >= 100u && h->status < 200u) {
        ev->flags |= QN_HTTP_FACT_INFORMATIONAL;
        reset_response(h);
        return QN_HTTP1_OK;
    }
    ev->flags |= QN_HTTP_FACT_HEADERS;
    if (h->responses >= h->opened)
        return QN_HTTP1_PROTOCOL;
    if (have_te && (te.malformed || !te.codings || te.chunked_seen > 1u))
        return QN_HTTP1_PROTOCOL;
    if (have_te && have_len)
        return QN_HTTP1_PROTOCOL;
    if (h->status == 204u || h->status == 304u) {
        complete(h, ev);
        return QN_HTTP1_OK;
    }
    if (have_te) {
        /* Chunked frames the body only when it is the final coding. */
        h->state = te.chunked_is_last ? H1_CHUNK_SIZE : H1_EOF_BODY;
    } else if (have_len) {
        h->left = content_len;
        h->state = H1_FIXED;
        if (!content_len)
            complete(h, ev);
    } else {
        h->state = H1_EOF_BODY;
    }
    return QN_HTTP1_OK;
}

void qn_http1_init(qn_http1 *h)
{
    memset(h, 0, sizeof *h);
    h->opened = 1u;
}

bool qn_http1_open_response(qn_http1 *h)
{
    if (!h || h->opened == UINT32_MAX)
        return false;
    h->opened++;
    return true;
}

qn_http1_rc qn_http1_feed(qn_http1 *h, const uint8_t *in, size_t inlen,
                          qn_http1_event *ev)
{
    memset(ev, 0, sizeof *ev);

    while (inlen) {
        switch (h->state) {
        case H1_HEAD:
            if (h->head_n >= sizeof h->head)
                return QN_HTTP1_SPACE;
            h->head[h->head_n++] = *in++;
            inlen--;
            if (h->head_n >= 4u && h->head[h->head_n - 4u] == '\r' &&
                h->head[h->head_n - 3u] == '\n' && h->head[h->head_n - 2u] == '\r' &&
                h->head[h->head_n - 1u] == '\n') {
                qn_http1_rc rc = parse_head(h, ev);
                if (rc != QN_HTTP1_OK)
                    return rc;
            }
            break;

        case H1_FIXED: {
            size_t take = h->left < inlen ? (size_t)h->left : inlen;
            body(h, in, take, ev);
            h->left -= take;
            in += take;
            inlen -= take;
            if (!h->left)
                complete(h, ev);
            break;
        }

        case H1_CHUNK_SIZE:
            if (h->head_n >= sizeof h->head)
                return QN_HTTP1_SPACE;
            h->head[h->head_n++] = *in++;
            inlen--;
            if (h->head_n >= 2u && h->head[h->head_n - 2u] == '\r' &&
                h->head[h->head_n - 1u] == '\n') {
                if (!parse_hex_line(h->head, h->head_n - 2u, &h->left))
                    return QN_HTTP1_PROTOCOL;
                h->head_n = 0;
                h->state = h->left ? H1_CHUNK_DATA : H1_TRAILERS;
            }
            break;

        case H1_CHUNK_DATA: {
            size_t take = h->left < inlen ? (size_t)h->left : inlen;
            body(h, in, take, ev);
            h->left -= take;
            in += take;
            inlen -= take;
            if (!h->left) {
                h->state = H1_CHUNK_CRLF;
                h->crlf_n = 0;
            }
            break;
        }

        case H1_CHUNK_CRLF:
            if (*in != (h->crlf_n ? '\n' : '\r'))
                return QN_HTTP1_PROTOCOL;
            h->crlf_n++;
            in++;
            inlen--;
            if (h->crlf_n == 2u) {
                h->head_n = 0;
                h->state = H1_CHUNK_SIZE;
            }
            break;

        case H1_TRAILERS:
            if (h->head_n >= sizeof h->head)
                return QN_HTTP1_SPACE;
            h->head[h->head_n++] = *in++;
            inlen--;
            if (h->head_n == 2u && h->head[0] == '\r' && h->head[1] == '\n') {
                complete(h, ev); /* the terminating CRLF alone: no trailer fields */
            } else if (h->head_n >= 4u && h->head[h->head_n - 4u] == '\r' &&
                       h->head[h->head_n - 3u] == '\n' &&
                       h->head[h->head_n - 2u] == '\r' &&
                       h->head[h->head_n - 1u] == '\n') {
                /* Same canonical fact HTTP/2 reports, so policy cannot diverge. */
                ev->flags |= QN_HTTP_FACT_TRAILERS;
                complete(h, ev);
            }
            break;

        case H1_EOF_BODY:
            body(h, in, inlen, ev);
            in += inlen;
            inlen = 0;
            break;

        default:
            return QN_HTTP1_PROTOCOL;
        }
    }
    return QN_HTTP1_OK;
}

qn_http1_rc qn_http1_eof(qn_http1 *h, qn_http1_event *ev)
{
    memset(ev, 0, sizeof *ev);
    if (h->state == H1_EOF_BODY) {
        complete(h, ev);
        return QN_HTTP1_OK;
    }
    return h->state == H1_HEAD && !h->head_n ? QN_HTTP1_OK : QN_HTTP1_PROTOCOL;
}
