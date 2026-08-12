#include "qanat/probe.h"
#include "qanat/util.h"

#include <limits.h>
#include <string.h>

int qn_http_build_get(uint8_t *buf, size_t cap, const char *host, const char *path)
{
    static const char prefix[] = "GET ";
    static const char between[] = " HTTP/1.1\r\nHost: ";
    static const char suffix[] =
        "\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n";
    const size_t fixed = (sizeof prefix - 1u) + (sizeof between - 1u) +
                         (sizeof suffix - 1u);
    size_t host_len, path_len, total;
    uint8_t *p;

    if (!buf || !cap || !host || !path)
        return -1;
    /* A caller cannot make this split the request, whatever it was handed. */
    if (!qn_valid_field(host, 253u) || !qn_valid_field(path, 1024u))
        return -1;

    host_len = strlen(host);
    path_len = strlen(path);
    if (path_len > SIZE_MAX - fixed || host_len > SIZE_MAX - fixed - path_len)
        return -1;
    total = fixed + path_len + host_len;
    if (total > (size_t)INT_MAX || total >= cap)
        return -1;

    p = buf;
    memcpy(p, prefix, sizeof prefix - 1u);
    p += sizeof prefix - 1u;
    memcpy(p, path, path_len);
    p += path_len;
    memcpy(p, between, sizeof between - 1u);
    p += sizeof between - 1u;
    memcpy(p, host, host_len);
    p += host_len;
    memcpy(p, suffix, sizeof suffix - 1u);
    p += sizeof suffix - 1u;
    *p = '\0';

    return (int)total;
}

#define QN_HTTP_STATUS_LINE_MAX 512u

/* HTTP evidence requires a valid version, separators, three-digit status, range and CRLF. */
static uint16_t parse_status(const uint8_t *b, size_t len)
{
    uint16_t code;
    size_t   i;
    bool     eol = false;

    if (!b || len < 12u || memcmp(b, "HTTP/1.", 7) ||
        (b[7] != '0' && b[7] != '1') || b[8] != ' ')
        return 0;
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9')
        return 0;

    code = (uint16_t)((b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0'));
    if (code < 100u || code > 599u)
        return 0;

    /* Exactly one space, or the end of the line, may follow the code. */
    if (len > 12u && b[12] != ' ' && b[12] != '\r')
        return 0;

    for (i = 12u; i < len && i < QN_HTTP_STATUS_LINE_MAX; i++) {
        if (b[i] == '\n')
            return 0; /* a bare LF is not a status-line terminator */
        if (b[i] == '\r') {
            if (i + 1u >= len)
                return 0; /* need the LF to call the line terminated */
            if (b[i + 1u] != '\n')
                return 0;
            eol = true;
            break;
        }
    }
    return eol ? code : 0;
}

/* CF-Ray ends with the serving colo code. */
static bool parse_cfray(const uint8_t *b, size_t len, char colo[4])
{
    const uint8_t *h = qn_find_ci(b, len, "\ncf-ray:");
    const uint8_t *p, *end, *dash = NULL;

    if (!h)
        return false;
    p   = h + 8;
    end = b + len;
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;
    for (const uint8_t *q = p; q < end && *q != '\r' && *q != '\n'; q++)
        if (*q == '-')
            dash = q;
    if (!dash || end - dash < 4)
        return false;

    for (int i = 0; i < 3; i++) {
        uint8_t c = dash[1 + i];
        if (c < 'A' || c > 'Z')
            return false;
        colo[i] = (char)c;
    }
    colo[3] = '\0';
    return true;
}

static bool key_is(const uint8_t *p, size_t n, const char *want)
{
    size_t i, w = strlen(want);

    if (n != w)
        return false;
    for (i = 0; i < n; i++) {
        uint8_t c = p[i];

        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + ('a' - 'A'));
        if (c != (uint8_t)want[i])
            return false;
    }
    return true;
}

static bool valid_colo(const uint8_t *p, size_t n)
{
    size_t i;

    if (n != 3u)
        return false;
    for (i = 0; i < 3u; i++)
        if (p[i] < 'A' || p[i] > 'Z')
            return false;
    return true;
}

/* Trace evidence requires a complete key=value line, not an embedded colo substring. */
bool qn_http_trace_parse(const uint8_t *b, size_t len, qn_trace_body *out)
{
    size_t pos = 0;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!b)
        return false;

    while (pos < len) {
        const uint8_t *line = b + pos;
        size_t         i    = pos, eq, klen, vlen;

        while (i < len && b[i] != '\n')
            i++;
        if (i >= len)
            break; /* an unterminated tail is not yet a line */
        {
            size_t end = i;

            if (end > pos && b[end - 1u] == '\r')
                end--;
            if (end == pos) { /* a blank line ends the body cleanly */
                pos = i + 1u;
                continue;
            }
            if (end - pos > QN_TRACE_LINE_MAX) {
                out->malformed = true;
                return false;
            }

            for (eq = pos; eq < end && b[eq] != '='; eq++)
                ;
            if (eq == end || eq == pos) {
                out->malformed = true;
                return false;
            }
            klen = eq - pos;
            vlen = end - eq - 1u;
            out->lines++;

            if (key_is(line, klen, "colo")) {
                if (!valid_colo(b + eq + 1u, vlen)) {
                    out->malformed = true;
                    return false;
                }
                if (out->have_colo && memcmp(out->colo, b + eq + 1u, 3u)) {
                    out->conflict = true;
                    return false;
                }
                memcpy(out->colo, b + eq + 1u, 3u);
                out->colo[3]   = '\0';
                out->have_colo = true;
            } else if (key_is(line, klen, "ip")) {
                char text[QN_ADDRSTRLEN];

                if (vlen >= sizeof text) {
                    out->malformed = true;
                    return false;
                }
                memcpy(text, b + eq + 1u, vlen);
                text[vlen] = '\0';
                if (!qn_addr_parse(text, &out->ip)) {
                    out->malformed = true;
                    return false;
                }
                out->have_ip = true;
            }
            pos = i + 1u;
        }
    }
    return out->have_colo;
}

bool qn_http_parse(const uint8_t *buf, size_t len, qn_http_reply *out)
{
    long hend;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!buf || len < 12)
        return false;

    out->status = parse_status(buf, len);
    if (!out->status)
        return false;

    hend          = qn_find_headers_end(buf, len);
    out->complete = hend > 0;

    {
        size_t hlen = hend > 0 ? (size_t)hend : len;

        /* Header hints are supporting evidence only: anyone can send them. */
        out->server_cloudflare =
            qn_find_ci(buf, hlen, "\nserver: cloudflare") != NULL;
        out->cf_ray = qn_find_ci(buf, hlen, "\ncf-ray:") != NULL;
        out->is_cloudflare = out->server_cloudflare || out->cf_ray;
        parse_cfray(buf, hlen, out->colo);

        if (hend > 0 && out->status == 200u) {
            qn_trace_body tb;

            if (qn_http_trace_parse(buf + hend, len - (size_t)hend, &tb)) {
                memcpy(out->colo, tb.colo, sizeof out->colo);
                out->colo_verified = true;
            } else if (tb.malformed || tb.conflict) {
                return false;
            }
        }
    }
    return true;
}
