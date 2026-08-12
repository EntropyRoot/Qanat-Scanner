#ifndef QANAT_CERTSCAN_H
#define QANAT_CERTSCAN_H

/* Streaming TLS 1.2 Certificate framing check (RFC 5246 7.4.2), cursor only. */

#include "qanat/tls.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    QN_CERTSCAN_LIST_LEN,
    QN_CERTSCAN_ENTRY_LEN,
    QN_CERTSCAN_ENTRY_BODY,
    QN_CERTSCAN_DONE,
    QN_CERTSCAN_FAILED
};

static inline void qn_cert_scan_init(qn_cert_scan *c, uint32_t total, uint32_t max)
{
    c->total = total;
    c->seen = c->list_left = c->entry_left = c->count = 0;
    c->acc[0] = c->acc[1] = c->acc[2] = 0;
    c->accn  = 0;
    /* The list length alone is three bytes, so anything shorter cannot frame. */
    c->state = (total < 3u || total > max) ? QN_CERTSCAN_FAILED : QN_CERTSCAN_LIST_LEN;
}

static inline uint32_t qn_cert_scan_acc(const qn_cert_scan *c)
{
    return ((uint32_t)c->acc[0] << 16) | ((uint32_t)c->acc[1] << 8) | c->acc[2];
}

static inline bool qn_cert_scan_push(qn_cert_scan *c, const uint8_t *p, size_t n)
{
    size_t i;

    if (c->state == QN_CERTSCAN_FAILED)
        return false;

    for (i = 0; i < n; i++) {
        if (c->seen == c->total) {
            c->state = QN_CERTSCAN_FAILED;
            return false;
        }
        c->seen++;

        switch (c->state) {
        case QN_CERTSCAN_LIST_LEN:
            c->acc[c->accn++] = p[i];
            if (c->accn < 3u)
                break;
            c->accn = 0;
            {
                uint32_t list = qn_cert_scan_acc(c);

                /* The list must consume the message exactly and be non-empty. */
                if (!list || list + 3u != c->total) {
                    c->state = QN_CERTSCAN_FAILED;
                    return false;
                }
                c->list_left = list;
                c->state     = QN_CERTSCAN_ENTRY_LEN;
            }
            break;

        case QN_CERTSCAN_ENTRY_LEN:
            c->acc[c->accn++] = p[i];
            if (c->accn < 3u)
                break;
            c->accn = 0;
            {
                uint32_t entry = qn_cert_scan_acc(c);

                if (c->list_left < 3u || !entry || entry > c->list_left - 3u) {
                    c->state = QN_CERTSCAN_FAILED;
                    return false;
                }
                c->list_left -= 3u + entry;
                c->entry_left = entry;
                c->state      = QN_CERTSCAN_ENTRY_BODY;
            }
            break;

        case QN_CERTSCAN_ENTRY_BODY:
            if (--c->entry_left == 0u) {
                c->count++;
                c->state = c->list_left ? QN_CERTSCAN_ENTRY_LEN : QN_CERTSCAN_DONE;
            }
            break;

        default:
            c->state = QN_CERTSCAN_FAILED;
            return false;
        }
    }
    return true;
}

/* True only when every length agreed and the message ended on a boundary. */
static inline bool qn_cert_scan_done(const qn_cert_scan *c)
{
    return c->state == QN_CERTSCAN_DONE && c->seen == c->total && c->count > 0u;
}

enum {
    QN_CERT13_CONTEXT_LEN,
    QN_CERT13_LIST_LEN,
    QN_CERT13_ENTRY_LEN,
    QN_CERT13_ENTRY_BODY,
    QN_CERT13_EXT_LEN,
    QN_CERT13_EXT_BODY,
    QN_CERT13_DONE,
    QN_CERT13_FAILED
};

static inline void qn_cert13_scan_init(qn_cert13_scan *c, uint32_t total, uint32_t max)
{
    memset(c, 0, sizeof *c);
    c->total = total;
    c->state = (total < 10u || total > max) ? QN_CERT13_FAILED : QN_CERT13_CONTEXT_LEN;
}

static inline uint32_t qn_cert13_acc24(const qn_cert13_scan *c)
{
    return ((uint32_t)c->acc[0] << 16) | ((uint32_t)c->acc[1] << 8) | c->acc[2];
}

static inline uint16_t qn_cert13_acc16(const qn_cert13_scan *c)
{
    return (uint16_t)(((uint16_t)c->acc[0] << 8) | c->acc[1]);
}

static inline bool qn_cert13_scan_push(qn_cert13_scan *c, const uint8_t *p, size_t n)
{
    size_t i;

    if (c->state == QN_CERT13_FAILED)
        return false;

    for (i = 0; i < n; i++) {
        if (c->seen == c->total || c->state == QN_CERT13_DONE) {
            c->state = QN_CERT13_FAILED;
            return false;
        }
        c->seen++;

        switch (c->state) {
        case QN_CERT13_CONTEXT_LEN:
            if (p[i] != 0u) {
                c->state = QN_CERT13_FAILED;
                return false;
            }
            c->state = QN_CERT13_LIST_LEN;
            break;

        case QN_CERT13_LIST_LEN:
            c->acc[c->accn++] = p[i];
            if (c->accn == 3u) {
                uint32_t list = qn_cert13_acc24(c);

                c->accn = 0u;
                if (!list || list + 4u != c->total) {
                    c->state = QN_CERT13_FAILED;
                    return false;
                }
                c->list_left = list;
                c->state = QN_CERT13_ENTRY_LEN;
            }
            break;

        case QN_CERT13_ENTRY_LEN:
            c->acc[c->accn++] = p[i];
            if (c->accn == 3u) {
                uint32_t entry = qn_cert13_acc24(c);

                c->accn = 0u;
                if (c->list_left < 5u || !entry || entry > c->list_left - 5u) {
                    c->state = QN_CERT13_FAILED;
                    return false;
                }
                c->list_left -= 3u;
                c->entry_left = entry;
                c->state = QN_CERT13_ENTRY_BODY;
            }
            break;

        case QN_CERT13_ENTRY_BODY:
            c->list_left--;
            if (--c->entry_left == 0u)
                c->state = QN_CERT13_EXT_LEN;
            break;

        case QN_CERT13_EXT_LEN:
            if (!c->list_left) {
                c->state = QN_CERT13_FAILED;
                return false;
            }
            c->list_left--;
            c->acc[c->accn++] = p[i];
            if (c->accn == 2u) {
                uint32_t extensions = qn_cert13_acc16(c);

                c->accn = 0u;
                if (extensions > c->list_left) {
                    c->state = QN_CERT13_FAILED;
                    return false;
                }
                c->extensions_left = extensions;
                if (extensions) {
                    c->state = QN_CERT13_EXT_BODY;
                } else {
                    c->count++;
                    c->state = c->list_left ? QN_CERT13_ENTRY_LEN : QN_CERT13_DONE;
                }
            }
            break;

        case QN_CERT13_EXT_BODY:
            c->list_left--;
            if (--c->extensions_left == 0u) {
                c->count++;
                c->state = c->list_left ? QN_CERT13_ENTRY_LEN : QN_CERT13_DONE;
            }
            break;

        default:
            c->state = QN_CERT13_FAILED;
            return false;
        }
    }
    return true;
}

static inline bool qn_cert13_scan_done(const qn_cert13_scan *c)
{
    return c->state == QN_CERT13_DONE && c->seen == c->total && c->count > 0u;
}

#endif /* QANAT_CERTSCAN_H */
