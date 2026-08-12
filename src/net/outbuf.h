#ifndef QANAT_NET_OUTBUF_H
#define QANAT_NET_OUTBUF_H

#include "qanat/util.h"

#include <string.h>

/* A partial write leaves a consumed prefix that remains reusable capacity. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len; /* bytes written into buf */
    size_t   off; /* bytes of buf already handed to the socket */
} qn_outbuf;

static inline void qn_outbuf_init(qn_outbuf *b, uint8_t *storage, size_t cap)
{
    b->buf = storage;
    b->cap = cap;
    b->len = 0;
    b->off = 0;
}

static inline void qn_outbuf_reset(qn_outbuf *b)
{
    b->len = 0;
    b->off = 0;
}

static inline size_t qn_outbuf_pending(const qn_outbuf *b)
{
    return b->len - b->off;
}

static inline const uint8_t *qn_outbuf_head(const qn_outbuf *b)
{
    return b->buf + b->off;
}

/* Slides the unsent tail down so the consumed prefix becomes usable again. */
static inline void qn_outbuf_compact(qn_outbuf *b)
{
    size_t pending = qn_outbuf_pending(b);

    if (!b->off)
        return;
    if (pending)
        memmove(b->buf, b->buf + b->off, pending);
    b->len = pending;
    b->off = 0;
}

static inline void qn_outbuf_consume(qn_outbuf *b, size_t n)
{
    b->off += n > qn_outbuf_pending(b) ? qn_outbuf_pending(b) : n;
    if (b->off == b->len)
        qn_outbuf_reset(b);
}

static inline bool qn_outbuf_queue(qn_outbuf *b, const uint8_t *p, size_t n)
{
    if (n > b->cap)
        return false;
    qn_outbuf_compact(b);
    if (n > b->cap - b->len)
        return false;
    memcpy(b->buf + b->len, p, n);
    b->len += n;
    return true;
}

/* Writable tail for producers that fill in place, such as the TLS record layer. */
static inline uint8_t *qn_outbuf_tail(qn_outbuf *b, size_t *room)
{
    qn_outbuf_compact(b);
    *room = b->cap - b->len;
    return b->buf + b->len;
}

static inline void qn_outbuf_commit(qn_outbuf *b, size_t n)
{
    b->len += n > b->cap - b->len ? b->cap - b->len : n;
}

#endif /* QANAT_NET_OUTBUF_H */
