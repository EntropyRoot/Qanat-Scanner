#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/task.h"
#include "qanat/crypto.h"
#include "qanat/netinfo.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ICMP_BATCH 64u

static const uint16_t kDiscoverPorts[] = { 80, 443, 22, 445, 8080, 139, 53, 7 };

const uint16_t *qn_discover_ports(uint32_t *count)
{
    *count = (uint32_t)(sizeof kDiscoverPorts / sizeof kDiscoverPorts[0]);
    return kDiscoverPorts;
}

static uint32_t addr_offset(const host_discover *s, const qn_addr *a)
{
    return a->u.v4 - s->prefix.net.u.v4;
}

static bool note_host(host_discover *s, const qn_addr *a, uint32_t rtt_us, uint16_t port)
{
    uint32_t     off;
    host_record *h;

    if (!s || !a || a->af != AF_INET || a->u.v4 < s->prefix.net.u.v4)
        return false;
    off = addr_offset(s, a);
    if (off >= s->span)
        return false;

    if (s->seen[off]) {
        h = &s->host[s->slot[off]];
        if (rtt_us && (!h->rtt_us || rtt_us < h->rtt_us))
            h->rtt_us = rtt_us;
        if (port && !h->open_hint)
            h->open_hint = port;
        return false;
    }
    if (s->n >= s->cap)
        return false;

    s->slot[off] = s->n;
    s->seen[off] = 1;

    h = &s->host[s->n++];
    memset(h, 0, sizeof *h);
    h->addr      = *a;
    h->rtt_us    = rtt_us;
    h->open_hint = port;
    h->alive     = 1;
    return true;
}

typedef struct {
    uint8_t  type, code;
    uint16_t cksum;
    uint16_t id, seq;
    uint8_t  pad[16];
} icmp_echo;

static uint16_t icmp_cksum(const void *buf, size_t len)
{
    const uint8_t *p   = (const uint8_t *)buf;
    uint32_t       sum = 0;

    for (; len > 1; len -= 2, p += 2)
        sum += ((uint32_t)p[0] << 8) | p[1];
    if (len)
        sum += (uint32_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static uint32_t icmp_rtt(const host_discover *s, const qn_addr *a, uint64_t now_ns)
{
    uint32_t off;
    uint64_t sent;

    if (!s || !a || a->af != AF_INET || a->u.v4 < s->prefix.net.u.v4)
        return 0;
    off = addr_offset(s, a);
    if (off >= s->span)
        return 0;
    sent = s->icmp_sent_ns[off];
    if (!sent || now_ns <= sent)
        return 0;
    return (uint32_t)QN_MIN((now_ns - sent) / 1000ull, (uint64_t)UINT32_MAX);
}

/* Nonce, offset, and a tag binding them, so probes cannot be cross-replayed. */
static void icmp_payload(const host_discover *s, uint32_t off, uint8_t pad[16])
{
    uint64_t tag = (s->icmp_nonce ^ 0x9E3779B97F4A7C15ull) * (off + 1u);
    uint32_t i;

    for (i = 0; i < 8u; i++)
        pad[i] = (uint8_t)(s->icmp_nonce >> (56u - 8u * i));
    pad[8]  = (uint8_t)(off >> 24);
    pad[9]  = (uint8_t)(off >> 16);
    pad[10] = (uint8_t)(off >> 8);
    pad[11] = (uint8_t)off;
    for (i = 0; i < 4u; i++)
        pad[12u + i] = (uint8_t)(tag >> (56u - 8u * i));
}

/* Returns the probe offset this reply answers, or -1. */
static long valid_icmp_reply(const host_discover *s, const struct sockaddr_in *from,
                             const uint8_t *buf, size_t len, qn_addr *addr)
{
    uint8_t   want[16];
    icmp_echo reply;
    uint32_t  off;

    /* Exact length: a longer packet with a valid checksum is not our reply. */
    if (!s || !from || !buf || !addr || len != sizeof reply)
        return -1;
    memcpy(&reply, buf, sizeof reply);
    if (reply.type != 0u || reply.code != 0u || icmp_cksum(buf, len) != 0u)
        return -1;

    off = ntohs(reply.seq);
    if (off >= s->span || !s->icmp_sent_ns[off])
        return -1; /* never probed, or already answered */

    icmp_payload(s, off, want);
    if (memcmp(reply.pad, want, sizeof want) != 0)
        return -1;

    addr->af = AF_INET;
    addr->u.v4 = ntohl(from->sin_addr.s_addr);
    if (addr->u.v4 != s->prefix.net.u.v4 + off)
        return -1;
    return (long)off;
}

/* Consumes the outstanding probe, so a second copy of a reply answers nothing. */
static bool accept_reply(host_discover *s, const struct sockaddr_in *from,
                         const uint8_t *buf, size_t len)
{
    qn_addr  a;
    uint32_t rtt;
    long     off = valid_icmp_reply(s, from, buf, len, &a);

    if (off < 0) {
        s->icmp_rejected++;
        return false;
    }
    rtt = icmp_rtt(s, &a, qn_now_ns());
    s->icmp_sent_ns[off] = 0;
    s->icmp_replied++;
    return note_host(s, &a, rtt, 0);
}

typedef struct {
    void    *ctx;
    int     (*open_socket)(void *ctx);
    int     (*set_recvbuf)(void *ctx, int fd, int bytes);
    int     (*send_batch)(void *ctx, int fd, struct mmsghdr *messages, unsigned count);
    ssize_t (*recv_one)(void *ctx, int fd, uint8_t *buffer, size_t capacity,
                        struct sockaddr_in *from, socklen_t *from_length);
    int      (*wait_fd)(void *ctx, struct pollfd *fd, int timeout_ms);
    int      (*close_fd)(void *ctx, int fd);
    uint64_t (*now_ns)(void *ctx);
    uint64_t (*now_ms)(void *ctx);
} qn_icmp_io;

static int system_icmp_open(void *ctx)
{
    (void)ctx;
    return socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
}

static int system_icmp_set_recvbuf(void *ctx, int fd, int bytes)
{
    (void)ctx;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
}

static int system_icmp_send_batch(void *ctx, int fd, struct mmsghdr *messages,
                                  unsigned count)
{
    (void)ctx;
    return sendmmsg(fd, messages, count, 0);
}

static ssize_t system_icmp_recv_one(void *ctx, int fd, uint8_t *buffer, size_t capacity,
                                    struct sockaddr_in *from, socklen_t *from_length)
{
    (void)ctx;
    return recvfrom(fd, buffer, capacity, 0, (struct sockaddr *)from, from_length);
}

static int system_icmp_wait(void *ctx, struct pollfd *fd, int timeout_ms)
{
    (void)ctx;
    return poll(fd, 1u, timeout_ms);
}

static int system_icmp_close(void *ctx, int fd)
{
    (void)ctx;
    return close(fd);
}

static uint64_t system_icmp_now_ns(void *ctx)
{
    (void)ctx;
    return qn_now_ns();
}

static uint64_t system_icmp_now_ms(void *ctx)
{
    (void)ctx;
    return qn_now_ms();
}

static const qn_icmp_io system_icmp_io = {
    NULL, system_icmp_open, system_icmp_set_recvbuf, system_icmp_send_batch,
    system_icmp_recv_one, system_icmp_wait, system_icmp_close,
    system_icmp_now_ns, system_icmp_now_ms
};

#if defined(QN_DISCOVER_TESTING)
static const qn_icmp_io *test_icmp_io;

static void icmp_test_set_io(const qn_icmp_io *io)
{
    test_icmp_io = io;
}
#endif

static const qn_icmp_io *icmp_current_io(void)
{
#if defined(QN_DISCOVER_TESTING)
    if (test_icmp_io)
        return test_icmp_io;
#endif
    return &system_icmp_io;
}

static bool icmp_cancelled(const host_discover *s)
{
    return s->cancel && atomic_load_explicit(s->cancel, memory_order_acquire);
}

static bool drain_icmp_replies(const qn_icmp_io *io, int fd, host_discover *s,
                               long *found, int *error)
{
    for (;;) {
        struct sockaddr_in from;
        socklen_t          fl = sizeof from;
        uint8_t            rb[128];
        ssize_t            n = io->recv_one(io->ctx, fd, rb, sizeof rb, &from, &fl);

        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && qn_errno_would_block(errno))
            return true;
        if (n < 0) {
            *error = errno ? errno : EIO;
            return false;
        }
        if (accept_reply(s, &from, rb, (size_t)n))
            (*found)++;
    }
}

qn_run_outcome host_discover_icmp(host_discover *s, uint32_t timeout_ms)
{
    const qn_icmp_io *io = icmp_current_io();
    struct mmsghdr      mh[ICMP_BATCH];
    struct iovec        iov[ICMP_BATCH];
    struct sockaddr_in  dst[ICMP_BATCH];
    icmp_echo           pkt[ICMP_BATCH];
    qn_run_outcome      outcome = QN_RUN_FAILED;
    int                 fd = -1;
    int                 error = 0;
    long                found = 0;

    if (!s)
        return QN_RUN_FAILED;
    s->icmp_ok = false;
    s->icmp_errno = 0;
    s->icmp_outcome = QN_RUN_FAILED;
    s->icmp_attempted = 0u;
    s->icmp_replied = 0u;
    s->icmp_found = 0u;
    s->icmp_unsent = s->host_count;
    s->icmp_rejected = 0u;
    if (s->icmp_sent_ns && s->span)
        memset(s->icmp_sent_ns, 0, (size_t)s->span * sizeof *s->icmp_sent_ns);
    if (icmp_cancelled(s)) {
        outcome = QN_RUN_CANCELLED;
        goto done;
    }
    if (s->prefix.af != AF_INET) {
        error = EAFNOSUPPORT;
        goto done;
    }

    fd = io->open_socket(io->ctx);
    if (fd < 0) {
        error = errno ? errno : EIO;
        goto done;
    }

    {
        int v = 262144;
        (void)io->set_recvbuf(io->ctx, fd, v);
    }

    s->icmp_ok = true;

    for (uint32_t base = 0; base < s->host_count; base += ICMP_BATCH) {
        uint32_t batch = QN_MIN(ICMP_BATCH, s->host_count - base);
        uint32_t sent_total = 0;
        unsigned stalls = 0;
        bool     failed = false;

        if (icmp_cancelled(s)) {
            outcome = QN_RUN_CANCELLED;
            goto done;
        }

        for (uint32_t i = 0; i < batch; i++) {
            uint32_t off = s->first_host + base + i;

            memset(&pkt[i], 0, sizeof pkt[i]);
            pkt[i].type = 8;
            pkt[i].seq  = htons((uint16_t)off);
            icmp_payload(s, off, pkt[i].pad);
            pkt[i].cksum = icmp_cksum(&pkt[i], sizeof pkt[i]);

            memset(&dst[i], 0, sizeof dst[i]);
            dst[i].sin_family      = AF_INET;
            dst[i].sin_addr.s_addr = htonl(s->prefix.net.u.v4 + off);

            iov[i].iov_base = &pkt[i];
            iov[i].iov_len  = sizeof pkt[i];

            memset(&mh[i], 0, sizeof mh[i]);
            mh[i].msg_hdr.msg_name    = &dst[i];
            mh[i].msg_hdr.msg_namelen = sizeof dst[i];
            mh[i].msg_hdr.msg_iov     = &iov[i];
            mh[i].msg_hdr.msg_iovlen  = 1;
        }

        while (sent_total < batch) {
            if (icmp_cancelled(s)) {
                outcome = QN_RUN_CANCELLED;
                goto done;
            }
            int sent = io->send_batch(io->ctx, fd, mh + sent_total,
                                      batch - sent_total);

            if (sent > 0) {
                uint64_t sent_at;

                if ((uint32_t)sent > batch - sent_total) {
                    error = EPROTO;
                    failed = true;
                    break;
                }
                sent_at = io->now_ns(io->ctx);
                for (int i = 0; i < sent; i++) {
                    uint32_t off = s->first_host + base + sent_total + (uint32_t)i;
                    s->icmp_sent_ns[off] = sent_at;
                }
                sent_total += (uint32_t)sent;
                s->probed += (uint32_t)sent;
                s->icmp_attempted += (uint32_t)sent;
                stalls = 0;
                if (!drain_icmp_replies(io, fd, s, &found, &error)) {
                    failed = true;
                    break;
                }
                continue;
            }
            if (sent < 0 && errno == EINTR)
                continue;
            if (sent < 0 && (qn_errno_would_block(errno) || errno == ENOBUFS) &&
                stalls++ < 4u) {
                struct pollfd out = { fd, POLLIN | POLLOUT, 0 };
                int prc;
                do {
                    prc = io->wait_fd(io->ctx, &out, 10);
                } while (prc < 0 && errno == EINTR);
                if (prc < 0) {
                    error = errno ? errno : EIO;
                    failed = true;
                    break;
                }
                if (prc > 0 && (out.revents & POLLIN) &&
                    !drain_icmp_replies(io, fd, s, &found, &error)) {
                    failed = true;
                    break;
                }
                continue;
            }
            if (sent < 0 && !qn_errno_would_block(errno) && errno != ENOBUFS) {
                error = errno ? errno : EIO;
                failed = true;
            }
            break;
        }
        if (failed)
            goto done;
        if (!drain_icmp_replies(io, fd, s, &found, &error))
            goto done;
    }

    {
        uint64_t start = io->now_ms(io->ctx);
        uint64_t deadline = start > UINT64_MAX - timeout_ms
                                ? UINT64_MAX
                                : start + timeout_ms;
        for (;;) {
            struct pollfd      pf = { fd, POLLIN, 0 };
            uint64_t           now = io->now_ms(io->ctx);

            if (icmp_cancelled(s)) {
                outcome = QN_RUN_CANCELLED;
                goto done;
            }
            if (now >= deadline)
                break;
            {
                uint64_t remain = deadline - now;
                int      wait_ms = remain > (uint64_t)INT_MAX ? INT_MAX : (int)remain;
                if (s->cancel && wait_ms > 25)
                    wait_ms = 25;
                int      prc = io->wait_fd(io->ctx, &pf, wait_ms);

                if (prc < 0 && errno == EINTR)
                    continue;
                if (prc < 0) {
                    error = errno ? errno : EIO;
                    goto done;
                }
                if (prc == 0)
                    break;
            }

            if (!drain_icmp_replies(io, fd, s, &found, &error))
                goto done;
        }
    }

    outcome = s->icmp_attempted == s->host_count ? QN_RUN_SUCCESS
                                                  : QN_RUN_INCOMPLETE;

done:
    s->icmp_unsent = s->icmp_attempted <= s->host_count
                         ? s->host_count - s->icmp_attempted
                         : 0u;
    s->icmp_found = found >= 0 && (uint64_t)found <= UINT32_MAX
                        ? (uint32_t)found
                        : 0u;
    if (fd >= 0 && io->close_fd(io->ctx, fd) != 0 &&
        outcome != QN_RUN_FAILED && outcome != QN_RUN_CANCELLED) {
        error = errno ? errno : EIO;
        outcome = QN_RUN_FAILED;
    }
    if (s->icmp_sent_ns && s->span)
        memset(s->icmp_sent_ns, 0, (size_t)s->span * sizeof *s->icmp_sent_ns);
    s->icmp_errno = outcome == QN_RUN_FAILED ? (error ? error : EIO) : 0;
    s->icmp_outcome = outcome;
    return outcome;
}

static qn_task_next hd_next_tcp(void *ctx, uint64_t idx, qn_job *out)
{
    host_discover *s = (host_discover *)ctx;
    uint32_t       nports;
    const uint16_t *ports = qn_discover_ports(&nports);
    uint64_t       host;
    uint64_t       port;
    uint32_t       off;

    if (!s->ntcp_host)
        return QN_TASK_EXHAUSTED;
    host = idx % s->ntcp_host;
    port = idx / s->ntcp_host;
    if (port >= nports)
        return QN_TASK_EXHAUSTED;

    off = s->tcp_host[host];

    out->addr.af   = AF_INET;
    out->addr.u.v4 = s->prefix.net.u.v4 + off;
    out->port      = ports[port];
    out->stage     = QN_STAGE_TCP;
    return QN_TASK_JOB;
}

static void hd_on_tcp(void *ctx, const qn_event *ev)
{
    host_discover *s = (host_discover *)ctx;

    s->probed++;
    s->tcp_completed++;
    s->tcp_attempted = s->tcp_completed;
    /* Refusal is sufficient evidence of host liveness. */
    if (ev->result == QN_R_OPEN)
        note_host(s, &ev->job.addr, ev->rtt_us, ev->job.port);
    else if (ev->result == QN_R_REFUSED)
        note_host(s, &ev->job.addr, ev->rtt_us, 0);
}

bool host_discover_init(host_discover *s, qn_arena *a, const qn_config *cfg)
{
    qn_netinfo ni;
    char       buf[64] = { 0 };
    uint64_t   hosts;

    memset(s, 0, sizeof *s);
    s->cfg  = cfg;
    s->step = -1;

    if (cfg->target && *cfg->target) {
        if (!qn_cidr_parse(cfg->target, &s->prefix))
            return false;
    } else {
        memset(&ni, 0, sizeof ni);
        qn_netinfo_ifaces(&ni);
        qn_netinfo_routes(&ni);
        if (!qn_netinfo_local_prefix(&ni, buf, sizeof buf))
            return false;
        if (!qn_cidr_parse(buf, &s->prefix))
            return false;
    }

    if (s->prefix.af != AF_INET)
        return false;

    hosts = ((uint64_t)1u << (32 - s->prefix.bits));
    if (hosts > QN_DISCOVER_MAX_HOSTS)
        return false;

    s->span = (uint32_t)hosts;
    s->first_host = s->prefix.bits < 31u ? 1u : 0u;
    s->host_count = s->prefix.bits < 31u ? s->span - 2u : s->span;
    qn_strlcpy(s->prefix_str, cfg->target && *cfg->target ? cfg->target : buf, sizeof s->prefix_str);

    s->cap  = s->span;
    s->host = QN_ARENA_ARRAY(a, host_record, s->cap);
    s->seen = QN_ARENA_ARRAY(a, uint8_t, s->span);
    s->slot = QN_ARENA_ARRAY(a, uint32_t, s->span);
    s->tcp_host = QN_ARENA_ARRAY(a, uint32_t, s->host_count ? s->host_count : 1u);
    s->icmp_sent_ns = QN_ARENA_ARRAY(a, uint64_t, s->span);
    if (!s->host || !s->seen || !s->slot || !s->tcp_host || !s->icmp_sent_ns)
        return false;
    memset(s->seen, 0, (size_t)s->span * sizeof *s->seen);
    memset(s->slot, 0, (size_t)s->span * sizeof *s->slot);
    memset(s->icmp_sent_ns, 0, (size_t)s->span * sizeof *s->icmp_sent_ns);

    /* Secure entropy, not the run seed: a reproducible nonce is a guessable one. */
    if (!qn_random_secure(&s->icmp_nonce, sizeof s->icmp_nonce) || !s->icmp_nonce)
        s->icmp_nonce = qn_now_ns() ^ ((uint64_t)getpid() << 32) ^ 0xA5A5F00DBEEF1234ull;

    {
        uint32_t nports;
        qn_discover_ports(&nports);
        /* Probes, not hosts: ICMP contributes one per host, TCP one per port. */
        s->total = s->host_count * nports;
        if (cfg->discover_method != QN_DISCOVER_TCP)
            s->total += s->host_count;
    }
    return true;
}

bool host_discover_next_phase(host_discover *s)
{
    uint32_t nports;

    qn_discover_ports(&nports);
    s->step++;

    if (s->step == 0 && s->cfg->discover_method != QN_DISCOVER_ICMP) {
        bool unresolved_only = s->cfg->discover_method == QN_DISCOVER_AUTO && s->icmp_ok;

        s->ntcp_host = 0;
        for (uint32_t i = 0; i < s->host_count; i++) {
            uint32_t off = s->first_host + i;
            if (!unresolved_only || !s->seen[off])
                s->tcp_host[s->ntcp_host++] = off;
        }
        if (!s->ntcp_host)
            return false;
        /* Denominator now covers both phases; probed counts probes from both. */
        s->total = s->icmp_attempted + s->ntcp_host * nports;
        s->task = (qn_task){ hd_next_tcp, hd_on_tcp, s,
                            (uint64_t)s->ntcp_host * nports, "sweep" };
        return true;
    }
    return false;
}

static int host_cmp(const void *a, const void *b)
{
    uint32_t x = ((const host_record *)a)->addr.u.v4;
    uint32_t y = ((const host_record *)b)->addr.u.v4;
    return (x > y) - (x < y);
}

void host_discover_finish(host_discover *s)
{
    if (s->n > 1)
        qsort(s->host, s->n, sizeof *s->host, host_cmp);
}
