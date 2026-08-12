#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/engine.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef PR_SET_TIMERSLACK
#define PR_SET_TIMERSLACK 29
#endif
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

#define QN_CLAIM_CHUNK 64u
#define QN_EPOLL_BATCH 256
#define QN_RING_MIN    1024u
#define QN_AUTO_MAX    1024u
#define QN_HARD_MAX    4096u
#define QN_FD_RESERVE  128u
#define QN_THERMAL_POLL_MS 3000u

/* With nothing in flight nothing will free up, so a job cannot retry forever. */
#define QN_LAUNCH_TRIES 64u

#if defined(QN_ENGINE_TESTING)
static qn_engine_test_fault engine_test_fault;

void qn_engine_test_set_fault(qn_engine_test_fault fault)
{
    engine_test_fault = fault;
}
#endif

static int engine_epoll_create(void)
{
#if defined(QN_ENGINE_TESTING)
    if (engine_test_fault == QN_ENGINE_TEST_EPOLL_CREATE) {
        errno = EMFILE;
        return -1;
    }
#endif
    return epoll_create1(EPOLL_CLOEXEC);
}

static int engine_thread_create(pthread_t *thread, void *(*entry)(void *), void *arg)
{
#if defined(QN_ENGINE_TESTING)
    if (engine_test_fault == QN_ENGINE_TEST_THREAD_CREATE)
        return EAGAIN;
#endif
    return pthread_create(thread, NULL, entry, arg);
}

static int engine_socket(int domain, int type, int protocol)
{
#if defined(QN_ENGINE_TESTING)
    (void)domain;
    (void)type;
    (void)protocol;
    errno = EMFILE;
    return -1;
#endif
    return socket(domain, type, protocol);
}

enum { PS_CONNECT = 0, PS_SEND, PS_RECV };

/* tw must remain first for the timeout-wheel cast. */
typedef struct qn_probe {
    qn_tw_node tw;
    qn_job     job;
    uint64_t   t0_ns;
    uint32_t   connect_us;
    uint32_t   rx_first_us;
    int        fd;
    uint32_t   slot;
    uint8_t    state;
    uint8_t    tls;
    uint16_t   io_len, io_off, rx_len;
    uint8_t    buf[QN_PROBE_BUF];
} qn_probe;

#define QN_DEADLINE_FLOOR_MS 120u

static void wstats_reset(qn_wstats *s)
{
    atomic_store_explicit(&s->claimed, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->issued, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->completed, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->open, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->refused, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->timeout, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->reset, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->unreach, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->cancelled, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->rx_bytes, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->local_launch_failures, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->syscall_failures, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->terminal_job_failures, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->local_terminal_failures, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->protocol_failures, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->unattempted, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->skipped, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->window, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->inflight, 0u, memory_order_relaxed);
    atomic_store_explicit(&s->deadline_ms, 0u, memory_order_relaxed);
}

static void aimd_init(qn_aimd *a, uint32_t start, uint32_t wmax, uint32_t timeout_ms)
{
    memset(a, 0, sizeof *a);
    a->wmax              = QN_MAX(wmax, 1u);
    a->wmin              = QN_MIN(16u, a->wmax);
    a->window            = QN_CLAMP(start, a->wmin, a->wmax);
    a->deadline_ms       = timeout_ms;
    a->deadline_floor_ms = QN_MIN(QN_DEADLINE_FLOOR_MS, timeout_ms);
}

/* The larger of baseline and EWMA protects slow live targets. */
static void aimd_retune_deadline(qn_aimd *a, uint32_t ceiling_ms)
{
    uint32_t from_base, from_ewma, want;

    if (a->ok_samples < 16)
        return;

    from_base = a->rtt_base_us / 1000u * 6u;
    from_ewma = a->rtt_ewma_us / 1000u * 3u;
    want      = QN_MAX(from_base, from_ewma);

    a->deadline_ms = QN_CLAMP(want, a->deadline_floor_ms, ceiling_ms);
}

static void aimd_cut(qn_aimd *a, uint32_t num, uint32_t den, uint64_t now_ms)
{
    /* Correlated failures may cut the window only once per interval. */
    if (now_ms - a->last_cut_ms < 200)
        return;
    a->window      = QN_MAX(a->wmin, a->window * num / den);
    a->last_cut_ms = now_ms;
    a->ok_run      = 0;
    a->batch_n = a->batch_timeouts = 0;
    a->cuts++;
}

/* Local resource pressure triggers an immediate hard backoff. */
static void aimd_pressure(qn_aimd *a, uint64_t now_ms)
{
    a->window      = QN_MAX(a->wmin, a->window * 3u / 5u);
    a->last_cut_ms = now_ms;
    a->cuts++;
}

static void aimd_sample(qn_aimd *a, uint32_t rtt_us, bool timed_out, uint64_t now_ms,
                        uint32_t ceiling_ms)
{
    a->batch_n++;
    if (timed_out) {
        a->batch_timeouts++;
    } else if (rtt_us) {
        a->rtt_ewma_us = a->rtt_ewma_us ? (a->rtt_ewma_us * 7u + rtt_us) / 8u : rtt_us;
        if (!a->rtt_base_us || rtt_us < a->rtt_base_us)
            a->rtt_base_us = rtt_us;
        if (a->ok_samples < 0xFFFFu)
            a->ok_samples++;
        aimd_retune_deadline(a, ceiling_ms);
    }

    if (a->batch_n < a->window)
        return;

    if (a->batch_timeouts * 4u > a->batch_n) {
        aimd_cut(a, 4, 5, now_ms);
    } else if (a->rtt_base_us && a->rtt_ewma_us > a->rtt_base_us * 2u) {
        /* Queueing delay is the early congestion signal. */
        aimd_cut(a, 9, 10, now_ms);
    } else {
        a->window = QN_MIN(a->wmax, a->window + 1u + a->window / 32u);
        a->ok_run++;
    }
    a->batch_n = a->batch_timeouts = 0;
}

static void sock_tune(int fd, uint32_t retries)
{
    int one = 1;
    int v;

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    /* Abortive close avoids scanner-side TIME_WAIT accumulation. */
    {
        struct linger lg = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }

    /* Probes only consume the response head. */
    v = 8192;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    v = 4096;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);

#ifdef TCP_SYNCNT
    v = (int)QN_CLAMP(retries + 1u, 1u, 4u);
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &v, sizeof v);
#endif
}

static qn_result errno_to_result(int e)
{
    switch (e) {
    case 0:            return QN_R_OPEN;
    case ECONNREFUSED: return QN_R_REFUSED;
    case ETIMEDOUT:    return QN_R_TIMEOUT;
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:        return QN_R_RESET;
    case EHOSTUNREACH:
    case ENETUNREACH:
    case EHOSTDOWN:
    case ENETDOWN:
    case ENETRESET:    return QN_R_UNREACH;
    case ECANCELED:    return QN_R_CANCELLED;
    default:           return QN_R_ERROR;
    }
}

static qn_failure_origin errno_origin(int e)
{
    switch (e) {
    case 0:            return QN_FAIL_NONE;
    case ECONNREFUSED:
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:        return QN_FAIL_PEER;
    case ETIMEDOUT:
    case EHOSTUNREACH:
    case ENETUNREACH:
    case EHOSTDOWN:
    case ENETDOWN:
    case ENETRESET:    return QN_FAIL_PATH;
    case ECANCELED:    return QN_FAIL_NONE;
    default:           return QN_FAIL_LOCAL;
    }
}

static qn_failure_origin result_origin(qn_result result)
{
    switch (result) {
    case QN_R_REFUSED:
    case QN_R_RESET:     return QN_FAIL_PEER;
    case QN_R_TIMEOUT:
    case QN_R_UNREACH:   return QN_FAIL_PATH;
    case QN_R_ERROR:     return QN_FAIL_LOCAL;
    default:             return QN_FAIL_NONE;
    }
}

static socklen_t sockaddr_of(const qn_addr *a, uint16_t port, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (a->af == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)(void *)ss;
        s->sin_family         = AF_INET;
        s->sin_port           = htons(port);
        s->sin_addr.s_addr    = htonl(a->u.v4);
        return sizeof *s;
    }
    {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)(void *)ss;
        s->sin6_family         = AF_INET6;
        s->sin6_port           = htons(port);
        memcpy(&s->sin6_addr, a->u.v6, 16);
        return sizeof *s;
    }
}

static void probe_release(qn_worker *w, qn_probe *p)
{
    if (p->tw.armed)
        qn_tw_disarm(&w->wheel, &p->tw);
    if (p->fd >= 0) {
        if (w->epfd >= 0)
            epoll_ctl(w->epfd, EPOLL_CTL_DEL, p->fd, NULL);
        close(p->fd);
        p->fd = -1;
    }
    w->freelist[w->nfree++] = p->slot;
    w->inflight--;
}

static void probe_finish_obs(qn_worker *w, qn_probe *p, qn_result res, uint32_t rtt_us,
                             qn_failure_origin origin, int sys_errno, int protocol_code)
{
    qn_event ev;
    uint64_t now_ms = qn_now_ms();

    memset(&ev, 0, sizeof ev);
    ev.job    = p->job;
    ev.result = (uint8_t)res;
    ev.tls    = p->tls;
    ev.rtt_us = rtt_us;
    ev.failure_origin = (uint8_t)origin;
    ev.sys_errno      = sys_errno;
    ev.protocol_code  = protocol_code;

    if (p->rx_len) {
        if (p->job.stage == QN_STAGE_BANNER) {
            uint16_t n = QN_MIN(p->rx_len, (uint16_t)QN_EVENT_BODY);
            memcpy(ev.body, p->buf, n);
            ev.blen = n;
        }
        atomic_fetch_add_explicit(&w->st->rx_bytes, p->rx_len, memory_order_relaxed);
    }

    switch (res) {
    case QN_R_OPEN:    atomic_fetch_add_explicit(&w->st->open, 1, memory_order_relaxed); break;
    case QN_R_REFUSED: atomic_fetch_add_explicit(&w->st->refused, 1, memory_order_relaxed); break;
    case QN_R_TIMEOUT: atomic_fetch_add_explicit(&w->st->timeout, 1, memory_order_relaxed); break;
    case QN_R_RESET:   atomic_fetch_add_explicit(&w->st->reset, 1, memory_order_relaxed); break;
    case QN_R_UNREACH: atomic_fetch_add_explicit(&w->st->unreach, 1, memory_order_relaxed); break;
    case QN_R_CANCELLED:
        atomic_fetch_add_explicit(&w->st->cancelled, 1, memory_order_relaxed);
        break;
    default:
        atomic_fetch_add_explicit(&w->st->terminal_job_failures, 1, memory_order_relaxed);
        break;
    }
    if (origin == QN_FAIL_PROTOCOL)
        atomic_fetch_add_explicit(&w->st->protocol_failures, 1, memory_order_relaxed);
    if (origin == QN_FAIL_LOCAL)
        atomic_fetch_add_explicit(&w->st->local_terminal_failures, 1,
                                  memory_order_relaxed);
    atomic_fetch_add_explicit(&w->st->completed, 1, memory_order_relaxed);

    if (!w->eng->cfg.no_adaptive && res != QN_R_CANCELLED && origin != QN_FAIL_LOCAL)
        aimd_sample(&w->aimd, rtt_us, res == QN_R_TIMEOUT, now_ms, w->eng->cfg.timeout_ms);

    (void)qn_ring_push(&w->out, &ev);
    probe_release(w, p);
}

static void probe_finish(qn_worker *w, qn_probe *p, qn_result res, uint32_t rtt_us)
{
    probe_finish_obs(w, p, res, rtt_us, result_origin(res), 0, 0);
}

/* A stage that speaks first may reuse a cached TFO cookie. */
static bool stage_speaks_first(uint8_t stage)
{
    return stage == QN_STAGE_TLS;
}

static int build_payload(qn_worker *w, qn_probe *p)
{
    if (w->eng->cfg.profile_instance)
        return qn_tls_build_hello_instance(p->buf, sizeof p->buf,
                                           w->eng->cfg.profile_instance, &w->rng);
    return qn_tls_build_hello(p->buf, sizeof p->buf, w->eng->cfg.sni, &w->rng,
                              (qn_tls_fp)w->eng->cfg.fingerprint);
}

static bool probe_launch(qn_worker *w, const qn_job *job)
{
    struct sockaddr_storage ss;
    socklen_t               slen;
    struct epoll_event      ee;
    qn_probe               *p;
    int                     fd, rc, err;
    bool                    tfo;

    w->launch_errno = 0;
    if (!w->nfree)
        return false;

#if defined(QN_ENGINE_TESTING)
    if (engine_test_fault == QN_ENGINE_TEST_SYNTHETIC_OPEN) {
        p = &w->slots[w->freelist[w->nfree - 1u]];
        p->job = *job;
        p->fd = -1;
        w->nfree--;
        w->inflight++;
        atomic_fetch_add_explicit(&w->st->issued, 1u, memory_order_relaxed);
        probe_finish_obs(w, p, QN_R_OPEN, 1000u, QN_FAIL_NONE, 0, 0u);
        return true;
    }
#endif

    fd = engine_socket(job->addr.af, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                       IPPROTO_TCP);
    if (fd < 0) {
        w->launch_errno = errno;
        if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM)
            aimd_pressure(&w->aimd, qn_now_ms());
        atomic_fetch_add_explicit(&w->st->local_launch_failures, 1, memory_order_relaxed);
        return false;
    }
    sock_tune(fd, w->eng->cfg.retries);

    p              = &w->slots[w->freelist[w->nfree - 1]];
    p->job         = *job;
    p->fd          = fd;
    p->tls         = QN_TLS_NONE;
    p->connect_us  = 0;
    p->rx_first_us = 0;
    p->io_len = p->io_off = p->rx_len = 0;
    slen                              = sockaddr_of(&job->addr, job->port, &ss);

    tfo = atomic_load_explicit(&w->eng->tfo, memory_order_relaxed) && stage_speaks_first(job->stage);
    if (tfo) {
        int n = build_payload(w, p);
        if (n <= 0) {
            tfo = false;
        } else {
            p->io_len = (uint16_t)n;
            p->state  = PS_SEND;
        }
    }

    p->t0_ns = qn_now_ns();

    if (tfo) {
        ssize_t n = sendto(fd, p->buf, p->io_len, MSG_FASTOPEN | MSG_NOSIGNAL,
                           (const struct sockaddr *)(const void *)&ss, slen);
        if (n >= 0) {
            p->io_off = (uint16_t)n;
            rc        = 0;
            err       = EINPROGRESS;
        } else {
            err = errno;
            rc  = -1;
            if (qn_errno_not_supported(err) || err == EINVAL) {
                atomic_store_explicit(&w->eng->tfo, false, memory_order_relaxed);
                p->state  = PS_CONNECT;
                p->io_len = 0;
                tfo       = false;
            }
        }
    }

    if (!tfo) {
        p->state = PS_CONNECT;
        rc       = connect(fd, (const struct sockaddr *)(const void *)&ss, slen);
        err      = rc == 0 ? 0 : errno;
    }

    if (rc != 0 && err != EINPROGRESS) {
        if (err == ENOBUFS || qn_errno_would_block(err) || err == EADDRNOTAVAIL) {
            /* Retry locally constrained launches without blaming the target. */
            aimd_pressure(&w->aimd, qn_now_ms());
            close(fd);
            p->fd = -1;
            w->launch_errno = err;
            return false;
        }
        w->nfree--;
        w->inflight++;
        atomic_fetch_add_explicit(&w->st->issued, 1, memory_order_relaxed);
        probe_finish_obs(w, p, errno_to_result(err),
                         err == ECONNREFUSED
                             ? (uint32_t)((qn_now_ns() - p->t0_ns) / 1000ull)
                             : 0u,
                         errno_origin(err), err, 0);
        return true;
    }

    if (w->epfd >= 0) {
        ee.events   = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        ee.data.ptr = p;
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, fd, &ee) != 0) {
            w->launch_errno = errno;
            close(fd);
            p->fd = -1;
            atomic_fetch_add_explicit(&w->st->local_launch_failures, 1, memory_order_relaxed);
            return false;
        }
    } else if (fd >= FD_SETSIZE) {
        close(fd);
        p->fd = -1;
        w->launch_errno = EMFILE;
        aimd_pressure(&w->aimd, qn_now_ms());
        return false;
    }

    w->nfree--;
    w->inflight++;
    atomic_fetch_add_explicit(&w->st->issued, 1, memory_order_relaxed);

    qn_tw_arm(&w->wheel, &p->tw, qn_now_ms(), w->aimd.deadline_ms);
    return true;
}

static void on_connected(qn_worker *w, qn_probe *p)
{
    uint32_t rtt = (uint32_t)((qn_now_ns() - p->t0_ns) / 1000ull);
    int      n;

    p->connect_us = rtt;

    switch (p->job.stage) {
    case QN_STAGE_TCP:
    case QN_STAGE_RTT:
        probe_finish(w, p, QN_R_OPEN, rtt);
        return;

    case QN_STAGE_BANNER:
        p->state  = PS_RECV;
        p->rx_len = 0;
        /* A passive read gets its own budget; the connect one is spent. */
        qn_tw_arm(&w->wheel, &p->tw, qn_now_ms(), w->aimd.deadline_ms);
        return;

    default:
        n = build_payload(w, p);
        break;
    }

    if (n <= 0) {
        probe_finish(w, p, QN_R_ERROR, rtt);
        return;
    }
    p->io_len = (uint16_t)n;
    p->io_off = 0;
    p->state  = PS_SEND;
}

static void on_writable(qn_worker *w, qn_probe *p)
{
    while (p->io_off < p->io_len) {
        ssize_t n = send(p->fd, p->buf + p->io_off, (size_t)(p->io_len - p->io_off), MSG_NOSIGNAL);
        if (n > 0) {
            p->io_off = (uint16_t)(p->io_off + n);
            continue;
        }
        if (n < 0 && qn_errno_would_block(errno))
            return;
        {
            int err = n < 0 ? errno : ECONNRESET;

            if (p->job.stage == QN_STAGE_TLS) {
                if (err == ECONNRESET || err == EPIPE)
                    p->tls = QN_TLS_RESET;
                else if (err == ETIMEDOUT)
                    p->tls = QN_TLS_SILENCE;
            }
            probe_finish_obs(w, p, errno_to_result(err), 0, errno_origin(err), err, 0);
        }
        return;
    }

    p->state  = PS_RECV;
    p->rx_len = 0;
    /* The receive deadline measures the peer, not the connect stage. */
    qn_tw_arm(&w->wheel, &p->tw, qn_now_ms(), w->aimd.deadline_ms);
}

static bool rx_complete(const qn_probe *p)
{
    if (p->job.stage == QN_STAGE_TLS) {
        uint32_t record_len;

        if (p->rx_len < 5u)
            return false;
        record_len = ((uint32_t)p->buf[3] << 8) | p->buf[4];
        return record_len > 16640u || (uint32_t)p->rx_len >= 5u + record_len;
    }
    return p->rx_len >= 32;
}

static void on_readable(qn_worker *w, qn_probe *p)
{
    uint32_t rtt = (uint32_t)((qn_now_ns() - p->t0_ns) / 1000ull);
    bool     eof = false;

    for (;;) {
        ssize_t n;
        size_t  room = sizeof p->buf - p->rx_len;

        if (!room)
            break;
        n = recv(p->fd, p->buf + p->rx_len, room, 0);

        if (n > 0) {
            if (!p->rx_len)
                p->rx_first_us = rtt;
            p->rx_len = (uint16_t)(p->rx_len + n);
            if (rx_complete(p))
                break;
            continue;
        }
        if (n == 0) {
            eof = true;
            break; /* clean EOF: classify whatever arrived */
        }
        if (qn_errno_would_block(errno))
            return;
        if (errno == EINTR)
            continue;

        {
            int err = errno;

            if (p->job.stage == QN_STAGE_TLS) {
                if (err == ECONNRESET)
                    p->tls = QN_TLS_RESET;
                else if (err == ETIMEDOUT)
                    p->tls = QN_TLS_SILENCE;
            }
            probe_finish_obs(w, p, errno_to_result(err), rtt, errno_origin(err), err, 0);
        }
        return;
    }

    if (p->job.stage == QN_STAGE_TLS) {
        p->tls = (uint8_t)qn_tls_classify(p->buf, p->rx_len);
        if (eof && !p->rx_len && p->tls == QN_TLS_SILENCE) {
            /* EOF before a TLS record is peer evidence, not a local scanner failure. */
            probe_finish_obs(w, p, QN_R_OPEN, rtt, QN_FAIL_PEER, 0,
                             QN_TLS_SILENCE);
            return;
        }
        if (p->tls == QN_TLS_GARBAGE) {
            probe_finish_obs(w, p, QN_R_OPEN, rtt, QN_FAIL_PROTOCOL, 0,
                             QN_TLS_GARBAGE);
            return;
        }
        if (p->tls == QN_TLS_ALERT) {
            probe_finish_obs(w, p, QN_R_OPEN, rtt, QN_FAIL_PEER, 0, QN_TLS_ALERT);
            return;
        }
    }

    probe_finish(w, p, QN_R_OPEN,
                 p->job.stage == QN_STAGE_BANNER
                     ? (p->rx_len ? p->rx_first_us : p->connect_us)
                     : rtt);
}

static void on_timeout(qn_worker *w, qn_probe *p)
{
    /* A short peer answer is not a timeout and must not train AIMD as silence. */
    if (p->rx_len) {
        if (p->job.stage == QN_STAGE_TLS)
            p->tls = (uint8_t)qn_tls_classify(p->buf, p->rx_len);
        if (p->tls == QN_TLS_GARBAGE) {
            probe_finish_obs(w, p, QN_R_OPEN, p->rx_first_us, QN_FAIL_PROTOCOL, 0,
                             QN_TLS_GARBAGE);
        } else if (p->tls == QN_TLS_ALERT) {
            probe_finish_obs(w, p, QN_R_OPEN, p->rx_first_us, QN_FAIL_PEER, 0,
                             QN_TLS_ALERT);
        } else {
            probe_finish(w, p, QN_R_OPEN, p->rx_first_us);
        }
        return;
    }

    if (p->job.stage == QN_STAGE_TLS)
        p->tls = (p->state == PS_CONNECT) ? QN_TLS_NONE : QN_TLS_SILENCE;
    if (p->job.stage == QN_STAGE_BANNER && p->state == PS_RECV) {
        probe_finish(w, p, QN_R_OPEN, p->connect_us);
        return;
    }
    probe_finish_obs(w, p, QN_R_TIMEOUT, 0, QN_FAIL_PATH, ETIMEDOUT, 0);
}

/* A token buys one network attempt; exhaustion, refusal, and local failure cost nothing. */
static bool tokens_ready(qn_worker *w, uint64_t now_ms)
{
    if (!w->rate_per_sec)
        return true;

    if (now_ms > w->token_ts_ms) {
        uint64_t add = (now_ms - w->token_ts_ms) * w->rate_per_sec * 1024ull / 1000ull;
        w->tokens    = QN_MIN(w->tokens + add, (uint64_t)w->rate_per_sec * 1024ull);
        w->token_ts_ms = now_ms;
    }
    return w->tokens >= 1024u;
}

static void tokens_debit(qn_worker *w)
{
    if (w->rate_per_sec && w->tokens >= 1024u)
        w->tokens -= 1024u;
}

static uint32_t tokens_wait_ms(const qn_worker *w)
{
    uint64_t den, need, ms;

    if (!w->rate_per_sec || w->tokens >= 1024u)
        return 1;
    need = 1024u - w->tokens;
    den  = (uint64_t)w->rate_per_sec * 1024u;
    ms   = (need * 1000u + den - 1u) / den;
    return (uint32_t)QN_CLAMP(ms, 1ull, 50ull);
}

static void thermal_update(qn_worker *w, uint64_t now_ms)
{
    qn_engine *e = w->eng;
    uint32_t   temp, pct, old;

    if (w->id || e->cfg.no_thermal || now_ms < w->thermal_next_ms)
        return;
    w->thermal_next_ms = now_ms + QN_THERMAL_POLL_MS;
    temp = qn_thermal_read();
    if (!temp)
        return;

    old = atomic_load_explicit(&e->thermal_pct, memory_order_relaxed);
    pct = old;
    if (temp >= 82000u)
        pct = 40u;
    else if (temp >= 76000u)
        pct = 55u;
    else if (temp >= 70000u)
        pct = 75u;
    else if (temp <= 65000u)
        pct = 100u;

    atomic_store_explicit(&e->thermal_mc, temp, memory_order_relaxed);
    /* Two agreeing polls before moving, so one wobble cannot halve the window. */
    if (pct == old) {
        w->thermal_want = pct;
        w->thermal_agree = 0;
        return;
    }
    if (pct != w->thermal_want) {
        w->thermal_want  = pct;
        w->thermal_agree = 1;
        return;
    }
    if (++w->thermal_agree < 2u)
        return;
    atomic_store_explicit(&e->thermal_pct, pct, memory_order_relaxed);
}

static uint32_t effective_window(const qn_worker *w)
{
    uint32_t pct = atomic_load_explicit(&w->eng->thermal_pct, memory_order_relaxed);
    uint32_t cap = (uint32_t)((uint64_t)w->aimd.wmax * pct / 100u);

    cap = QN_CLAMP(cap, w->aimd.wmin, w->aimd.wmax);
    return QN_MIN(w->aimd.window, cap);
}

static bool claim_next(qn_worker *w, uint64_t *idx)
{
    qn_engine *e = w->eng;

    if (w->claim_cur >= w->claim_end) {
        w->claim_cur = atomic_fetch_add_explicit(&e->cursor, QN_CLAIM_CHUNK, memory_order_relaxed);
        w->claim_end = w->claim_cur + QN_CLAIM_CHUNK;
    }
    *idx = w->claim_cur++;
    return !e->task->domain || *idx < e->task->domain;
}

/* A job that was drawn but never launched still owes the task one event. */
static void job_terminal(qn_worker *w, const qn_job *job, qn_result res,
                         qn_failure_origin origin, int sys_errno)
{
    qn_event ev;

    memset(&ev, 0, sizeof ev);
    ev.job            = *job;
    ev.result         = (uint8_t)res;
    ev.failure_origin = (uint8_t)origin;
    ev.sys_errno      = sys_errno;

    if (res == QN_R_CANCELLED)
        atomic_fetch_add_explicit(&w->st->cancelled, 1, memory_order_relaxed);
    else {
        atomic_fetch_add_explicit(&w->st->terminal_job_failures, 1, memory_order_relaxed);
        if (origin == QN_FAIL_LOCAL)
            atomic_fetch_add_explicit(&w->st->local_terminal_failures, 1,
                                      memory_order_relaxed);
        if (origin == QN_FAIL_PROTOCOL)
            atomic_fetch_add_explicit(&w->st->protocol_failures, 1,
                                      memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&w->st->completed, 1, memory_order_relaxed);
    (void)qn_ring_push(&w->out, &ev);
}

static void job_abandon(qn_worker *w, const qn_job *job)
{
    job_terminal(w, job, QN_R_ERROR, QN_FAIL_LOCAL, w->launch_errno ? w->launch_errno : EIO);
}

static void engine_fatal(qn_worker *w, int error)
{
    qn_engine *e = w->eng;
    uint32_t   expected = UINT32_MAX;

    if (!error)
        error = EIO;
    /* Publish fatal last so acquire readers also observe its errno and worker id. */
    if (atomic_compare_exchange_strong_explicit(&e->fatal_worker, &expected, w->id,
                                                memory_order_relaxed,
                                                memory_order_relaxed)) {
        atomic_store_explicit(&e->fatal_errno, error, memory_order_relaxed);
        atomic_store_explicit(&e->fatal, true, memory_order_release);
    }
    atomic_store_explicit(&e->stopping, true, memory_order_release);
}

static void worker_fill(qn_worker *w, uint64_t now_ms)
{
    const qn_task *t      = w->eng->task;
    uint32_t       window = effective_window(w);
    uint32_t       rcap   = w->out.mask + 1u;

    while (w->inflight < window && w->nfree) {
        uint64_t idx;
        qn_job   job;

        /* Reserve enough ring slots for every in-flight result. */
        if (qn_ring_len(&w->out) + w->inflight + 1u >= rcap)
            return;
        if (!w->has_pending && w->drained)
            return;
        if (!tokens_ready(w, now_ms))
            return;

        if (w->has_pending) {
            job = w->pending_job;
        } else {
            qn_task_next rc;

            if (!claim_next(w, &idx)) {
                w->drained      = true;
                w->drain_reason = QN_TASK_EXHAUSTED;
                return;
            }
            /* Drawn is claimed: an index the task declines must not vanish. */
            atomic_fetch_add_explicit(&w->st->claimed, 1, memory_order_relaxed);
            memset(&job, 0, sizeof job);
            rc = t->next(t->ctx, idx, &job);
            if (rc != QN_TASK_JOB) {
                atomic_fetch_add_explicit(&w->st->skipped, 1, memory_order_relaxed);
                w->drained      = true;
                w->drain_reason = rc;
                if (rc == QN_TASK_STOP_CONDITION)
                    atomic_store_explicit(&w->eng->stop_condition, true,
                                          memory_order_release);
                else if (rc == QN_TASK_CANCELLED)
                    atomic_store_explicit(&w->eng->stopping, true, memory_order_release);
                else if (rc == QN_TASK_FATAL)
                    engine_fatal(w, EIO);
                return;
            }
        }

        if (!probe_launch(w, &job)) {
            /* Retry the claimed job because drawing again would skip its address. */
            w->pending_job = job;
            w->has_pending = true;
            if (w->inflight || ++w->pending_tries < QN_LAUNCH_TRIES)
                return;
            job_abandon(w, &job);
            w->has_pending   = false;
            w->pending_tries = 0;
            continue;
        }

        /* Debit only now: the attempt reached the network. */
        tokens_debit(w);
        w->has_pending   = false;
        w->pending_tries = 0;
    }
}

/* Retirement accounts for active probes, the pending job, and every undrawn claim. */
static void worker_retire(qn_worker *w)
{
    qn_engine *e      = w->eng;
    uint64_t   domain = e->task ? e->task->domain : 0u;
    uint64_t   tail;

    for (uint32_t s = 0; s < w->nslots; s++)
        if (w->slots[s].fd >= 0)
            probe_finish_obs(w, &w->slots[s], QN_R_CANCELLED, 0, QN_FAIL_NONE, 0, 0);

    if (w->has_pending) {
        bool fatal = atomic_load_explicit(&e->fatal, memory_order_acquire);

        job_terminal(w, &w->pending_job, fatal ? QN_R_ERROR : QN_R_CANCELLED,
                     fatal ? QN_FAIL_LOCAL : QN_FAIL_NONE,
                     fatal ? atomic_load_explicit(&e->fatal_errno, memory_order_relaxed) : 0);
        w->has_pending = false;
    }

    /* The unused tail of a reserved chunk is this worker's responsibility too. */
    tail = (domain && w->claim_end > domain) ? domain : w->claim_end;
    if (tail > w->claim_cur) {
        uint64_t lost = tail - w->claim_cur;
        /* A tail the run meant to leave is skipped; one it still owed is not. */
        bool deliberate = w->drain_reason == QN_TASK_EXHAUSTED ||
                          w->drain_reason == QN_TASK_STOP_CONDITION ||
                          atomic_load_explicit(&e->stop_condition, memory_order_acquire);

        atomic_fetch_add_explicit(&w->st->claimed, lost, memory_order_relaxed);
        atomic_fetch_add_explicit(deliberate ? &w->st->skipped : &w->st->unattempted,
                                  lost, memory_order_relaxed);
    }
    w->claim_cur = w->claim_end;
}

enum { QEV_IN = 1u << 0, QEV_OUT = 1u << 1, QEV_ERR = 1u << 2, QEV_HUP = 1u << 3 };

static int sock_error(int fd)
{
    int       err = 0;
    socklen_t sl  = sizeof err;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl) != 0)
        err = errno;
    return err;
}

static void dispatch_probe(qn_worker *w, qn_probe *p, uint32_t fl)
{
    uint32_t rtt;
    int      err;

    if (p->fd < 0)
        return;
    QN_PREFETCH(p->buf);
    rtt = (uint32_t)((qn_now_ns() - p->t0_ns) / 1000ull);

    if (p->state == PS_CONNECT && (fl & (QEV_OUT | QEV_ERR | QEV_HUP))) {
        err = sock_error(p->fd);
        /* A hangup before the connection came up is a refusal, not an EOF. */
        if (!err && (fl & (QEV_ERR | QEV_HUP)))
            err = ECONNRESET;
        if (err) {
            probe_finish_obs(w, p, errno_to_result(err), err == ETIMEDOUT ? 0u : rtt,
                             errno_origin(err), err, 0);
            return;
        }
        on_connected(w, p);
    }

    if (p->fd >= 0 && p->state == PS_SEND && (fl & QEV_OUT)) {
        on_writable(w, p);
        /* Edge-triggered: a reply that landed mid-send is not re-reported. */
        if (p->fd >= 0 && p->state == PS_RECV)
            fl |= QEV_IN;
    }

    /* Drain readable bytes before a simultaneous error closes their socket. */
    if (p->fd >= 0 && p->state == PS_RECV && (fl & QEV_IN))
        on_readable(w, p);

    if (p->fd < 0 || !(fl & (QEV_ERR | QEV_HUP)))
        return;

    err = sock_error(p->fd);
    if (!err) {
        /* Hangup with nothing pending is a clean EOF: classify what arrived. */
        if (p->job.stage == QN_STAGE_TLS) {
            p->tls = (uint8_t)qn_tls_classify(p->buf, p->rx_len);
            if (p->tls == QN_TLS_GARBAGE) {
                probe_finish_obs(w, p, QN_R_OPEN, p->rx_len ? p->rx_first_us : rtt,
                                 QN_FAIL_PROTOCOL, 0, QN_TLS_GARBAGE);
                return;
            }
        }
        probe_finish_obs(w, p, QN_R_OPEN,
                         p->rx_len ? p->rx_first_us
                                   : (p->job.stage == QN_STAGE_BANNER
                                          ? p->connect_us : rtt),
                         QN_FAIL_PEER, 0, 0);
        return;
    }
    if (p->job.stage == QN_STAGE_TLS) {
        if (err == ECONNRESET)
            p->tls = QN_TLS_RESET;
        else if (err == ETIMEDOUT)
            p->tls = QN_TLS_SILENCE;
    }
    probe_finish_obs(w, p, errno_to_result(err), err == ETIMEDOUT ? 0u : rtt,
                     errno_origin(err), err, 0);
}

static int worker_select(qn_worker *w, int timeout_ms)
{
    fd_set         rfds, wfds, efds;
    struct timeval tv;
    int            maxfd = -1;
    int            rc;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    for (uint32_t i = 0; i < w->nslots; i++) {
        qn_probe *p = &w->slots[i];

        if (p->fd < 0)
            continue;
        if (p->state == PS_RECV)
            FD_SET(p->fd, &rfds);
        else
            FD_SET(p->fd, &wfds);
        FD_SET(p->fd, &efds);
        if (p->fd > maxfd)
            maxfd = p->fd;
    }

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    rc = select(maxfd + 1, &rfds, &wfds, &efds, &tv);
    w->now_ms = qn_now_ms();
    if (rc <= 0)
        return rc;

    for (uint32_t i = 0; i < w->nslots; i++) {
        qn_probe *p = &w->slots[i];
        uint32_t  fl = 0;

        if (p->fd < 0)
            continue;
        if (FD_ISSET(p->fd, &rfds))
            fl |= QEV_IN;
        if (FD_ISSET(p->fd, &wfds))
            fl |= QEV_OUT;
        if (FD_ISSET(p->fd, &efds))
            fl |= QEV_ERR;
        if (fl)
            dispatch_probe(w, p, fl);
    }
    return rc;
}

static void *worker_main(void *arg)
{
    qn_worker         *w = (qn_worker *)arg;
    qn_engine         *e = w->eng;
    struct epoll_event evs[QN_EPOLL_BATCH];

    if (!e->cfg.no_affinity && e->topo)
        (void)qn_pin_thread(w->cpu);

    /* Android's default timer slack is too large for an 8 ms wheel. */
    prctl(PR_SET_TIMERSLACK, 1UL, 0UL, 0UL, 0UL);

    for (;;) {
        uint64_t now_ms;
        int      nev = 0, timeout;

        if (atomic_load_explicit(&e->stopping, memory_order_relaxed))
            break;

        now_ms = w->now_ms = qn_now_ms();
        thermal_update(w, now_ms);
        worker_fill(w, now_ms);
        if (w->drained && !w->has_pending && !w->inflight)
            break;

        atomic_store_explicit(&w->st->window, effective_window(w), memory_order_relaxed);
        atomic_store_explicit(&w->st->inflight, w->inflight, memory_order_relaxed);
        atomic_store_explicit(&w->st->deadline_ms, w->aimd.deadline_ms, memory_order_relaxed);

        timeout = w->inflight ? (int)qn_tw_next_timeout(&w->wheel, now_ms, 50u)
                              : (int)tokens_wait_ms(w);
        if (w->epfd >= 0)
            nev = epoll_wait(w->epfd, evs, QN_EPOLL_BATCH, timeout);
        else
            nev = worker_select(w, timeout);

        /* Deadlines armed below must run from after the wait, not before it. */
        now_ms = w->now_ms = qn_now_ms();

        if (nev < 0) {
            if (errno == EINTR)
                continue;
            atomic_fetch_add_explicit(&w->st->syscall_failures, 1, memory_order_relaxed);
            engine_fatal(w, errno);
            break;
        }

        if (w->epfd >= 0)
            for (int i = 0; i < nev; i++) {
                uint32_t fl = 0;

                if (evs[i].events & (EPOLLIN | EPOLLRDHUP))
                    fl |= QEV_IN;
                if (evs[i].events & EPOLLOUT)
                    fl |= QEV_OUT;
                if (evs[i].events & EPOLLERR)
                    fl |= QEV_ERR;
                if (evs[i].events & EPOLLHUP)
                    fl |= QEV_HUP;
                dispatch_probe(w, (qn_probe *)evs[i].data.ptr, fl);
            }

        for (;;) {
            qn_tw_node *n = qn_tw_expire(&w->wheel, now_ms);
            if (!n)
                break;
            on_timeout(w, (qn_probe *)(void *)n);
        }
    }

    worker_retire(w);
    atomic_fetch_sub_explicit(&e->alive, 1, memory_order_release);
    return NULL;
}

static uint32_t ring_capacity(uint32_t slots)
{
    uint32_t cap = QN_RING_MIN;
    uint32_t need = slots <= (UINT32_MAX - 2u) / 2u ? slots * 2u + 2u : UINT32_MAX;

    while (cap < need && cap <= UINT32_MAX / 2u)
        cap <<= 1;
    return cap;
}

static uint32_t topology_cpu(const qn_topology *t, uint32_t worker)
{
    uint32_t clusters, total = 0, nth;

    if (!t || !t->nclusters)
        return 0;
    clusters = t->heterogeneous ? QN_MIN(t->nclusters, 2u) : t->nclusters;
    for (uint32_t c = 0; c < clusters; c++)
        total += t->cluster[c].count;
    if (!total)
        return 0;

    nth = worker % total;
    for (uint32_t c = 0; c < clusters; c++) {
        for (uint32_t cpu = 0; cpu < QN_MAX_CPUS; cpu++) {
            if (!(t->cluster[c].mask & (1u << cpu)))
                continue;
            if (!nth)
                return cpu;
            nth--;
        }
    }
    return 0;
}

bool qn_engine_init(qn_engine *e, const qn_config *cfg, const qn_topology *topo)
{
    uint32_t nofile, fd_cap, max_safe, per_worker;
    size_t probe_bytes, free_bytes, event_bytes, worker_bytes, stats_bytes;
    size_t per_worker_bytes, workers_total, need;

    memset(e, 0, sizeof *e);
    e->cfg  = *cfg;
    e->topo = topo;

    e->nworkers = cfg->workers ? cfg->workers : qn_topology_workers(topo, true);
    e->nworkers = QN_CLAMP(e->nworkers, 1u, 16u);
    if (cfg->rate && e->nworkers > cfg->rate)
        e->nworkers = cfg->rate;

    nofile = qn_raise_nofile();
    fd_cap = nofile > QN_FD_RESERVE ? nofile - QN_FD_RESERVE : QN_MAX(nofile / 2u, 1u);
    max_safe = QN_MIN(fd_cap, QN_HARD_MAX);
    if (cfg->select_backend)
        max_safe = QN_MIN(max_safe, (uint32_t)FD_SETSIZE > QN_FD_RESERVE
                                       ? (uint32_t)FD_SETSIZE - QN_FD_RESERVE
                                       : 1u);

    if (cfg->concurrency) {
        if (cfg->concurrency > max_safe) {
            e->init_errno = EMFILE;
            return false;
        }
        e->concurrency = cfg->concurrency;
    } else {
        e->concurrency = QN_MIN(max_safe, QN_MIN(QN_AUTO_MAX, QN_MAX(64u, e->nworkers * 128u)));
    }
    e->concurrency = QN_MAX(e->concurrency, 1u);

    e->nworkers = QN_MIN(e->nworkers, QN_MAX(e->concurrency / 16u, 1u));
    per_worker  = (e->concurrency + e->nworkers - 1u) / e->nworkers;
    e->ring_cap = ring_capacity(per_worker);

    if (!qn_size_mul(sizeof(qn_probe), per_worker, &probe_bytes) ||
        !qn_size_mul(sizeof(uint32_t), per_worker, &free_bytes) ||
        !qn_size_mul(sizeof(qn_event), e->ring_cap, &event_bytes) ||
        probe_bytes > SIZE_MAX - free_bytes ||
        probe_bytes + free_bytes > SIZE_MAX - event_bytes ||
        probe_bytes + free_bytes + event_bytes > SIZE_MAX - 4096u) {
        e->init_errno = EOVERFLOW;
        return false;
    }
    per_worker_bytes = probe_bytes + free_bytes + event_bytes + 4096u;
    if (!qn_size_mul(per_worker_bytes, e->nworkers, &workers_total) ||
        !qn_size_mul(sizeof(qn_worker), e->nworkers, &worker_bytes) ||
        !qn_size_mul(sizeof(qn_wstats), e->nworkers, &stats_bytes) ||
        workers_total > SIZE_MAX - worker_bytes ||
        workers_total + worker_bytes > SIZE_MAX - stats_bytes ||
        workers_total + worker_bytes + stats_bytes > SIZE_MAX - 65536u) {
        e->init_errno = EOVERFLOW;
        return false;
    }
    need = workers_total + worker_bytes + stats_bytes + 65536u;

    e->init_errno = pthread_mutex_init(&e->rate_lock, NULL);
    if (e->init_errno != 0)
        return false;
    atomic_store_explicit(&e->status, QN_ENGINE_IDLE, memory_order_relaxed);
    atomic_store_explicit(&e->fatal_worker, UINT32_MAX, memory_order_relaxed);

    if (!qn_arena_init(&e->arena, need)) {
        e->init_errno = errno ? errno : ENOMEM;
        pthread_mutex_destroy(&e->rate_lock);
        return false;
    }

    e->w  = QN_ARENA_LINE(&e->arena, qn_worker, e->nworkers);
    e->st = QN_ARENA_LINE(&e->arena, qn_wstats, e->nworkers);
    if (!e->w || !e->st) {
        e->init_errno = ENOMEM;
        qn_arena_free(&e->arena);
        pthread_mutex_destroy(&e->rate_lock);
        return false;
    }

    for (uint32_t i = 0; i < e->nworkers; i++) {
        qn_worker *w = &e->w[i];

        w->eng    = e;
        w->id     = i;
        w->st     = &e->st[i];
        w->epfd   = -1;
        w->cpu    = topology_cpu(topo, i);
        w->nslots = e->concurrency / e->nworkers + (i < e->concurrency % e->nworkers ? 1u : 0u);

        w->slots    = QN_ARENA_LINE(&e->arena, qn_probe, w->nslots);
        w->freelist = QN_ARENA_ARRAY(&e->arena, uint32_t, w->nslots);
        if (!w->slots || !w->freelist ||
            !qn_ring_init(&w->out, &e->arena, e->ring_cap, sizeof(qn_event))) {
            e->init_errno = ENOMEM;
            qn_arena_free(&e->arena);
            pthread_mutex_destroy(&e->rate_lock);
            return false;
        }
        for (uint32_t s = 0; s < w->nslots; s++) {
            w->slots[s].slot = s;
            w->slots[s].fd   = -1;
            w->freelist[s]   = w->nslots - 1u - s;
        }
        w->nfree = w->nslots;
        {
            uint64_t master = cfg->effective_seed;

            if (!cfg->seed_explicit && !master)
                master = qn_rng_entropy();
            qn_rng_seed(&w->rng,
                        qn_seed_derive(master, 0x574F524B45520000ull + i));
        }
    }

    atomic_store_explicit(&e->thermal_pct, 100u, memory_order_relaxed);
    qn_arena_prefault(&e->arena);
    return true;
}

void qn_engine_destroy(qn_engine *e)
{
    qn_engine_stop(e);
    pthread_mutex_destroy(&e->rate_lock);
    qn_arena_free(&e->arena);
    memset(e, 0, sizeof *e);
}

bool qn_engine_start(qn_engine *e, const qn_task *t)
{
    uint32_t started = 0;
    uint32_t failed_worker = UINT32_MAX;
    int      start_error = 0;

    if (!e || !t || !t->next || !t->on_event) {
        if (e)
            e->init_errno = EINVAL;
        return false;
    }
    if (atomic_load_explicit(&e->started, memory_order_relaxed))
        return false;
    e->task = t;
    atomic_store_explicit(&e->cursor, 0, memory_order_relaxed);
    atomic_store_explicit(&e->stopping, false, memory_order_relaxed);
    atomic_store_explicit(&e->stop_condition, false, memory_order_relaxed);
    atomic_store_explicit(&e->tfo, true, memory_order_relaxed);
    atomic_store_explicit(&e->fatal, false, memory_order_relaxed);
    atomic_store_explicit(&e->fatal_errno, 0, memory_order_relaxed);
    atomic_store_explicit(&e->fatal_worker, UINT32_MAX, memory_order_relaxed);
    atomic_store_explicit(&e->alive, 0, memory_order_relaxed);
    atomic_store_explicit(&e->started, true, memory_order_relaxed);
    atomic_store_explicit(&e->status, QN_ENGINE_RUNNING, memory_order_relaxed);
    e->t_start_ms = qn_now_ms();
    pthread_mutex_lock(&e->rate_lock);
    e->rate_last_completed = 0;
    e->rate_last_ms        = 0;
    pthread_mutex_unlock(&e->rate_lock);
    atomic_store_explicit(&e->rate_ewma, 0u, memory_order_relaxed);
    e->select_workers      = 0;

    for (uint32_t i = 0; i < e->nworkers; i++) {
        qn_worker *w = &e->w[i];
        uint32_t   start_window;

        w->drained       = false;
        w->drain_reason  = QN_TASK_JOB;
        w->launched      = false;
        w->has_pending   = false;
        w->pending_tries = 0;
        w->launch_errno  = 0;
        w->claim_cur     = 0;
        w->claim_end     = 0;
        w->inflight      = 0;
        w->nfree         = w->nslots;
        w->now_ms        = e->t_start_ms;
        w->rate_per_sec = e->cfg.rate ? e->cfg.rate / e->nworkers +
                                           (i < e->cfg.rate % e->nworkers ? 1u : 0u)
                                     : 0u;
        w->tokens      = (uint64_t)w->rate_per_sec * 1024u;
        w->token_ts_ms = e->t_start_ms;
        w->thermal_next_ms = e->t_start_ms;
        for (uint32_t s = 0; s < w->nslots; s++) {
            w->slots[s].fd = -1;
            memset(&w->slots[s].tw, 0, sizeof w->slots[s].tw);
            w->freelist[s] = w->nslots - 1 - s;
        }
        wstats_reset(w->st);
        /* Reset prevents a prior task's event reaching this task's callback. */
        qn_ring_reset(&w->out);
        qn_tw_init(&w->wheel, e->t_start_ms);
        start_window = e->cfg.no_adaptive ? w->nslots : QN_MIN(64u, w->nslots);
        aimd_init(&w->aimd, start_window, w->nslots, e->cfg.timeout_ms);
        atomic_store_explicit(&w->st->deadline_ms, w->aimd.deadline_ms, memory_order_relaxed);

        w->epfd = e->cfg.select_backend ? -1 : engine_epoll_create();
        if (w->epfd < 0) {
            int epoll_error = errno ? errno : EIO;
            uint32_t select_cap = (uint32_t)FD_SETSIZE > QN_FD_RESERVE
                                      ? (uint32_t)FD_SETSIZE - QN_FD_RESERVE
                                      : 1u;
            if (e->concurrency > select_cap) {
                start_error = epoll_error;
                failed_worker = i;
                break;
            }
            e->select_workers++;
        }
        atomic_fetch_add_explicit(&e->alive, 1u, memory_order_relaxed);
        {
            int thread_error = engine_thread_create(&w->tid, worker_main, w);

            if (thread_error != 0) {
                start_error = thread_error;
                failed_worker = i;
                atomic_fetch_sub_explicit(&e->alive, 1u, memory_order_relaxed);
                if (w->epfd >= 0)
                    close(w->epfd);
                w->epfd = -1;
                break;
            }
        }
        w->launched = true;
        started++;
    }

    if (started != e->nworkers) {
        atomic_store_explicit(&e->stopping, true, memory_order_relaxed);
        for (uint32_t i = 0; i < started; i++) {
            pthread_join(e->w[i].tid, NULL);
            e->w[i].launched = false;
            if (e->w[i].epfd >= 0) {
                close(e->w[i].epfd);
                e->w[i].epfd = -1;
            }
        }
        atomic_store_explicit(&e->alive, 0, memory_order_relaxed);
        atomic_store_explicit(&e->started, false, memory_order_relaxed);
        if (!start_error)
            start_error = EIO;
        e->init_errno = start_error;
        atomic_store_explicit(&e->fatal_errno, start_error, memory_order_relaxed);
        atomic_store_explicit(&e->fatal_worker, failed_worker, memory_order_relaxed);
        atomic_store_explicit(&e->fatal, true, memory_order_release);
        atomic_store_explicit(&e->status, QN_ENGINE_FATAL, memory_order_release);
        return false;
    }
    return true;
}

uint32_t qn_engine_poll(qn_engine *e, uint32_t max_events)
{
    qn_event batch[128];
    uint32_t total = 0;

    if (!e->task)
        return 0;

    for (uint32_t i = 0; i < e->nworkers && total < max_events; i++) {
        uint32_t want = QN_MIN((uint32_t)QN_ARRAY_LEN(batch), max_events - total);
        uint32_t got  = qn_ring_pop_batch(&e->w[i].out, batch, want);

        for (uint32_t k = 0; k < got; k++)
            e->task->on_event(e->task->ctx, &batch[k]);
        total += got;
    }
    return total;
}

bool qn_engine_done(const qn_engine *e)
{
    if (!atomic_load_explicit(&e->started, memory_order_relaxed))
        return true;
    if (atomic_load_explicit(&e->alive, memory_order_acquire))
        return false;
    for (uint32_t i = 0; i < e->nworkers; i++)
        if (qn_ring_len(&e->w[i].out))
            return false;
    return true;
}

bool qn_engine_failed(const qn_engine *e, int *error_out, uint32_t *worker_out)
{
    bool failed = atomic_load_explicit(&e->fatal, memory_order_acquire);

    if (error_out)
        *error_out = failed ? atomic_load_explicit(&e->fatal_errno, memory_order_relaxed) : 0;
    if (worker_out)
        *worker_out = failed ? atomic_load_explicit(&e->fatal_worker, memory_order_relaxed)
                             : UINT32_MAX;
    return failed;
}

void qn_engine_join(qn_engine *e)
{
    if (!atomic_load_explicit(&e->started, memory_order_relaxed))
        return;
    for (uint32_t i = 0; i < e->nworkers; i++) {
        if (e->w[i].launched) {
            pthread_join(e->w[i].tid, NULL);
            e->w[i].launched = false;
        }
        if (e->w[i].epfd >= 0) {
            close(e->w[i].epfd);
            e->w[i].epfd = -1;
        }
    }
    atomic_store_explicit(&e->started, false, memory_order_relaxed);

    /* Settle the run's outcome once every worker has retired its own work. */
    if (atomic_load_explicit(&e->fatal, memory_order_acquire))
        atomic_store_explicit(&e->status, QN_ENGINE_FATAL, memory_order_release);
    else if (atomic_load_explicit(&e->stopping, memory_order_relaxed))
        atomic_store_explicit(&e->status, QN_ENGINE_CANCELLED, memory_order_release);
    else if (atomic_load_explicit(&e->stop_condition, memory_order_acquire))
        atomic_store_explicit(&e->status, QN_ENGINE_STOPPED, memory_order_release);
    else
        atomic_store_explicit(&e->status, QN_ENGINE_COMPLETE, memory_order_release);
}

void qn_engine_stop(qn_engine *e)
{
    atomic_store_explicit(&e->stopping, true, memory_order_release);
    qn_engine_join(e);
}

qn_engine_status qn_engine_state(const qn_engine *e)
{
    return (qn_engine_status)atomic_load_explicit(&e->status, memory_order_acquire);
}

const char *qn_engine_status_str(qn_engine_status s)
{
    switch (s) {
    case QN_ENGINE_RUNNING:   return "running";
    case QN_ENGINE_COMPLETE:  return "complete";
    case QN_ENGINE_STOPPED:   return "stop-condition-met";
    case QN_ENGINE_CANCELLED: return "cancelled";
    case QN_ENGINE_FATAL:     return "infrastructure-failure";
    default:                  return "idle";
    }
}

const char *qn_task_next_str(qn_task_next r)
{
    switch (r) {
    case QN_TASK_JOB:            return "job";
    case QN_TASK_EXHAUSTED:      return "exhausted";
    case QN_TASK_STOP_CONDITION: return "stop-condition";
    case QN_TASK_CANCELLED:      return "cancelled";
    default:                     return "fatal";
    }
}

/* claimed == completed + skipped + unattempted once the workers are joined. */
bool qn_engine_accounted(const qn_engine *e, uint64_t *missing)
{
    qn_engine_snapshot sn;
    uint64_t           seen;

    qn_engine_stats(e, &sn);
    if (sn.completed > sn.claimed || sn.skipped > sn.claimed - sn.completed ||
        sn.unattempted > sn.claimed - sn.completed - sn.skipped) {
        if (missing)
            *missing = 0u;
        return false;
    }
    seen = sn.completed + sn.skipped + sn.unattempted;
    if (missing)
        *missing = sn.claimed > seen ? sn.claimed - seen : 0u;
    return sn.claimed == seen;
}

/* One place decides what a run amounts to, so every front end agrees. */
static qn_run_outcome engine_outcome(const qn_engine_finalization *f)
{
    if (f->failed || f->stats.status == QN_ENGINE_FATAL)
        return QN_RUN_FAILED;
    if (!f->accounted || f->stats.events_dropped)
        return QN_RUN_FAILED;
    if (f->stats.local_terminal_failures)
        return QN_RUN_FAILED;
    if (f->stats.status == QN_ENGINE_CANCELLED)
        return QN_RUN_CANCELLED;
    /* Work still owed is incomplete; work deliberately left is not. */
    if (f->stats.unattempted)
        return QN_RUN_INCOMPLETE;
    return QN_RUN_SUCCESS;
}

void qn_engine_finalize(qn_engine *e, bool cancel,
                        qn_engine_finalization *out)
{
    qn_engine_finalization result;

    memset(&result, 0, sizeof result);
    result.fatal_worker = UINT32_MAX;
    if (cancel)
        qn_engine_stop(e);
    else
        qn_engine_join(e);
    while (qn_engine_poll(e, UINT32_MAX))
        ;
    qn_engine_stats(e, &result.stats);
    result.accounted = qn_engine_accounted(e, &result.missing);
    result.failed = qn_engine_failed(e, &result.fatal_errno,
                                     &result.fatal_worker);
    result.outcome = engine_outcome(&result);
    if (out)
        *out = result;
}

void qn_engine_stats(const qn_engine *e, qn_engine_snapshot *out)
{
    uint64_t now = qn_now_ms();

    memset(out, 0, sizeof *out);
    for (uint32_t i = 0; i < e->nworkers; i++) {
        const qn_wstats *s = &e->st[i];

        out->claimed += atomic_load_explicit(&s->claimed, memory_order_relaxed);
        out->issued += atomic_load_explicit(&s->issued, memory_order_relaxed);
        out->completed += atomic_load_explicit(&s->completed, memory_order_relaxed);
        out->open += atomic_load_explicit(&s->open, memory_order_relaxed);
        out->refused += atomic_load_explicit(&s->refused, memory_order_relaxed);
        out->timeout += atomic_load_explicit(&s->timeout, memory_order_relaxed);
        out->reset += atomic_load_explicit(&s->reset, memory_order_relaxed);
        out->unreach += atomic_load_explicit(&s->unreach, memory_order_relaxed);
        out->cancelled += atomic_load_explicit(&s->cancelled, memory_order_relaxed);
        out->rx_bytes += atomic_load_explicit(&s->rx_bytes, memory_order_relaxed);
        out->local_launch_failures +=
            atomic_load_explicit(&s->local_launch_failures, memory_order_relaxed);
        out->syscall_failures +=
            atomic_load_explicit(&s->syscall_failures, memory_order_relaxed);
        out->terminal_job_failures +=
            atomic_load_explicit(&s->terminal_job_failures, memory_order_relaxed);
        out->local_terminal_failures +=
            atomic_load_explicit(&s->local_terminal_failures, memory_order_relaxed);
        out->protocol_failures +=
            atomic_load_explicit(&s->protocol_failures, memory_order_relaxed);
        out->unattempted += atomic_load_explicit(&s->unattempted, memory_order_relaxed);
        out->skipped += atomic_load_explicit(&s->skipped, memory_order_relaxed);
        out->window += atomic_load_explicit(&s->window, memory_order_relaxed);
        out->inflight += atomic_load_explicit(&s->inflight, memory_order_relaxed);
        out->events_dropped += atomic_load_explicit(&e->w[i].out.dropped, memory_order_relaxed);
    }
    out->network_failures = out->refused + out->timeout + out->reset + out->unreach;
    out->elapsed_ms  = e->t_start_ms ? now - e->t_start_ms : 0;
    out->thermal_mc  = atomic_load_explicit(&e->thermal_mc, memory_order_relaxed);
    out->thermal_pct = atomic_load_explicit(&e->thermal_pct, memory_order_relaxed);
    out->rate_now    = atomic_load_explicit(&e->rate_ewma, memory_order_relaxed);
    out->status      = qn_engine_state(e);
}

void qn_engine_rate_sample(qn_engine *e)
{
    qn_engine_snapshot sn;
    uint64_t           now = qn_now_ms();

    qn_engine_stats(e, &sn);
    pthread_mutex_lock(&e->rate_lock);
    if (!e->rate_last_ms) {
        e->rate_last_ms        = now;
        e->rate_last_completed = sn.completed;
    } else if (now > e->rate_last_ms + 100) {
        uint64_t d    = sn.completed - e->rate_last_completed;
        uint32_t inst = (uint32_t)(d * 1000ull / (now - e->rate_last_ms));
        uint32_t prev = atomic_load_explicit(&e->rate_ewma, memory_order_relaxed);

        atomic_store_explicit(&e->rate_ewma, prev ? (prev * 3u + inst) / 4u : inst,
                              memory_order_relaxed);
        e->rate_last_completed = sn.completed;
        e->rate_last_ms        = now;
    }
    pthread_mutex_unlock(&e->rate_lock);
}

uint32_t qn_engine_deadline_ms(const qn_engine *e)
{
    uint32_t worst = 0;

    for (uint32_t i = 0; i < e->nworkers; i++) {
        uint32_t deadline = atomic_load_explicit(&e->st[i].deadline_ms, memory_order_relaxed);
        if (deadline > worst)
            worst = deadline;
    }
    return worst ? worst : e->cfg.timeout_ms;
}

const char *qn_engine_backend(const qn_engine *e)
{
    if (e->cfg.select_backend)
        return "select";
    if (!e->select_workers)
        return "epoll";
    return e->select_workers == e->nworkers ? "select" : "hybrid";
}

static bool cellular_link_present(void)
{
    DIR           *d = opendir("/sys/class/net");
    struct dirent *ent;
    bool           found = false;

    if (!d)
        return false;
    while ((ent = readdir(d)) != NULL) {
        const char *n = ent->d_name;

        if (!strncmp(n, "rmnet", 5u) || !strncmp(n, "ccmni", 5u) ||
            !strncmp(n, "pdp", 3u) || !strncmp(n, "wwan", 4u)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

void qn_engine_warm_radio(const qn_config *cfg)
{
    static const char *anchors[] = { "1.1.1.1", "8.8.8.8" };

    if (cfg->warm_mode == QN_WARM_OFF ||
        (cfg->warm_mode == QN_WARM_AUTO &&
         (cfg->mode != QN_MODE_CF || !cellular_link_present())))
        return;

    for (unsigned i = 0; i < QN_ARRAY_LEN(anchors); i++) {
        struct sockaddr_storage ss;
        socklen_t               slen;
        qn_addr                 a;
        int                     fd;

        if (!qn_addr_parse(anchors[i], &a))
            continue;
        fd = engine_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (fd < 0)
            continue;
        {
            struct timeval tv = { 0, 400000 };
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
        slen = sockaddr_of(&a, 443, &ss);
        connect(fd, (const struct sockaddr *)(const void *)&ss, slen);
        close(fd);
    }
}
