/* Deep verification: full handshake, real bytes, then an idle hold. */

#include "qanat/verify.h"

#include "qanat/http1.h"
#include "qanat/http2.h"
#include "qanat/profile.h"
#include "qanat/probe.h"
#include "qanat/request_gate.h"
#include "qanat/tls_hello.h"
#include "outbuf.h"
#include "flowmeter.h"
#include "qanat/util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#define VER_OUT_BUF 8192
#define VER_IN_BUF  16384
#define VER_APP_BUF 32768
#define VER_EARLY_APP_BUF 16384
#define VER_REQ_BUF 2048
#define VER_PATH_MAX 700u /* fits the stricter 1024-byte HPACK request block */
#define VER_FLOW_MAX (16u * 1024u * 1024u)

typedef enum {
    C_FREE = 0,
    C_CONNECT,
    C_SOCKS_METHOD,
    C_SOCKS_CONNECT,
    C_HANDSHAKE,
    C_BODY,
    C_IDLE,
    C_DONE
} cstate;
typedef enum { P_NONE = 0, P_HTTP1, P_HTTP2 } proto;
typedef enum { POOL_NONE = 0, POOL_ACTIVE, POOL_STABILITY } pool_class;

typedef struct {
    size_t active_live;
    size_t stability_live;
    size_t active_limit;
    size_t stability_limit;
    size_t peak_active;
    size_t peak_stability;
} verify_pool;

typedef struct {
    qn_tls_session tls;
    qn_rng         rng;
    int            fd;
    uint8_t        st;
    uint8_t        pool_class;
    size_t         idx;
    verify_pool   *pool;
    qn_socks5_client socks;

    uint64_t t_start, t_conn, t_hs, t_first;
    uint64_t profile_seed;
    uint64_t early_app_ns;
    uint64_t t_flow_progress; /* last time flow bytes actually advanced */
    uint64_t flow_requested;
    uint64_t deadline;
    uint64_t overall_deadline;
    uint64_t idle_until;
    uint64_t idle_start;
    uint64_t t_flow_end; /* latched once, so finalize is idempotent */
    uint64_t trace_bytes;
    uint64_t flow_bytes;
    uint64_t t_flow;

    uint8_t   outstore[VER_OUT_BUF];
    qn_outbuf out;
    qn_request_gate request;
    uint8_t   early_app[VER_EARLY_APP_BUF];
    size_t    early_app_n;

    qn_http1 h1;
    qn_h2    h2;

    bool trace_done;
    bool flow_sent;
    bool flow_done;
    uint8_t proto;
} conn;

typedef enum {
    VERIFY_ALLOC_WORK = 0,
    VERIFY_ALLOC_SLOTS,
    VERIFY_ALLOC_INBUF,
    VERIFY_ALLOC_APPBUF
} verify_alloc_kind;

#if defined(QN_VERIFY_TESTING)
static qn_verify_test_fault verify_test_fault;
static void                *verify_test_event_ptr;
static uint32_t             verify_test_wait_step;
static bool                 verify_test_short_seen;

void qn_verify_test_set_fault(qn_verify_test_fault fault)
{
    verify_test_fault = fault;
    verify_test_event_ptr = NULL;
    verify_test_wait_step = 0u;
    verify_test_short_seen = false;
}

bool qn_verify_test_short_write_seen(void)
{
    return verify_test_short_seen;
}

static bool verify_test_fake_transport(void)
{
    return verify_test_fault == QN_VERIFY_TEST_EPOLL_CTL ||
           verify_test_fault == QN_VERIFY_TEST_EPOLL_WAIT ||
           verify_test_fault == QN_VERIFY_TEST_READ ||
           verify_test_fault == QN_VERIFY_TEST_SHORT_WRITE;
}
#endif

static void *verify_alloc(size_t count, size_t size, verify_alloc_kind kind,
                          bool zero)
{
#if defined(QN_VERIFY_TESTING)
    bool fail = (kind == VERIFY_ALLOC_WORK &&
                 verify_test_fault == QN_VERIFY_TEST_WORK_ALLOC) ||
                (kind == VERIFY_ALLOC_SLOTS &&
                 verify_test_fault == QN_VERIFY_TEST_SLOT_ALLOC) ||
                (kind == VERIFY_ALLOC_INBUF &&
                 verify_test_fault == QN_VERIFY_TEST_INBUF_ALLOC) ||
                (kind == VERIFY_ALLOC_APPBUF &&
                 verify_test_fault == QN_VERIFY_TEST_APPBUF_ALLOC);

    if (fail) {
        errno = ENOMEM;
        return NULL;
    }
#else
    (void)kind;
#endif
    return zero ? calloc(count, size) : malloc(count * size);
}

static int verify_epoll_create(void)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fault == QN_VERIFY_TEST_EPOLL_CREATE) {
        errno = EMFILE;
        return -1;
    }
#endif
    return epoll_create1(EPOLL_CLOEXEC);
}

static int verify_epoll_ctl(int ep, int op, int fd, struct epoll_event *event)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fake_transport()) {
        if (verify_test_fault == QN_VERIFY_TEST_EPOLL_CTL && op == EPOLL_CTL_ADD) {
            errno = EIO;
            return -1;
        }
        if (event && (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD))
            verify_test_event_ptr = event->data.ptr;
        return 0;
    }
#endif
    return epoll_ctl(ep, op, fd, event);
}

static int verify_epoll_wait(int ep, struct epoll_event *events, int maxevents,
                             int timeout)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fake_transport()) {
        (void)ep;
        (void)timeout;
        if (verify_test_fault == QN_VERIFY_TEST_EPOLL_WAIT) {
            errno = EIO;
            return -1;
        }
        if (!events || maxevents < 1 || !verify_test_event_ptr) {
            errno = EINVAL;
            return -1;
        }
        memset(events, 0, sizeof *events);
        events[0].events = verify_test_wait_step++ == 0u ? EPOLLOUT : EPOLLIN;
        events[0].data.ptr = verify_test_event_ptr;
        return 1;
    }
#endif
    return epoll_wait(ep, events, maxevents, timeout);
}

static int verify_get_socket_error(int fd, int *error, socklen_t *length)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fake_transport()) {
        (void)fd;
        if (!error || !length || *length < sizeof *error) {
            errno = EINVAL;
            return -1;
        }
        *error = 0;
        *length = sizeof *error;
        return 0;
    }
#endif
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, error, length);
}

static ssize_t verify_send(int fd, const void *buffer, size_t length, int flags)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fake_transport()) {
        (void)fd;
        (void)buffer;
        (void)flags;
        if (verify_test_fault == QN_VERIFY_TEST_SHORT_WRITE &&
            !verify_test_short_seen && length > 1u) {
            verify_test_short_seen = true;
            return (ssize_t)(length / 2u);
        }
        return (ssize_t)length;
    }
#endif
    return send(fd, buffer, length, flags);
}

static ssize_t verify_read(int fd, void *buffer, size_t length)
{
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fake_transport()) {
        (void)fd;
        (void)buffer;
        (void)length;
        if (verify_test_fault == QN_VERIFY_TEST_READ) {
            errno = EIO;
            return -1;
        }
        return 0;
    }
#endif
    return read(fd, buffer, length);
}

static bool absorb_app(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg,
                       const uint8_t *p, size_t n, uint64_t observed_ns);

void qn_verify_defaults(qn_verify_cfg *c)
{
    memset(c, 0, sizeof *c);
    c->sni         = "www.cloudflare.com";
    c->trace_path  = "/cdn-cgi/trace";
    c->fp          = QN_TLS_FP_CHROME;
    c->allow_tls12 = true;
    c->port        = 443;
    c->concurrency = 64;
    c->stability_concurrency = 512;
    c->timeout_ms  = 8000;
    c->idle_ms     = 5000;
    c->want_bytes  = 0; /* opt-in: needs an SNI that serves bulk data */
}

qn_run_outcome qn_verify_run_outcome(qn_verify_state state)
{
    switch (state) {
    case QN_VERIFY_COMPLETE:      return QN_RUN_SUCCESS;
    case QN_VERIFY_PARTIAL:       return QN_RUN_INCOMPLETE;
    case QN_VERIFY_CANCELLED:     return QN_RUN_CANCELLED;
    case QN_VERIFY_INFRA_FAILURE: return QN_RUN_FAILED;
    default:                      return QN_RUN_FAILED;
    }
}

bool qn_verify_plan_pools(uint32_t active, uint32_t stability,
                          uint32_t idle_ms, size_t candidates,
                          uint32_t fd_budget, qn_verify_pool_plan *out)
{
    uint32_t active_n, stability_n, total_n;

    if (!out || !candidates || !fd_budget)
        return false;
    active_n = active ? active : 64u;
    active_n = (uint32_t)QN_MIN((size_t)QN_MIN(active_n, fd_budget),
                                candidates);
    if (!active_n)
        return false;
    stability_n = idle_ms ? stability : 0u;
    stability_n = (uint32_t)QN_MIN((size_t)stability_n, candidates);
    total_n = active_n;
    if (stability_n > UINT32_MAX - total_n)
        total_n = UINT32_MAX;
    else
        total_n += stability_n;
    total_n = (uint32_t)QN_MIN((size_t)QN_MIN(total_n, fd_budget),
                               candidates);
    if (total_n < candidates)
        stability_n = total_n - active_n;
    else
        stability_n = QN_MIN(stability_n, total_n);
    out->active = active_n;
    out->stability = stability_n;
    out->total = total_n;
    return true;
}

static uint32_t verify_fd_budget(void)
{
    struct rlimit limit;
    uint64_t      current;

    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return 1u;
    current = limit.rlim_cur == RLIM_INFINITY ? UINT32_MAX
                                               : (uint64_t)limit.rlim_cur;
    if (current > 64u)
        current -= 64u;
    else
        current = QN_MAX(current / 2u, 1u);
    return (uint32_t)QN_MIN(current, (uint64_t)UINT32_MAX);
}

bool qn_verify_fingerprint(const qn_verify_cfg *cfg, char ja3[33], char ja4[40])
{
    qn_tls_session s;
    qn_tls_config  tc;
    qn_rng         rng;
    qn_profile_instance local_profile;
    const qn_profile_instance *profile;
    uint8_t        buf[4096];
    bool           ok = false;

    if (!ja3 || !ja4)
        return false;
    ja3[0] = 0;
    ja4[0] = 0;
    if (!cfg || !qn_valid_hostname(cfg->sni) || cfg->fp < QN_TLS_FP_CHROME ||
        cfg->fp >= QN_TLS_FP_COUNT)
        return false;
    profile = cfg->profile;
    if (!profile) {
        if (!qn_profile_instance_init(&local_profile, cfg->fp,
                                      qn_profile_seed_from_run(cfg->seed), cfg->sni,
                                      cfg->allow_tls12, cfg->cert_strict))
            return false;
        profile = &local_profile;
    }

    memset(&tc, 0, sizeof tc);
    tc.profile     = profile;
    tc.sni         = cfg->sni;
    tc.fp          = cfg->fp;
    tc.allow_tls12 = cfg->allow_tls12;
    tc.cert_strict = cfg->cert_strict;
    if (cfg->deterministic) {
        qn_rng_seed(&rng, qn_profile_wire_seed(cfg->seed, 0u));
        tc.rng = &rng;
    }

    qn_tls_init(&s, &tc);
    /* Both must be real; reporting one of two is a half-truth in a preview. */
    if (qn_tls_start(&s, buf, sizeof buf) > 0 && s.ja3[0] && s.ja4[0]) {
        qn_strlcpy(ja3, s.ja3, 33);
        qn_strlcpy(ja4, s.ja4, 40);
        ok = true;
    } else {
        ja3[0] = 0;
        ja4[0] = 0;
    }
    qn_tls_free(&s);
    return ok;
}

static void note(qn_verify_result *r, const char *why)
{
    qn_terminal_observation *terminal = &r->observation.terminal;

    if (!terminal->reason[0])
        qn_strlcpy(terminal->reason, why, sizeof terminal->reason);
}

static void failure(qn_verify_result *r, qn_terminal_outcome outcome,
                    qn_failure_origin origin,
                    qn_result transport, qn_tls_outcome tls, int sys_errno,
                    int protocol_code, const char *why)
{
    qn_observation *observation = &r->observation;

    observation->transport.result = (uint8_t)transport;
    observation->tls.outcome = (uint8_t)tls;
    qn_observation_fail(observation, outcome, origin, sys_errno,
                        protocol_code, why);
}

static bool local_resource_error(int error)
{
    switch (error) {
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        return true;
    default:
        return false;
    }
}

static void network_failure(qn_verify_result *r, int error, const char *fallback)
{
    switch (error) {
    case ECONNREFUSED:
        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_REFUSED, QN_TLS_NONE,
                error, 0, "refused");
        break;
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:
        failure(r, QN_TERM_RESET, QN_FAIL_PEER, QN_R_RESET, QN_TLS_RESET,
                error, 0, "reset");
        break;
    case ETIMEDOUT:
        failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                QN_TLS_SILENCE, error, 0, "timeout");
        break;
    case EHOSTUNREACH:
    case ENETUNREACH:
    case EHOSTDOWN:
    case ENETDOWN:
    case ENETRESET:
        failure(r, QN_TERM_INCONCLUSIVE, QN_FAIL_PATH, QN_R_UNREACH, QN_TLS_NONE,
                error, 0, "unreachable");
        break;
    default:
        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                error, 0, fallback);
        break;
    }
}

static int dial(const qn_addr *a, uint16_t port)
{
    int fd;
    int one = 1;

    if (!a || !port) {
        errno = EINVAL;
        return -1;
    }
#if defined(QN_VERIFY_TESTING)
    if (verify_test_fault == QN_VERIFY_TEST_SOCKET) {
        errno = EMFILE;
        return -1;
    }
    if (verify_test_fake_transport())
        return open("/dev/null", O_RDWR | O_CLOEXEC);
#endif
    if (a->af == AF_INET6) {
        struct sockaddr_in6 sa;
        fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return -1;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6;
        sa.sin6_port   = htons(port);
        memcpy(&sa.sin6_addr, a->u.v6, 16);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 && errno != EINPROGRESS) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
    } else if (a->af == AF_INET) {
        struct sockaddr_in sa;
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return -1;
        memset(&sa, 0, sizeof sa);
        sa.sin_family      = AF_INET;
        sa.sin_port        = htons(port);
        sa.sin_addr.s_addr = htonl(a->u.v4);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 && errno != EINPROGRESS) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return fd;
}

static bool arm(int ep, conn *c, uint32_t events)
{
    struct epoll_event ee;
    memset(&ee, 0, sizeof ee);
    ee.events   = events;
    ee.data.ptr = c;
    return verify_epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ee) == 0;
}

/* The transfer end is latched when bytes stop so the later idle hold cannot extend it. */
static void flow_finalize(conn *c, qn_verify_result *r)
{
    uint64_t       now;
    qn_flow_sample s;
    qn_flow_report rep;
    qn_flow_observation *flow = &r->observation.flow;

    if (!c->t_flow_end)
        c->t_flow_end = qn_now_ns();
    now = c->t_flow_end;

    memset(&s, 0, sizeof s);
    s.requested = c->flow_requested;
    s.received  = c->flow_bytes;
    if (c->t_flow && now > c->t_flow)
        s.span_ns = now - c->t_flow;
    if (c->t_flow_progress && now > c->t_flow_progress)
        s.since_progress_ns = now - c->t_flow_progress;
    qn_flow_report_of(&s, &rep);

    flow->requested = s.requested;
    flow->received = s.received;
    flow->completed = rep.completed;
    flow->kbps = rep.kbps;
    flow->partial_kbps = rep.partial_kbps;
    flow->stall_us = rep.stall_us;
}

static void finish(int ep, conn *c, qn_verify_result *r)
{
    if (c->fd >= 0) {
        verify_epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    qn_tls_free(&c->tls);
    r->observation.bytes = c->trace_bytes + c->flow_bytes;
    flow_finalize(c, r);

    if (!r->observation.transport.connected)
        note(r, "no-tcp");
    if (r->observation.terminal.outcome == QN_TERM_NONE)
        r->observation.terminal.outcome = r->observation.transport.connected
                                              ? QN_TERM_SUCCESS
                                              : QN_TERM_DEAD;
    r->observation.completed = true;
    r->classification = qn_observation_classify(&r->observation);
    c->st = C_DONE;
}

static void finish_without_conn(qn_verify_result *r)
{
    if (r->observation.terminal.outcome == QN_TERM_NONE)
        r->observation.terminal.outcome = r->observation.transport.connected
                                              ? QN_TERM_SUCCESS
                                              : QN_TERM_DEAD;
    r->observation.completed = true;
    r->classification = qn_observation_classify(&r->observation);
}

/* MSG_NOSIGNAL prevents a mid-request peer close from killing a headless process. */
static bool flush_out(conn *c)
{
    while (qn_outbuf_pending(&c->out)) {
        ssize_t w = verify_send(c->fd, qn_outbuf_head(&c->out),
                                qn_outbuf_pending(&c->out), MSG_NOSIGNAL);
        if (w > 0) {
            qn_outbuf_consume(&c->out, (size_t)w);
            continue;
        }
        if (w < 0 && qn_errno_would_block(errno))
            return true;
        if (w < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

static bool queue(conn *c, const uint8_t *p, size_t n)
{
    return qn_outbuf_queue(&c->out, p, n);
}

static bool tls_payload(conn *c, const uint8_t *p, size_t n)
{
    uint8_t rec[VER_REQ_BUF + 64u];
    int     m = qn_tls_send_app(&c->tls, p, n, rec, sizeof rec);

    return m > 0 && queue(c, rec, (size_t)m);
}

static void request_begin(conn *c, qn_verify_result *r, uint8_t request_index)
{
    qn_request_gate_begin(&c->request, request_index);
    c->early_app_n = 0u;
    c->early_app_ns = 0u;
    if (request_index == 1u) {
        r->observation.http.request_queued = true;
        r->observation.http.request_fully_flushed = false;
    } else {
        r->observation.flow.request_queued = true;
        r->observation.flow.request_fully_flushed = false;
    }
}

static uint32_t request_elapsed_us(const conn *c, uint64_t observed_ns)
{
    return qn_request_gate_elapsed_us(&c->request, observed_ns);
}

static bool request_flush_commit(conn *c, qn_verify_result *r,
                                 const qn_verify_cfg *cfg)
{
    uint8_t  request_index;
    size_t   early_n;
    uint64_t observed_ns;

    if (!c->request.queued || c->request.fully_flushed ||
        qn_outbuf_pending(&c->out))
        return true;

    if (!qn_request_gate_mark_flushed(&c->request, 0u, qn_now_ns()))
        return false;
    request_index = c->request.index;
    if (request_index == 1u) {
        r->observation.http.request_fully_flushed = true;
        qn_edge_policy_apply(&r->observation);
    } else {
        r->observation.flow.request_fully_flushed = true;
        c->t_flow = c->request.wire_ns;
        c->t_flow_progress = c->t_flow;
    }

    early_n = c->early_app_n;
    observed_ns = c->early_app_ns;
    c->early_app_n = 0u;
    c->early_app_ns = 0u;
    if (!early_n)
        return true;
    return absorb_app(c, r, cfg, c->early_app, early_n, observed_ns);
}

static const char *flow_path(const qn_verify_cfg *cfg, char out[64])
{
    if (cfg->flow_path)
        return cfg->flow_path;
    if (snprintf(out, 64, "/__down?bytes=%u", cfg->want_bytes) <= 0)
        return NULL;
    return out;
}

static bool valid_request_path(const char *path)
{
    size_t n;

    if (!path || path[0] != '/')
        return false;
    n = strlen(path);
    if (!n || n > VER_PATH_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)path[i];

        /* Pre-encoded ASCII origin-form excludes whitespace, CRLF, and fragments. */
        if (ch < 0x21u || ch > 0x7Eu || ch == '#')
            return false;
    }
    return true;
}

static bool valid_verify_cfg(const qn_verify_cfg *cfg)
{
    return cfg && qn_valid_hostname(cfg->sni) && cfg->port != 0u &&
           cfg->fp >= QN_TLS_FP_CHROME && cfg->fp < QN_TLS_FP_COUNT &&
           valid_request_path(cfg->trace_path) &&
           (!cfg->flow_path || valid_request_path(cfg->flow_path)) &&
           cfg->want_bytes <= VER_FLOW_MAX &&
           (!cfg->profile ||
            (cfg->profile->version == QN_PROFILE_INSTANCE_VERSION &&
             cfg->profile->support != QN_PROFILE_UNSUPPORTED &&
             !strcmp(cfg->profile->sni, cfg->sni))) &&
           (!cfg->socks_enabled ||
            ((cfg->socks_address.af == AF_INET || cfg->socks_address.af == AF_INET6) &&
             cfg->socks_port != 0u && cfg->socks_target_port != 0u &&
             qn_valid_hostname(cfg->socks_target_host)));
}

static bool start_tls(conn *c, qn_verify_result *result,
                      const qn_verify_cfg *cfg)
{
    int hello_length;

    result->observation.transport.connected = true;
    c->t_conn = qn_now_ns();
    c->deadline = qn_now_ms() + cfg->timeout_ms;
    result->observation.transport.connect_us =
        (uint32_t)((c->t_conn - c->t_start) / 1000u);
    result->observation.transport.result = QN_R_OPEN;
    errno = 0;
    hello_length = qn_tls_start(&c->tls, c->outstore, sizeof c->outstore);
    if (hello_length <= 0)
        return false;
    qn_outbuf_commit(&c->out, (size_t)hello_length);
    c->st = C_HANDSHAKE;
    return true;
}

static uint64_t trace_budget_ms(const qn_verify_cfg *cfg)
{
    uint64_t budget = (uint64_t)cfg->timeout_ms * 4u;

    return QN_CLAMP(budget, 5000ull, 60000ull);
}

static bool send_trace(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg)
{
    uint8_t req[VER_REQ_BUF];
    const qn_profile_instance *profile = cfg->profile;
    int     n;

    if (!profile)
        return false;
    qn_strlcpy(r->observation.tls.alpn,
               c->tls.alpn[0] ? c->tls.alpn : "none",
               sizeof r->observation.tls.alpn);
    if (!strcmp(c->tls.alpn, "h2")) {
        int m;
        qn_h2_init(&c->h2);
        n = qn_h2_preface_instance(profile, req, sizeof req);
        if (n < 0)
            return false;
        m = qn_h2_get_instance(profile, 1u, cfg->sni, cfg->trace_path,
                               req + n, sizeof req - (size_t)n);
        if (m < 0)
            return false;
        /* Only a stream we have asked for may deliver anything back. */
        if (!qn_h2_open_stream(&c->h2, 1u))
            return false;
        n += m;
        c->proto = P_HTTP2;
        r->observation.http.protocol = QN_HTTP_PROTOCOL_2;
    } else if (!c->tls.alpn[0] || !strcmp(c->tls.alpn, "http/1.1")) {
        qn_http1_init(&c->h1);
        n = qn_profile_instance_http1_get(profile, cfg->sni, cfg->trace_path,
                                          req, sizeof req);
        if (n < 0)
            return false;
        c->proto = P_HTTP1;
        r->observation.http.protocol = QN_HTTP_PROTOCOL_1;
    } else {
        failure(r, QN_TERM_UNSUPPORTED, QN_FAIL_UNSUPPORTED, QN_R_OPEN,
                QN_TLS_SERVERHELLO, 0, 0, "unsupported-alpn");
        return false;
    }
    if (!tls_payload(c, req, (size_t)n))
        return false;
    request_begin(c, r, 1u);
    c->deadline = qn_now_ms() + cfg->timeout_ms;
    c->overall_deadline = qn_now_ms() + trace_budget_ms(cfg);
    return true;
}

static uint64_t flow_budget_ms(const qn_verify_cfg *cfg)
{
    uint64_t at_64k = ((uint64_t)cfg->want_bytes * 1000u + 65535u) / 65536u;
    uint64_t budget = QN_MAX((uint64_t)cfg->timeout_ms * 4u, at_64k);

    return QN_CLAMP(budget, 30000ull, 300000ull);
}

static bool send_flow(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg)
{
    uint8_t     req[VER_REQ_BUF];
    char        dynamic_path[64];
    const char *path = flow_path(cfg, dynamic_path);
    const char *host = cfg->sni; /* Cloudflare rejects Host that disagrees with SNI */
    const qn_profile_instance *profile = cfg->profile;
    int         n;

    if (!path || !profile)
        return false;
    if (c->proto == P_HTTP2) {
        n = qn_h2_get_instance(profile, 3u, host, path, req, sizeof req);
        if (n >= 0 && !qn_h2_open_stream(&c->h2, 3u))
            return false;
    } else {
        if (!qn_http1_open_response(&c->h1))
            return false;
        n = qn_profile_instance_http1_get(profile, host, path, req, sizeof req);
    }
    if (n < 0 || !tls_payload(c, req, (size_t)n)) {
        note(r, "flow-request");
        return false;
    }
    request_begin(c, r, 2u);
    c->flow_sent = true;
    c->flow_requested = cfg->want_bytes;
    r->observation.flow.requested = cfg->want_bytes;
    c->deadline = qn_now_ms() + cfg->timeout_ms;
    c->overall_deadline = qn_now_ms() + flow_budget_ms(cfg);
    return true;
}

static void start_idle(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg)
{
    verify_pool *pool = c->pool;

    r->observation.bytes = c->trace_bytes + c->flow_bytes;
    flow_finalize(c, r);
    r->observation.stability.requested_ms = cfg->idle_ms;
    c->st = C_IDLE;
    c->idle_start = qn_now_ms();
    if (pool && c->pool_class == POOL_ACTIVE) {
        if (pool->active_live)
            pool->active_live--;
        c->pool_class = POOL_NONE;
    }
    if (cfg->idle_ms && pool &&
        pool->stability_live < pool->stability_limit) {
        pool->stability_live++;
        pool->peak_stability = QN_MAX(pool->peak_stability,
                                      pool->stability_live);
        c->pool_class = POOL_STABILITY;
        r->observation.stability.admitted = true;
        c->idle_until = c->idle_start + cfg->idle_ms;
    } else {
        r->observation.stability.capacity_limited = cfg->idle_ms != 0u;
        if (r->observation.stability.capacity_limited)
            note(r, "hold-capacity");
        c->idle_until = c->idle_start;
    }
    c->deadline = c->idle_until + 500u;
    c->overall_deadline = 0;
}

static bool absorb_h2(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg,
                      const uint8_t *p, size_t n, uint64_t observed_ns)
{
    uint8_t     control[128];
    size_t      control_n;
    qn_h2_event ev;
    qn_h2_rc    rc = qn_h2_feed(&c->h2, p, n, control, sizeof control,
                                &control_n, &ev);

    if (rc != QN_H2_OK) {
        qn_terminal_outcome outcome = rc == QN_H2_UNSUPPORTED || rc == QN_H2_SPACE
                                          ? QN_TERM_UNSUPPORTED
                                          : QN_TERM_PROTOCOL_INVALID;
        qn_failure_origin origin = outcome == QN_TERM_UNSUPPORTED
                                       ? QN_FAIL_UNSUPPORTED
                                       : QN_FAIL_PROTOCOL;
        const char *why = rc == QN_H2_UNSUPPORTED
                              ? "h2-unsupported"
                              : (rc == QN_H2_SPACE ? "h2-space" : "h2-protocol");

        failure(r, outcome, origin, QN_R_OPEN, QN_TLS_SERVERHELLO,
                0, (int)rc, why);
        return false;
    }
    if (control_n && !tls_payload(c, control, control_n)) {
        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                QN_TLS_SERVERHELLO, ENOBUFS, 0, "h2-control");
        return false;
    }

    for (size_t i = 0; i < ev.nstreams; i++) {
        const qn_h2_stream_event *event = &ev.stream[i];
        bool had_headers = r->observation.http.final_headers;
        bool first_trace_body = c->trace_bytes == 0u;

        qn_observation_apply_http(&r->observation, event);
        if ((event->flags & QN_HTTP_FACT_HEADERS) &&
            event->response_index == 1u && !had_headers)
            r->observation.http.ttfb_us = request_elapsed_us(c, observed_ns);
        if (event->flags & QN_HTTP_FACT_BODY) {
            if (event->response_index == 1u) {
                c->trace_bytes += event->body_bytes;
                if (first_trace_body)
                    r->observation.http.trace_body_us =
                        request_elapsed_us(c, observed_ns);
            } else if (event->response_index == 2u) {
                c->flow_bytes += event->body_bytes;
                c->t_flow_progress = observed_ns;
                c->deadline = qn_now_ms() + cfg->timeout_ms;
            }
        }
        if (event->flags & QN_HTTP_FACT_RESET) {
            failure(r, QN_TERM_RESET, QN_FAIL_PEER, QN_R_RESET,
                    QN_TLS_SERVERHELLO, 0, 0, "h2-reset");
            return false;
        }
        if ((event->flags & QN_HTTP_FACT_DONE) &&
            event->response_index == 1u && !c->trace_done) {
            c->trace_done = true;
            if (!cfg->want_bytes)
                start_idle(c, r, cfg);
            else if (!send_flow(c, r, cfg)) {
                failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                        QN_TLS_SERVERHELLO, ENOBUFS, 0, "flow-request");
                return false;
            }
        } else if ((event->flags & QN_HTTP_FACT_DONE) &&
                   event->response_index == 2u) {
            c->flow_done = true;
            if (c->flow_bytes < cfg->want_bytes) {
                failure(r, QN_TERM_INCONCLUSIVE, QN_FAIL_PEER, QN_R_OPEN,
                        QN_TLS_SERVERHELLO, 0, 0, "short-flow");
                return false;
            }
            start_idle(c, r, cfg);
        }
    }

    if (ev.flags & QN_H2_EV_GOAWAY) {
        note(r, "h2-goaway");
        if (c->st == C_IDLE)
            return true;
        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN,
                QN_TLS_SERVERHELLO, 0, 0, "h2-goaway");
        return false;
    }
    return true;
}

static bool absorb_h1(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg,
                      const uint8_t *p, size_t n, uint64_t observed_ns)
{
    qn_http1_event ev;
    qn_http1_rc    rc = qn_http1_feed(&c->h1, p, n, &ev);
    bool           had_headers = r->observation.http.final_headers;
    bool           first_trace_body = c->trace_bytes == 0u;

    if (rc != QN_HTTP1_OK) {
        qn_terminal_outcome outcome = rc == QN_HTTP1_SPACE
                                          ? QN_TERM_UNSUPPORTED
                                          : QN_TERM_PROTOCOL_INVALID;
        qn_failure_origin origin = rc == QN_HTTP1_SPACE
                                       ? QN_FAIL_UNSUPPORTED
                                       : QN_FAIL_PROTOCOL;

        failure(r, outcome, origin, QN_R_OPEN, QN_TLS_SERVERHELLO,
                0, (int)rc, rc == QN_HTTP1_SPACE ? "h1-space" : "h1-protocol");
        return false;
    }
    qn_observation_apply_http(&r->observation, &ev);
    if ((ev.flags & QN_HTTP_FACT_HEADERS) && ev.response_index == 1u && !had_headers)
        r->observation.http.ttfb_us = request_elapsed_us(c, observed_ns);
    if (ev.flags & QN_HTTP_FACT_BODY) {
        if (ev.response_index == 2u || c->flow_sent) {
            c->flow_bytes += ev.body_bytes;
            c->t_flow_progress = observed_ns;
        } else {
            c->trace_bytes += ev.body_bytes;
            if (first_trace_body)
                r->observation.http.trace_body_us =
                    request_elapsed_us(c, observed_ns);
        }
    }
    if ((ev.flags & QN_HTTP_FACT_DONE) && ev.response_index == 1u && !c->trace_done) {
        c->trace_done = true;
        if (!cfg->want_bytes)
            start_idle(c, r, cfg);
        else if (!send_flow(c, r, cfg)) {
            failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                    QN_TLS_SERVERHELLO, ENOBUFS, 0, "flow-request");
            return false;
        }
    } else if ((ev.flags & QN_HTTP_FACT_DONE) && ev.response_index == 2u) {
        c->flow_done = true;
        if (c->flow_bytes < cfg->want_bytes) {
            failure(r, QN_TERM_INCONCLUSIVE, QN_FAIL_PEER, QN_R_OPEN,
                    QN_TLS_SERVERHELLO, 0, 0, "short-flow");
            return false;
        }
        start_idle(c, r, cfg);
    }
    return true;
}

static bool absorb_h1_eof(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg)
{
    qn_http1_event ev;
    qn_http1_rc    rc = qn_http1_eof(&c->h1, &ev);

    if (rc != QN_HTTP1_OK) {
        failure(r, QN_TERM_PROTOCOL_INVALID, QN_FAIL_PROTOCOL, QN_R_OPEN,
                QN_TLS_SERVERHELLO, 0, (int)rc, "h1-eof-protocol");
        return false;
    }
    qn_observation_apply_http(&r->observation, &ev);
    if (!(ev.flags & QN_HTTP_FACT_DONE))
        return true;

    if (ev.response_index == 1u && !c->trace_done) {
        c->trace_done = true;
        if (cfg->want_bytes)
            failure(r, QN_TERM_INCONCLUSIVE, QN_FAIL_PEER, QN_R_OPEN,
                    QN_TLS_SERVERHELLO, 0, 0, "trace-only-closed");
        else
            note(r, "trace-closed");
    } else if (ev.response_index == 2u) {
        c->flow_done = true;
        if (c->flow_bytes < cfg->want_bytes)
            failure(r, QN_TERM_INCONCLUSIVE, QN_FAIL_PEER, QN_R_OPEN,
                    QN_TLS_SERVERHELLO, 0, 0, "short-flow");
    }
    return true;
}

static bool absorb_app(conn *c, qn_verify_result *r, const qn_verify_cfg *cfg,
                       const uint8_t *p, size_t n, uint64_t observed_ns)
{
    if (!n)
        return true;
    switch (qn_request_gate_app(&c->request, n)) {
    case QN_REQUEST_APP_NONE:
        return true;
    case QN_REQUEST_APP_REJECT:
        failure(r, QN_TERM_PROTOCOL_INVALID, QN_FAIL_PROTOCOL, QN_R_OPEN,
                QN_TLS_SERVERHELLO, 0, 0, "app-before-request");
        return false;
    case QN_REQUEST_APP_QUARANTINE:
        if (n > sizeof c->early_app - c->early_app_n) {
            failure(r, QN_TERM_UNSUPPORTED, QN_FAIL_UNSUPPORTED, QN_R_OPEN,
                    QN_TLS_SERVERHELLO, 0, 0, "early-app-space");
            return false;
        }
        if (!c->early_app_n)
            c->early_app_ns = observed_ns;
        memcpy(c->early_app + c->early_app_n, p, n);
        c->early_app_n += n;
        return true;
    case QN_REQUEST_APP_PARSE:
        break;
    default:
        return false;
    }
    if (!c->t_first && c->request.index == 1u) {
        c->t_first = observed_ns;
        r->observation.http.app_first_us = request_elapsed_us(c, observed_ns);
    }
    c->deadline = qn_now_ms() + cfg->timeout_ms;
    return c->proto == P_HTTP2 ? absorb_h2(c, r, cfg, p, n, observed_ns)
                               : absorb_h1(c, r, cfg, p, n, observed_ns);
}

static void retire_conn(int ep, conn *c, qn_verify_result *r, size_t *live, size_t *done)
{
    if (c->pool) {
        if (c->pool_class == POOL_ACTIVE && c->pool->active_live)
            c->pool->active_live--;
        else if (c->pool_class == POOL_STABILITY &&
                 c->pool->stability_live)
            c->pool->stability_live--;
        c->pool_class = POOL_NONE;
    }
    finish(ep, c, r);
    if (*live)
        (*live)--;
    (*done)++;
}

static void set_infra(qn_verify_status *status, int error)
{
    status->state = QN_VERIFY_INFRA_FAILURE;
    status->fatal_errno = error ? error : EIO;
}

size_t qn_verify_slot_bytes(void)
{
    return sizeof(conn);
}

size_t qn_verify_result_bytes(void)
{
    return sizeof(qn_addr) + sizeof(qn_verify_result) * 2u;
}

size_t qn_verify_fixed_bytes(void)
{
    return VER_IN_BUF + VER_APP_BUF;
}

qn_verify_status qn_verify_run(const qn_verify_cfg *cfg, const qn_addr *addrs, size_t n,
                               qn_verify_result *out)
{
    qn_verify_status status = { .state = QN_VERIFY_COMPLETE };
    qn_verify_cfg    c0;
    qn_profile_instance local_profile;
    qn_verify_pool_plan plan;
    verify_pool      pool = { 0 };
    qn_verify_result *caller_out = out, *work = NULL;
    conn            *cs = NULL;
    uint8_t         *inbuf = NULL, *appbuf = NULL;
    int              ep = -1;
    size_t           next = 0, live = 0, done = 0, handshakes = 0, i;
    size_t           work_bytes, slot_bytes;
    uint32_t         slots = 0;
    bool             stop = false;

    if (n <= UINT32_MAX)
        status.unattempted = (uint32_t)n;
    if (!cfg || (!addrs && n) || (!out && n) || n > UINT32_MAX) {
        set_infra(&status, EINVAL);
        if (n > UINT32_MAX)
            status.fatal_errno = EOVERFLOW;
        return status;
    }
    c0 = *cfg;
    if (!c0.profile) {
        if (!qn_profile_instance_init(&local_profile, c0.fp,
                                      qn_profile_seed_from_run(c0.seed), c0.sni,
                                      c0.allow_tls12, c0.cert_strict)) {
            set_infra(&status, EINVAL);
            return status;
        }
        c0.profile = &local_profile;
    }
    if (!valid_verify_cfg(&c0)) {
        set_infra(&status, EINVAL);
        return status;
    }
    for (i = 0; i < n; i++) {
        if (addrs[i].af != AF_INET && addrs[i].af != AF_INET6) {
            set_infra(&status, EAFNOSUPPORT);
            return status;
        }
    }
    if (n) {
        if (!qn_size_mul(n, sizeof *work, &work_bytes)) {
            set_infra(&status, EOVERFLOW);
            return status;
        }
        work = (qn_verify_result *)verify_alloc(1u, work_bytes, VERIFY_ALLOC_WORK,
                                                true);
        if (!work) {
            set_infra(&status, ENOMEM);
            return status;
        }
        out = work;
        for (i = 0; i < n; i++)
            out[i].addr = addrs[i];
    }
    if (c0.progress_total)
        atomic_store_explicit(c0.progress_total,
                              c0.progress_grand_total ? c0.progress_grand_total : n,
                              memory_order_release);
    if (c0.progress_done)
        atomic_store_explicit(c0.progress_done, c0.progress_base,
                              memory_order_release);
    if (!n)
        return status;
    if (c0.cancel && atomic_load_explicit(c0.cancel, memory_order_acquire)) {
        status.state = QN_VERIFY_CANCELLED;
        goto out;
    }
    if (!c0.concurrency)
        c0.concurrency = 64u;
    if (!c0.stability_concurrency)
        c0.stability_concurrency = 512u;
    if (!c0.timeout_ms)
        c0.timeout_ms = 1u;
    if (!qn_verify_plan_pools(c0.concurrency, c0.stability_concurrency,
                              c0.idle_ms, n, verify_fd_budget(), &plan)) {
        set_infra(&status, EMFILE);
        goto out;
    }
    memset(&pool, 0, sizeof pool);
    pool.active_limit = plan.active;
    pool.stability_limit = plan.stability;
    status.active_limit = plan.active;
    status.stability_limit = plan.stability;
    slots = plan.total;

    ep = verify_epoll_create();
    if (ep < 0) {
        set_infra(&status, errno);
        goto out;
    }
    if (!qn_size_mul(slots, sizeof *cs, &slot_bytes)) {
        set_infra(&status, EOVERFLOW);
        goto out;
    }
    cs = (conn *)verify_alloc(1u, slot_bytes, VERIFY_ALLOC_SLOTS, true);
    inbuf = (uint8_t *)verify_alloc(1u, VER_IN_BUF, VERIFY_ALLOC_INBUF, false);
    appbuf = (uint8_t *)verify_alloc(1u, VER_APP_BUF, VERIFY_ALLOC_APPBUF, false);
    if (!cs || !inbuf || !appbuf) {
        set_infra(&status, ENOMEM);
        goto out;
    }
    for (i = 0; i < slots; i++)
        cs[i].fd = -1;

    while (done < n && !stop) {
        struct epoll_event evs[128];
        int                nev, k;
        uint64_t           now;

        if (c0.progress_done)
            atomic_store_explicit(c0.progress_done, c0.progress_base + done,
                                  memory_order_release);
        if (c0.cancel && atomic_load_explicit(c0.cancel, memory_order_acquire)) {
            status.state = QN_VERIFY_CANCELLED;
            break;
        }

        for (i = 0; i < slots && next < n &&
                    pool.active_live < pool.active_limit; i++) {
            conn              *c = &cs[i];
            struct epoll_event ee;
            qn_tls_config      tc;
            qn_verify_result  *r;
            int                dial_error;

            if (c->st != C_FREE && c->st != C_DONE)
                continue;

            memset(c, 0, sizeof *c);
            qn_outbuf_init(&c->out, c->outstore, sizeof c->outstore);
            c->pool = &pool;
            c->idx = next++;
            r = &out[c->idx];
            r->observation.transport.attempted = true;
            c->t_start = qn_now_ns();
            c->fd = dial(c0.socks_enabled ? &c0.socks_address : &addrs[c->idx],
                         c0.socks_enabled ? c0.socks_port : c0.port);
            if (c->fd < 0) {
                dial_error = errno;
                network_failure(r, dial_error, "socket");
                if (r->observation.terminal.origin == QN_FAIL_LOCAL ||
                    local_resource_error(dial_error)) {
                    set_infra(&status, dial_error);
                    stop = true;
                    break;
                }
                finish_without_conn(r);
                done++;
                c->st = C_DONE;
                continue;
            }

            memset(&tc, 0, sizeof tc);
            tc.profile     = c0.profile;
            tc.sni         = c0.sni;
            tc.fp          = c0.fp;
            tc.allow_tls12 = c0.allow_tls12;
            tc.cert_strict = c0.cert_strict;
            c->profile_seed = c0.deterministic
                                  ? qn_profile_wire_seed(c0.seed, (uint64_t)c->idx)
                                  : qn_rng_entropy();
            if (c0.deterministic || c0.fp == QN_TLS_FP_RANDOM) {
                qn_rng_seed(&c->rng, c->profile_seed);
                tc.rng = &c->rng;
            }
            qn_tls_init(&c->tls, &tc);

            c->st       = C_CONNECT;
            c->deadline = qn_now_ms() + c0.timeout_ms;
            memset(&ee, 0, sizeof ee);
            ee.events   = EPOLLOUT;
            ee.data.ptr = c;
            if (verify_epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) != 0) {
                int ctl_error = errno;
                failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                        ctl_error, 0, "epoll-add");
                set_infra(&status, ctl_error);
                stop = true;
                break;
            }
            c->pool_class = POOL_ACTIVE;
            pool.active_live++;
            pool.peak_active = QN_MAX(pool.peak_active, pool.active_live);
            live++;
        }
        if (stop)
            break;
        if (!live) {
            /* An empty slot set is terminal only when no undialed candidates remain. */
            if (next < n)
                continue;
            if (done < n)
                set_infra(&status, EIO);
            break;
        }

        nev = verify_epoll_wait(ep, evs, (int)QN_ARRAY_LEN(evs), 100);
        now = qn_now_ms();
        if (nev < 0) {
            if (errno == EINTR)
                continue;
            set_infra(&status, errno);
            break;
        }

        for (k = 0; k < nev && !stop; k++) {
            conn             *c  = (conn *)evs[k].data.ptr;
            qn_verify_result *r  = &out[c->idx];
            uint32_t          fl = evs[k].events;

            if (c->st == C_DONE || c->fd < 0)
                continue;

            if (c->st == C_CONNECT && (fl & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
                int       err = 0;
                socklen_t sl  = sizeof err;

                if (verify_get_socket_error(c->fd, &err, &sl) != 0) {
                    err = errno;
                    failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                            err, 0, "getsockopt");
                    set_infra(&status, err);
                    stop = true;
                    break;
                }
                if (err) {
                    network_failure(r, err, "connect");
                    if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                        set_infra(&status, err);
                        stop = true;
                        break;
                    }
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }

                c->deadline = qn_now_ms() + c0.timeout_ms;
                if (c0.socks_enabled) {
                    uint8_t greeting[3];

                    if (!qn_socks5_init(&c->socks, c0.socks_target_host,
                                        c0.socks_target_port) ||
                        qn_socks5_greeting(greeting) != sizeof greeting ||
                        !qn_outbuf_queue(&c->out, greeting, sizeof greeting)) {
                        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                QN_TLS_NONE, EINVAL, 0, "socks-init");
                        set_infra(&status, EINVAL);
                        stop = true;
                        break;
                    }
                    c->st = C_SOCKS_METHOD;
                } else if (!start_tls(c, r, &c0)) {
                    int hello_error = errno ? errno : EIO;
                    failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                            hello_error, 0, "hello");
                    set_infra(&status, hello_error);
                    stop = true;
                    break;
                }
                if (!flush_out(c)) {
                    int write_error = errno ? errno : EIO;
                    network_failure(r, write_error, "write");
                    if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                        set_infra(&status, write_error);
                        stop = true;
                        break;
                    }
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }
                if (!arm(ep, c, qn_outbuf_pending(&c->out) ? (EPOLLIN | EPOLLOUT) : EPOLLIN)) {
                    int arm_error = errno;
                    failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                            arm_error, 0, "epoll-mod");
                    set_infra(&status, arm_error);
                    stop = true;
                }
                continue;
            }

            if ((fl & EPOLLOUT) && qn_outbuf_pending(&c->out)) {
                if (!flush_out(c)) {
                    int write_error = errno ? errno : EIO;
                    network_failure(r, write_error, "write");
                    if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                        set_infra(&status, write_error);
                        stop = true;
                        break;
                    }
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }
                if (!request_flush_commit(c, r, &c0)) {
                    if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                        set_infra(&status, EIO);
                        stop = true;
                        break;
                    }
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }
                if (!qn_outbuf_pending(&c->out) && !arm(ep, c, EPOLLIN)) {
                    int arm_error = errno;
                    failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                            arm_error, 0, "epoll-mod");
                    set_infra(&status, arm_error);
                    stop = true;
                    break;
                }
            }

            if (fl & EPOLLIN) {
                ssize_t got = verify_read(c->fd, inbuf, VER_IN_BUF);

                if (got == 0) {
                    if (r->observation.tls.handshake_complete &&
                        c->proto == P_HTTP1 && c->st == C_BODY)
                        (void)absorb_h1_eof(c, r, &c0);
                    else if (c->st == C_IDLE)
                        note(r, "peer-closed");
                    else if (c->st == C_SOCKS_METHOD || c->st == C_SOCKS_CONNECT)
                        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PROTOCOL, QN_R_OPEN,
                                QN_TLS_NONE, 0, 0, "socks-eof");
                    else if (!r->observation.tls.handshake_complete)
                        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN,
                                QN_TLS_NONE, 0, 0, "early-eof");
                    else
                        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN,
                                QN_TLS_SERVERHELLO, 0, 0, "peer-closed");
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }
                if (got < 0) {
                    int read_error = errno;
                    if (qn_errno_would_block(read_error) || read_error == EINTR)
                        continue;
                    network_failure(r, read_error, "read");
                    if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                        set_infra(&status, read_error);
                        stop = true;
                        break;
                    }
                    if (c->st == C_IDLE)
                        note(r, "reset-idle");
                    retire_conn(ep, c, r, &live, &done);
                    continue;
                }

                if (c->st == C_SOCKS_METHOD || c->st == C_SOCKS_CONNECT) {
                    uint8_t request[263];
                    size_t consumed = 0u;
                    size_t output_length = 0u;
                    qn_socks5_action action = qn_socks5_feed(
                        &c->socks, inbuf, (size_t)got, &consumed, request,
                        sizeof request, &output_length);

                    if (action == QN_SOCKS5_FAILED) {
                        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PROTOCOL, QN_R_OPEN,
                                QN_TLS_NONE, 0, (int)c->socks.error, "socks-protocol");
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }
                    if (action == QN_SOCKS5_SEND_CONNECT) {
                        if (!qn_outbuf_queue(&c->out, request, output_length)) {
                            failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                    QN_TLS_NONE, ENOBUFS, 0, "socks-request");
                            set_infra(&status, ENOBUFS);
                            stop = true;
                            break;
                        }
                        c->st = C_SOCKS_CONNECT;
                    } else if (action == QN_SOCKS5_READY && !start_tls(c, r, &c0)) {
                        int hello_error = errno ? errno : EIO;

                        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                QN_TLS_NONE, hello_error, 0, "hello");
                        set_infra(&status, hello_error);
                        stop = true;
                        break;
                    }
                    if (qn_outbuf_pending(&c->out) && !flush_out(c)) {
                        network_failure(r, errno ? errno : EIO, "socks-write");
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }
                    if (!arm(ep, c, qn_outbuf_pending(&c->out)
                                        ? (EPOLLIN | EPOLLOUT) : EPOLLIN)) {
                        int arm_error = errno;

                        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                QN_TLS_NONE, arm_error, 0, "epoll-mod");
                        set_infra(&status, arm_error);
                        stop = true;
                    }
                    continue;
                }

                {
                    qn_tls_io io;
                    qn_tls_rc rc;
                    size_t    room = 0;
                    uint64_t  observed_ns = qn_now_ns();

                    memset(&io, 0, sizeof io);
                    io.in     = inbuf;
                    io.inlen  = (size_t)got;
                    io.out    = qn_outbuf_tail(&c->out, &room);
                    io.outcap = room;
                    io.app    = appbuf;
                    io.appcap = VER_APP_BUF;

                    rc = qn_tls_recv(&c->tls, &io);
                    qn_outbuf_commit(&c->out, io.outlen);

                    if (rc == QN_TLS_RC_DONE &&
                        !r->observation.tls.handshake_complete) {
                        qn_tls_observation *tls = &r->observation.tls;

                        tls->handshake_complete = true;
                        c->t_hs = qn_now_ns();
                        tls->handshake_us =
                            (uint32_t)((c->t_hs - c->t_conn) / 1000u);
                        tls->version = c->tls.version;
                        qn_strlcpy(tls->peer_cn, c->tls.peer_cn,
                                   sizeof tls->peer_cn);
                        qn_strlcpy(tls->peer_issuer, c->tls.peer_issuer,
                                   sizeof tls->peer_issuer);
                        tls->cert_state = (uint8_t)qn_tls_cert_status(&c->tls);
                        tls->suite = c->tls.suite;
                        tls->outcome = QN_TLS_SERVERHELLO;
                        handshakes++;

                        if (!send_trace(c, r, &c0)) {
                            if (r->observation.terminal.origin == QN_FAIL_UNSUPPORTED) {
                                retire_conn(ep, c, r, &live, &done);
                                continue;
                            }
                            failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                    QN_TLS_NONE, EINVAL, 0, "request");
                            set_infra(&status, EINVAL);
                            stop = true;
                            break;
                        }
                        c->st = C_BODY;
                    } else if (rc == QN_TLS_RC_ALERT) {
                        failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN,
                                QN_TLS_ALERT, 0, (int)rc,
                                r->observation.tls.handshake_complete
                                    ? "alert"
                                    : "alert-hs");
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    } else if (rc != QN_TLS_RC_MORE && rc != QN_TLS_RC_OK &&
                               rc != QN_TLS_RC_DONE) {
                        qn_terminal_outcome outcome =
                            rc == QN_TLS_RC_UNSUPPORTED || rc == QN_TLS_RC_SPACE
                                ? QN_TERM_UNSUPPORTED
                                : QN_TERM_PROTOCOL_INVALID;
                        qn_failure_origin origin = rc == QN_TLS_RC_UNSUPPORTED ||
                                                           rc == QN_TLS_RC_SPACE
                                                        ? QN_FAIL_UNSUPPORTED
                                                        : QN_FAIL_PROTOCOL;
                        failure(r, outcome, origin, QN_R_OPEN,
                                r->observation.tls.handshake_complete
                                    ? QN_TLS_SERVERHELLO
                                    : QN_TLS_NONE,
                                0, (int)rc, qn_tls_rc_str(rc));
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }

                    if (io.applen &&
                        !absorb_app(c, r, &c0, appbuf, io.applen, observed_ns)) {
                        if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                            set_infra(&status, EIO);
                            stop = true;
                            break;
                        }
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }
                    if (qn_outbuf_pending(&c->out) && !flush_out(c)) {
                        int write_error = errno ? errno : EIO;
                        network_failure(r, write_error, "write");
                        if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                            set_infra(&status, write_error);
                            stop = true;
                            break;
                        }
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }
                    if (!request_flush_commit(c, r, &c0)) {
                        if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                            set_infra(&status, EIO);
                            stop = true;
                            break;
                        }
                        retire_conn(ep, c, r, &live, &done);
                        continue;
                    }
                    if (!arm(ep, c, qn_outbuf_pending(&c->out) ? (EPOLLIN | EPOLLOUT) : EPOLLIN)) {
                        int arm_error = errno;
                        failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR,
                                QN_TLS_NONE, arm_error, 0, "epoll-mod");
                        set_infra(&status, arm_error);
                        stop = true;
                    }
                }
                continue;
            }

            if (fl & (EPOLLERR | EPOLLHUP)) {
                int       err = 0;
                socklen_t sl = sizeof err;

                if (verify_get_socket_error(c->fd, &err, &sl) != 0) {
                    err = errno;
                    failure(r, QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                            err, 0, "getsockopt");
                    set_infra(&status, err);
                    stop = true;
                    break;
                }
                if (err)
                    network_failure(r, err, "hangup");
                else if (!r->observation.tls.handshake_complete)
                    failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN, QN_TLS_NONE,
                            0, 0, "hangup");
                else if (c->st == C_IDLE)
                    note(r, c->st == C_IDLE ? "peer-closed" : "hangup");
                else
                    failure(r, QN_TERM_PEER_REJECTED, QN_FAIL_PEER, QN_R_OPEN,
                            QN_TLS_SERVERHELLO, 0, 0, "hangup");
                if (r->observation.terminal.origin == QN_FAIL_LOCAL) {
                    set_infra(&status, err);
                    stop = true;
                    break;
                }
                retire_conn(ep, c, r, &live, &done);
            }
        }

        if (stop)
            break;
        now = qn_now_ms();
        for (i = 0; i < slots; i++) {
            conn             *c = &cs[i];
            qn_verify_result *r;

            if (c->st == C_FREE || c->st == C_DONE || c->fd < 0)
                continue;
            r = &out[c->idx];

            if (c->st == C_IDLE && now >= c->idle_until) {
                if (r->observation.stability.admitted) {
                    /* What was held, not what was asked for. */
                    r->observation.stability.survived = true;
                    r->observation.stability.held_ms =
                        (uint32_t)QN_MIN(now - c->idle_start,
                                         (uint64_t)UINT32_MAX);
                    note(r, "held");
                }
                retire_conn(ep, c, r, &live, &done);
                continue;
            }
            if (c->overall_deadline && now >= c->overall_deadline) {
                failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                        QN_TLS_SERVERHELLO, ETIMEDOUT, 0,
                        c->flow_sent ? "flow-overall-timeout"
                                     : "trace-overall-timeout");
                retire_conn(ep, c, r, &live, &done);
                continue;
            }
            if (now >= c->deadline) {
                if (c->st == C_SOCKS_METHOD || c->st == C_SOCKS_CONNECT)
                    failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                            QN_TLS_NONE, ETIMEDOUT, 0, "socks-timeout");
                else if (!r->observation.transport.connected)
                    failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                            QN_TLS_NONE, ETIMEDOUT, 0, "connect-timeout");
                else if (!r->observation.tls.handshake_complete)
                    failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                            QN_TLS_SILENCE, ETIMEDOUT, 0, "handshake-timeout");
                else if (c->flow_sent && !c->flow_done)
                    failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                            QN_TLS_SERVERHELLO, ETIMEDOUT, 0, "flow-stalled");
                else
                    failure(r, QN_TERM_TIMEOUT, QN_FAIL_PATH, QN_R_TIMEOUT,
                            QN_TLS_SERVERHELLO, ETIMEDOUT, 0, "trace-timeout");
                retire_conn(ep, c, r, &live, &done);
            }
        }
    }

    if (status.state == QN_VERIFY_COMPLETE && done < n)
        status.state = QN_VERIFY_PARTIAL;

out:
    /* Every candidate is typed as finished, cut short, or never dialed. */
    status.attempted   = (uint32_t)next;
    status.unattempted = (uint32_t)(n - next);
    status.cancelled   = 0u;
    for (i = 0; i < next; i++) {
        if (out[i].observation.completed)
            continue;
        if (status.state == QN_VERIFY_CANCELLED) {
            failure(&out[i], QN_TERM_CANCELLED, QN_FAIL_CANCELLED, QN_R_CANCELLED,
                    QN_TLS_NONE, ECANCELED, 0, "cancelled");
        } else {
            int why = status.fatal_errno ? status.fatal_errno : EIO;

            failure(&out[i], QN_TERM_LOCAL_ERROR, QN_FAIL_LOCAL, QN_R_ERROR, QN_TLS_NONE,
                    why, 0, "cut-short");
        }
        finish_without_conn(&out[i]);
        status.cancelled++;
    }
    for (i = next; i < n; i++) {
        failure(&out[i], QN_TERM_CANCELLED, QN_FAIL_CANCELLED, QN_R_CANCELLED,
                QN_TLS_NONE, ECANCELED, 0, "unattempted");
        out[i].classification = qn_observation_classify(&out[i].observation);
    }
    status.completed = (uint32_t)done;
    status.handshakes = (uint32_t)handshakes;
    status.peak_active = (uint32_t)pool.peak_active;
    status.peak_stability = (uint32_t)pool.peak_stability;
    if (c0.progress_done)
        atomic_store_explicit(c0.progress_done, c0.progress_base + done,
                              memory_order_release);
    if (cs) {
        for (i = 0; i < slots; i++) {
            if (cs[i].fd >= 0) {
                if (ep >= 0)
                    (void)verify_epoll_ctl(ep, EPOLL_CTL_DEL, cs[i].fd, NULL);
                close(cs[i].fd);
                cs[i].fd = -1;
            }
            if (cs[i].st != C_FREE && cs[i].st != C_DONE)
                qn_tls_free(&cs[i].tls);
        }
    }
    free(cs);
    free(inbuf);
    free(appbuf);
    if (ep >= 0)
        close(ep);
    /* Infrastructure failure cannot commit partial results over prior peer evidence. */
    if (status.state != QN_VERIFY_INFRA_FAILURE)
        memcpy(caller_out, out, n * sizeof *out);
    free(work);
    return status;
}
