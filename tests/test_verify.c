/* The observation classifier, driven against a peer that misbehaves on purpose. */

#include "qanat/verify.h"

#include "netsim.h"

#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

/* A loopback port nothing listens on, so every dial is refused at once. */
static uint16_t closed_port(void)
{
    struct sockaddr_in sa;
    socklen_t          sl   = sizeof sa;
    uint16_t           port = 0;
    int                fd   = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
        return 0;
    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7F000001u);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0 &&
        getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
        port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

static qn_addr loopback(void)
{
    qn_addr a;
    memset(&a, 0, sizeof a);
    a.af   = 2; /* AF_INET */
    a.u.v4 = 0x7F000001u;
    return a;
}

static qn_verify_result run_one(qn_netsim_mode mode, uint32_t after, uint32_t timeout_ms,
                                qn_verify_status *status)
{
    qn_netsim       *sim = qn_netsim_start(mode, after);
    qn_verify_cfg    cfg;
    qn_verify_result r;
    qn_addr          a = loopback();

    memset(&r, 0, sizeof r);
    memset(status, 0, sizeof *status);
    if (!sim) {
        failures++;
        return r;
    }

    qn_verify_defaults(&cfg);
    cfg.port        = qn_netsim_port(sim);
    cfg.sni         = "example.com";
    cfg.timeout_ms  = timeout_ms;
    cfg.idle_ms     = 200;
    cfg.concurrency = 1;

    *status = qn_verify_run(&cfg, &a, 1, &r);
    qn_netsim_stop(sim);
    return r;
}

static void test_ladder_rules(void)
{
    typedef struct {
        bool connected, tls, http, edge, flow, stable, completed;
        qn_terminal_outcome terminal;
        qn_highest_rung want_rung;
        qn_terminal_outcome want_terminal;
    } classifier_case;
    static const classifier_case cases[] = {
        { false, false, false, false, false, false, false,
          QN_TERM_NONE, QN_RUNG_NONE, QN_TERM_NONE },
        { false, false, false, false, false, false, true,
          QN_TERM_NONE, QN_RUNG_NONE, QN_TERM_DEAD },
        { true, false, false, false, false, false, true,
          QN_TERM_NONE, QN_RUNG_TCP, QN_TERM_SUCCESS },
        { true, true, false, false, false, false, true,
          QN_TERM_NONE, QN_RUNG_TLS, QN_TERM_SUCCESS },
        { true, true, true, false, false, false, true,
          QN_TERM_NONE, QN_RUNG_HTTP, QN_TERM_SUCCESS },
        { true, true, true, true, false, false, true,
          QN_TERM_NONE, QN_RUNG_EDGE, QN_TERM_SUCCESS },
        { true, true, true, true, true, false, true,
          QN_TERM_NONE, QN_RUNG_FLOWING, QN_TERM_SUCCESS },
        { true, true, true, true, false, true, true,
          QN_TERM_NONE, QN_RUNG_STABLE, QN_TERM_SUCCESS },
        { true, true, true, false, true, true, true,
          QN_TERM_NONE, QN_RUNG_HTTP, QN_TERM_SUCCESS },
        { true, true, true, true, true, true, true,
          QN_TERM_PROTOCOL_INVALID, QN_RUNG_STABLE, QN_TERM_PROTOCOL_INVALID },
        { true, true, false, false, false, false, true,
          QN_TERM_UNSUPPORTED, QN_RUNG_TLS, QN_TERM_UNSUPPORTED }
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        qn_observation observation;
        qn_classification got;

        qn_observation_init(&observation);
        observation.transport.connected = cases[i].connected;
        observation.tls.handshake_complete = cases[i].tls;
        observation.http.final_headers = cases[i].http;
        observation.edge.verified = cases[i].edge;
        observation.flow.completed = cases[i].flow;
        observation.stability.survived = cases[i].stable;
        observation.completed = cases[i].completed;
        observation.terminal.outcome = (uint8_t)cases[i].terminal;
        got = qn_observation_classify(&observation);
        CHECK(got.highest_rung_reached == cases[i].want_rung);
        CHECK(got.terminal_outcome == cases[i].want_terminal);
    }

    {
        qn_observation observation;
        qn_http_event event;

        qn_observation_init(&observation);
        observation.transport.connected = true;
        observation.tls.handshake_complete = true;
        observation.http.request_queued = true;
        observation.http.final_headers = true;
        observation.http.status = 200u;
        memset(&event, 0, sizeof event);
        event.response_index = 1u;
        event.flags = QN_HTTP_FACT_TRACE_COLO | QN_HTTP_FACT_CF_RAY;
        memcpy(event.colo, "FRA", 4u);
        qn_observation_apply_http(&observation, &event);
        CHECK(!observation.edge.verified);
        observation.http.request_fully_flushed = true;
        qn_edge_policy_apply(&observation);
        CHECK(observation.edge.verified);
        CHECK(strcmp(observation.edge.colo, "FRA") == 0);
    }
}

static void test_stability_pool_plan(void)
{
    qn_verify_pool_plan plan;

    CHECK(qn_verify_plan_pools(64u, 512u, 5000u, 16384u, 4096u,
                               &plan));
    CHECK(plan.active == 64u);
    CHECK(plan.stability == 512u);
    CHECK(plan.total == 576u);

    CHECK(qn_verify_plan_pools(64u, 512u, 5000u, 32u, 4096u,
                               &plan));
    CHECK(plan.active == 32u);
    CHECK(plan.stability == 32u);
    CHECK(plan.total == 32u);

    CHECK(qn_verify_plan_pools(64u, 512u, 5000u, 16384u, 200u,
                               &plan));
    CHECK(plan.active == 64u);
    CHECK(plan.stability == 136u);
    CHECK(plan.total == 200u);

    CHECK(qn_verify_plan_pools(64u, 512u, 0u, 16384u, 4096u,
                               &plan));
    CHECK(plan.active == 64u);
    CHECK(plan.stability == 0u);
    CHECK(plan.total == 64u);
    CHECK(!qn_verify_plan_pools(64u, 512u, 5000u, 1u, 0u, &plan));
}

static void test_config_validation_is_transactional(void)
{
    qn_verify_cfg    cfg;
    qn_verify_result r, snapshot;
    qn_verify_status status;
    qn_addr          a = loopback();

    qn_verify_defaults(&cfg);
    memset(&r, 0xA5, sizeof r);
    snapshot = r;
    cfg.trace_path = "/ok\r\nInjected: yes";
    status = qn_verify_run(&cfg, &a, 1u, &r);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE && status.fatal_errno == EINVAL);
    CHECK(status.attempted == 0u && status.completed == 0u);
    CHECK(memcmp(&r, &snapshot, sizeof r) == 0);

    qn_verify_defaults(&cfg);
    cfg.sni = "127.0.0.1";
    status = qn_verify_run(&cfg, &a, 1u, &r);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE && status.fatal_errno == EINVAL);

    qn_verify_defaults(&cfg);
    a.af = 0u;
    status = qn_verify_run(&cfg, &a, 1u, &r);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE && status.fatal_errno == EAFNOSUPPORT);

#if SIZE_MAX > UINT32_MAX
    a = loopback();
    status = qn_verify_run(&cfg, &a, (size_t)UINT32_MAX + 1u, &r);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE && status.fatal_errno == EOVERFLOW);
#endif

    {
        char ja3[33], ja4[40];
        CHECK(!qn_verify_fingerprint(NULL, ja3, ja4));
        CHECK(ja3[0] == '\0' && ja4[0] == '\0');
    }
}

static void test_pre_cancel(void)
{
    qn_verify_cfg    cfg;
    qn_verify_result r;
    qn_addr          a = loopback();
    _Atomic bool     cancel;
    _Atomic size_t   done;
    _Atomic size_t   total;
    qn_verify_status status;

    qn_verify_defaults(&cfg);
    atomic_init(&cancel, true);
    atomic_init(&done, 99u);
    atomic_init(&total, 0u);
    cfg.cancel = &cancel;
    cfg.progress_done = &done;
    cfg.progress_total = &total;

    status = qn_verify_run(&cfg, &a, 1, &r);
    CHECK(status.state == QN_VERIFY_CANCELLED);
    CHECK(status.attempted == 0u);
    CHECK(status.completed == 0u);
    CHECK(!r.observation.completed);
    CHECK(atomic_load(&done) == 0u);
    CHECK(atomic_load(&total) == 1u);
}

static void test_fd_exhaustion_is_transactional(void)
{
    struct rlimit    saved, limited;
    qn_verify_cfg    cfg;
    qn_verify_result r, snapshot;
    qn_verify_status status;
    qn_addr          a = loopback();
    int              fd[128];
    size_t           nfd = 0;

    if (getrlimit(RLIMIT_NOFILE, &saved) != 0) {
        CHECK(false);
        return;
    }
    limited = saved;
    if (limited.rlim_cur == RLIM_INFINITY || limited.rlim_cur > 64u)
        limited.rlim_cur = 64u;
    if (limited.rlim_cur < 8u || setrlimit(RLIMIT_NOFILE, &limited) != 0) {
        CHECK(false);
        return;
    }

    while (nfd < sizeof fd / sizeof fd[0]) {
        int next = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (next < 0)
            break;
        fd[nfd++] = next;
    }
    CHECK(errno == EMFILE);

    qn_verify_defaults(&cfg);
    cfg.sni = "example.com";
    memset(&r, 0xA5, sizeof r);
    snapshot = r;
    status = qn_verify_run(&cfg, &a, 1u, &r);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE);
    CHECK(status.fatal_errno == EMFILE || status.fatal_errno == ENFILE);
    CHECK(status.attempted == 0u && status.completed == 0u);
    CHECK(memcmp(&r, &snapshot, sizeof r) == 0);

    while (nfd)
        close(fd[--nfd]);
    CHECK(setrlimit(RLIMIT_NOFILE, &saved) == 0);
}

/* QN2-001: failure of an entire slot batch cannot abandon later candidates. */
static void test_failed_batch_does_not_abandon_the_rest(void)
{
    qn_verify_cfg    cfg;
    qn_verify_result r[5];
    qn_verify_status status;
    qn_addr          addrs[5];
    size_t           i;

    /* Immediate dial failure retires the first batch before epoll runs. */
    for (i = 0; i < 5u; i++) {
        memset(&addrs[i], 0, sizeof addrs[i]);
        addrs[i].af   = 2; /* AF_INET */
        addrs[i].u.v4 = 0xF0000001u + (uint32_t)i;
    }

    qn_verify_defaults(&cfg);
    cfg.sni         = "example.com";
    cfg.port        = 443u;
    cfg.concurrency = 2u;
    cfg.timeout_ms  = 300u;
    cfg.idle_ms     = 0u;
    cfg.want_bytes  = 0u;

    memset(r, 0, sizeof r);
    status = qn_verify_run(&cfg, addrs, 5u, r);

    /* Only a genuine resource shortage is a different, already-tested path. */
    if (status.state == QN_VERIFY_INFRA_FAILURE &&
        (status.fatal_errno == EMFILE || status.fatal_errno == ENFILE ||
         status.fatal_errno == ENOBUFS || status.fatal_errno == ENOMEM)) {
        fprintf(stderr, "  note: host is out of descriptors; batch path not exercised\n");
        return;
    }
    if (status.state == QN_VERIFY_INFRA_FAILURE)
        fprintf(stderr, "  batch abandoned as infrastructure failure, errno %d\n",
                status.fatal_errno);
    CHECK(status.state != QN_VERIFY_INFRA_FAILURE);

    if (status.attempted != 5u)
        fprintf(stderr, "  only %u of 5 candidates were attempted (%u unattempted)\n",
                status.attempted, status.unattempted);
    CHECK(status.attempted == 5u);
    CHECK(status.unattempted == 0u);
    /* The audit's invariant: nothing may be implicitly untouched. */
    CHECK(status.attempted + status.unattempted == 5u);
    CHECK(status.completed + status.cancelled == status.attempted);

    for (i = 0; i < 5u; i++) {
        CHECK(r[i].observation.completed);
        CHECK(r[i].observation.terminal.origin != QN_FAIL_NONE);
    }
}

/* Cancellation must leave every element typed, not half-written. */
static void test_cancel_types_every_candidate(void)
{
    qn_verify_cfg    cfg;
    qn_verify_result r[4];
    qn_verify_status status;
    qn_addr          addrs[4];
    _Atomic bool     cancel;
    size_t           i;

    for (i = 0; i < 4u; i++)
        addrs[i] = loopback();
    atomic_init(&cancel, true);

    qn_verify_defaults(&cfg);
    cfg.sni         = "example.com";
    cfg.port        = closed_port();
    cfg.concurrency = 2u;
    cfg.cancel      = &cancel;
    CHECK(cfg.port != 0);
    if (!cfg.port)
        return;

    memset(r, 0, sizeof r);
    status = qn_verify_run(&cfg, addrs, 4u, r);
    CHECK(status.state == QN_VERIFY_CANCELLED);
    CHECK(status.attempted + status.unattempted == 4u);
    CHECK(status.completed + status.cancelled == status.attempted);
}

/* Refusal is a peer observation, not absence of evidence and not interference. */
static void test_refused(void)
{
    qn_verify_cfg    cfg;
    qn_verify_result r;
    qn_addr          a = loopback();
    qn_netsim       *sim = qn_netsim_start(QN_NETSIM_RST_ON_CONNECT, 1);
    uint16_t         port;

    if (!sim) {
        failures++;
        return;
    }
    port = qn_netsim_port(sim);
    qn_netsim_stop(sim); /* free the port again */

    memset(&r, 0, sizeof r);
    qn_verify_defaults(&cfg);
    cfg.port        = port;
    cfg.sni         = "example.com";
    cfg.timeout_ms  = 1500;
    cfg.concurrency = 1;

    {
        qn_verify_status status = qn_verify_run(&cfg, &a, 1, &r);
        CHECK(status.state == QN_VERIFY_COMPLETE);
        CHECK(status.completed == 1u);
    }
    CHECK(r.classification.terminal_outcome == QN_TERM_PEER_REJECTED);
    CHECK(r.observation.terminal.origin == QN_FAIL_PEER);
    CHECK(r.observation.transport.result == QN_R_REFUSED);
    fprintf(stderr, "  refused        -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

/* A reset after partial handshake traffic must never become a working verdict. */
static void test_reset_mid_handshake(void)
{
    qn_verify_status status;
    qn_verify_result r = run_one(QN_NETSIM_RST_AFTER_BYTES, 64, 2000, &status);

    CHECK(status.state == QN_VERIFY_COMPLETE);
    CHECK(r.observation.completed);
    CHECK(r.classification.terminal_outcome == QN_TERM_RESET);
    CHECK(r.classification.highest_rung_reached < QN_RUNG_TLS);
    CHECK(r.observation.terminal.origin == QN_FAIL_PEER);
    CHECK(r.observation.transport.result == QN_R_RESET);
    fprintf(stderr, "  rst mid-flight -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

static void test_silent(void)
{
    qn_verify_status status;
    qn_verify_result r = run_one(QN_NETSIM_ACCEPT_SILENT, 0, 700, &status);

    /* Connected but never answered: below handshake, and not called dead. */
    CHECK(r.classification.highest_rung_reached == QN_RUNG_TCP);
    CHECK(r.classification.terminal_outcome == QN_TERM_TIMEOUT);
    CHECK(r.observation.terminal.origin == QN_FAIL_PATH);
    CHECK(r.observation.transport.result == QN_R_TIMEOUT);
    CHECK(status.state == QN_VERIFY_COMPLETE);
    CHECK(r.observation.transport.connect_us > 0);
    fprintf(stderr, "  silent         -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

static void test_garbage(void)
{
    qn_verify_status status;
    qn_verify_result r = run_one(QN_NETSIM_GARBAGE, 0, 1500, &status);

    CHECK(r.classification.highest_rung_reached < QN_RUNG_TLS);
    CHECK(r.classification.terminal_outcome == QN_TERM_PROTOCOL_INVALID);
    CHECK(r.observation.terminal.origin == QN_FAIL_PROTOCOL);
    CHECK(status.state == QN_VERIFY_COMPLETE);
    fprintf(stderr, "  non-tls answer -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

static void test_early_eof(void)
{
    qn_verify_status status;
    qn_verify_result r = run_one(QN_NETSIM_EOF_AFTER_BYTES, 64, 1500, &status);

    CHECK(r.classification.highest_rung_reached < QN_RUNG_TLS);
    CHECK(r.classification.terminal_outcome == QN_TERM_PEER_REJECTED);
    CHECK(r.observation.terminal.origin == QN_FAIL_PEER);
    CHECK(status.state == QN_VERIFY_COMPLETE);
    fprintf(stderr, "  early eof      -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

/* A peer that dribbles a truncated record must not hang or be believed. */
static void test_drip(void)
{
    qn_verify_status status;
    qn_verify_result r = run_one(QN_NETSIM_DRIP, 0, 1500, &status);

    CHECK(r.classification.highest_rung_reached < QN_RUNG_TLS);
    CHECK(r.classification.terminal_outcome == QN_TERM_PROTOCOL_INVALID);
    CHECK(r.observation.completed);
    CHECK(status.state == QN_VERIFY_COMPLETE);
    fprintf(stderr, "  byte drip      -> %-10s %s\n",
            qn_classification_str(r.classification), r.observation.terminal.reason);
}

int main(void)
{
    test_stability_pool_plan();
    test_ladder_rules();
    test_config_validation_is_transactional();
    test_pre_cancel();
    test_fd_exhaustion_is_transactional();
    test_failed_batch_does_not_abandon_the_rest();
    test_cancel_types_every_candidate();
    test_refused();
    test_reset_mid_handshake();
    test_silent();
    test_garbage();
    test_early_eof();
    test_drip();

    if (failures) {
        fprintf(stderr, "verify tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("verify tests: ok\n");
    return 0;
}
