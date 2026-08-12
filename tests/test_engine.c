/* Engine invariants that only break under pressure or across restarts. */

#include "qanat/engine.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

#define DOMAIN 384u

/* This stub models next() as a permanent address claim rather than a replay. */
typedef struct {
    uint32_t issued;  /* addresses handed out */
    uint32_t drawn;   /* calls to next() */
    uint32_t events;  /* events delivered back */
    uint8_t  seen[DOMAIN];
    uint16_t port;
    bool     dup;
    bool     out_of_range;
} stub;

static qn_task_next stub_next(void *ctx, uint64_t idx, qn_job *out)
{
    stub *s = (stub *)ctx;

    (void)idx;
    s->drawn++;
    if (s->issued >= DOMAIN)
        return QN_TASK_EXHAUSTED;

    out->addr.af   = AF_INET;
    out->addr.u.v4 = 0x7F000001u;
    out->port      = s->port;
    out->stage     = QN_STAGE_TCP;
    out->token     = s->issued++;
    return QN_TASK_JOB;
}

static void stub_on_event(void *ctx, const qn_event *ev)
{
    stub *s = (stub *)ctx;

    s->events++;
    if (ev->job.token >= DOMAIN) {
        s->out_of_range = true;
        return;
    }
    if (s->seen[ev->job.token])
        s->dup = true;
    s->seen[ev->job.token] = 1;
}

/* A port nothing listens on, so every probe ends in an immediate refusal. */
static uint16_t closed_port(void)
{
    struct sockaddr_in sa;
    socklen_t          sl = sizeof sa;
    uint16_t           port = 0;
    int                fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

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

typedef struct {
    int      fd;
    uint16_t port;
    pthread_t tid;
} silent_server;

static void *silent_server_main(void *arg)
{
    silent_server *server = (silent_server *)arg;
    int client = accept(server->fd, NULL, NULL);

    if (client >= 0) {
        qn_sleep_ms(350);
        close(client);
    }
    return NULL;
}

static bool silent_server_start(silent_server *server)
{
    struct sockaddr_in sa;
    socklen_t          sl = sizeof sa;

    memset(server, 0, sizeof *server);
    server->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (server->fd < 0)
        return false;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7F000001u);
    if (bind(server->fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(server->fd, 1) != 0 ||
        getsockname(server->fd, (struct sockaddr *)&sa, &sl) != 0) {
        close(server->fd);
        return false;
    }
    server->port = ntohs(sa.sin_port);
    if (pthread_create(&server->tid, NULL, silent_server_main, server) != 0) {
        close(server->fd);
        return false;
    }
    return true;
}

static void silent_server_stop(silent_server *server)
{
    pthread_join(server->tid, NULL);
    close(server->fd);
}

/* Leaves `headroom` descriptors free, so probe_launch() must fail and retry. */
static bool fd_squeeze(rlim_t *saved, int headroom)
{
    struct rlimit rl;
    int           lowest = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (lowest < 0 || getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        if (lowest >= 0)
            close(lowest);
        return false;
    }
    close(lowest);
    *saved      = rl.rlim_cur;
    rl.rlim_cur = (rlim_t)lowest + (rlim_t)headroom;
    return rl.rlim_cur < *saved && setrlimit(RLIMIT_NOFILE, &rl) == 0;
}

static void fd_restore(rlim_t saved)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return;
    rl.rlim_cur = saved;
    setrlimit(RLIMIT_NOFILE, &rl);
}

static void drain(qn_engine *e)
{
    while (!qn_engine_done(e))
        qn_engine_poll(e, 4096);
    qn_engine_join(e);
    while (qn_engine_poll(e, 4096))
        ;
}

static void cfg_defaults(qn_config *c)
{
    memset(c, 0, sizeof *c);
    c->workers      = 1;
    c->concurrency  = 64;
    c->timeout_ms   = 800;
    c->no_thermal   = true;
    c->no_affinity  = true;
    c->warm_mode    = (uint8_t)QN_WARM_OFF;
}

/* QN2-007: every reserved index must become completed or explicitly unattempted. */
static void check_accounted(qn_engine *e, const char *what)
{
    qn_engine_snapshot sn;
    uint64_t           reserved = atomic_load_explicit(&e->cursor, memory_order_relaxed);
    uint64_t           missing  = 0;

    qn_engine_stats(e, &sn);
    if (e->task && e->task->domain && reserved > e->task->domain)
        reserved = e->task->domain;

    if (sn.claimed != reserved)
        fprintf(stderr, "  %s: reserved %llu indices but only claimed %llu\n", what,
                (unsigned long long)reserved, (unsigned long long)sn.claimed);
    CHECK(sn.claimed == reserved);

    if (!qn_engine_accounted(e, &missing))
        fprintf(stderr, "  %s: %llu of %llu claimed jobs vanished\n", what,
                (unsigned long long)missing, (unsigned long long)sn.claimed);
    CHECK(missing == 0u);
    CHECK(sn.completed + sn.skipped + sn.unattempted == reserved);
}

/* QN2-007: a stop with work in flight must terminate every claimed job. */
static void test_stop_accounts_for_everything(void)
{
    qn_config cfg;
    qn_engine e;
    qn_task   t;
    stub      s;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    cfg.rate = 40u; /* slow enough that a stop lands mid-run */
    CHECK(qn_engine_init(&e, &cfg, NULL));

    t = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "stop" };
    CHECK(qn_engine_start(&e, &t));
    CHECK(qn_engine_state(&e) == QN_ENGINE_RUNNING);

    for (int i = 0; i < 500; i++) {
        qn_engine_snapshot sn;

        qn_engine_stats(&e, &sn);
        if (sn.claimed >= 8u)
            break;
        qn_sleep_ms(1);
    }
    qn_engine_stop(&e);
    while (qn_engine_poll(&e, 4096))
        ;

    CHECK(qn_engine_state(&e) == QN_ENGINE_CANCELLED);
    check_accounted(&e, "stop");
    /* Whatever was claimed came back exactly once. */
    CHECK(!s.dup);
    CHECK(!s.out_of_range);
    qn_engine_destroy(&e);
}

/* QN2-037: a rate token stands for a network attempt, not for a draw. */
static void test_tokens_track_attempts(void)
{
    qn_config          cfg;
    qn_engine          e;
    qn_task            t;
    stub               s;
    qn_engine_snapshot sn;
    rlim_t             saved = 0;
    bool               tight;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    cfg.rate = 2000u;
    CHECK(qn_engine_init(&e, &cfg, NULL));

    t     = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "tokens" };
    tight = fd_squeeze(&saved, 12);
    CHECK(qn_engine_start(&e, &t));
    drain(&e);
    if (tight)
        fd_restore(saved);

    qn_engine_stats(&e, &sn);
    /* Local launch retries cannot consume the address budget. */
    CHECK(sn.issued == sn.claimed);
    CHECK(sn.completed == DOMAIN);
    fprintf(stderr, "  tokens: %llu claimed, %llu issued, %llu launch retries\n",
            (unsigned long long)sn.claimed, (unsigned long long)sn.issued,
            (unsigned long long)sn.local_launch_failures);
    /* Synchronous refusal may release each descriptor before pressure becomes observable. */
    if (tight && !sn.local_launch_failures)
        fprintf(stderr, "  note: dials complete synchronously here, no fd pressure\n");
    check_accounted(&e, "tokens");
    qn_engine_destroy(&e);
}

/* QN2-038: many launch retries for one job still leave one terminal outcome. */
static void test_counters_separate_retries_from_outcomes(void)
{
    qn_config          cfg;
    qn_engine          e;
    qn_task            t;
    stub               s;
    qn_engine_snapshot sn;
    rlim_t             saved = 0;
    bool               tight;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    t     = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "counters" };
    tight = fd_squeeze(&saved, 10);
    CHECK(qn_engine_start(&e, &t));
    drain(&e);
    if (tight)
        fd_restore(saved);

    qn_engine_stats(&e, &sn);
    CHECK(sn.completed == DOMAIN);
    CHECK(s.events == DOMAIN);
    /* Refusals are network outcomes and must not land in a local bucket. */
    CHECK(sn.network_failures == sn.refused + sn.timeout + sn.reset + sn.unreach);
    CHECK(sn.refused > 0u);
    CHECK(sn.terminal_job_failures + sn.open + sn.network_failures + sn.cancelled ==
          sn.completed);
    CHECK(sn.syscall_failures == 0u);
    CHECK(sn.events_dropped == 0u);
    qn_engine_destroy(&e);
}

/* The ring is the single owner of publication-drop accounting. */
static void test_event_drop_has_one_owner(void)
{
    qn_config          cfg;
    qn_engine          e;
    qn_engine_snapshot sn;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    atomic_store_explicit(&e.w[0].out.dropped, 1u, memory_order_relaxed);
    qn_engine_stats(&e, &sn);
    CHECK(sn.events_dropped == 1u);
    qn_engine_destroy(&e);
}

/* Corrupt surplus outcomes must not wrap the diagnostic missing count. */
static void test_accounting_difference_saturates(void)
{
    qn_config cfg;
    qn_engine e;
    uint64_t  missing = UINT64_MAX;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    atomic_store_explicit(&e.st[0].claimed, 1u, memory_order_relaxed);
    atomic_store_explicit(&e.st[0].completed, 2u, memory_order_relaxed);
    CHECK(!qn_engine_accounted(&e, &missing));
    CHECK(missing == 0u);
    qn_engine_destroy(&e);
}

static void test_finalize_drains_after_join(void)
{
    qn_config               cfg;
    qn_engine               e;
    qn_task                 t;
    stub                    s;
    qn_engine_finalization  final;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;
    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    t = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "finalize" };
    CHECK(qn_engine_start(&e, &t));
    while (atomic_load_explicit(&e.alive, memory_order_acquire))
        qn_sleep_ms(1);

    CHECK(s.events == 0u);
    qn_engine_finalize(&e, false, &final);
    CHECK(s.events == DOMAIN);
    CHECK(final.accounted);
    CHECK(final.missing == 0u);
    CHECK(final.stats.events_dropped == 0u);
    qn_engine_destroy(&e);
}

typedef struct {
    uint16_t port;
    uint32_t events;
    qn_event event;
} banner_case;

static qn_task_next banner_next(void *ctx, uint64_t idx, qn_job *out)
{
    banner_case *test = (banner_case *)ctx;

    if (idx)
        return QN_TASK_EXHAUSTED;
    memset(out, 0, sizeof *out);
    out->addr.af = AF_INET;
    out->addr.u.v4 = 0x7F000001u;
    out->port = test->port;
    out->stage = QN_STAGE_BANNER;
    return QN_TASK_JOB;
}

static void banner_event(void *ctx, const qn_event *event)
{
    banner_case *test = (banner_case *)ctx;

    test->event = *event;
    test->events++;
}

static void test_silent_banner_preserves_open(void)
{
    qn_config     cfg;
    qn_engine     e;
    qn_task       task;
    silent_server server;
    banner_case   test;

    if (!silent_server_start(&server)) {
        CHECK(false);
        return;
    }
    memset(&test, 0, sizeof test);
    test.port = server.port;
    cfg_defaults(&cfg);
    cfg.timeout_ms = 150u;
    CHECK(qn_engine_init(&e, &cfg, NULL));
    task = (qn_task){ banner_next, banner_event, &test, 1u, "banner" };
    CHECK(qn_engine_start(&e, &task));
    drain(&e);
    CHECK(test.events == 1u);
    CHECK(test.event.result == QN_R_OPEN);
    CHECK(test.event.failure_origin == QN_FAIL_NONE);
    CHECK(test.event.blen == 0u);
    qn_engine_destroy(&e);
    silent_server_stop(&server);
}

/* QN2-040: concurrent readers must not race, and must not mutate the engine. */
typedef struct {
    qn_engine        *eng;
    _Atomic bool     *go;
    uint64_t          reads;
} reader_arg;

static void *stats_reader(void *v)
{
    reader_arg *a = (reader_arg *)v;

    while (atomic_load_explicit(a->go, memory_order_acquire)) {
        qn_engine_snapshot sn;

        qn_engine_stats(a->eng, &sn);
        a->reads++;
    }
    return NULL;
}

static void test_concurrent_stats_readers(void)
{
    qn_config    cfg;
    qn_engine    e;
    qn_task      t;
    stub         s;
    pthread_t    tid[3];
    reader_arg   arg[3];
    _Atomic bool go;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    t = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "readers" };
    atomic_init(&go, true);

    CHECK(qn_engine_start(&e, &t));
    for (int i = 0; i < 3; i++) {
        arg[i].eng   = &e;
        arg[i].go    = &go;
        arg[i].reads = 0;
        CHECK(pthread_create(&tid[i], NULL, stats_reader, &arg[i]) == 0);
    }
    drain(&e);
    atomic_store_explicit(&go, false, memory_order_release);
    for (int i = 0; i < 3; i++)
        pthread_join(tid[i], NULL);

    CHECK(s.events == DOMAIN);
    check_accounted(&e, "readers");
    qn_engine_destroy(&e);
}

/* FD-pressure retries must not redraw and silently abandon a claimed address. */
static void test_coverage_under_fd_pressure(void)
{
    qn_config  cfg;
    qn_engine  e;
    qn_task    t;
    stub       s;
    rlim_t     saved = 0;
    bool       tight;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));

    t = (qn_task){ stub_next, stub_on_event, &s, DOMAIN, "pressure" };
    tight = fd_squeeze(&saved, 12);
    if (!tight)
        fprintf(stderr, "  note: could not lower RLIMIT_NOFILE; pressure not exercised\n");

    CHECK(qn_engine_start(&e, &t));
    drain(&e);
    if (tight)
        fd_restore(saved);

    /* Every claimed address returns exactly once without exceeding the domain. */
    CHECK(s.events == DOMAIN);
    CHECK(s.issued == DOMAIN);
    CHECK(!s.dup);
    CHECK(!s.out_of_range);
    for (uint32_t i = 0; i < DOMAIN; i++)
        CHECK(s.seen[i] == 1);
    CHECK(s.drawn <= DOMAIN + 1u);
    if (s.drawn > DOMAIN + 1u)
        fprintf(stderr, "  next() called %u times for a domain of %u\n", s.drawn, DOMAIN);

    qn_engine_destroy(&e);
}

/* Restart must never deliver a cancelled predecessor's ring events. */
static void test_restart_drops_stale_events(void)
{
    qn_config cfg;
    qn_engine e;
    qn_task   t1, t2;
    stub      a, b;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    a.port = b.port = closed_port();
    CHECK(a.port != 0);
    if (!a.port)
        return;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));

    /* Stop mid-flight and deliberately do not poll what is left behind. */
    t1 = (qn_task){ stub_next, stub_on_event, &a, DOMAIN, "first" };
    CHECK(qn_engine_start(&e, &t1));
    for (int i = 0; i < 500; i++) {
        qn_engine_snapshot sn;

        qn_engine_stats(&e, &sn);
        if (sn.completed >= 32u)
            break;
        qn_sleep_ms(1);
    }
    qn_engine_stop(&e);

    b.port = a.port;
    t2 = (qn_task){ stub_next, stub_on_event, &b, DOMAIN, "second" };
    CHECK(qn_engine_start(&e, &t2));
    drain(&e);

    CHECK(b.events == b.issued);
    CHECK(!b.dup);
    CHECK(!b.out_of_range);
    if (b.events != b.issued)
        fprintf(stderr, "  second task got %u events for %u addresses\n", b.events, b.issued);

    qn_engine_destroy(&e);
}

/* P0-1: --limit's shape, a task that declines while indices remain. */
#define STOP_AFTER 40u

typedef struct {
    uint32_t issued;
    uint32_t events;
    uint16_t port;
    bool     declined;
} stopper;

static qn_task_next stopper_next(void *ctx, uint64_t idx, qn_job *out)
{
    stopper *s = (stopper *)ctx;

    (void)idx;
    if (s->issued >= STOP_AFTER) {
        s->declined = true;
        return QN_TASK_STOP_CONDITION;
    }
    out->addr.af   = AF_INET;
    out->addr.u.v4 = 0x7F000001u;
    out->port      = s->port;
    out->stage     = QN_STAGE_TCP;
    out->token     = s->issued++;
    return QN_TASK_JOB;
}

static void stopper_on_event(void *ctx, const qn_event *ev)
{
    (void)ev;
    ((stopper *)ctx)->events++;
}

static void test_stop_condition_is_a_success(void)
{
    qn_config          cfg;
    qn_engine          e;
    qn_task            t;
    stopper            s;
    qn_engine_snapshot sn;
    uint64_t           reserved;

    memset(&s, 0, sizeof s);
    s.port = closed_port();
    CHECK(s.port != 0);
    if (!s.port)
        return;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));

    t = (qn_task){ stopper_next, stopper_on_event, &s, DOMAIN, "stop-condition" };
    CHECK(qn_engine_start(&e, &t));
    drain(&e);

    qn_engine_stats(&e, &sn);
    reserved = atomic_load_explicit(&e.cursor, memory_order_relaxed);
    if (reserved > DOMAIN)
        reserved = DOMAIN;

    CHECK(s.declined);
    CHECK(s.events == STOP_AFTER);

    /* Every reserved index is claimed: the one next() declined must not vanish. */
    if (sn.claimed != reserved)
        fprintf(stderr, "  stop-condition: reserved %llu indices but claimed %llu\n",
                (unsigned long long)reserved, (unsigned long long)sn.claimed);
    CHECK(sn.claimed == reserved);

    /* Stop-condition success owes no unattempted tail. */
    if (sn.unattempted)
        fprintf(stderr, "  stop-condition: %llu of %llu reported never attempted\n",
                (unsigned long long)sn.unattempted, (unsigned long long)sn.claimed);
    CHECK(sn.unattempted == 0u);

    qn_engine_destroy(&e);
}

/* An engine that has never run must still be safe to poll and join. */
static void test_idle_lifecycle(void)
{
    qn_config cfg;
    qn_engine e;

    cfg_defaults(&cfg);
    CHECK(qn_engine_init(&e, &cfg, NULL));
    CHECK(qn_engine_done(&e));
    CHECK(qn_engine_poll(&e, 64) == 0);
    qn_engine_join(&e);
    qn_engine_destroy(&e);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        if (!strcmp(argv[1], "drops"))
            test_event_drop_has_one_owner();
        else if (!strcmp(argv[1], "finalize"))
            test_finalize_drains_after_join();
        else if (!strcmp(argv[1], "banner"))
            test_silent_banner_preserves_open();
        else
            CHECK(false);
        if (failures) {
            fprintf(stderr, "engine tests: %d failure(s)\n", failures);
            return 1;
        }
        printf("engine tests: ok\n");
        return 0;
    }
    test_idle_lifecycle();
    test_stop_accounts_for_everything();
    test_stop_condition_is_a_success();
    test_tokens_track_attempts();
    test_counters_separate_retries_from_outcomes();
    test_event_drop_has_one_owner();
    test_accounting_difference_saturates();
    test_finalize_drains_after_join();
    test_silent_banner_preserves_open();
    test_concurrent_stats_readers();
    test_coverage_under_fd_pressure();
    test_restart_drops_stale_events();

    if (failures) {
        fprintf(stderr, "engine tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("engine tests: ok\n");
    return 0;
}
