#ifndef QANAT_ENGINE_H
#define QANAT_ENGINE_H

#include <pthread.h>
#include <stdatomic.h>

#include "qanat/arena.h"
#include "qanat/cpuinfo.h"
#include "qanat/outcome.h"
#include "qanat/probe.h"
#include "qanat/ring.h"
#include "qanat/timewheel.h"

typedef struct QN_ALIGNED(QN_CACHELINE) {
    qn_addr  addr;
    uint16_t port;
    uint8_t  stage;
    uint8_t  flags;
    uint64_t token;
} qn_job;

typedef struct {
    qn_job   job;
    uint32_t rtt_us;
    uint8_t  result;
    uint8_t  tls;
    uint16_t http_status;
    char     colo[4];
    uint16_t blen;
    uint8_t  failure_origin;
    uint8_t  _pad;
    int32_t  sys_errno;
    int32_t  protocol_code;
    uint8_t  body[QN_EVENT_BODY];
} qn_event;

typedef struct qn_engine qn_engine;

/* A run that ended FATAL or CANCELLED must not be finalised as if it worked. */
typedef enum {
    QN_ENGINE_IDLE = 0,
    QN_ENGINE_RUNNING,
    QN_ENGINE_COMPLETE,
    QN_ENGINE_STOPPED, /* a stop condition the task asked for: still a success */
    QN_ENGINE_CANCELLED,
    QN_ENGINE_FATAL
} qn_engine_status;

const char *qn_engine_status_str(qn_engine_status s);

/* A boolean cannot tell a satisfied goal from an empty domain or a failure. */
typedef enum {
    QN_TASK_JOB = 0,        /* out holds the next job */
    QN_TASK_EXHAUSTED,      /* the domain holds no more work */
    QN_TASK_STOP_CONDITION, /* the task's own goal was met */
    QN_TASK_CANCELLED,      /* the task was cancelled from outside */
    QN_TASK_FATAL           /* the task cannot continue */
} qn_task_next;

const char *qn_task_next_str(qn_task_next r);

typedef struct {
    /* next() runs on workers; on_event() runs on the owner thread. */
    qn_task_next (*next)(void *ctx, uint64_t idx, qn_job *out);
    void (*on_event)(void *ctx, const qn_event *ev);
    void    *ctx;
    uint64_t domain;
    const char *label;
} qn_task;

/* Cache-line counters separate launch retries from each job's one terminal outcome. */
typedef struct QN_ALIGNED(QN_CACHELINE) {
    _Atomic uint64_t claimed;   /* indices drawn from the task */
    _Atomic uint64_t issued;    /* sockets actually launched */
    _Atomic uint64_t completed; /* terminal events published */
    _Atomic uint64_t open;
    _Atomic uint64_t refused;
    _Atomic uint64_t timeout;
    _Atomic uint64_t reset;
    _Atomic uint64_t unreach;
    _Atomic uint64_t cancelled;
    _Atomic uint64_t rx_bytes;

    _Atomic uint64_t local_launch_failures; /* retry level, never terminal */
    _Atomic uint64_t syscall_failures;      /* epoll_wait or select level */
    _Atomic uint64_t terminal_job_failures; /* one per job that ended in error */
    _Atomic uint64_t local_terminal_failures; /* terminal failures caused locally */
    _Atomic uint64_t protocol_failures;     /* terminal, origin PROTOCOL */
    _Atomic uint64_t unattempted;           /* claimed, still owed when it ended */
    _Atomic uint64_t skipped;               /* claimed, deliberately not run */

    _Atomic uint32_t window;
    _Atomic uint32_t inflight;
    _Atomic uint32_t deadline_ms;
} qn_wstats;

_Static_assert(sizeof(qn_wstats) % QN_CACHELINE == 0, "worker stats must be cache-line isolated");

/* Delay-aware AIMD over in-flight sockets. */
typedef struct {
    uint32_t window;
    uint32_t wmin, wmax;
    uint32_t ok_run;
    uint32_t batch_n, batch_timeouts;
    uint32_t rtt_base_us;
    uint32_t rtt_ewma_us;
    uint32_t ok_samples;
    uint32_t deadline_ms;
    uint32_t deadline_floor_ms;
    uint64_t last_cut_ms;
    uint64_t cuts;
} qn_aimd;

typedef struct qn_worker {
    qn_engine   *eng;
    pthread_t    tid;
    uint32_t     id;
    uint32_t     cpu;
    int          epfd;
    qn_timewheel wheel;
    qn_rng       rng;
    qn_aimd      aimd;
    qn_ring      out;

    struct qn_probe *slots;
    uint32_t        *freelist;
    uint32_t         nslots;
    uint32_t         nfree;
    uint32_t         inflight;

    uint64_t now_ms;
    uint64_t tokens;
    uint64_t token_ts_ms;
    uint64_t thermal_next_ms;
    uint32_t thermal_want;  /* level two consecutive polls must agree on */
    uint32_t thermal_agree;
    uint32_t rate_per_sec;

    /* A claimed job remains pending until launch succeeds or fails terminally. */
    qn_job   pending_job;
    uint32_t pending_tries;
    int      launch_errno;
    bool     has_pending;

    /* Chunked claims avoid one shared atomic per probe. */
    uint64_t claim_cur, claim_end;
    bool     drained;
    bool     launched;
    /* Why this worker stopped drawing; decides who owns the unused tail. */
    qn_task_next drain_reason;

    qn_wstats *st;
} qn_worker;

struct qn_engine {
    qn_config         cfg;
    const qn_topology *topo;
    qn_worker        *w;
    qn_wstats        *st;
    uint32_t          nworkers;
    uint32_t          concurrency;
    uint32_t          ring_cap;
    uint32_t          select_workers;
    int               init_errno;

    _Atomic uint64_t cursor QN_ALIGNED(QN_CACHELINE);
    uint8_t          _cursor_pad[QN_CACHELINE - sizeof(uint64_t)];
    _Atomic uint32_t alive;
    _Atomic bool     stopping;
    _Atomic bool     started;
    _Atomic bool     tfo;
    _Atomic bool     stop_condition; /* a task reported its goal was met */
    _Atomic bool     fatal;
    _Atomic int      fatal_errno;
    _Atomic uint32_t fatal_worker;
    _Atomic int      status;
    _Atomic uint32_t thermal_mc;
    _Atomic uint32_t thermal_pct;

    const qn_task *task;
    qn_arena       arena;
    uint64_t       t_start_ms;

    /* Rate sampling mutates, so it is owner-driven and locked, never a read. */
    pthread_mutex_t  rate_lock;
    uint64_t         rate_last_completed;
    uint64_t         rate_last_ms;
    _Atomic uint32_t rate_ewma;
};

bool qn_engine_init(qn_engine *e, const qn_config *cfg, const qn_topology *topo);
void qn_engine_destroy(qn_engine *e);

bool     qn_engine_start(qn_engine *e, const qn_task *t);
uint32_t qn_engine_poll(qn_engine *e, uint32_t max_events);
bool     qn_engine_done(const qn_engine *e);
bool     qn_engine_failed(const qn_engine *e, int *error_out, uint32_t *worker_out);
void     qn_engine_stop(qn_engine *e);
void     qn_engine_join(qn_engine *e);

typedef struct {
    uint64_t claimed, issued, completed;
    uint64_t open, refused, timeout, reset, unreach, cancelled, rx_bytes;
    uint64_t local_launch_failures, syscall_failures;
    uint64_t terminal_job_failures, local_terminal_failures, protocol_failures;
    uint64_t network_failures; /* derived: refused + timeout + reset + unreach */
    uint64_t events_dropped, unattempted, skipped;
    uint32_t window, inflight;
    uint64_t elapsed_ms;
    uint32_t rate_now;
    uint32_t thermal_mc;
    uint32_t thermal_pct;
    qn_engine_status status;
} qn_engine_snapshot;

typedef struct {
    qn_engine_snapshot stats;
    uint64_t           missing;
    int                 fatal_errno;
    uint32_t            fatal_worker;
    bool                accounted;
    bool                failed;
    qn_run_outcome      outcome;
} qn_engine_finalization;

/* A pure snapshot: safe from any thread and mutates nothing. */
void qn_engine_stats(const qn_engine *e, qn_engine_snapshot *out);

/* Explicitly a sampling operation; the owner thread drives it on its cadence. */
void qn_engine_rate_sample(qn_engine *e);

qn_engine_status qn_engine_state(const qn_engine *e);

/* Claimed work is fully accounted for only after the workers are joined. */
bool qn_engine_accounted(const qn_engine *e, uint64_t *missing);
void qn_engine_finalize(qn_engine *e, bool cancel,
                        qn_engine_finalization *out);
uint32_t qn_engine_deadline_ms(const qn_engine *e);
const char *qn_engine_backend(const qn_engine *e);

/* Wakes a cellular radio before timed samples. */
void qn_engine_warm_radio(const qn_config *cfg);

#if defined(QN_ENGINE_TESTING)
typedef enum {
    QN_ENGINE_TEST_NONE = 0,
    QN_ENGINE_TEST_EPOLL_CREATE,
    QN_ENGINE_TEST_THREAD_CREATE,
    QN_ENGINE_TEST_SOCKET,
    QN_ENGINE_TEST_SYNTHETIC_OPEN
} qn_engine_test_fault;

void qn_engine_test_set_fault(qn_engine_test_fault fault);
#endif

#endif /* QANAT_ENGINE_H */
