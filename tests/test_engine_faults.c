#include "qanat/engine.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

typedef struct {
    uint32_t events;
    qn_event last;
} fault_context;

typedef struct {
    uint32_t stop_at;
    uint32_t events;
    bool     duplicate[130];
} model_context;

static qn_task_next fault_next(void *context, uint64_t index, qn_job *job)
{
    (void)context;
    if (index)
        return QN_TASK_EXHAUSTED;
    memset(job, 0, sizeof *job);
    job->addr.af = AF_INET;
    job->addr.u.v4 = 0xC0000201u;
    job->port = 443u;
    job->stage = QN_STAGE_TCP;
    return QN_TASK_JOB;
}

static qn_task_next empty_next(void *context, uint64_t index, qn_job *job)
{
    (void)context;
    (void)index;
    (void)job;
    return QN_TASK_EXHAUSTED;
}

static void fault_event(void *context, const qn_event *event)
{
    fault_context *state = (fault_context *)context;

    state->events++;
    state->last = *event;
}

static qn_task_next model_next(void *context, uint64_t index, qn_job *job)
{
    model_context *state = (model_context *)context;

    if (index == state->stop_at)
        return QN_TASK_STOP_CONDITION;
    memset(job, 0, sizeof *job);
    job->addr.af = AF_INET;
    job->addr.u.v4 = 0xC0000201u + (uint32_t)index;
    job->port = 443u;
    job->stage = QN_STAGE_TCP;
    job->token = (uint32_t)index;
    return QN_TASK_JOB;
}

static void model_event(void *context, const qn_event *event)
{
    model_context *state = (model_context *)context;

    if (event->job.token >= 130u || state->duplicate[event->job.token]) {
        failures++;
        return;
    }
    state->duplicate[event->job.token] = true;
    state->events++;
}

static void engine_config(qn_config *config)
{
    qn_config_defaults(config);
    config->workers = 1u;
    config->concurrency = 16u;
    config->timeout_ms = 100u;
    config->no_adaptive = true;
    config->no_affinity = true;
    config->no_thermal = true;
    config->warm_mode = QN_WARM_OFF;
}

static void test_thread_start_failure_is_typed(void)
{
    qn_config config;
    qn_engine engine;
    fault_context context;
    qn_task task;
    int error = 0;
    uint32_t worker = UINT32_MAX;

    memset(&context, 0, sizeof context);
    engine_config(&config);
    CHECK(qn_engine_init(&engine, &config, NULL));
    task = (qn_task){ empty_next, fault_event, &context, 1u, "offline-empty" };
    qn_engine_test_set_fault(QN_ENGINE_TEST_THREAD_CREATE);
    CHECK(!qn_engine_start(&engine, &task));
    CHECK(qn_engine_state(&engine) == QN_ENGINE_FATAL);
    CHECK(qn_engine_failed(&engine, &error, &worker));
    CHECK(error == EAGAIN && worker == 0u);
    CHECK(!atomic_load_explicit(&engine.started, memory_order_relaxed));
    qn_engine_destroy(&engine);
}

static void test_epoll_failure_uses_bounded_select_fallback(void)
{
    qn_config config;
    qn_engine engine;
    fault_context context;
    qn_task task;
    qn_engine_finalization final;

    memset(&context, 0, sizeof context);
    engine_config(&config);
    CHECK(qn_engine_init(&engine, &config, NULL));
    task = (qn_task){ empty_next, fault_event, &context, 1u, "offline-empty" };
    qn_engine_test_set_fault(QN_ENGINE_TEST_EPOLL_CREATE);
    CHECK(qn_engine_start(&engine, &task));
    CHECK(strcmp(qn_engine_backend(&engine), "select") == 0);
    qn_engine_finalize(&engine, false, &final);
    CHECK(final.outcome == QN_RUN_SUCCESS);
    CHECK(final.stats.status == QN_ENGINE_COMPLETE);
    CHECK(final.accounted);
    CHECK(context.events == 0u);
    qn_engine_destroy(&engine);
}

static void test_socket_exhaustion_cannot_be_success(void)
{
    qn_config config;
    qn_engine engine;
    fault_context context;
    qn_task task;
    qn_engine_finalization final;

    memset(&context, 0, sizeof context);
    engine_config(&config);
    CHECK(qn_engine_init(&engine, &config, NULL));
    task = (qn_task){ fault_next, fault_event, &context, 1u, "offline-socket-fault" };
    qn_engine_test_set_fault(QN_ENGINE_TEST_SOCKET);
    CHECK(qn_engine_start(&engine, &task));
    qn_engine_finalize(&engine, false, &final);
    CHECK(final.accounted && final.missing == 0u);
    CHECK(final.stats.claimed == 1u && final.stats.completed == 1u);
    CHECK(final.stats.local_launch_failures > 0u);
    CHECK(final.stats.local_terminal_failures == 1u);
    CHECK(final.outcome == QN_RUN_FAILED);
    CHECK(context.events == 1u);
    CHECK(context.last.result == QN_R_ERROR);
    CHECK(context.last.failure_origin == QN_FAIL_LOCAL);
    CHECK(context.last.sys_errno == EMFILE);
    qn_engine_destroy(&engine);
}

static void test_stop_accounting_matches_chunk_model(void)
{
    enum { DOMAIN = 130u, CHUNK = 64u };

    for (uint32_t stop = 0u; stop < DOMAIN; stop++) {
        qn_config config;
        qn_engine engine;
        model_context context;
        qn_task task;
        qn_engine_finalization final;
        uint64_t claimed = ((uint64_t)stop / CHUNK + 1u) * CHUNK;

        if (claimed > DOMAIN)
            claimed = DOMAIN;
        memset(&context, 0, sizeof context);
        context.stop_at = stop;
        engine_config(&config);
        CHECK(qn_engine_init(&engine, &config, NULL));
        task = (qn_task){ model_next, model_event, &context, DOMAIN, "offline-model" };
        qn_engine_test_set_fault(QN_ENGINE_TEST_SYNTHETIC_OPEN);
        CHECK(qn_engine_start(&engine, &task));
        qn_engine_finalize(&engine, false, &final);
        CHECK(final.accounted && final.missing == 0u);
        CHECK(final.outcome == QN_RUN_SUCCESS);
        CHECK(final.stats.status == QN_ENGINE_STOPPED);
        CHECK(final.stats.claimed == claimed);
        CHECK(final.stats.issued == stop && final.stats.completed == stop);
        CHECK(final.stats.skipped == claimed - stop);
        CHECK(final.stats.unattempted == 0u);
        CHECK(context.events == stop);
        qn_engine_destroy(&engine);
    }
}

int main(void)
{
    test_thread_start_failure_is_typed();
    test_epoll_failure_uses_bounded_select_fallback();
    test_socket_exhaustion_cannot_be_success();
    test_stop_accounting_matches_chunk_model();
    qn_engine_test_set_fault(QN_ENGINE_TEST_NONE);

    if (failures) {
        fprintf(stderr, "engine fault tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("engine fault tests: ok\n");
    return 0;
}
