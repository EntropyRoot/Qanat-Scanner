/* Boundary behaviour of the Cloudflare scan task, driven through its own API. */

#include "qanat/task.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void open_event(qn_event *ev, uint32_t token, uint32_t rtt_us)
{
    memset(ev, 0, sizeof *ev);
    ev->job.addr.af   = AF_INET;
    ev->job.addr.u.v4 = 0xC0000200u + token;
    ev->job.port      = 443u;
    ev->job.token     = token;
    ev->result        = QN_R_OPEN;
    ev->rtt_us        = rtt_us;
}

static void destroy_scan(cf_scan *scan, qn_arena *arena)
{
    cf_scan_destroy(scan);
    qn_arena_free(arena);
}

/* A reachable target above the historical cap owns matching storage. */
static void test_limit_above_cap_cannot_overflow(void)
{
    qn_arena  arena;
    qn_config cfg;
    cf_scan   s;
    uint32_t  i;
    const uint32_t target = 21384u;

    CHECK(qn_arena_init(&arena, 96u << 20));
    qn_config_defaults(&cfg);
    cfg.mode = QN_MODE_CF;
    cfg.scan.mode = QN_SCAN_REACHABLE;
    cfg.scan.reachable_target = target;
    cfg.scan.candidate_auto = false;
    cfg.scan.candidate_capacity = target;

    CHECK(cf_scan_init(&s, &arena, &cfg));
    CHECK(s.cap == target);
    CHECK(s.limit == target);
    CHECK(cf_scan_next_phase(&s));
    CHECK(s.task.on_event != NULL);

    /* Feed more reachable candidates than the raw limit would have allowed. */
    for (i = 0; i < target + 2000u; i++) {
        qn_event ev;

        open_event(&ev, i % 4096u, 1000u + i);
        s.task.on_event(s.task.ctx, &ev);
        if (s.n > s.cap) {
            fprintf(stderr, "  wrote %u records into a capacity of %u\n", s.n, s.cap);
            break;
        }
    }

    CHECK(s.n <= s.cap);
    CHECK(s.n == s.cap);
    CHECK(atomic_load_explicit(&s.full, memory_order_acquire));
    destroy_scan(&s, &arena);
}

/* A limit below the cap still stops exactly where it says it will. */
static void test_limit_below_cap_is_exact(void)
{
    qn_arena  arena;
    qn_config cfg;
    cf_scan   s;
    uint32_t  i;
    const uint32_t target = 12u;

    CHECK(qn_arena_init(&arena, 32u << 20));
    qn_config_defaults(&cfg);
    cfg.mode = QN_MODE_CF;
    cfg.scan.mode = QN_SCAN_REACHABLE;
    cfg.scan.reachable_target = target;
    cfg.scan.candidate_auto = false;
    cfg.scan.candidate_capacity = target;

    CHECK(cf_scan_init(&s, &arena, &cfg));
    CHECK(s.cap == 12u);
    CHECK(s.limit == 12u);
    CHECK(cf_scan_next_phase(&s));

    for (i = 0; i < 100u; i++) {
        qn_event ev;

        open_event(&ev, i, 1000u + i);
        s.task.on_event(s.task.ctx, &ev);
    }
    CHECK(s.n == 12u);
    CHECK(atomic_load_explicit(&s.full, memory_order_acquire));
    destroy_scan(&s, &arena);
}

/* With no limit the top-K path keeps at most the allocated capacity. */
static void test_unlimited_uses_topk_bound(void)
{
    qn_arena  arena;
    qn_config cfg;
    cf_scan   s;
    uint32_t  i;

    CHECK(qn_arena_init(&arena, 96u << 20));
    qn_config_defaults(&cfg);
    cfg.mode = QN_MODE_CF;

    CHECK(cf_scan_init(&s, &arena, &cfg));
    CHECK(s.cap == cfg.scan_plan.candidate_capacity);
    CHECK(s.cap > 16384u);
    CHECK(s.limit == 0u);
    CHECK(cf_scan_next_phase(&s));

    for (i = 0; i < 5000u; i++) {
        qn_event ev;

        open_event(&ev, i % 4096u, 500u + (i % 977u));
        s.task.on_event(s.task.ctx, &ev);
    }
    CHECK(s.n <= s.cap);
    CHECK(s.reached == 5000u);
    destroy_scan(&s, &arena);
}

/* P0-1: a satisfied --limit is the task's goal being met, not an empty domain. */
static void test_limit_reports_a_stop_condition(void)
{
    qn_arena  arena;
    qn_config cfg;
    cf_scan   s;
    qn_job    job;
    uint32_t  i;
    const uint32_t target = 5u;

    CHECK(qn_arena_init(&arena, 32u << 20));
    qn_config_defaults(&cfg);
    cfg.mode = QN_MODE_CF;
    cfg.scan.mode = QN_SCAN_REACHABLE;
    cfg.scan.reachable_target = target;
    cfg.scan.candidate_auto = false;
    cfg.scan.candidate_capacity = target;

    CHECK(cf_scan_init(&s, &arena, &cfg));
    CHECK(cf_scan_next_phase(&s));

    /* Before the limit the sweep still hands out work. */
    memset(&job, 0, sizeof job);
    CHECK(s.task.next(s.task.ctx, 0u, &job) == QN_TASK_JOB);

    for (i = 0; i < target; i++) {
        qn_event ev;

        open_event(&ev, i, 1000u + i);
        s.task.on_event(s.task.ctx, &ev);
    }
    CHECK(s.n == target);
    CHECK(atomic_load_explicit(&s.full, memory_order_acquire));

    /* The range is nowhere near spent, so this must not read as exhaustion. */
    memset(&job, 0, sizeof job);
    CHECK(s.task.next(s.task.ctx, 1u, &job) == QN_TASK_STOP_CONDITION);
    CHECK(s.set.total > target);
    destroy_scan(&s, &arena);
}

static void write_ranges(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");

    CHECK(file != NULL);
    if (!file)
        return;
    CHECK(fwrite(text, 1u, strlen(text), file) == strlen(text));
    CHECK(fclose(file) == 0);
}

static void task_test_path(char path[128], const char *tag)
{
    const char *directory = getenv("TMPDIR");
    int length;

    if (!directory || !directory[0])
        directory = "/tmp";
    length = snprintf(path, 128u, "%s/qanat-task-%ld-%s", directory,
                      (long)getpid(), tag);
    CHECK(length > 0 && length < 128);
}

static void deterministic_cf_config(qn_config *cfg, const char *ranges)
{
    qn_config_defaults(cfg);
    cfg->mode = QN_MODE_CF;
    cfg->ranges_file = ranges;
    cfg->seed_explicit = true;
    cfg->seed = UINT64_C(0x123456789abcdef0);
    cfg->effective_seed = cfg->seed;
}

static bool collect_sweep_tokens(cf_scan *scan, uint64_t *tokens, size_t count,
                                 bool *seen, size_t seen_count)
{
    qn_job job;

    if (!cf_scan_next_phase(scan))
        return false;
    for (size_t i = 0u; i < count; i++) {
        if (scan->task.next(scan->task.ctx, i, &job) != QN_TASK_JOB ||
            job.token >= seen_count || seen[job.token])
            return false;
        seen[job.token] = true;
        tokens[i] = job.token;
    }
    return scan->task.next(scan->task.ctx, count, &job) == QN_TASK_EXHAUSTED;
}

static void test_full_and_coverage_100_cover_all_normalized_ranges_once(void)
{
    char path[128];
    uint64_t full_tokens[8], coverage_tokens[8];
    bool full_seen[8] = { false }, coverage_seen[8] = { false };

    task_test_path(path, "ranges.txt");
    write_ranges(path,
                 "10.0.0.0/30\n"
                 "10.0.0.2/31\n"
                 "10.0.0.4/30\n");

    for (unsigned pass = 0u; pass < 2u; pass++) {
        qn_arena arena;
        qn_config cfg;
        cf_scan scan;
        bool initialized;

        CHECK(qn_arena_init(&arena, 16u << 20));
        deterministic_cf_config(&cfg, path);
        cfg.scan.mode = pass == 0u ? QN_SCAN_FULL : QN_SCAN_COVERAGE;
        cfg.scan.coverage_ppm = QN_COVERAGE_SCALE;
        initialized = cf_scan_init(&scan, &arena, &cfg);
        CHECK(initialized);
        if (!initialized) {
            cf_scan_destroy(&scan);
            qn_arena_free(&arena);
            continue;
        }
        CHECK(scan.input_prefixes == 3u);
        CHECK(scan.normalized_prefixes == 1u);
        CHECK(scan.input_addresses == 10u);
        CHECK(scan.duplicate_addresses == 2u);
        CHECK(scan.set.total == 8u);
        CHECK(cfg.scan_plan.exact_full && cfg.scan_plan.mode == QN_SCAN_FULL);
        if (pass == 0u)
            CHECK(collect_sweep_tokens(&scan, full_tokens, 8u, full_seen, 8u));
        else
            CHECK(collect_sweep_tokens(&scan, coverage_tokens, 8u,
                                       coverage_seen, 8u));
        destroy_scan(&scan, &arena);
    }
    CHECK(memcmp(full_tokens, coverage_tokens, sizeof full_tokens) == 0);
    for (size_t i = 0u; i < 8u; i++) {
        CHECK(full_seen[i]);
        CHECK(coverage_seen[i]);
    }
    CHECK(unlink(path) == 0);
}

static void test_partial_selection_is_unique_and_seed_deterministic(void)
{
    char path[128];

    task_test_path(path, "selection.txt");
    write_ranges(path, "10.0.0.0/24\n10.0.1.0/24\n");
    for (int policy = QN_SELECTION_UNIFORM; policy <= QN_SELECTION_HYBRID;
         policy++) {
        qn_arena first_arena, second_arena;
        qn_config first_cfg, second_cfg;
        cf_scan first, second;
        uint64_t first_tokens[65], second_tokens[65];
        bool first_seen[512] = { false }, second_seen[512] = { false };
        bool first_ok, second_ok;

        CHECK(qn_arena_init(&first_arena, 16u << 20));
        CHECK(qn_arena_init(&second_arena, 16u << 20));
        deterministic_cf_config(&first_cfg, path);
        deterministic_cf_config(&second_cfg, path);
        first_cfg.scan.mode = second_cfg.scan.mode = QN_SCAN_BUDGET;
        first_cfg.scan.address_budget = second_cfg.scan.address_budget = 65u;
        first_cfg.scan.selection = second_cfg.scan.selection =
            (qn_selection_policy)policy;
        first_cfg.scan.candidate_auto = second_cfg.scan.candidate_auto = false;
        first_cfg.scan.candidate_capacity = second_cfg.scan.candidate_capacity = 65u;
        first_ok = cf_scan_init(&first, &first_arena, &first_cfg);
        second_ok = cf_scan_init(&second, &second_arena, &second_cfg);
        CHECK(first_ok && second_ok);
        if (first_ok && second_ok) {
            CHECK(collect_sweep_tokens(&first, first_tokens, 65u,
                                       first_seen, 512u));
            CHECK(collect_sweep_tokens(&second, second_tokens, 65u,
                                       second_seen, 512u));
            CHECK(memcmp(first_tokens, second_tokens, sizeof first_tokens) == 0);
            if (policy != QN_SELECTION_UNIFORM) {
                bool low = false, high = false;

                for (size_t i = 0u; i < 65u; i++) {
                    low |= first_tokens[i] < 256u;
                    high |= first_tokens[i] >= 256u;
                }
                CHECK(low && high);
            }
        }
        cf_scan_destroy(&first);
        cf_scan_destroy(&second);
        qn_arena_free(&first_arena);
        qn_arena_free(&second_arena);
    }
    CHECK(unlink(path) == 0);
}

static void test_large_candidate_and_finalist_plans_allocate_bounded_storage(void)
{
    for (unsigned all = 0u; all < 2u; all++) {
        qn_arena arena;
        qn_config cfg;
        cf_scan scan;
        bool initialized;

        CHECK(qn_arena_init(&arena, 48u << 20));
        deterministic_cf_config(&cfg, NULL);
        cfg.scan.mode = QN_SCAN_BUDGET;
        cfg.scan.address_budget = 100000u;
        cfg.scan.candidate_auto = false;
        cfg.scan.candidate_capacity = 65536u;
        cfg.scan.finalists_auto = false;
        cfg.scan.finalists_all = all != 0u;
        cfg.scan.finalist_limit = all ? 0u : 1024u;
        cfg.scan.memory_auto = false;
        cfg.scan.memory_budget_bytes = UINT64_C(512) << 20;
        cfg.scan.verify_concurrency_auto = false;
        cfg.scan.verify_concurrency = 32u;
        initialized = cf_scan_init(&scan, &arena, &cfg);
        CHECK(initialized);
        if (initialized) {
            CHECK(scan.cap == 65536u);
            CHECK(cfg.scan_plan.finalist_limit == (all ? 65536u : 1024u));
            CHECK(cfg.scan_plan.verify_concurrency == 32u);
            CHECK(cfg.scan_plan.verification_batch_size == 128u);
            CHECK(scan.candidate_arena.used <= cfg.scan_plan.estimated_candidate_bytes);
            CHECK(cfg.scan_plan.estimated_total_bytes ==
                  cfg.scan_plan.estimated_working_bytes +
                  cfg.scan_plan.estimated_candidate_bytes +
                  cfg.scan_plan.estimated_verifier_bytes);
        }
        cf_scan_destroy(&scan);
        qn_arena_free(&arena);
    }
}

static bool phase_open_all(cf_scan *scan, bool tls_phase, uint32_t round,
                           uint32_t lucky, uint32_t stable, uint32_t runner_up)
{
    uint64_t total = scan->task.domain;

    for (uint64_t i = 0u; i < total; i++) {
        qn_event event;
        qn_job job;
        uint32_t rtt = 200000u;

        memset(&job, 0, sizeof job);
        if (scan->task.next(scan->task.ctx, i, &job) != QN_TASK_JOB)
            return false;
        memset(&event, 0, sizeof event);
        event.job = job;
        event.result = QN_R_OPEN;
        if (tls_phase) {
            event.tls = QN_TLS_SERVERHELLO;
            rtt = 30000u + (uint32_t)i;
        } else if (job.token == stable) {
            rtt = 10000u;
        } else if (job.token == runner_up) {
            rtt = 12000u;
        } else if (job.token == lucky) {
            rtt = round == 0u ? 100u : 600000u;
        }
        event.rtt_us = rtt;
        scan->task.on_event(scan->task.ctx, &event);
    }
    {
        qn_job exhausted;

        return scan->task.next(scan->task.ctx, total, &exhausted) ==
               QN_TASK_EXHAUSTED;
    }
}

static bool finalists_contain(const cf_scan *scan, uint32_t index)
{
    for (uint32_t i = 0u; i < scan->nfinalist; i++)
        if (scan->finalist[i] == index)
            return true;
    return false;
}

static void test_robust_samples_select_finalists_after_calibration(void)
{
    qn_arena arena;
    qn_config cfg;
    cf_scan scan;
    uint32_t lucky, stable, runner_up;
    uint32_t round = 0u;
    bool initialized;

    CHECK(qn_arena_init(&arena, 32u << 20));
    deterministic_cf_config(&cfg, NULL);
    cfg.samples = 5u;
    cfg.scan.mode = QN_SCAN_BUDGET;
    cfg.scan.address_budget = 8u;
    cfg.scan.candidate_auto = false;
    cfg.scan.candidate_capacity = 8u;
    cfg.scan.finalists_auto = false;
    cfg.scan.finalist_limit = 2u;
    initialized = cf_scan_init(&scan, &arena, &cfg);
    CHECK(initialized);
    if (!initialized) {
        cf_scan_destroy(&scan);
        qn_arena_free(&arena);
        return;
    }

    CHECK(cf_scan_next_phase(&scan));
    CHECK(phase_open_all(&scan, false, 0u, UINT32_MAX, UINT32_MAX, UINT32_MAX));
    CHECK(scan.n == 8u);
    CHECK(cf_scan_next_phase(&scan));
    CHECK(phase_open_all(&scan, true, 0u, UINT32_MAX, UINT32_MAX, UINT32_MAX));
    CHECK(cf_scan_next_phase(&scan));
    CHECK(scan.phase == CF_PHASE_RTT);
    CHECK(scan.ncalibration == 8u);
    CHECK(scan.nfinalist == 0u);
    lucky = scan.active[0];
    stable = scan.active[1];
    runner_up = scan.active[2];

    do {
        CHECK(scan.phase == CF_PHASE_RTT);
        CHECK(phase_open_all(&scan, false, round, lucky, stable, runner_up));
        round++;
    } while (cf_scan_next_phase(&scan));

    CHECK(round >= 3u);
    CHECK(scan.phase == CF_PHASE_DONE);
    CHECK(scan.ncalibration == 8u);
    CHECK(scan.nfinalist == 2u);
    CHECK(finalists_contain(&scan, stable));
    CHECK(finalists_contain(&scan, runner_up));
    CHECK(!finalists_contain(&scan, lucky));
    CHECK(scan.rec[stable].rtt_med_us == 10000u);
    CHECK(scan.rec[lucky].rtt_min_us == 100u);
    CHECK(scan.rec[stable].score > scan.rec[lucky].score);
    destroy_scan(&scan, &arena);
}

int main(void)
{
    test_limit_above_cap_cannot_overflow();
    test_limit_below_cap_is_exact();
    test_unlimited_uses_topk_bound();
    test_limit_reports_a_stop_condition();
    test_full_and_coverage_100_cover_all_normalized_ranges_once();
    test_partial_selection_is_unique_and_seed_deterministic();
    test_large_candidate_and_finalist_plans_allocate_bounded_storage();
    test_robust_samples_select_finalists_after_calibration();

    if (failures) {
        fprintf(stderr, "task tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("task tests: ok\n");
    return 0;
}
