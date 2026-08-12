#include "qanat/scan_plan.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; } } while (0)

static qn_scan_environment environment(uint64_t total)
{
    qn_scan_environment env;

    memset(&env, 0, sizeof env);
    env.total_addresses = total;
    env.available_memory_bytes = UINT64_C(512) << 20;
    env.fd_limit = 4096u;
    env.input_prefixes = 24u;
    env.cpu_count = 8u;
    env.candidate_bytes = 256u;
    env.verifier_slot_bytes = 65536u;
    env.verifier_result_bytes = 512u;
    return env;
}

static void test_defaults_and_auto_resolution(void)
{
    qn_scan_request request;
    qn_scan_environment env = environment(65536u);
    qn_scan_plan first, second;

    qn_scan_request_defaults(&request);
    CHECK(request.mode == QN_SCAN_AUTO);
    CHECK(request.selection == QN_SELECTION_HYBRID);
    CHECK(qn_scan_plan_resolve(&request, &env, &first));
    CHECK(first.requested_mode == QN_SCAN_AUTO && first.mode == QN_SCAN_FULL);
    CHECK(first.planned_addresses == 65536u && first.exact_full);
    CHECK(qn_scan_plan_resolve(&request, &env, &second));
    CHECK(memcmp(&first, &second, sizeof first) == 0);

    env.total_addresses = 65537u;
    CHECK(qn_scan_plan_resolve(&request, &env, &first));
    CHECK(first.mode == QN_SCAN_COVERAGE && first.coverage_ppm == 100000u);
    CHECK(first.planned_addresses == 6554u && !first.exact_full);

    env = environment(UINT64_C(1) << 24);
    env.mobile = true;
    env.cpu_count = 2u;
    CHECK(qn_scan_plan_resolve(&request, &env, &first));
    CHECK(first.memory_budget_bytes == (UINT64_C(128) << 20));
    CHECK(first.verify_concurrency == 8u);
    CHECK(first.stability_concurrency == 64u);

    env = environment(UINT64_C(1) << 24);
    env.fd_limit = 70u;
    CHECK(qn_scan_plan_resolve(&request, &env, &first));
    CHECK(first.estimated_fds <= env.fd_limit);
    CHECK(first.verify_concurrency + first.stability_concurrency <= 6u);

    env.fd_limit = 65u;
    CHECK(!qn_scan_plan_resolve(&request, &env, &first));
    CHECK(strstr(first.error, "fewer than two") != NULL);

    env = environment(UINT64_C(1) << 24);
    env.available_memory_bytes = UINT64_C(8) << 20;
    CHECK(!qn_scan_plan_resolve(&request, &env, &first));
    CHECK(first.memory_budget_bytes == (UINT64_C(4) << 20));
    CHECK(strstr(first.error, "memory budget") != NULL);
}

static void test_percentage_fixed_point(void)
{
    uint32_t ppm;
    uint64_t n = 0u;

    CHECK(qn_coverage_parse("12.5%", &ppm));
    CHECK(ppm == 125000u);
    CHECK(qn_coverage_count(UINT64_C(4294967297), ppm, &n));
    CHECK(n == UINT64_C(536870913));
    CHECK(qn_coverage_parse("0.01", &ppm));
    CHECK(ppm == 100u);
    CHECK(!qn_coverage_parse("0.0099%", &ppm));
    CHECK(!qn_coverage_parse("100.0001%", &ppm));
}

static void test_full_equals_coverage_100(void)
{
    qn_scan_request full, coverage;
    qn_scan_environment env = environment(UINT64_C(1) << 40);
    qn_scan_plan a, b;

    qn_scan_request_defaults(&full);
    coverage = full;
    full.mode = QN_SCAN_FULL;
    coverage.mode = QN_SCAN_COVERAGE;
    coverage.coverage_ppm = QN_COVERAGE_SCALE;
    CHECK(qn_scan_plan_resolve(&full, &env, &a));
    CHECK(qn_scan_plan_resolve(&coverage, &env, &b));
    CHECK(a.mode == QN_SCAN_FULL && b.mode == QN_SCAN_FULL);
    CHECK(a.planned_addresses == env.total_addresses);
    CHECK(b.planned_addresses == a.planned_addresses);
    CHECK(a.exact_full && b.exact_full);
}

static void test_independent_pipeline_sizes(void)
{
    qn_scan_request req;
    qn_scan_environment env = environment(2000000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&req);
    req.mode = QN_SCAN_BUDGET;
    req.address_budget = 1000000u;
    req.candidate_auto = false;
    req.candidate_capacity = 65536u;
    req.finalists_auto = false;
    req.finalist_limit = 1024u;
    req.output_all = false;
    req.output_limit = 100u;
    req.scan_concurrency_auto = false;
    req.scan_concurrency = 256u;
    req.verify_concurrency_auto = false;
    req.verify_concurrency = 32u;
    req.stability_concurrency_auto = false;
    req.stability_concurrency = 64u;
    CHECK(qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(plan.planned_addresses == 1000000u);
    CHECK(plan.candidate_capacity == 65536u);
    CHECK(plan.finalist_limit == 1024u);
    CHECK(plan.output_limit == 100u);
    CHECK(plan.verify_concurrency == 32u);
    CHECK(plan.finalist_limit > plan.verify_concurrency);
    CHECK(plan.verification_batch_size >= plan.verify_concurrency);
}

static void test_all_and_resource_rejection(void)
{
    qn_scan_request req;
    qn_scan_environment env = environment(100000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&req);
    req.mode = QN_SCAN_FULL;
    req.candidate_auto = false;
    req.candidate_capacity = 65536u;
    req.finalists_auto = false;
    req.finalists_all = true;
    req.output_all = true;
    CHECK(qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(plan.finalist_limit == 65536u);
    CHECK(plan.output_limit == 65536u);

    req.memory_auto = false;
    req.memory_budget_bytes = 1u << 20;
    CHECK(!qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(strstr(plan.error, "memory budget") != NULL);

    req.memory_budget_bytes = UINT64_C(512) << 20;
    req.finalists_all = false;
    req.finalist_limit = 65537u;
    CHECK(!qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(strstr(plan.error, "Finalist Count") != NULL);
}

static void test_working_set_is_inside_the_memory_contract(void)
{
    qn_scan_request request;
    qn_scan_environment env = environment(100000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&request);
    request.mode = QN_SCAN_FULL;
    request.memory_auto = false;
    request.memory_budget_bytes = UINT64_C(128) << 20;
    env.working_bytes = UINT64_C(16) << 20;
    env.working_capacity_bytes = UINT64_C(48) << 20;
    CHECK(qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(plan.estimated_working_bytes == (UINT64_C(16) << 20));
    CHECK(plan.estimated_total_bytes == plan.estimated_working_bytes +
                                            plan.estimated_candidate_bytes +
                                            plan.estimated_verifier_bytes);

    env.working_capacity_bytes = UINT64_C(8) << 20;
    CHECK(!qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(strstr(plan.error, "working arena") != NULL);

    env.working_capacity_bytes = UINT64_C(48) << 20;
    request.memory_budget_bytes = UINT64_C(16) << 20;
    CHECK(!qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(strstr(plan.error, "working set") != NULL);
}

static void test_finalist_boundaries(void)
{
    static const uint64_t finalists[] = { 257u, 1024u };
    qn_scan_request request;
    qn_scan_environment env = environment(1000000u);
    qn_scan_plan plan;
    size_t i;

    qn_scan_request_defaults(&request);
    request.mode = QN_SCAN_BUDGET;
    request.address_budget = 500000u;
    request.candidate_auto = false;
    request.candidate_capacity = 65536u;
    request.verify_concurrency_auto = false;
    request.verify_concurrency = 32u;
    for (i = 0u; i < sizeof finalists / sizeof finalists[0]; i++) {
        request.finalists_auto = false;
        request.finalists_all = false;
        request.finalist_limit = finalists[i];
        CHECK(qn_scan_plan_resolve(&request, &env, &plan));
        CHECK(plan.candidate_capacity == 65536u);
        CHECK(plan.finalist_limit == finalists[i]);
        CHECK(plan.verify_concurrency == 32u);
        CHECK(plan.verification_batch_size == 128u);
    }
    request.finalists_all = true;
    request.finalist_limit = 0u;
    CHECK(qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(plan.finalists_all && plan.finalist_limit == 65536u);
    CHECK(plan.verification_batch_size == 128u);
}

static void test_reachable_and_budget_are_not_counts_of_same_thing(void)
{
    qn_scan_request req;
    qn_scan_environment env = environment(10000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&req);
    req.mode = QN_SCAN_REACHABLE;
    req.reachable_target = 4096u;
    req.candidate_auto = false;
    req.candidate_capacity = 4096u;
    CHECK(qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(plan.planned_addresses == 10000u);
    CHECK(plan.reachable_target == 4096u);

    req.mode = QN_SCAN_BUDGET;
    req.address_budget = 4096u;
    req.reachable_target = 0u;
    CHECK(qn_scan_plan_resolve(&req, &env, &plan));
    CHECK(plan.planned_addresses == 4096u);
    CHECK(plan.reachable_target == 0u);
}

static void test_reachable_auto_does_not_conflate_candidate_capacity(void)
{
    qn_scan_request request;
    qn_scan_environment env = environment(100000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&request);
    request.mode = QN_SCAN_REACHABLE;
    request.reachable_target = 70000u;
    CHECK(request.candidate_auto);
    CHECK(qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(plan.reachable_target == 70000u);
    CHECK(plan.candidate_capacity >= plan.reachable_target);
    CHECK(plan.finalist_limit != plan.reachable_target);
}

static void test_presets_are_only_initial_values(void)
{
    qn_scan_request request;

    qn_scan_request_defaults(&request);
    qn_scan_preset_apply(&request, QN_PRESET_QUICK);
    CHECK(qn_scan_preset_detect(&request) == QN_PRESET_QUICK);
    CHECK(request.mode == QN_SCAN_COVERAGE);
    CHECK(request.coverage_ppm == 10000u);
    CHECK(request.selection == QN_SELECTION_HYBRID);
    CHECK(!request.finalists_auto && request.finalist_limit == 64u);

    qn_scan_preset_apply(&request, QN_PRESET_BALANCED);
    CHECK(qn_scan_preset_detect(&request) == QN_PRESET_BALANCED);
    CHECK(request.coverage_ppm == 100000u);
    CHECK(!request.candidate_auto && request.candidate_capacity == 16384u);
    CHECK(!request.finalists_auto && request.finalist_limit == 256u);

    qn_scan_preset_apply(&request, QN_PRESET_DEEP);
    CHECK(qn_scan_preset_detect(&request) == QN_PRESET_DEEP);
    CHECK(request.coverage_ppm == 250000u);
    CHECK(request.candidate_capacity == 65536u);
    CHECK(request.finalist_limit == 1024u);

    qn_scan_preset_apply(&request, QN_PRESET_FULL);
    CHECK(request.mode == QN_SCAN_FULL);
    CHECK(request.candidate_auto && request.finalists_auto);

    request.output_limit = 777u;
    CHECK(qn_scan_preset_detect(&request) == QN_PRESET_CUSTOM);
    qn_scan_preset_apply(&request, QN_PRESET_CUSTOM);
    CHECK(request.output_limit == 777u);
}

static void test_request_validation_catches_cross_field_errors(void)
{
    qn_scan_request request;
    char error[192];

    qn_scan_request_defaults(&request);
    request.candidate_auto = false;
    request.candidate_capacity = 64u;
    request.finalists_auto = false;
    request.finalist_limit = 65u;
    CHECK(!qn_scan_request_validate(&request, error, sizeof error));
    CHECK(strstr(error, "Finalist Count") != NULL);

    request.finalist_limit = 32u;
    request.mode = QN_SCAN_REACHABLE;
    request.reachable_target = 65u;
    CHECK(!qn_scan_request_validate(&request, error, sizeof error));
    CHECK(strstr(error, "Reachable Target") != NULL);
}

static void test_tunnel_resource_contract(void)
{
    qn_scan_request request;
    qn_scan_environment env = environment(100000u);
    qn_scan_plan plan;

    qn_scan_request_defaults(&request);
    request.tunnel_enabled = true;
    request.tunnel_target = 10u;
    request.tunnel_concurrency = 4u;
    request.tunnel_attempts = 2u;
    env.verifier_fixed_bytes = 262144u;
    CHECK(qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(plan.tunnel_target == 10u);
    CHECK(plan.estimated_tunnel_bytes > 0u);
    CHECK(plan.estimated_total_bytes == plan.estimated_candidate_bytes +
                                        plan.estimated_working_bytes +
                                        (plan.estimated_verifier_bytes >
                                                 plan.estimated_tunnel_bytes
                                             ? plan.estimated_verifier_bytes
                                             : plan.estimated_tunnel_bytes));
    env.fd_limit = 70u;
    request.tunnel_concurrency = 3u;
    CHECK(!qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(strstr(plan.error, "Tunnel Concurrency") != NULL);
    request.tunnel_concurrency = 33u;
    env.fd_limit = 4096u;
    CHECK(!qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(strstr(plan.error, "1 to 32") != NULL);
    request.tunnel_concurrency = 2u;
    request.tunnel_attempts = 3u;
    CHECK(!qn_scan_plan_resolve(&request, &env, &plan));
    CHECK(strstr(plan.error, "1 to 2") != NULL);
}

static void test_settings_round_trip_and_rejects_corruption(void)
{
    char directory[] = "qanat-plan-settings-XXXXXX";
    char path[256];
    char legacy[256];
    char nested[256];
    char error[192];
    qn_scan_request saved, loaded, unchanged;
    FILE *file;

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(path, sizeof path, "%s/nested/scan-plan.conf", directory) > 0);
    qn_scan_preset_apply(&saved, QN_PRESET_DEEP);
    saved.mode = QN_SCAN_BUDGET;
    saved.address_budget = UINT64_C(1000000);
    saved.output_all = true;
    saved.output_limit = 0u;
    saved.verify_concurrency_auto = false;
    saved.verify_concurrency = 32u;
    CHECK(qn_scan_settings_save(path, &saved, error, sizeof error));
    memset(&loaded, 0xa5, sizeof loaded);
    CHECK(qn_scan_settings_load(path, &loaded, error, sizeof error));
    CHECK(qn_scan_request_equal(&saved, &loaded));

    CHECK(snprintf(legacy, sizeof legacy, "%s/nested/scan-plan-v1.conf",
                   directory) > 0);
    {
        FILE *source = fopen(path, "r");
        FILE *target = fopen(legacy, "w");
        char *line = NULL;
        size_t capacity = 0u;

        CHECK(source != NULL);
        CHECK(target != NULL);
        if (source && target) {
            while (getline(&line, &capacity, source) >= 0) {
                if (!strncmp(line, "version=", 8u))
                    CHECK(fputs("version=1\n", target) >= 0);
                else if (strncmp(line, "tunnel_", 7u))
                    CHECK(fputs(line, target) >= 0);
            }
        }
        free(line);
        if (source)
            CHECK(fclose(source) == 0);
        if (target)
            CHECK(fclose(target) == 0);
    }
    saved.tunnel_enabled = true;
    saved.tunnel_target = 7u;
    loaded = saved;
    CHECK(qn_scan_settings_load(legacy, &loaded, error, sizeof error));
    CHECK(!loaded.tunnel_enabled);
    CHECK(!loaded.tunnel_all);
    CHECK(loaded.tunnel_target == 0u);
    CHECK(loaded.tunnel_concurrency == 1u);
    CHECK(loaded.tunnel_attempts == 2u);

    unchanged = loaded;
    saved.coverage_ppm = 99u;
    CHECK(!qn_scan_settings_save(path, &saved, error, sizeof error));
    CHECK(qn_scan_settings_load(path, &loaded, error, sizeof error));
    CHECK(qn_scan_request_equal(&unchanged, &loaded));

    file = fopen(path, "w");
    CHECK(file != NULL);
    if (file) {
        CHECK(fputs("version=1\nmode=18446744073709551616\n", file) >= 0);
        CHECK(fclose(file) == 0);
    }
    loaded = unchanged;
    CHECK(!qn_scan_settings_load(path, &loaded, error, sizeof error));
    CHECK(qn_scan_request_equal(&unchanged, &loaded));

    CHECK(unlink(path) == 0);
    CHECK(unlink(legacy) == 0);
    CHECK(snprintf(nested, sizeof nested, "%s/nested", directory) > 0);
    CHECK(rmdir(nested) == 0);
    CHECK(rmdir(directory) == 0);
}

int main(void)
{
    test_defaults_and_auto_resolution();
    test_percentage_fixed_point();
    test_full_equals_coverage_100();
    test_independent_pipeline_sizes();
    test_all_and_resource_rejection();
    test_working_set_is_inside_the_memory_contract();
    test_finalist_boundaries();
    test_reachable_and_budget_are_not_counts_of_same_thing();
    test_reachable_auto_does_not_conflate_candidate_capacity();
    test_presets_are_only_initial_values();
    test_request_validation_catches_cross_field_errors();
    test_tunnel_resource_contract();
    test_settings_round_trip_and_rejects_corruption();
    if (failures) {
        fprintf(stderr, "scan plan tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("scan plan tests: ok");
    return 0;
}
