#ifndef QANAT_SCAN_PLAN_H
#define QANAT_SCAN_PLAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QN_SCAN_PLAN_VERSION 1u
#define QN_SCAN_SETTINGS_VERSION 1u
#define QN_SCORE_VERSION     2u
#define QN_COVERAGE_SCALE    UINT32_C(1000000)

typedef enum {
    QN_SCAN_AUTO = 0,
    QN_SCAN_FULL,
    QN_SCAN_COVERAGE,
    QN_SCAN_BUDGET,
    QN_SCAN_REACHABLE
} qn_scan_mode;

typedef enum {
    QN_SELECTION_UNIFORM = 0,
    QN_SELECTION_STRATIFIED,
    QN_SELECTION_ADAPTIVE,
    QN_SELECTION_HYBRID
} qn_selection_policy;

typedef enum {
    QN_RANK_BALANCED = 0,
    QN_RANK_LATENCY,
    QN_RANK_STABILITY,
    QN_RANK_THROUGHPUT
} qn_rank_policy;

typedef enum {
    QN_PRESET_CUSTOM = 0,
    QN_PRESET_QUICK,
    QN_PRESET_BALANCED,
    QN_PRESET_DEEP,
    QN_PRESET_FULL
} qn_scan_preset;

typedef struct {
    qn_scan_mode         mode;
    qn_selection_policy selection;
    qn_rank_policy      rank_by;
    uint32_t            coverage_ppm;
    uint32_t            explore_percent;
    uint64_t            address_budget;
    uint64_t            reachable_target;
    uint64_t            candidate_capacity;
    uint64_t            finalist_limit;
    uint64_t            output_limit;
    uint64_t            memory_budget_bytes;
    uint32_t            scan_concurrency;
    uint32_t            verify_concurrency;
    uint32_t            stability_concurrency;
    bool                candidate_auto;
    bool                finalists_auto;
    bool                finalists_all;
    bool                output_all;
    bool                memory_auto;
    bool                scan_concurrency_auto;
    bool                verify_concurrency_auto;
    bool                stability_concurrency_auto;
} qn_scan_request;

#define QN_SCAN_REQUEST_INIT                                                        \
    {                                                                               \
        .mode = QN_SCAN_AUTO, .selection = QN_SELECTION_HYBRID,                    \
        .rank_by = QN_RANK_BALANCED, .coverage_ppm = 100000u,                      \
        .explore_percent = 20u, .candidate_auto = true, .finalists_auto = true,    \
        .output_limit = 20u, .memory_auto = true,                                  \
        .scan_concurrency_auto = true, .verify_concurrency_auto = true,             \
        .stability_concurrency_auto = true                                          \
    }

typedef struct {
    uint64_t total_addresses;
    uint64_t available_memory_bytes;
    uint64_t fd_limit;
    uint32_t input_prefixes;
    uint32_t normalized_prefixes;
    uint64_t input_addresses;
    uint64_t duplicate_addresses;
    uint32_t cpu_count;
    size_t   candidate_bytes;
    size_t   candidate_fixed_bytes;
    size_t   verifier_slot_bytes;
    size_t   verifier_result_bytes;
    size_t   verifier_fixed_bytes;
    uint64_t working_bytes;
    uint64_t working_capacity_bytes;
    size_t   page_size;
    bool     mobile;
} qn_scan_environment;

typedef struct {
    uint32_t            version;
    qn_scan_mode         requested_mode;
    qn_scan_mode         mode;
    qn_selection_policy selection;
    qn_rank_policy      rank_by;
    uint32_t            coverage_ppm;
    uint32_t            explore_percent;
    uint64_t            total_addresses;
    uint64_t            planned_addresses;
    uint64_t            reachable_target;
    uint64_t            candidate_capacity;
    uint64_t            finalist_limit;
    uint64_t            output_limit;
    uint64_t            memory_budget_bytes;
    uint64_t            estimated_candidate_bytes;
    uint64_t            estimated_verifier_bytes;
    uint64_t            estimated_working_bytes;
    uint64_t            estimated_total_bytes;
    uint64_t            fd_limit;
    uint64_t            estimated_fds;
    uint32_t            scan_concurrency;
    uint32_t            verify_concurrency;
    uint32_t            stability_concurrency;
    uint32_t            verification_batch_size;
    uint32_t            input_prefixes;
    uint32_t            normalized_prefixes;
    uint64_t            input_addresses;
    uint64_t            duplicate_addresses;
    bool                finalists_all;
    bool                output_all;
    bool                representative;
    bool                exact_full;
    bool                auto_adjusted;
    bool                valid;
    char                error[192];
} qn_scan_plan;

void qn_scan_request_defaults(qn_scan_request *request);
bool qn_scan_request_equal(const qn_scan_request *left,
                           const qn_scan_request *right);
bool qn_scan_request_validate(const qn_scan_request *request,
                              char *error, size_t error_capacity);
void qn_scan_preset_apply(qn_scan_request *request, qn_scan_preset preset);
const char *qn_scan_preset_str(qn_scan_preset preset);
qn_scan_preset qn_scan_preset_detect(const qn_scan_request *request);
bool qn_scan_settings_default_path(char *path, size_t capacity);
bool qn_scan_settings_save(const char *path, const qn_scan_request *request,
                           char *error, size_t error_capacity);
bool qn_scan_settings_load(const char *path, qn_scan_request *request,
                           char *error, size_t error_capacity);
bool qn_coverage_parse(const char *text, uint32_t *coverage_ppm);
bool qn_coverage_count(uint64_t total, uint32_t coverage_ppm, uint64_t *count);
bool qn_size_parse(const char *text, uint64_t *bytes);
bool qn_scan_plan_resolve(const qn_scan_request *request,
                          const qn_scan_environment *environment,
                          qn_scan_plan *plan);
const char *qn_scan_mode_str(qn_scan_mode mode);
const char *qn_selection_str(qn_selection_policy policy);
const char *qn_rank_policy_str(qn_rank_policy policy);
bool qn_scan_mode_parse(const char *text, qn_scan_mode *mode);
bool qn_selection_parse(const char *text, qn_selection_policy *policy);
bool qn_rank_policy_parse(const char *text, qn_rank_policy *policy);

#endif
