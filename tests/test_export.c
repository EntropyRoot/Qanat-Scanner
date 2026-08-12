#include "qanat/probe.h"
#include "qanat/profile.h"
#include "qanat/task.h"
#include "qanat/tls.h"
#include "qanat/util.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

/* Printable-name stubs keep this regression isolated from the TLS state machine. */
const char *qn_tls_fp_str(qn_tls_fp fp)
{
    return fp == QN_TLS_FP_CHROME ? "chrome" : "other";
}

const char *qn_profile_support_str(qn_profile_support support)
{
    return support == QN_PROFILE_CAPABILITY_CONSTRAINED ? "capability-constrained" : "exact";
}

const char *qn_tls_outcome_str(qn_tls_outcome outcome)
{
    return outcome == QN_TLS_SERVERHELLO ? "server-hello" : "none";
}

const char *qn_diag_state_str(qn_diag_state state)
{
    return state == QN_DIAG_POSITIVE ? "positive" : "not-run";
}

static char *read_all(const char *path)
{
    FILE  *f;
    char  *buf;
    long   end;
    size_t size;

    f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    end = ftell(f);
    if (end < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    size = (size_t)end;
    if (size == SIZE_MAX) {
        fclose(f);
        return NULL;
    }
    buf = (char *)malloc(size + 1u);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1u, size, f) != size || fclose(f) != 0) {
        free(buf);
        return NULL;
    }
    buf[size] = '\0';
    return buf;
}

static void write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");

    CHECK(file != NULL);
    if (!file)
        return;
    CHECK(fwrite(text, 1u, strlen(text), file) == strlen(text));
    CHECK(fclose(file) == 0);
}

static void init_cf(cf_scan *cf, qn_config *cfg, cf_record rec[3])
{
    static qn_profile_instance profile;

    memset(cf, 0, sizeof *cf);
    memset(rec, 0, 3u * sizeof *rec);
    qn_config_defaults(cfg);
    cfg->mode = QN_MODE_CF;
    cfg->sni = "example.com";
    cfg->effective_seed = 42u;
    cfg->scan_plan.version = QN_SCAN_PLAN_VERSION;
    cfg->scan_plan.requested_mode = QN_SCAN_COVERAGE;
    cfg->scan_plan.mode = QN_SCAN_COVERAGE;
    cfg->scan_plan.selection = QN_SELECTION_HYBRID;
    cfg->scan_plan.rank_by = QN_RANK_BALANCED;
    cfg->scan_plan.coverage_ppm = 100000u;
    cfg->scan_plan.explore_percent = 20u;
    cfg->scan_plan.total_addresses = 1524736u;
    cfg->scan_plan.planned_addresses = 152474u;
    cfg->scan_plan.candidate_capacity = 65536u;
    cfg->scan_plan.finalist_limit = 1024u;
    cfg->scan_plan.output_limit = 3u;
    cfg->scan_plan.scan_concurrency = 256u;
    cfg->scan_plan.verify_concurrency = 32u;
    cfg->scan_plan.stability_concurrency = 16u;
    cfg->scan_plan.verification_batch_size = 32u;
    cfg->scan_plan.memory_budget_bytes = 256u * 1024u * 1024u;
    cfg->scan_plan.estimated_candidate_bytes = 32u * 1024u * 1024u;
    cfg->scan_plan.estimated_verifier_bytes = 4u * 1024u * 1024u;
    cfg->scan_plan.estimated_working_bytes = 8u * 1024u * 1024u;
    cfg->scan_plan.estimated_total_bytes = 44u * 1024u * 1024u;
    cfg->scan_plan.fd_limit = 1024u;
    cfg->scan_plan.estimated_fds = 306u;
    cfg->scan_plan.valid = true;
    memset(&profile, 0, sizeof profile);
    profile.version = QN_PROFILE_INSTANCE_VERSION;
    profile.requested = QN_TLS_FP_CHROME;
    profile.resolved = QN_TLS_FP_CHROME;
    profile.support = QN_PROFILE_CAPABILITY_CONSTRAINED;
    cfg->profile_instance = &profile;

    cf->cfg = cfg;
    cf->rec = rec;
    cf->n = 3u;
    cf->cap = 3u;
    cf->set.total = 1524736u;
    cf->input_prefixes = 24u;
    cf->normalized_prefixes = 22u;
    cf->input_addresses = 1600000u;
    cf->duplicate_addresses = 75264u;
    cf->ranges_bytes = 4096u;
    cf->sweep_completed = 93u;
    cf->reached = 3u;
    cf->clean = 3u;
    cf->edges = 2u;
    atomic_init(&cf->bandit.issued, 97u);
    cf->sweep_stats.claimed = 97u;
    cf->sweep_stats.issued = 93u;
    cf->sweep_stats.completed = 93u;
    cf->sweep_stats.skipped = 1u;
    cf->sweep_stats.unattempted = 3u;
    cf->nfinalist = 3u;
    cf->verify_completed = 3u;

    CHECK(qn_addr_parse("192.0.2.10", &rec[0].addr));
    CHECK(qn_addr_parse("198.51.100.20", &rec[1].addr));
    CHECK(qn_addr_parse("203.0.113.30", &rec[2].addr));

    rec[0].highest_rung_reached = QN_RUNG_TLS;
    rec[0].terminal_outcome = QN_TERM_SUCCESS;
    rec[0].verified = 1u;
    rec[1].highest_rung_reached = QN_RUNG_EDGE;
    rec[1].terminal_outcome = QN_TERM_SUCCESS;
    rec[1].verified = 1u;
    rec[1].rtt_p90_us = 12345u;
    rec[1].tls_outcome = QN_TLS_SERVERHELLO;
    rec[2].highest_rung_reached = QN_RUNG_STABLE;
    rec[2].terminal_outcome = QN_TERM_SUCCESS;
    rec[2].verified = 1u;
}

static void test_json_and_template(void)
{
    char       dir_template[] = "qanat-export-test-XXXXXX";
    char       json_path[128], xray_path[128], empty_path[128], empty_json_path[128];
    char      *dir, *body;
    qn_config  cfg;
    cf_scan    cf;
    cf_record  rec[3];

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(json_path, sizeof json_path, "%s/results.json", dir) > 0);
    CHECK(snprintf(xray_path, sizeof xray_path, "%s/xray.json", dir) > 0);
    CHECK(snprintf(empty_path, sizeof empty_path, "%s/empty.txt", dir) > 0);
    CHECK(snprintf(empty_json_path, sizeof empty_json_path, "%s/empty.json", dir) > 0);
    init_cf(&cf, &cfg, rec);

    CHECK(qn_export_json(json_path, &cf, NULL, NULL, NULL) == QN_RUN_SUCCESS);
    body = read_all(json_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"schema\": 6") != NULL);
        CHECK(strstr(body, "\"build_fingerprint\":") != NULL);
        CHECK(strstr(body, "\"result_scope\": \"best-observed-among-scanned-addresses\"") != NULL);
        CHECK(strstr(body, "\"candidate_capacity\": 65536") != NULL);
        CHECK(strstr(body, "\"finalist_limit\": 1024") != NULL);
        CHECK(strstr(body, "\"calibration_cohort\":") != NULL);
        CHECK(strstr(body, "\"verify_concurrency\": 32") != NULL);
        CHECK(strstr(body, "\"estimated_working_bytes\": 8388608") != NULL);
        CHECK(strstr(body, "\"support\": \"capability-constrained\"") != NULL);
        CHECK(strstr(body, "\"score_version\": 2") != NULL);
        CHECK(strstr(body, "\"highest_rung_reached\": \"stable-after-marker\"") != NULL);
        CHECK(strstr(body, "\"terminal_outcome\": \"success\"") != NULL);
        CHECK(strstr(body, "\"unique_addresses\": 1524736") != NULL);
        CHECK(strstr(body, "\"claimed\": 97") != NULL);
        CHECK(strstr(body, "\"completed\": 93") != NULL);
        CHECK(strstr(body, "\"unattempted\": 3") != NULL);
        CHECK(strstr(body, "\"reachable\": 3") != NULL);
        CHECK(strstr(body, "\"rtt_p90_us\": 12345") != NULL);
        CHECK(strstr(body, "\"verification_completed\": true") != NULL);
        CHECK(strstr(body, "\"verified\":") == NULL);
        free(body);
    }

    rec[0].verified = 0u;
    cfg.scan_plan.output_limit = 2u;
    CHECK(qn_export_json(json_path, &cf, NULL, NULL, NULL) == QN_RUN_SUCCESS);
    body = read_all(json_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "192.0.2.10") == NULL);
        CHECK(strstr(body, "198.51.100.20") != NULL);
        CHECK(strstr(body, "203.0.113.30") != NULL);
        CHECK(strstr(body, "\"output_results\": 2") != NULL);
        free(body);
    }
    rec[0].verified = 1u;
    cfg.scan_plan.output_limit = 3u;

    CHECK(qn_export_config(xray_path, 1u, &cf) == QN_RUN_SUCCESS);
    body = read_all(xray_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "198.51.100.20") != NULL);
        CHECK(strstr(body, "203.0.113.30") != NULL);
        CHECK(strstr(body, "192.0.2.10") == NULL);
        CHECK(strstr(body, "REPLACE_UUID") != NULL);
        free(body);
    }

    cfg.sni = "www.cloudflare.com";
    CHECK(qn_export_config(xray_path, 1u, &cf) == QN_RUN_SUCCESS);
    body = read_all(xray_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "REPLACE_SNI") != NULL);
        CHECK(strstr(body, "\"serverName\": \"www.cloudflare.com\"") == NULL);
        free(body);
    }
    cfg.sni = "example.com";

    rec[1].highest_rung_reached = QN_RUNG_TLS;
    rec[2].verified = 0u;
    CHECK(qn_export_config(empty_path, 0u, &cf) == QN_RUN_SUCCESS);
    body = read_all(empty_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "no verified address exposed a Cloudflare marker") != NULL);
        CHECK(strstr(body, "192.0.2.10") == NULL);
        free(body);
    }
    CHECK(qn_export_config(empty_json_path, 1u, &cf) == QN_RUN_SUCCESS);
    body = read_all(empty_json_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"outbounds\": []") != NULL);
        CHECK(body[0] == '{');
        free(body);
    }

    rec[1].highest_rung_reached = 255u;
    rec[1].verified = 1u;
    CHECK(qn_export_config(empty_json_path, 1u, &cf) == QN_RUN_SUCCESS);
    body = read_all(empty_json_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"outbounds\": []") != NULL);
        CHECK(strstr(body, "198.51.100.20") == NULL);
        free(body);
    }

    cf.n = 0u;
    cf.cap = 0u;
    cf.rec = NULL;
    CHECK(qn_export_config(empty_json_path, 1u, &cf) == QN_RUN_SUCCESS);
    body = read_all(empty_json_path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"outbounds\": []") != NULL);
        free(body);
    }

    CHECK(unlink(json_path) == 0);
    CHECK(unlink(xray_path) == 0);
    CHECK(unlink(empty_path) == 0);
    CHECK(unlink(empty_json_path) == 0);
    CHECK(rmdir(dir) == 0);
}

static void test_host_icmp_outcome_is_exported(void)
{
    char          dir_template[] = "qanat-host-export-test-XXXXXX";
    char          path[128];
    char         *dir, *body;
    qn_config     cfg;
    host_discover hd;

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(path, sizeof path, "%s/results.json", dir) > 0);
    qn_config_defaults(&cfg);
    cfg.mode = QN_MODE_DISCOVER;
    cfg.discover_method = QN_DISCOVER_ICMP;
    memset(&hd, 0, sizeof hd);
    hd.cfg = &cfg;
    hd.icmp_outcome = QN_RUN_FAILED;
    hd.icmp_errno = EACCES;
    hd.icmp_attempted = 7u;
    hd.icmp_replied = 2u;
    hd.icmp_rejected = 1u;
    hd.icmp_unsent = 247u;
    hd.icmp_found = 2u;
    qn_strlcpy(hd.prefix_str, "192.0.2.0/24", sizeof hd.prefix_str);

    CHECK(qn_export_json(path, NULL, NULL, &hd, NULL) == QN_RUN_SUCCESS);
    body = read_all(path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"schema\": 6") != NULL);
        CHECK(strstr(body, "\"requested\": true") != NULL);
        CHECK(strstr(body, "\"outcome\": \"failed\"") != NULL);
        CHECK(strstr(body, "\"errno\": 13") != NULL);
        CHECK(strstr(body, "\"attempted\": 7") != NULL);
        CHECK(strstr(body, "\"unsent\": 247") != NULL);
        free(body);
    }
    CHECK(unlink(path) == 0);
    CHECK(rmdir(dir) == 0);
}

static void test_output_failures_are_typed_and_transactional(void)
{
    static const qn_export_test_fault faults[] = {
        QN_EXPORT_TEST_SHORT_WRITE,
        QN_EXPORT_TEST_FSYNC,
        QN_EXPORT_TEST_RENAME
    };
    char        dir_template[] = "qanat-output-fault-test-XXXXXX";
    char        path[128], missing[160];
    char       *dir, *body;
    qn_config   cfg;
    port_scan   ps;

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(path, sizeof path, "%s/results.json", dir) > 0);
    CHECK(snprintf(missing, sizeof missing, "%s/missing/results.json", dir) > 0);
    qn_config_defaults(&cfg);
    memset(&ps, 0, sizeof ps);
    ps.cfg = &cfg;
    qn_strlcpy(ps.target_str, "localhost", sizeof ps.target_str);

    CHECK(qn_export_json(NULL, NULL, &ps, NULL, NULL) == QN_RUN_FAILED);
    CHECK(qn_export_json("", NULL, &ps, NULL, NULL) == QN_RUN_FAILED);
    CHECK(qn_export_json(missing, NULL, &ps, NULL, NULL) == QN_RUN_INCOMPLETE);

    for (size_t i = 0u; i < QN_ARRAY_LEN(faults); i++) {
        write_text(path, "old-result\n");
        qn_export_test_set_fault(faults[i]);
        CHECK(qn_export_json(path, NULL, &ps, NULL, NULL) == QN_RUN_INCOMPLETE);
        qn_export_test_set_fault(QN_EXPORT_TEST_NONE);
        body = read_all(path);
        CHECK(body != NULL);
        if (body) {
            CHECK(strcmp(body, "old-result\n") == 0);
            free(body);
        }
    }

    CHECK(unlink(path) == 0);
    CHECK(rmdir(dir) == 0);
}

static void test_csv_formula_neutralization(void)
{
    char        dir_template[] = "qanat-csv-test-XXXXXX";
    char        path[128];
    char       *dir, *body;
    qn_config   cfg;
    port_scan   ps;
    port_record rec;

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(path, sizeof path, "%s/results.csv", dir) > 0);
    qn_config_defaults(&cfg);
    memset(&ps, 0, sizeof ps);
    memset(&rec, 0, sizeof rec);
    ps.cfg = &cfg;
    ps.open = &rec;
    ps.nopen = 1u;
    ps.opencap = 1u;
    qn_strlcpy(ps.target_str, "localhost", sizeof ps.target_str);
    rec.port = 443u;
    rec.rtt_us = 1000u;
    qn_strlcpy(rec.banner, "=1+1", sizeof rec.banner);

    CHECK(qn_export_csv(path, NULL, &ps, NULL) == QN_RUN_SUCCESS);
    body = read_all(path);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "\"'=1+1\"") != NULL);
        free(body);
    }
    CHECK(unlink(path) == 0);
    CHECK(rmdir(dir) == 0);
}

/* A hostile peer cannot carry terminal controls or invalid UTF-8 into a report. */
static void test_export_neutralizes_hostile_fields(void)
{
    static const char hostile[] = "\x1b[31mRED\x1b]0;t\x07 \x7f \xc0\xaf \xed\xa0\x80 ok";
    char        dir_template[] = "qanat-inject-test-XXXXXX";
    char        jpath[128], cpath[128];
    char       *dir, *body;
    qn_config   cfg;
    port_scan   ps;
    port_record rec;

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(jpath, sizeof jpath, "%s/results.json", dir) > 0);
    CHECK(snprintf(cpath, sizeof cpath, "%s/results.csv", dir) > 0);
    qn_config_defaults(&cfg);
    memset(&ps, 0, sizeof ps);
    memset(&rec, 0, sizeof rec);
    ps.cfg     = &cfg;
    ps.open    = &rec;
    ps.nopen   = 1u;
    ps.opencap = 1u;
    qn_strlcpy(ps.target_str, "localhost", sizeof ps.target_str);
    rec.port = 443u;
    qn_strlcpy(rec.banner, hostile, sizeof rec.banner);

    CHECK(qn_export_json(jpath, NULL, &ps, NULL, NULL) == QN_RUN_SUCCESS);
    body = read_all(jpath);
    CHECK(body != NULL);
    if (body) {
        /* Raw controls and invalid UTF-8 never survive export. */
        CHECK(strchr(body, '\x1b') == NULL);
        CHECK(strchr(body, '\x07') == NULL);
        CHECK(strchr(body, '\x7f') == NULL);
        CHECK(strstr(body, "\\u001b") != NULL);
        CHECK(strstr(body, "\\u007f") != NULL);
        CHECK(strstr(body, "\\ufffd") != NULL);
        CHECK(strstr(body, (const char *)"\xc0") == NULL);
        CHECK(strstr(body, (const char *)"\xed\xa0\x80") == NULL);
        free(body);
    }

    CHECK(qn_export_csv(cpath, NULL, &ps, NULL) == QN_RUN_SUCCESS);
    body = read_all(cpath);
    CHECK(body != NULL);
    if (body) {
        CHECK(strchr(body, '\x1b') == NULL);
        CHECK(strchr(body, '\x07') == NULL);
        CHECK(strchr(body, '\x7f') == NULL);
        CHECK(strstr(body, (const char *)"\xed\xa0\x80") == NULL);
        free(body);
    }

    CHECK(unlink(jpath) == 0);
    CHECK(unlink(cpath) == 0);
    CHECK(rmdir(dir) == 0);
}

/* Valid multi-byte UTF-8 must survive unchanged; escaping is not mangling. */
static void test_export_keeps_valid_utf8(void)
{
    char        dir_template[] = "qanat-utf8-test-XXXXXX";
    char        jpath[128];
    char       *dir, *body;
    qn_config   cfg;
    port_scan   ps;
    port_record rec;

    dir = mkdtemp(dir_template);
    CHECK(dir != NULL);
    if (!dir)
        return;
    CHECK(snprintf(jpath, sizeof jpath, "%s/results.json", dir) > 0);
    qn_config_defaults(&cfg);
    memset(&ps, 0, sizeof ps);
    memset(&rec, 0, sizeof rec);
    ps.cfg     = &cfg;
    ps.open    = &rec;
    ps.nopen   = 1u;
    ps.opencap = 1u;
    qn_strlcpy(ps.target_str, "localhost", sizeof ps.target_str);
    rec.port = 443u;
    qn_strlcpy(rec.banner, "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x8c\x8d",
               sizeof rec.banner);

    CHECK(qn_export_json(jpath, NULL, &ps, NULL, NULL) == QN_RUN_SUCCESS);
    body = read_all(jpath);
    CHECK(body != NULL);
    if (body) {
        CHECK(strstr(body, "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x8c\x8d") != NULL);
        CHECK(strstr(body, "\\ufffd") == NULL);
        free(body);
    }
    CHECK(unlink(jpath) == 0);
    CHECK(rmdir(dir) == 0);
}

int main(void)
{
    test_json_and_template();
    test_host_icmp_outcome_is_exported();
    test_output_failures_are_typed_and_transactional();
    test_csv_formula_neutralization();
    test_export_neutralizes_hostile_fields();
    test_export_keeps_valid_utf8();
    if (failures) {
        fprintf(stderr, "export tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("export tests: ok");
    return 0;
}
