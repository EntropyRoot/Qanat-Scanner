#include "qanat/task.h"
#include "qanat/netinfo.h"
#include "qanat/profile.h"
#include "qanat/tls.h"
#include "qanat/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    FILE       *f;
    char       *tmp;
    const char *path;
    bool        owned;
} qn_output;

#if defined(QN_EXPORT_TESTING)
static qn_export_test_fault output_test_fault;

void qn_export_test_set_fault(qn_export_test_fault fault)
{
    output_test_fault = fault;
}
#endif

static bool sync_parent_dir(const char *path)
{
    char *dir, *slash;
    int   fd, rc, saved;

    dir = strdup(path);
    if (!dir)
        return false;
    slash = strrchr(dir, '/');
    if (!slash) {
        free(dir);
        dir = strdup(".");
        if (!dir)
            return false;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    saved = errno;
    free(dir);
    if (fd < 0) {
        errno = saved;
        return false;
    }
    rc = fsync(fd);
    saved = errno;
    close(fd);
    if (rc == 0 || saved == EINVAL || saved == ENOTSUP || saved == EROFS)
        return true;
    errno = saved;
    return false;
}

static bool output_open(qn_output *out, const char *path, bool stdout_ok)
{
    size_t n;
    int    fd;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!path) {
        if (!stdout_ok)
            return false;
        out->f = stdout;
        return true;
    }
    if (!*path)
        return false;
    n = strlen(path);
    if (n > SIZE_MAX - sizeof ".tmp.XXXXXX")
        return false;
    out->tmp = (char *)malloc(n + sizeof ".tmp.XXXXXX");
    if (!out->tmp)
        return false;
    memcpy(out->tmp, path, n);
    memcpy(out->tmp + n, ".tmp.XXXXXX", sizeof ".tmp.XXXXXX");
    fd = mkstemp(out->tmp);
    if (fd < 0)
        goto fail;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    out->f = fdopen(fd, "w");
    if (!out->f) {
        int saved = errno;
        close(fd);
        errno = saved;
        goto fail;
    }
    out->path = path;
    out->owned = true;
    return true;

fail:
    {
        int saved = errno;
        if (out->tmp) {
            (void)unlink(out->tmp);
            free(out->tmp);
        }
        memset(out, 0, sizeof *out);
        errno = saved;
    }
    return false;
}

static bool output_finish(qn_output *out)
{
    bool ok;

    if (!out || !out->f)
        return false;
    if (!out->owned) {
        ok = fflush(out->f) == 0 && !ferror(out->f);
        memset(out, 0, sizeof *out);
        return ok;
    }

#if defined(QN_EXPORT_TESTING)
    if (output_test_fault == QN_EXPORT_TEST_SHORT_WRITE) {
        errno = EIO;
        ok = false;
    } else
#endif
    ok = fflush(out->f) == 0 && !ferror(out->f);
    if (ok) {
#if defined(QN_EXPORT_TESTING)
        if (output_test_fault == QN_EXPORT_TEST_FSYNC) {
            errno = EIO;
            ok = false;
        } else
#endif
        if (fsync(fileno(out->f)) != 0) {
            ok = false;
        }
    }
    if (fclose(out->f) != 0)
        ok = false;
    out->f = NULL;
    if (ok
#if defined(QN_EXPORT_TESTING)
        && output_test_fault != QN_EXPORT_TEST_RENAME
#endif
        && rename(out->tmp, out->path) == 0) {
        ok = sync_parent_dir(out->path);
    } else {
#if defined(QN_EXPORT_TESTING)
        if (ok && output_test_fault == QN_EXPORT_TEST_RENAME)
            errno = EIO;
#endif
        ok = false;
    }
    if (!ok)
        (void)unlink(out->tmp);
    free(out->tmp);
    memset(out, 0, sizeof *out);
    return ok;
}

static qn_run_outcome output_outcome(bool persisted)
{
    return persisted ? QN_RUN_SUCCESS : QN_RUN_INCOMPLETE;
}

/* Scalar length, or 0 for malformed, overlong, surrogate or out-of-range. */
static size_t utf8_next(const unsigned char *s, uint32_t *cp)
{
    unsigned char c = s[0];
    size_t        need, i;
    uint32_t      v;

    if (c < 0x80u) {
        *cp = c;
        return 1u;
    }
    if (c >= 0xC2u && c <= 0xDFu) { need = 1u; v = c & 0x1Fu; }
    else if (c >= 0xE0u && c <= 0xEFu) { need = 2u; v = c & 0x0Fu; }
    else if (c >= 0xF0u && c <= 0xF4u) { need = 3u; v = c & 0x07u; }
    else return 0u;

    for (i = 1u; i <= need; i++) {
        if ((s[i] & 0xC0u) != 0x80u)
            return 0u;
        v = (v << 6) | (uint32_t)(s[i] & 0x3Fu);
    }
    if ((need == 2u && v < 0x800u) || (need == 3u && v < 0x10000u))
        return 0u; /* overlong */
    if (v >= 0xD800u && v <= 0xDFFFu)
        return 0u; /* lone surrogate */
    if (v > 0x10FFFFu)
        return 0u;
    *cp = v;
    return need + 1u;
}

/* The one place a string becomes JSON: always valid UTF-8, never a control. */
static void json_str(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    fputc('"', f);
    while (*p) {
        uint32_t cp;
        size_t   n = utf8_next(p, &cp);

        if (!n) {
            fputs("\\ufffd", f); /* not decodable: say so rather than pass it on */
            p++;
            continue;
        }
        if (cp == '"' || cp == '\\')
            fprintf(f, "\\%c", (int)cp);
        else if (cp < 0x20u || cp == 0x7Fu || (cp >= 0x80u && cp <= 0x9Fu))
            fprintf(f, "\\u%04x", (unsigned)cp);
        else
            fwrite(p, 1u, n, f);
        p += n;
    }
    fputc('"', f);
}

static void json_hex(FILE *f, const uint8_t *bytes, size_t count)
{
    fputc('"', f);
    for (size_t i = 0u; i < count; i++)
        fprintf(f, "%02x", bytes[i]);
    fputc('"', f);
}

static uint32_t cf_output_count(const cf_scan *cf)
{
    uint64_t limit;
    uint32_t count = 0u;

    if (!cf || !cf->cfg)
        return 0u;
    limit = cf->cfg->scan_plan.valid ? cf->cfg->scan_plan.output_limit : cf->n;
    for (uint32_t i = 0u; i < cf->n && count < limit; i++)
        if (cf->rec[i].verified)
            count++;
    return count;
}

/* Same for CSV: never closes its quote, starts a formula, or carries a control. */
static void csv_str(FILE *f, const char *s, bool neutralize_formula)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    fputc('"', f);
    if (neutralize_formula && (*p == '=' || *p == '+' || *p == '-' || *p == '@'))
        fputc('\'', f);
    while (*p) {
        uint32_t cp;
        size_t   n = utf8_next(p, &cp);

        if (!n) {
            fputc('?', f);
            p++;
            continue;
        }
        if (cp < 0x20u || cp == 0x7Fu || (cp >= 0x80u && cp <= 0x9Fu)) {
            fputc(' ', f);
        } else {
            if (cp == '"')
                fputc('"', f);
            fwrite(p, 1u, n, f);
        }
        p += n;
    }
    fputc('"', f);
}

static bool valid_sources(const cf_scan *cf, const port_scan *ps, const host_discover *hd)
{
    if (cf && cf->cfg && (cf->n > cf->cap || (cf->n && !cf->rec)))
        return false;
    if (ps && ps->cfg && (ps->nopen > ps->opencap || (ps->nopen && !ps->open)))
        return false;
    if (hd && hd->cfg && (hd->n > hd->cap || (hd->n && !hd->host)))
        return false;
    return true;
}

static bool has_netinfo(const qn_netinfo *ni)
{
    return ni && (ni->niface || ni->ndns || ni->has_gateway || ni->has_public ||
                  ni->gw_rtt_us || ni->inet_rtt_us || ni->dns_rtt_us ||
                  ni->gateway_state != QN_DIAG_NOT_RUN ||
                  ni->internet_state != QN_DIAG_NOT_RUN ||
                  ni->public_state != QN_DIAG_NOT_RUN || ni->dns_state != QN_DIAG_NOT_RUN ||
                  ni->captive_state != QN_DIAG_NOT_RUN);
}

qn_run_outcome qn_export_json(const char *path, const cf_scan *cf,
                              const port_scan *ps, const host_discover *hd,
                              const qn_netinfo *ni)
{
    qn_output output;
    FILE     *f;
    char      addr[QN_ADDRSTRLEN];

    if (!path || !*path || !valid_sources(cf, ps, hd))
        return QN_RUN_FAILED;
    if (!output_open(&output, path, false))
        return QN_RUN_INCOMPLETE;
    f = output.f;

    fprintf(f, "{\n  \"tool\": \"" QN_NAME "\",\n  \"version\": \"" QN_VERSION
               "\",\n  \"build_fingerprint\": \"" QN_BUILD_FINGERPRINT "\",\n");

    if (cf && cf->cfg) {
        const qn_scan_plan *plan = &cf->cfg->scan_plan;
        const qn_profile_instance *profile = cf->cfg->profile_instance;
        uint32_t output_n = cf_output_count(cf);

        fprintf(f, "  \"cloudflare\": {\n");
        fprintf(f,
                "    \"result_scope\": \"%s\",\n"
                "    \"range_snapshot\": {\"bytes\": %llu, \"sha256\": ",
                plan->exact_full ? "complete-loaded-range-set"
                                 : "best-observed-among-scanned-addresses",
                (unsigned long long)cf->ranges_bytes);
        json_hex(f, cf->ranges_digest, sizeof cf->ranges_digest);
        fprintf(f,
                ", \"input_prefixes\": %u, \"normalized_prefixes\": %u, "
                "\"input_addresses\": %llu, \"unique_addresses\": %llu, "
                "\"duplicate_addresses_removed\": %llu},\n",
                cf->input_prefixes, cf->normalized_prefixes,
                (unsigned long long)cf->input_addresses,
                (unsigned long long)cf->set.total,
                (unsigned long long)cf->duplicate_addresses);
        fprintf(f,
                "    \"scan_plan\": {\"version\": %u, \"requested_mode\": \"%s\", "
                "\"resolved_mode\": \"%s\", \"selection\": \"%s\", "
                "\"explore_percent\": %u, \"coverage_ppm\": %u, "
                "\"rank_by\": \"%s\", \"total_addresses\": %llu, "
                "\"planned_addresses\": %llu, \"reachable_target\": %llu, "
                "\"candidate_capacity\": %llu, \"finalist_limit\": %llu, "
                "\"finalists_all\": %s, \"output_limit\": %llu, "
                "\"output_all\": %s, \"scan_concurrency\": %u, "
                "\"verify_concurrency\": %u, \"stability_concurrency\": %u, "
                "\"verification_batch_size\": %u, \"memory_budget_bytes\": %llu, "
                "\"estimated_candidate_bytes\": %llu, "
                "\"estimated_verifier_bytes\": %llu, "
                "\"estimated_working_bytes\": %llu, "
                "\"estimated_total_bytes\": %llu, \"fd_limit\": %llu, "
                "\"estimated_fds\": %llu, \"representative\": %s, "
                "\"exact_full\": %s, \"auto_adjusted\": %s},\n",
                plan->version, qn_scan_mode_str(plan->requested_mode),
                qn_scan_mode_str(plan->mode), qn_selection_str(plan->selection),
                plan->explore_percent, plan->coverage_ppm,
                qn_rank_policy_str(plan->rank_by),
                (unsigned long long)plan->total_addresses,
                (unsigned long long)plan->planned_addresses,
                (unsigned long long)plan->reachable_target,
                (unsigned long long)plan->candidate_capacity,
                (unsigned long long)plan->finalist_limit,
                plan->finalists_all ? "true" : "false",
                (unsigned long long)plan->output_limit,
                plan->output_all ? "true" : "false", plan->scan_concurrency,
                plan->verify_concurrency, plan->stability_concurrency,
                plan->verification_batch_size,
                (unsigned long long)plan->memory_budget_bytes,
                (unsigned long long)plan->estimated_candidate_bytes,
                (unsigned long long)plan->estimated_verifier_bytes,
                (unsigned long long)plan->estimated_working_bytes,
                (unsigned long long)plan->estimated_total_bytes,
                (unsigned long long)plan->fd_limit,
                (unsigned long long)plan->estimated_fds,
                plan->representative ? "true" : "false",
                plan->exact_full ? "true" : "false",
                plan->auto_adjusted ? "true" : "false");
        fprintf(f,
                "    \"accounting\": {\"claimed\": %llu, \"started\": %llu, "
                "\"completed\": %llu, \"skipped\": %llu, "
                "\"unattempted\": %llu, \"cancelled\": %llu, "
                "\"failed_locally\": %llu, \"reachable\": %u, "
                "\"tls_capable\": %u, \"retained_candidates\": %u, "
                "\"candidate_dropped\": %llu, \"candidate_replaced\": %llu, "
                "\"late_reachable_discarded\": %llu, "
                "\"candidate_truncated\": %s, \"finalists_queued\": %u, "
                "\"calibration_cohort\": %u, "
                "\"finalists_verified\": %u, \"verified_endpoints\": %u, "
                "\"output_results\": %u},\n",
                (unsigned long long)cf->sweep_stats.claimed,
                (unsigned long long)cf->sweep_stats.issued,
                (unsigned long long)cf->sweep_stats.completed,
                (unsigned long long)cf->sweep_stats.skipped,
                (unsigned long long)cf->sweep_stats.unattempted,
                (unsigned long long)cf->sweep_stats.cancelled,
                (unsigned long long)cf->sweep_stats.local_terminal_failures,
                cf->reached, cf->clean, cf->n,
                (unsigned long long)cf->candidate_dropped,
                (unsigned long long)cf->candidate_replaced,
                (unsigned long long)cf->late_reachable_discarded,
                cf->candidate_truncated ? "true" : "false", cf->nfinalist,
                cf->ncalibration,
                cf->verify_completed, cf->edges, output_n);
        fprintf(f, "    \"profile\": {\"version\": %u, \"requested\": ",
                profile ? profile->version : 0u);
        json_str(f, profile ? qn_tls_fp_str(profile->requested) : "unavailable");
        fprintf(f, ", \"resolved\": ");
        json_str(f, profile ? qn_tls_fp_str(profile->resolved) : "unavailable");
        fprintf(f, ", \"support\": ");
        json_str(f, profile ? qn_profile_support_str(profile->support) : "unavailable");
        fprintf(f, "},\n    \"score_version\": %u,\n", QN_SCORE_VERSION);
        fprintf(f, "    \"interference_suspected\": %u,\n"
                   "    \"inconclusive\": %u,\n    \"local_errors\": %u,\n"
                   "    \"confirmed_edges\": %u,\n",
                cf->suspected, cf->inconclusive, cf->local_errors, cf->edges);
        fprintf(f, "    \"operator\": ");
        json_str(f, cf->oper);
        fprintf(f, ",\n    \"seed\": %llu,\n",
                (unsigned long long)cf->cfg->effective_seed);
        fprintf(f, "    \"results\": [\n");
        uint32_t emitted = 0u;
        for (uint32_t i = 0; i < cf->n && emitted < output_n; i++) {
            const cf_record *r = &cf->rec[i];
            qn_classification classification = qn_cf_record_classification(r);
            if (!r->verified)
                continue;
            qn_addr_str(&r->addr, addr, sizeof addr);
            fprintf(f, "      {\"address\": ");
            json_str(f, addr);
            fprintf(f, ", \"verdict\": ");
            json_str(f, qn_classification_str(classification));
            fprintf(f, ", \"highest_rung_reached\": ");
            json_str(f, qn_highest_rung_str(classification.highest_rung_reached));
            fprintf(f, ", \"terminal_outcome\": ");
            json_str(f, qn_terminal_outcome_str(classification.terminal_outcome));
            fprintf(f,
                    ", \"rtt_min_us\": %u, \"rtt_median_us\": %u, \"rtt_p90_us\": %u, "
                    "\"rtt_median_ci90_us\": ",
                    r->rtt_min_us, r->rtt_med_us, r->rtt_p90_us);
            if (r->rtt_ci90_valid)
                fprintf(f, "[%u, %u]", r->rtt_ci90_lo_us, r->rtt_ci90_hi_us);
            else
                fprintf(f, "null");
            fprintf(f,
                    ", \"samples\": %u, \"mean_consecutive_rtt_delta_us\": %u, "
                    "\"loss_pct\": %u, \"colo\": ",
                    r->samples.n, r->rtt_delta_mean_us, r->loss_pct);
            json_str(f, r->colo);
            fprintf(f,
                    ", \"http_status\": %u, \"score\": %u, \"score_version\": %u, "
                    "\"score_components\": {\"edge\": %u, \"latency\": %u, "
                    "\"stability\": %u, \"confidence\": %u, \"throughput\": %u}, "
                    "\"confidence\": %u, "
                    "\"verification_completed\": %s, \"failure_origin\": ",
                    r->http_status, r->score, r->score_version, r->score_edge,
                    r->score_latency, r->score_stability, r->score_confidence,
                    r->score_throughput, r->confidence,
                    r->verified ? "true" : "false");
            json_str(f, qn_failure_origin_str((qn_failure_origin)r->failure_origin));
            fprintf(f, ", \"transport_result\": ");
            json_str(f, qn_result_str((qn_result)r->transport_result));
            fprintf(f, ", \"tls_outcome\": ");
            json_str(f, qn_tls_outcome_str((qn_tls_outcome)r->tls_outcome));
            fprintf(f,
                    ", \"sys_errno\": %d, \"tls_version\": %u, \"tls_suite\": %u, "
                    "\"handshake_us\": %u, \"ttfb_us\": %u, \"bytes\": %llu, "
                    "\"kbps\": %u, \"idle_held_ms\": %u, \"alpn\": ",
                    r->sys_errno, r->tls_version, r->tls_suite, r->handshake_us, r->ttfb_us,
                    (unsigned long long)r->bytes, r->kbps, r->idle_held_ms);
            json_str(f, r->alpn);
            fprintf(f, ", \"reason\": ");
            json_str(f, r->verify_reason);
            emitted++;
            fprintf(f, "}%s\n", emitted < output_n ? "," : "");
        }
        fprintf(f, "    ]\n  },\n");
    }

    if (ps && ps->cfg) {
        fprintf(f, "  \"ports\": {\n    \"target\": ");
        json_str(f, ps->target_str);
        fprintf(f, ",\n    \"scanned\": %u,\n    \"closed\": %u,\n    \"filtered\": %u,\n",
                ps->nports, ps->refused, ps->filtered);
        fprintf(f, "    \"open\": [\n");
        for (uint32_t i = 0; i < ps->nopen; i++) {
            const port_record *r = &ps->open[i];
            fprintf(f, "      {\"port\": %u, \"service\": ", r->port);
            json_str(f, qn_service_name(r->port));
            fprintf(f, ", \"rtt_us\": %u, \"banner\": ", r->rtt_us);
            json_str(f, r->banner);
            fprintf(f, "}%s\n", i + 1 < ps->nopen ? "," : "");
        }
        fprintf(f, "    ]\n  },\n");
    }

    if (hd && hd->cfg) {
        bool icmp_requested = hd->cfg->discover_method != QN_DISCOVER_TCP;

        fprintf(f, "  \"hosts\": {\n    \"prefix\": ");
        json_str(f, hd->prefix_str);
        fprintf(f,
                ",\n    \"icmp\": {\"requested\": %s, \"outcome\": ",
                icmp_requested ? "true" : "false");
        if (icmp_requested)
            json_str(f, qn_run_outcome_str(hd->icmp_outcome));
        else
            fprintf(f, "null");
        fprintf(f,
                ", \"errno\": %d, \"available\": %s, \"attempted\": %u, "
                "\"replied\": %u, \"rejected\": %u, \"unsent\": %u, "
                "\"hosts_found\": %u},\n    \"tcp\": {\"attempted\": %u, "
                "\"completed\": %u},\n    \"found\": [\n",
                icmp_requested ? hd->icmp_errno : 0,
                hd->icmp_ok ? "true" : "false", hd->icmp_attempted,
                hd->icmp_replied, hd->icmp_rejected, hd->icmp_unsent,
                hd->icmp_found, hd->tcp_attempted, hd->tcp_completed);
        for (uint32_t i = 0; i < hd->n; i++) {
            const host_record *r = &hd->host[i];
            qn_addr_str(&r->addr, addr, sizeof addr);
            fprintf(f, "      {\"address\": \"%s\", \"rtt_us\": %u, \"first_answer\": %u}%s\n",
                    addr, r->rtt_us, r->open_hint, i + 1 < hd->n ? "," : "");
        }
        fprintf(f, "    ]\n  },\n");
    }

    if (has_netinfo(ni)) {
        fprintf(f, "  \"network\": {\n");
        if (ni->has_gateway) {
            qn_addr_str(&ni->gateway, addr, sizeof addr);
            fprintf(f, "    \"gateway\": ");
            json_str(f, addr);
            fprintf(f, ",\n");
        }
        if (ni->has_public) {
            qn_addr_str(&ni->public_v4, addr, sizeof addr);
            fprintf(f, "    \"public_address\": ");
            json_str(f, addr);
            fprintf(f, ",\n    \"colo\": ");
            json_str(f, ni->public_colo);
            fprintf(f, ",\n");
        }
        fprintf(f, "    \"gateway_rtt_us\": %u,\n    \"internet_rtt_us\": %u,\n",
                ni->gw_rtt_us, ni->inet_rtt_us);
        fprintf(f, "    \"dns_rtt_us\": %u,\n    \"gateway_state\": \"%s\",\n"
                   "    \"internet_state\": \"%s\",\n    \"public_state\": \"%s\",\n"
                   "    \"dns_state\": \"%s\",\n"
                   "    \"dns_divergent\": %s,\n    \"captive_state\": \"%s\",\n"
                   "    \"captive_portal\": %s\n",
                ni->dns_rtt_us, qn_diag_state_str((qn_diag_state)ni->gateway_state),
                qn_diag_state_str((qn_diag_state)ni->internet_state),
                qn_diag_state_str((qn_diag_state)ni->public_state),
                qn_diag_state_str((qn_diag_state)ni->dns_state),
                ni->dns_divergent ? "true" : "false",
                qn_diag_state_str((qn_diag_state)ni->captive_state),
                ni->captive_portal ? "true" : "false");
        fprintf(f, "  },\n");
    }

    fprintf(f, "  \"schema\": %u\n}\n", QN_EXPORT_SCHEMA);
    return output_outcome(output_finish(&output));
}

qn_run_outcome qn_export_csv(const char *path, const cf_scan *cf,
                             const port_scan *ps, const host_discover *hd)
{
    qn_output output;
    FILE     *f;
    char      addr[QN_ADDRSTRLEN];

    if (!path || !*path || !valid_sources(cf, ps, hd))
        return QN_RUN_FAILED;
    if (!output_open(&output, path, false))
        return QN_RUN_INCOMPLETE;
    f = output.f;

    if (cf && cf->cfg) {
        uint32_t output_n = cf_output_count(cf);

        fprintf(f, "kind,address,verdict,highest_rung_reached,terminal_outcome,"
                   "rtt_min_us,rtt_median_us,rtt_p90_us,rtt_ci90_lo_us,"
                   "rtt_ci90_hi_us,mean_consecutive_rtt_delta_us,loss_pct,colo,score,"
                   "score_version,score_edge,score_latency,score_stability,"
                   "score_confidence,score_throughput\n");
        uint32_t emitted = 0u;
        for (uint32_t i = 0; i < cf->n && emitted < output_n; i++) {
            const cf_record *r = &cf->rec[i];
            qn_classification classification = qn_cf_record_classification(r);
            if (!r->verified)
                continue;
            qn_addr_str(&r->addr, addr, sizeof addr);
            fprintf(f, "cloudflare,%s,%s,%s,%s,%u,%u,%u,", addr,
                    qn_classification_str(classification),
                    qn_highest_rung_str(classification.highest_rung_reached),
                    qn_terminal_outcome_str(classification.terminal_outcome),
                    r->rtt_min_us,
                    r->rtt_med_us, r->rtt_p90_us);
            if (r->rtt_ci90_valid)
                fprintf(f, "%u,%u,", r->rtt_ci90_lo_us, r->rtt_ci90_hi_us);
            else
                fprintf(f, ",,");
            fprintf(f, "%u,%u,%s,%u,%u,%u,%u,%u,%u,%u\n",
                    r->rtt_delta_mean_us, r->loss_pct,
                    r->colo[0] ? r->colo : "", r->score, r->score_version,
                    r->score_edge, r->score_latency, r->score_stability,
                    r->score_confidence, r->score_throughput);
            emitted++;
        }
    }

    if (ps && ps->cfg) {
        fprintf(f, "kind,target,port,service,rtt_us,banner\n");
        for (uint32_t i = 0; i < ps->nopen; i++) {
            const port_record *r = &ps->open[i];
            fprintf(f, "port,");
            csv_str(f, ps->target_str, false);
            fprintf(f, ",%u,", r->port);
            csv_str(f, qn_service_name(r->port), false);
            fprintf(f, ",%u,", r->rtt_us);
            csv_str(f, r->banner, true);
            fputc('\n', f);
        }
    }

    if (hd && hd->cfg) {
        fprintf(f, "kind,address,rtt_us,first_answer\n");
        for (uint32_t i = 0; i < hd->n; i++) {
            const host_record *r = &hd->host[i];
            qn_addr_str(&r->addr, addr, sizeof addr);
            fprintf(f, "host,%s,%u,%u\n", addr, r->rtt_us, r->open_hint);
        }
    }

    return output_outcome(output_finish(&output));
}

typedef enum { XP_LIST = 0, XP_XRAY, XP_SINGBOX } xp_fmt;

bool qn_export_fmt_parse(const char *s, uint8_t *out)
{
    if (!s || !out)
        return false;
    if (!strcmp(s, "list"))
        *out = XP_LIST;
    else if (!strcmp(s, "xray"))
        *out = XP_XRAY;
    else if (!strcmp(s, "singbox") || !strcmp(s, "sing-box"))
        *out = XP_SINGBOX;
    else
        return false;
    return true;
}

static bool config_exportable(const cf_record *record)
{
    return record && record->verified &&
           qn_classification_has_marker(qn_cf_record_classification(record));
}

static uint32_t config_export_count(const cf_scan *cf)
{
    uint32_t count = 0u;
    uint64_t limit = cf && cf->cfg && cf->cfg->scan_plan.valid
                         ? cf->cfg->scan_plan.output_limit
                         : (cf ? cf->n : 0u);

    for (uint32_t i = 0u; cf && i < cf->n && count < limit; i++)
        if (config_exportable(&cf->rec[i]))
            count++;
    return count;
}

qn_run_outcome qn_export_config(const char *path, uint8_t fmt, const cf_scan *cf)
{
    const char      *sni, *template_sni, *fp;
    char             addr[QN_ADDRSTRLEN];
    qn_output        output;
    FILE            *f;
    uint32_t         n, emitted;

    if (!cf || !cf->cfg || cf->n > cf->cap || (cf->n && !cf->rec) || fmt > XP_SINGBOX ||
        cf->cfg->fingerprint >= QN_TLS_FP_COUNT)
        return QN_RUN_FAILED;

    n   = config_export_count(cf);
    sni = cf->cfg->sni ? cf->cfg->sni : "www.cloudflare.com";
    template_sni = strcmp(sni, "www.cloudflare.com") ? sni : "REPLACE_SNI";
    fp  = qn_tls_fp_str((qn_tls_fp)cf->cfg->fingerprint);
    if (!qn_valid_hostname(sni))
        return QN_RUN_FAILED;

    if (!output_open(&output, path, true))
        return QN_RUN_INCOMPLETE;
    f = output.f;

    if (!n) {
        if (fmt == XP_LIST)
            fprintf(f, "# no verified address exposed a Cloudflare marker; nothing to export\n");
        else
            fprintf(f,
                    "{\n  \"_comment\": \"no verified address exposed a Cloudflare marker\",\n"
                    "  \"outbounds\": []\n}\n");
        return output_outcome(output_finish(&output));
    }

    if (fmt == XP_LIST) {
        fprintf(f, "# qanat build %s: %s, fingerprint %s, %s\n",
                QN_BUILD_FINGERPRINT, sni, fp,
                cf->cfg->scan_plan.exact_full
                    ? "best observed after complete loaded range set"
                    : "best observed among scanned addresses");
        emitted = 0u;
        for (uint32_t i = 0u; i < cf->n && emitted < n; i++) {
            const cf_record *record = &cf->rec[i];

            if (!config_exportable(record))
                continue;
            qn_addr_str(&record->addr, addr, sizeof addr);
            fprintf(f, "%s\t%s\t%uus\tconf=%u\n", addr,
                    qn_classification_str(qn_cf_record_classification(record)),
                    record->rtt_med_us, record->confidence);
            emitted++;
        }
        return output_outcome(output_finish(&output));
    }

    /* Preserve measured fields while forcing the default public SNI to be replaced. */
    if (fmt == XP_XRAY) {
        fprintf(f, "{\n  \"_comment\": \"qanat export: replace REPLACE_* with your own\",\n");
        fprintf(f, "  \"_build_fingerprint\": \"" QN_BUILD_FINGERPRINT "\",\n");
        fprintf(f, "  \"outbounds\": [\n");
        emitted = 0u;
        for (uint32_t i = 0u; i < cf->n && emitted < n; i++) {
            const cf_record *record = &cf->rec[i];

            if (!config_exportable(record))
                continue;
            qn_addr_str(&record->addr, addr, sizeof addr);
            fprintf(f,
                    "    {\n"
                    "      \"tag\": \"qanat-%u\",\n"
                    "      \"protocol\": \"vless\",\n"
                    "      \"settings\": { \"vnext\": [ { \"address\": ",
                    emitted);
            json_str(f, addr);
            fprintf(f,
                    ", \"port\": 443,\n"
                    "        \"users\": [ { \"id\": \"REPLACE_UUID\", \"encryption\": \"none\","
                    " \"flow\": \"\" } ] } ] },\n"
                    "      \"streamSettings\": {\n"
                    "        \"network\": \"ws\",\n"
                    "        \"security\": \"tls\",\n"
                    "        \"tlsSettings\": { \"serverName\": ");
            json_str(f, template_sni);
            fprintf(f, ", \"fingerprint\": ");
            json_str(f, fp);
            fprintf(f,
                    ", \"allowInsecure\": false },\n"
                    "        \"wsSettings\": { \"path\": \"REPLACE_PATH\","
                    " \"headers\": { \"Host\": ");
            json_str(f, template_sni);
            fprintf(f, " } }\n      }\n    }%s\n", emitted + 1u < n ? "," : "");
            emitted++;
        }
        fprintf(f, "  ]\n}\n");
        return output_outcome(output_finish(&output));
    }

    fprintf(f, "{\n  \"_comment\": \"qanat export: replace REPLACE_* with your own\",\n");
    fprintf(f, "  \"_build_fingerprint\": \"" QN_BUILD_FINGERPRINT "\",\n");
    fprintf(f, "  \"outbounds\": [\n");
    emitted = 0u;
    for (uint32_t i = 0u; i < cf->n && emitted < n; i++) {
        const cf_record *record = &cf->rec[i];

        if (!config_exportable(record))
            continue;
        qn_addr_str(&record->addr, addr, sizeof addr);
        fprintf(f,
                "    {\n"
                "      \"type\": \"vless\",\n"
                "      \"tag\": \"qanat-%u\",\n"
                "      \"server\": ",
                emitted);
        json_str(f, addr);
        fprintf(f,
                ",\n      \"server_port\": 443,\n"
                "      \"uuid\": \"REPLACE_UUID\",\n"
                "      \"tls\": { \"enabled\": true, \"server_name\": ");
        json_str(f, template_sni);
        fprintf(f, ",\n        \"utls\": { \"enabled\": true, \"fingerprint\": ");
        json_str(f, fp);
        fprintf(f,
                " } },\n"
                "      \"transport\": { \"type\": \"ws\", \"path\": \"REPLACE_PATH\","
                " \"headers\": { \"Host\": ");
        json_str(f, template_sni);
        fprintf(f, " } }\n    }%s\n", emitted + 1u < n ? "," : "");
        emitted++;
    }
    fprintf(f, "  ]\n}\n");
    return output_outcome(output_finish(&output));
}
