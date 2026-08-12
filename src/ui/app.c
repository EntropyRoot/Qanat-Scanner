#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/ui.h"

#include "qanat/profile.h"
#include "qanat/task.h"
#include "qanat/verify.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FRAME_MS      33
#define POLL_BUDGET   8192
#define ARENA_BYTES   (48u << 20)

typedef enum { BG_NONE = 0, BG_NETINFO, BG_ICMP, BG_CF_VERIFY } bg_kind;

struct qn_app {
    qn_config   *cfg;
    qn_term      term;
    qn_screen    scr;
    qn_input     input;
    qn_topology  topo;
    qn_engine    eng;
    qn_arena     arena;

    qn_view view;
    bool    quit;
    bool    engine_ready;
    bool    engine_live;
    bool    scan_done;
    bool    waiting_bg;
    bool    detail_open;
    bool    cf_prepared;
    bool    cf_launched;
    bool    plan_confirm_pending;
    bool    plan_request_changed;
    /* The same outcome as headless; the exit code derives only from this value. */
    qn_run_outcome outcome;

    cf_scan       cf;
    port_scan     ps;
    host_discover hd;
    qn_netinfo    ni;
    qn_profile_instance profile_instance;
    _Atomic bool  ni_ready;

    pthread_t       bg_tid;
    bool            bg_joinable;
    _Atomic int     bg_kind;
    _Atomic bool    bg_busy;
    _Atomic int     bg_result;
    _Atomic bool    bg_cancel;
    _Atomic size_t  verify_done;
    _Atomic size_t  verify_total;

    qn_spark spark;
    qn_scan_editor plan_editor;
    uint32_t sel, scroll;
    uint64_t t_start_ms;
    uint64_t last_spark_ms;
    uint64_t last_thermal_ms;
    uint64_t last_frame_ms;
    uint32_t thermal_mc;
    char     status[160];
};

static void status(qn_app *a, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->status, sizeof a->status, fmt, ap);
    va_end(ap);
}

static uint32_t verdict_color(const cf_record *record)
{
    const qn_theme *t = qn_theme_get();
    qn_classification classification = qn_cf_record_classification(record);

    if (classification.terminal_outcome != QN_TERM_SUCCESS) {
        switch (classification.terminal_outcome) {
        case QN_TERM_LOCAL_ERROR:
        case QN_TERM_PROTOCOL_INVALID:
        case QN_TERM_INTERFERENCE:
            return t->bad;
        case QN_TERM_NONE:
            return t->faint;
        default:
            return t->warn;
        }
    }
    switch (classification.highest_rung_reached) {
    case QN_RUNG_STABLE:
    case QN_RUNG_FLOWING:
    case QN_RUNG_EDGE:
        return t->good;
    case QN_RUNG_TLS:
    case QN_RUNG_HTTP:
        return t->info;
    case QN_RUNG_TCP:
        return t->warn;
    default:
        return t->faint;
    }
}

static bool cf_verifying(const qn_app *a)
{
    return atomic_load_explicit(&a->bg_busy, memory_order_acquire) &&
           atomic_load_explicit(&a->bg_kind, memory_order_relaxed) == BG_CF_VERIFY;
}

static const cf_record *cf_display_records(const qn_app *a, uint32_t *n)
{
    *n = a->cf.n;
    return a->cf.rec;
}

static uint32_t rows_in_view(const qn_app *a)
{
    switch (a->view) {
    case QN_VIEW_CF: {
        uint32_t n;
        (void)cf_display_records(a, &n);
        return n;
    }
    case QN_VIEW_PORTS: return a->ps.nopen;
    case QN_VIEW_HOSTS: return a->waiting_bg ? 0u : a->hd.n;
    default:            return 0;
    }
}

static void *bg_main(void *arg)
{
    qn_app *a = (qn_app *)arg;

    switch (atomic_load(&a->bg_kind)) {
    case BG_NETINFO:
        qn_netinfo_collect(&a->ni, a->cfg->timeout_ms);
        atomic_store(&a->ni_ready, true);
        break;
    case BG_ICMP:
        atomic_store_explicit(&a->bg_result,
                              (int)host_discover_icmp(&a->hd, 900),
                              memory_order_release);
        break;
    case BG_CF_VERIFY: {
        bool ok = cf_scan_verify(&a->cf);
        qn_run_outcome outcome = ok
                                     ? QN_RUN_SUCCESS
                                     : qn_verify_run_outcome(
                                           (qn_verify_state)a->cf.verify_state);

        cf_scan_finish(&a->cf);
        if (atomic_load_explicit(&a->bg_cancel, memory_order_acquire))
            outcome = QN_RUN_CANCELLED;
        atomic_store_explicit(&a->bg_result, (int)outcome, memory_order_release);
        break;
    }
    default:
        break;
    }
    atomic_store(&a->bg_busy, false);
    return NULL;
}

static void bg_reap(qn_app *a)
{
    if (a->bg_joinable && !atomic_load(&a->bg_busy)) {
        pthread_join(a->bg_tid, NULL);
        a->bg_joinable = false;
    }
}

static bool bg_start(qn_app *a, bg_kind k)
{
    int error;

    bg_reap(a);
    if (atomic_load(&a->bg_busy))
        return false;
    atomic_store_explicit(&a->bg_result, 0, memory_order_relaxed);
    atomic_store(&a->bg_kind, (int)k);
    atomic_store(&a->bg_busy, true);
    error = pthread_create(&a->bg_tid, NULL, bg_main, a);
    if (error != 0) {
        atomic_store_explicit(&a->bg_result, -error, memory_order_release);
        atomic_store(&a->bg_busy, false);
        return false;
    }
    a->bg_joinable = true;
    return true;
}

static void finish_scan_results(qn_app *a)
{
    switch (a->cfg->mode) {
    case QN_MODE_CF:       cf_scan_finish(&a->cf); break;
    case QN_MODE_PORTS:    port_scan_finish(&a->ps); break;
    case QN_MODE_DISCOVER: host_discover_finish(&a->hd); break;
    default: break;
    }
    a->engine_live = false;
    a->scan_done = true;
}

static bool finalize_engine_phase(qn_app *a, bool cancel)
{
    qn_engine_finalization final;

    if (!a->engine_live)
        return true;
    qn_engine_finalize(&a->eng, cancel, &final);
    if (a->cfg->mode == QN_MODE_CF)
        cf_scan_account_phase(&a->cf, &final);
    a->engine_live = false;
    a->outcome = qn_run_outcome_worst(a->outcome, final.outcome);
    if (final.failed) {
        finish_scan_results(a);
        status(a, "engine worker %u failed: %s", final.fatal_worker,
               strerror(final.fatal_errno ? final.fatal_errno : EIO));
        return false;
    }
    if (final.stats.events_dropped) {
        finish_scan_results(a);
        status(a, "result queue overflowed (%llu records)",
               (unsigned long long)final.stats.events_dropped);
        return false;
    }
    if (!final.accounted) {
        finish_scan_results(a);
        status(a, "phase lost %llu of %llu claimed jobs",
               (unsigned long long)final.missing,
               (unsigned long long)final.stats.claimed);
        return false;
    }
    if (final.stats.local_terminal_failures) {
        finish_scan_results(a);
        status(a, "phase had %llu terminal local failure(s)",
               (unsigned long long)final.stats.local_terminal_failures);
        return false;
    }
    if (final.stats.status == QN_ENGINE_STOPPED)
        status(a, "stop condition met after %llu of %llu",
               (unsigned long long)final.stats.completed,
               (unsigned long long)final.stats.claimed);
    if (cancel)
        finish_scan_results(a);
    return true;
}

static bool advance_phase(qn_app *a)
{
    const qn_task *t = NULL;

    switch (a->cfg->mode) {
    case QN_MODE_CF:
        if (cf_scan_next_phase(&a->cf))
            t = &a->cf.task;
        break;
    case QN_MODE_PORTS:
        if (port_scan_next_phase(&a->ps))
            t = &a->ps.task;
        break;
    case QN_MODE_DISCOVER:
        if (host_discover_next_phase(&a->hd))
            t = &a->hd.task;
        break;
    default:
        break;
    }

    if (!t) {
        if (a->cfg->mode == QN_MODE_CF) {
            a->engine_live = false;
            atomic_store_explicit(&a->verify_done, 0u, memory_order_relaxed);
            atomic_store_explicit(&a->verify_total, 0u, memory_order_relaxed);
            if (a->cf.n) {
                pthread_mutex_lock(&a->cf.records_lock);
                for (uint32_t i = 0; i < a->cf.n; i++)
                    qn_cf_finalize_rank(&a->cf.rec[i], a->cfg->scan_plan.rank_by);
                pthread_mutex_unlock(&a->cf.records_lock);
            }
            if (bg_start(a, BG_CF_VERIFY)) {
                a->waiting_bg = true;
                status(a, "verifying finalists with full TLS and HTTPS");
                return true;
            }
            cf_scan_finish(&a->cf);
            a->scan_done = true;
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
            status(a, "could not start full verification");
            return false;
        }
        finish_scan_results(a);
        status(a, "scan complete in %.1fs", (double)(qn_now_ms() - a->t_start_ms) / 1000.0);
        return false;
    }

    if (!qn_engine_start(&a->eng, t)) {
        a->engine_live = false;
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, "engine failed to start");
        return false;
    }
    a->engine_live = true;
    status(a, "phase: %s", t->label ? t->label : "?");
    return true;
}

static void reset_scan_state(qn_app *a)
{
    if (a->engine_ready) {
        qn_engine_destroy(&a->eng);
        a->engine_ready = false;
    }
    cf_scan_destroy(&a->cf);
    memset(&a->cf, 0, sizeof a->cf);
    qn_arena_reset(&a->arena);
    a->scan_done  = false;
    a->waiting_bg = false;
    a->detail_open = false;
    a->cf_prepared = false;
    a->cf_launched = false;
    a->plan_confirm_pending = false;
    a->sel        = 0;
    a->scroll     = 0;
    qn_spark_reset(&a->spark);
    atomic_store_explicit(&a->bg_cancel, false, memory_order_release);
    atomic_store_explicit(&a->verify_done, 0u, memory_order_relaxed);
    atomic_store_explicit(&a->verify_total, 0u, memory_order_relaxed);
}

static void discard_unlaunched_plan(qn_app *a)
{
    if (!a->cf_prepared || a->cf_launched)
        return;
    cf_scan_destroy(&a->cf);
    memset(&a->cf, 0, sizeof a->cf);
    qn_arena_reset(&a->arena);
    a->cf_prepared = false;
    a->plan_confirm_pending = false;
    a->cfg->scan_plan_valid = false;
    a->cfg->profile_instance = NULL;
}

static bool prepare_cf_scan(qn_app *a)
{
    char error[192];

    if (!qn_scan_request_validate(&a->cfg->scan, error, sizeof error)) {
        status(a, "%s", error);
        return false;
    }
    reset_scan_state(a);
    a->outcome = QN_RUN_SUCCESS;
    a->cfg->scan_plan_valid = false;
    memset(&a->cfg->scan_plan, 0, sizeof a->cfg->scan_plan);
    if (!qn_profile_instance_init(
            &a->profile_instance, (qn_tls_fp)a->cfg->fingerprint,
            qn_profile_seed_from_run(a->cfg->effective_seed),
            a->cfg->sni, true, a->cfg->cert_strict)) {
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, "client profile is unsupported by this build");
        return false;
    }
    a->cfg->profile_instance = &a->profile_instance;
    if (!cf_scan_init(&a->cf, &a->arena, a->cfg)) {
        cf_scan_destroy(&a->cf);
        memset(&a->cf, 0, sizeof a->cf);
        qn_arena_reset(&a->arena);
        a->cfg->profile_instance = NULL;
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, a->cfg->scan_plan.error[0]
                      ? "resource plan rejected: %s"
                      : "range snapshot or resource plan could not be prepared",
               a->cfg->scan_plan.error);
        return false;
    }
    a->cf.cancel       = &a->bg_cancel;
    a->cf.verify_done  = &a->verify_done;
    a->cf.verify_total = &a->verify_total;
    a->cf_prepared = true;
    a->cf_launched = false;
    a->plan_confirm_pending = true;
    a->plan_request_changed = false;
    a->view = QN_VIEW_PLAN;
    status(a, a->cfg->scan_plan.exact_full
                  ? "full range plan ready; press Enter again to confirm all addresses"
                  : "resource plan ready; press Enter again to start");
    return true;
}

static bool launch_cf_scan(qn_app *a)
{
    if (!a->cf_prepared || a->cf_launched || !a->plan_confirm_pending) {
        status(a, "review the effective resource plan before starting");
        return false;
    }
    if (!qn_engine_init(&a->eng, a->cfg, &a->topo)) {
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, "engine resource plan rejected: %s",
               strerror(a->eng.init_errno ? a->eng.init_errno : EIO));
        return false;
    }
    a->engine_ready = true;
    a->cf_launched = true;
    a->plan_confirm_pending = false;
    a->t_start_ms = qn_now_ms();
    qn_engine_warm_radio(a->cfg);
    a->view = QN_VIEW_CF;
    return advance_phase(a);
}

static bool start_non_cf_scan(qn_app *a)
{
    reset_scan_state(a);
    a->outcome = QN_RUN_SUCCESS;
    a->t_start_ms = qn_now_ms();

    switch (a->cfg->mode) {
    case QN_MODE_PORTS:
        if (!port_scan_init(&a->ps, &a->arena, a->cfg)) {
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
            status(a, "could not resolve '%s' or parse the port list",
                   a->cfg->target ? a->cfg->target : "(none)");
            return false;
        }
        break;
    case QN_MODE_DISCOVER:
        if (!host_discover_init(&a->hd, &a->arena, a->cfg)) {
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
            status(a, "no local prefix to sweep (pass one as the target, /16 or narrower)");
            return false;
        }
        a->hd.cancel = &a->bg_cancel;
        break;
    default:
        return false;
    }

    if (!qn_engine_init(&a->eng, a->cfg, &a->topo)) {
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, "engine resource plan rejected: %s",
               strerror(a->eng.init_errno ? a->eng.init_errno : EIO));
        return false;
    }
    a->engine_ready = true;
    if (a->cfg->mode == QN_MODE_DISCOVER &&
        a->cfg->discover_method != QN_DISCOVER_TCP) {
        if (bg_start(a, BG_ICMP)) {
            a->waiting_bg = true;
            status(a, a->cfg->discover_method == QN_DISCOVER_ICMP
                          ? "probing ICMP"
                          : "probing ICMP before the TCP phase");
            return true;
        }
        a->hd.icmp_outcome = QN_RUN_FAILED;
        a->hd.icmp_errno = -atomic_load_explicit(&a->bg_result, memory_order_acquire);
        if (a->cfg->discover_method != QN_DISCOVER_AUTO)
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        if (a->cfg->discover_method == QN_DISCOVER_ICMP) {
            finish_scan_results(a);
            status(a, "could not start ICMP worker: %s",
                   strerror(a->hd.icmp_errno ? a->hd.icmp_errno : EIO));
            return false;
        }
    }

    if (a->cfg->mode != QN_MODE_DISCOVER)
        qn_engine_warm_radio(a->cfg);
    return advance_phase(a);
}

static bool start_scan(qn_app *a)
{
    bg_reap(a);
    if (a->engine_live || atomic_load(&a->bg_busy)) {
        status(a, "background work is still active");
        return false;
    }
    if (a->cfg->mode == QN_MODE_CF)
        return a->plan_confirm_pending ? launch_cf_scan(a) : prepare_cf_scan(a);
    return start_non_cf_scan(a);
}

static void pump(qn_app *a)
{
    bg_reap(a);
    if (a->waiting_bg && !atomic_load_explicit(&a->bg_busy, memory_order_acquire)) {
        bg_kind completed =
            (bg_kind)atomic_load_explicit(&a->bg_kind, memory_order_acquire);

        a->waiting_bg = false;
        if (completed == BG_CF_VERIFY) {
            qn_run_outcome result =
                (qn_run_outcome)atomic_load_explicit(&a->bg_result,
                                                     memory_order_acquire);

            a->scan_done = true;
            a->outcome = qn_run_outcome_worst(a->outcome, result);
            if (result == QN_RUN_CANCELLED) {
                status(a, "verification cancelled; preliminary results kept");
            } else if (result == QN_RUN_INCOMPLETE) {
                status(a, "verification incomplete after %u/%u results; preliminary results kept",
                       a->cf.verify_completed, a->cf.verify_attempted);
            } else if (result == QN_RUN_FAILED) {
                status(a, "verifier infrastructure failure (%s); preliminary results kept",
                       strerror(a->cf.verify_errno ? a->cf.verify_errno : EIO));
            } else if (a->cf.io_warn[0]) {
                a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_INCOMPLETE);
                status(a, "%s", a->cf.io_warn); /* a file we promised to write */
            } else
                status(a, "scan complete in %.1fs",
                       (double)(qn_now_ms() - a->t_start_ms) / 1000.0);
        } else if (completed == BG_ICMP) {
            qn_run_outcome icmp =
                (qn_run_outcome)atomic_load_explicit(&a->bg_result,
                                                     memory_order_acquire);

            if (icmp == QN_RUN_CANCELLED ||
                a->cfg->discover_method != QN_DISCOVER_AUTO)
                a->outcome = qn_run_outcome_worst(a->outcome, icmp);
            if (a->cfg->discover_method == QN_DISCOVER_ICMP) {
                finish_scan_results(a);
                if (icmp == QN_RUN_SUCCESS)
                    status(a, "ICMP discovery complete: %u hosts", a->hd.icmp_found);
                else if (icmp == QN_RUN_CANCELLED)
                    status(a, "ICMP discovery cancelled");
                else if (icmp == QN_RUN_INCOMPLETE)
                    status(a, "ICMP discovery incomplete: %u probes unsent",
                           a->hd.icmp_unsent);
                else
                    status(a, "ICMP discovery failed: %s",
                           strerror(a->hd.icmp_errno ? a->hd.icmp_errno : EIO));
            } else if (icmp == QN_RUN_CANCELLED) {
                finish_scan_results(a);
                status(a, "ICMP discovery cancelled; TCP discovery was not started");
            } else {
                (void)advance_phase(a);
                if (icmp == QN_RUN_FAILED)
                    status(a, "ICMP failed (%s); TCP discovery continues",
                           strerror(a->hd.icmp_errno ? a->hd.icmp_errno : EIO));
                else if (icmp == QN_RUN_INCOMPLETE)
                    status(a, "ICMP left %u probes unsent; TCP discovery continues",
                           a->hd.icmp_unsent);
            }
        } else {
            advance_phase(a);
        }
    }
    if (!a->engine_live)
        return;

    qn_engine_poll(&a->eng, POLL_BUDGET);

    if (qn_engine_done(&a->eng)) {
        if (!finalize_engine_phase(a, false))
            return;
        advance_phase(a);
    }
}

static const char *mode_name(qn_mode m)
{
    switch (m) {
    case QN_MODE_CF:       return "cloudflare";
    case QN_MODE_PORTS:    return "ports";
    case QN_MODE_DISCOVER: return "discover";
    case QN_MODE_NETINFO:  return "network";
    default:               return "idle";
    }
}

static void draw_header(qn_app *a)
{
    const qn_theme *t = qn_theme_get();
    qn_screen      *s = &a->scr;
    char            buf[160];
    int             x;

    qn_fill(s, 0, 0, s->w, 1, ' ', t->head_fg, t->head_bg, 0);

    x = qn_text(s, 1, 0, QN_NAME, t->accent, t->head_bg, QN_ATTR_BOLD);
    x += 1;
    x += qn_text(s, x + 1, 0, QN_VERSION, t->faint, t->head_bg, 0) + 2;

    snprintf(buf, sizeof buf, "%s", mode_name(a->cfg->mode));
    x += qn_text(s, x, 0, buf, t->fg, t->head_bg, QN_ATTR_BOLD) + 2;

    if (a->topo.soc[0]) {
        snprintf(buf, sizeof buf, "%s", a->topo.soc);
        x += qn_text(s, x, 0, buf, t->dim, t->head_bg, 0) + 2;
    }

    snprintf(buf, sizeof buf, "%uw/%uc", a->eng.nworkers, a->eng.concurrency);
    x += qn_text(s, x, 0, buf, t->dim, t->head_bg, 0) + 2;

    if (a->thermal_mc) {
        uint32_t c   = a->thermal_mc / 1000u;
        uint32_t col = c >= 70 ? t->bad : (c >= 55 ? t->warn : t->dim);
        snprintf(buf, sizeof buf, "%uC", c);
        qn_text(s, x, 0, buf, col, t->head_bg, 0);
    }

    {
        uint64_t elapsed_ms = qn_now_ms() - a->t_start_ms;
        int      n = snprintf(buf, sizeof buf, "%" PRIu64 ".%us",
                              elapsed_ms / 1000u,
                              (unsigned)((elapsed_ms % 1000u) / 100u));

        if (n < 0)
            n = 0;
        qn_text(s, (int)s->w - n - 1, 0, buf, t->dim, t->head_bg, 0);
    }
}

static void draw_footer(qn_app *a)
{
    const qn_theme *t = qn_theme_get();
    qn_screen      *s = &a->scr;
    int             y = (int)s->h - 1;
    int             x;

    qn_fill(s, 0, y, s->w, 1, ' ', t->head_fg, t->head_bg, 0);

    x = 1;
    if (a->view == QN_VIEW_PLAN) {
        x += qn_text(s, x, y, "arrows", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " choose  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "type", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " custom  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "enter", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " edit/review  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "w/r", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " save/load  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "tab", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " view", t->dim, t->head_bg, 0);
    } else {
        x += qn_text(s, x, y, "1-7", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " view  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "s", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " plan/start  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "x", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " stop  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "e", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " export  ", t->dim, t->head_bg, 0);
        x += qn_text(s, x, y, "q", t->accent, t->head_bg, QN_ATTR_BOLD);
        x += qn_text(s, x, y, " quit", t->dim, t->head_bg, 0);
    }

    if (a->status[0]) {
        int n = (int)strlen(a->status);
        if (x + 2 < (int)s->w - n - 1)
            qn_textn(s, (int)s->w - n - 1, y, a->status, n, t->info, t->head_bg, 0);
    }
}

static void draw_tabs(qn_app *a, int y)
{
    static const char *names[QN_VIEW__COUNT] = { "dash", "cloudflare", "scan plan",
                                                 "ports", "hosts", "network", "help" };
    const qn_theme    *t                     = qn_theme_get();
    qn_screen         *s                     = &a->scr;
    int                x                     = 1;

    qn_fill(s, 0, y, s->w, 1, ' ', t->fg, t->bg, 0);
    for (int i = 0; i < QN_VIEW__COUNT; i++) {
        bool     on = (int)a->view == i;
        uint32_t fg = on ? t->sel_fg : t->faint;
        uint32_t bg = on ? t->sel_bg : t->bg;

        qn_put(s, x, y, ' ', fg, bg, 0);
        x += 1 + qn_text(s, x + 1, y, names[i], fg, bg, on ? QN_ATTR_BOLD : 0);
        qn_put(s, x, y, ' ', fg, bg, 0);
        x += 2;
    }
}

static void draw_progress_pair(qn_app *a, const qn_rect *box, int y,
                               const char *left_label, uint64_t left_value,
                               const char *right_label, uint64_t right_value,
                               uint32_t color)
{
    char left[32], right[32];
    int half = box->w / 2;

    qn_fmt_count(left_value, left, sizeof left);
    qn_fmt_count(right_value, right, sizeof right);
    qn_kv(&a->scr, box->x + 2, y, half - 3, left_label, left, color);
    qn_kv(&a->scr, box->x + half + 1, y, box->w - half - 3,
          right_label, right, color);
}

static void draw_dash(qn_app *a, qn_rect r)
{
    const qn_theme    *t = qn_theme_get();
    qn_screen         *s = &a->scr;
    qn_engine_snapshot sn;
    char               buf[96], b2[32];
    int                y;
    qn_rect            left, right;
    bool               verifying = cf_verifying(a);

    if (a->engine_ready)
        qn_engine_stats(&a->eng, &sn);
    else
        memset(&sn, 0, sizeof sn);

    left  = (qn_rect){ r.x, r.y, r.w / 2 - 1, 11 };
    right = (qn_rect){ r.x + r.w / 2, r.y, r.w - r.w / 2, 11 };

    qn_box(s, left, "engine", false);
    y = left.y + 1;

    qn_fmt_count(sn.completed, buf, sizeof buf);
    qn_kv(s, left.x + 2, y++, left.w - 4, "probes", buf, t->fg);

    snprintf(buf, sizeof buf, "%u/s", sn.rate_now);
    qn_kv(s, left.x + 2, y++, left.w - 4, "rate  ", buf, t->accent);

    snprintf(buf, sizeof buf, "%u  (%u in flight)", sn.window, sn.inflight);
    qn_kv(s, left.x + 2, y++, left.w - 4, "window", buf, t->info);

    snprintf(buf, sizeof buf, "%ums",
             a->engine_ready ? qn_engine_deadline_ms(&a->eng) : 0u);
    qn_kv(s, left.x + 2, y++, left.w - 4, "deadln", buf, t->dim);

    qn_fmt_count(sn.open, buf, sizeof buf);
    qn_kv(s, left.x + 2, y++, left.w - 4, "open  ", buf, t->good);

    qn_fmt_count(sn.timeout, buf, sizeof buf);
    qn_kv(s, left.x + 2, y++, left.w - 4, "silent", buf, t->faint);

    qn_fmt_count(sn.refused + sn.reset, buf, sizeof buf);
    qn_kv(s, left.x + 2, y++, left.w - 4, "reject", buf, t->warn);

    y++;
    qn_text(s, left.x + 2, y, "throughput", t->dim, t->panel, 0);
    qn_sparkline(s, (qn_rect){ left.x + 13, y, left.w - 15, 1 }, &a->spark, t->accent);

    qn_box(s, right, "progress", false);
    y = right.y + 1;

    {
        uint64_t domain;
        uint64_t completed;
        double   frac;
        unsigned pct_tenths;

        if (verifying) {
            completed = atomic_load_explicit(&a->verify_done, memory_order_acquire);
            domain = atomic_load_explicit(&a->verify_total, memory_order_acquire);
        } else {
            completed = sn.completed;
            domain = a->eng.task ? a->eng.task->domain : 0;
        }
        frac = domain ? (double)completed / (double)domain : 0.0;

        if (frac > 1.0)
            frac = 1.0;
        pct_tenths = (unsigned)(frac * 1000.0 + 0.5);

        snprintf(buf, sizeof buf, "%s", verifying
                                            ? "verify"
                                            : (a->engine_live && a->eng.task && a->eng.task->label
                                                   ? a->eng.task->label
                                                   : (a->scan_done ? "done" : "idle")));
        qn_kv(s, right.x + 2, y++, right.w - 4, "phase ", buf, t->accent2);

        qn_gauge(s, (qn_rect){ right.x + 2, y, right.w - 12, 1 }, frac, t->bar_fill, t->bar_track);
        snprintf(buf, sizeof buf, "%3u.%u%%", pct_tenths / 10u, pct_tenths % 10u);
        qn_text(s, right.x + right.w - 9, y, buf, t->fg, t->panel, QN_ATTR_BOLD);
        y += 2;
    }

    switch (a->cfg->mode) {
    case QN_MODE_CF:
        if (verifying) {
            size_t done  = atomic_load_explicit(&a->verify_done, memory_order_acquire);
            size_t total = atomic_load_explicit(&a->verify_total, memory_order_acquire);

            snprintf(buf, sizeof buf, "%zu / %zu", done, total);
            qn_kv(s, right.x + 2, y++, right.w - 4, "finalists ", buf, t->accent);
            qn_kv(s, right.x + 2, y++, right.w - 4, "protocol  ", "TLS + HTTPS", t->info);
            qn_kv(s, right.x + 2, y++, right.w - 4, "control   ", "x to cancel", t->warn);
            break;
        }
        if (a->cfg->scan_plan.mode == QN_SCAN_REACHABLE)
            snprintf(buf, sizeof buf, "%u / %llu", a->cf.reached,
                     (unsigned long long)a->cfg->scan_plan.reachable_target);
        else
            snprintf(buf, sizeof buf, "%u", a->cf.reached);
        qn_kv(s, right.x + 2, y++, right.w - 4, "reachable", buf, t->warn);
        snprintf(buf, sizeof buf, "%u", a->cf.clean);
        qn_kv(s, right.x + 2, y++, right.w - 4, "handshake", buf, t->good);
        snprintf(buf, sizeof buf, "%u", a->cf.suspected);
        qn_kv(s, right.x + 2, y++, right.w - 4, "suspected", buf, t->bad);
        snprintf(buf, sizeof buf, "%u", a->cf.edges);
        qn_kv(s, right.x + 2, y++, right.w - 4, "confirmed", buf, t->info);
        break;

    case QN_MODE_PORTS:
        qn_kv(s, right.x + 2, y++, right.w - 4, "target   ", a->ps.target_str, t->fg);
        snprintf(buf, sizeof buf, "%u", a->ps.nopen);
        qn_kv(s, right.x + 2, y++, right.w - 4, "open     ", buf, t->good);
        snprintf(buf, sizeof buf, "%u", a->ps.refused);
        qn_kv(s, right.x + 2, y++, right.w - 4, "closed   ", buf, t->warn);
        snprintf(buf, sizeof buf, "%u", a->ps.filtered);
        qn_kv(s, right.x + 2, y++, right.w - 4, "filtered ", buf, t->faint);
        break;

    case QN_MODE_DISCOVER:
        qn_kv(s, right.x + 2, y++, right.w - 4, "prefix   ", a->hd.prefix_str, t->fg);
        if (a->waiting_bg) {
            qn_kv(s, right.x + 2, y++, right.w - 4, "icmp     ", "probing", t->info);
        } else {
            snprintf(buf, sizeof buf, "%u", a->hd.n);
            qn_kv(s, right.x + 2, y++, right.w - 4, "hosts    ", buf, t->good);
            snprintf(buf, sizeof buf, "%s", a->hd.icmp_ok ? "yes" : "unavailable");
            qn_kv(s, right.x + 2, y++, right.w - 4, "icmp     ", buf,
                  a->hd.icmp_ok ? t->good : t->faint);
        }
        break;

    default:
        break;
    }

    {
        qn_rect hr = { r.x, r.y + 12, r.w, r.h - 12 };

        if (a->cfg->mode == QN_MODE_CF && hr.h >= 5) {
            qn_engine_snapshot sweep = a->cf.sweep_stats;
            uint64_t failed;
            uint64_t output;
            int row = hr.y + 1;

            if (a->engine_live && a->cf.phase == CF_PHASE_SWEEP)
                qn_engine_stats(&a->eng, &sweep);
            failed = sweep.local_terminal_failures + a->cf.local_errors;
            output = QN_MIN((uint64_t)a->cf.edges,
                            a->cfg->scan_plan_valid
                                ? a->cfg->scan_plan.output_limit
                                : (uint64_t)a->cf.edges);
            qn_box(s, hr, "scan accounting", false);
            draw_progress_pair(a, &hr, row++, "unique", a->cfg->scan_plan.total_addresses,
                               "planned", a->cfg->scan_plan.planned_addresses, t->fg);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "reserved", sweep.claimed,
                                   "started", sweep.issued, t->accent);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "completed", sweep.completed,
                                   "skipped", sweep.skipped, t->good);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "cancelled", sweep.cancelled,
                                   "local failed", failed, failed ? t->bad : t->dim);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "reachable", a->cf.reached,
                                   "TLS capable", a->cf.clean, t->info);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "retained", a->cf.n,
                                   "replacements", a->cf.candidate_replaced, t->warn);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row++, "calibration cohort", a->cf.ncalibration,
                                   "finalists queued", a->cf.nfinalist, t->accent2);
            if (row < hr.y + hr.h - 1)
                draw_progress_pair(a, &hr, row, "finalists verified", a->cf.verify_completed,
                                   "output results", output, t->good);
        } else {
            qn_hist *h = a->cfg->mode == QN_MODE_PORTS ? &a->ps.hist : &a->cf.hist;

            if (hr.h >= 5) {
                qn_box(s, hr, "round-trip distribution", false);
                if (h->total) {
                    qn_histogram(s, (qn_rect){ hr.x + 2, hr.y + 1,
                                               QN_MIN(hr.w - 4, QN_HIST_BINS),
                                               hr.h - 3 },
                                 h, t->accent);
                    for (int i = 0; i < QN_MIN(hr.w - 4, (int)QN_HIST_BINS); i += 4) {
                        uint32_t lo, hi;
                        qn_hist_bin_range((uint32_t)i, &lo, &hi);
                        qn_fmt_dur(lo, b2, sizeof b2);
                        qn_text(s, hr.x + 2 + i, hr.y + hr.h - 2,
                                b2, t->faint, t->panel, 0);
                    }
                } else {
                    qn_text(s, hr.x + 2, hr.y + 2,
                            "no samples yet", t->faint, t->panel, 0);
                }
            }
        }
    }
}

static void format_memory(uint64_t bytes, char *buffer, size_t capacity)
{
    uint64_t mib = bytes >> 20;
    uint64_t tenth = ((bytes & ((UINT64_C(1) << 20) - 1u)) * 10u) >> 20;

    (void)snprintf(buffer, capacity, "%" PRIu64 ".%" PRIu64 " MiB", mib, tenth);
}

static unsigned plan_rows_between(qn_scan_field first, qn_scan_field last)
{
    const char *previous = NULL;
    unsigned rows = 0u;

    for (int value = (int)first; value <= (int)last; value++) {
        const char *group = qn_scan_field_group((qn_scan_field)value);

        if (!previous || strcmp(previous, group))
            rows++;
        rows++;
        previous = group;
    }
    return rows;
}

static void plan_keep_selected_visible(qn_scan_editor *editor, int height)
{
    if (editor->field < (qn_scan_field)editor->scroll)
        editor->scroll = (uint16_t)editor->field;
    while (editor->scroll < QN_SCAN_FIELD__COUNT &&
           plan_rows_between((qn_scan_field)editor->scroll, editor->field) >
               (unsigned)QN_MAX(height, 1))
        editor->scroll++;
}

static void draw_plan_fields(qn_app *a, qn_rect panel)
{
    const qn_theme *theme = qn_theme_get();
    qn_scan_editor *editor = &a->plan_editor;
    qn_screen *screen = &a->scr;
    const char *previous = NULL;
    int y = panel.y + 1;
    int bottom = panel.y + panel.h - 1;
    int value_x = panel.x + QN_MAX(panel.w / 2, 22);

    plan_keep_selected_visible(editor, panel.h - 2);
    for (int value = (int)editor->scroll;
         value < QN_SCAN_FIELD__COUNT && y < bottom; value++) {
        qn_scan_field field = (qn_scan_field)value;
        const char *group = qn_scan_field_group(field);
        char text[64];
        bool selected = editor->field == field;
        bool active = qn_scan_field_active(field, &a->cfg->scan);
        uint32_t foreground = active ? theme->fg : theme->faint;
        uint32_t background = selected ? theme->sel_bg : theme->panel;

        if (!previous || strcmp(previous, group)) {
            if (y >= bottom)
                break;
            qn_textn(screen, panel.x + 2, y++, group, panel.w - 4,
                     theme->accent2, theme->panel, QN_ATTR_BOLD);
        }
        if (y >= bottom)
            break;
        qn_fill(screen, panel.x + 1, y, panel.w - 2, 1, ' ',
                selected ? theme->sel_fg : foreground, background, 0);
        qn_textn(screen, panel.x + 2, y, qn_scan_field_label(field),
                 QN_MAX(value_x - panel.x - 3, 1),
                 selected ? theme->sel_fg : foreground, background,
                 selected ? QN_ATTR_BOLD : 0);
        if (field == QN_SCAN_FIELD_REVIEW && a->plan_confirm_pending)
            (void)snprintf(text, sizeof text, "Confirm Start");
        else
            (void)qn_scan_field_value(editor, &a->cfg->scan, field,
                                      text, sizeof text);
        qn_textn(screen, value_x, y, text,
                 QN_MAX(panel.x + panel.w - value_x - 2, 1),
                 selected ? theme->sel_fg : (active ? theme->accent : theme->faint),
                 background, selected ? QN_ATTR_BOLD : 0);
        y++;
        previous = group;
    }
}

static void draw_plan_summary(qn_app *a, qn_rect panel)
{
    const qn_theme *theme = qn_theme_get();
    qn_screen *screen = &a->scr;
    const qn_scan_plan *plan = &a->cfg->scan_plan;
    char value[96];
    int y = panel.y + 1;
    int width = panel.w - 4;

    if (!a->cfg->scan_plan_valid || !a->cf_prepared || a->plan_request_changed) {
        qn_textn(screen, panel.x + 2, y++, "No effective plan yet.", width,
                 theme->warn, theme->panel, QN_ATTR_BOLD);
        qn_textn(screen, panel.x + 2, y++,
                 "Select Review / Start and press Enter.", width,
                 theme->dim, theme->panel, 0);
        qn_textn(screen, panel.x + 2, y++,
                 "Ranges and resource limits are validated first.", width,
                 theme->dim, theme->panel, 0);
        qn_textn(screen, panel.x + 2, y++,
                 "No probe starts until the second confirmation.", width,
                 theme->good, theme->panel, 0);
        return;
    }

    qn_kv(screen, panel.x + 2, y++, width, "mode",
          qn_scan_mode_str(plan->mode), theme->accent);
    (void)snprintf(value, sizeof value, "%u / %u",
                   plan->input_prefixes, plan->normalized_prefixes);
    qn_kv(screen, panel.x + 2, y++, width, "prefixes", value, theme->fg);
    qn_fmt_count(plan->total_addresses, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "unique addresses", value, theme->fg);
    qn_fmt_count(plan->duplicate_addresses, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "overlap removed", value, theme->dim);
    qn_fmt_count(plan->planned_addresses, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "planned attempts", value, theme->accent2);
    qn_fmt_count(plan->candidate_capacity, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "candidate capacity", value, theme->fg);
    qn_fmt_count(plan->finalist_limit, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "finalists", value, theme->fg);
    qn_fmt_count(plan->output_limit, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "output results", value, theme->fg);
    (void)snprintf(value, sizeof value, "%u / %u / %u",
                   plan->scan_concurrency, plan->verify_concurrency,
                   plan->stability_concurrency);
    qn_kv(screen, panel.x + 2, y++, width, "scan / verify / hold", value, theme->info);
    (void)snprintf(value, sizeof value, "%u", plan->verification_batch_size);
    qn_kv(screen, panel.x + 2, y++, width, "verification batch", value, theme->info);
    format_memory(plan->estimated_candidate_bytes, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "candidate memory", value, theme->dim);
    format_memory(plan->estimated_verifier_bytes, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "verifier memory", value, theme->dim);
    format_memory(plan->estimated_working_bytes, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "range / working memory", value, theme->dim);
    format_memory(plan->estimated_total_bytes, value, sizeof value);
    qn_kv(screen, panel.x + 2, y++, width, "estimated memory", value, theme->accent);
    (void)snprintf(value, sizeof value, "%" PRIu64 " / %" PRIu64,
                   plan->estimated_fds, plan->fd_limit);
    qn_kv(screen, panel.x + 2, y++, width, "file descriptors", value, theme->dim);
    if (y < panel.y + panel.h - 2) {
        qn_fmt_count(a->cf.n, value, sizeof value);
        qn_kv(screen, panel.x + 2, y++, width, "retained now", value, theme->good);
    }
    if (y < panel.y + panel.h - 2) {
        (void)snprintf(value, sizeof value, "%" PRIu64 " / %" PRIu64 "%s",
                       a->cf.candidate_dropped, a->cf.candidate_replaced,
                       a->cf.candidate_truncated ? " truncated" : "");
        qn_kv(screen, panel.x + 2, y++, width, "dropped / replaced", value,
              a->cf.candidate_truncated ? theme->warn : theme->dim);
    }
    if (y < panel.y + panel.h - 1)
        qn_textn(screen, panel.x + 2, y,
                 plan->exact_full ? "Complete loaded range set"
                                  : "Best observed among scanned addresses",
                 width, plan->exact_full ? theme->good : theme->warn,
                 theme->panel, QN_ATTR_BOLD);
}

static void draw_plan(qn_app *a, qn_rect r)
{
    const qn_theme *theme = qn_theme_get();
    qn_rect fields, summary;
    char title[32];

    if (r.w < 72 || r.h < 14) {
        qn_box(&a->scr, r, "Scan Plan", true);
        qn_printf(&a->scr, r.x + 2, r.y + 2, theme->warn, theme->panel,
                  QN_ATTR_BOLD, "Terminal is %dx%d; Scan Plan needs at least 72x14.",
                  r.w, r.h);
        qn_textn(&a->scr, r.x + 2, r.y + 4,
                 "Resize the terminal; values and validation are preserved.",
                 r.w - 4, theme->dim, theme->panel, 0);
        return;
    }
    (void)snprintf(title, sizeof title, "Scan Plan%s",
                   a->plan_editor.dirty ? " *" : "");
    fields = (qn_rect){ r.x, r.y, r.w * 55 / 100, r.h };
    summary = (qn_rect){ fields.x + fields.w, r.y, r.w - fields.w, r.h };
    qn_box(&a->scr, fields, title, true);
    qn_box(&a->scr, summary, "Resource Plan", a->plan_confirm_pending);
    draw_plan_fields(a, fields);
    draw_plan_summary(a, summary);
}

static void draw_table_head(qn_app *a, qn_rect r, const char *cols)
{
    const qn_theme *t = qn_theme_get();
    qn_fill(&a->scr, r.x, r.y, r.w, 1, ' ', t->head_fg, t->head_bg, 0);
    qn_textn(&a->scr, r.x + 1, r.y, cols, r.w - 2, t->head_fg, t->head_bg, QN_ATTR_BOLD);
}

static void clamp_scroll(qn_app *a, uint32_t nrows, uint32_t visible)
{
    if (!nrows) {
        a->sel = a->scroll = 0;
        return;
    }
    if (a->sel >= nrows)
        a->sel = nrows - 1;
    if (a->sel < a->scroll)
        a->scroll = a->sel;
    if (visible && a->sel >= a->scroll + visible)
        a->scroll = a->sel - visible + 1;
    if (visible && nrows > visible && a->scroll > nrows - visible)
        a->scroll = nrows - visible;
}

static void draw_cf(qn_app *a, qn_rect r)
{
    const qn_theme *t       = qn_theme_get();
    qn_screen      *s       = &a->scr;
    uint32_t        visible = (uint32_t)QN_MAX(r.h - 1, 0);
    uint32_t        nrecords;
    const cf_record *records = cf_display_records(a, &nrecords);
    char            rtt[24], jit[24];

    draw_table_head(a, r, "  #  ADDRESS           E STATE       MEDIAN  RTT DELTA   LOSS  COLO  SCORE");
    if (cf_verifying(a)) {
        size_t done  = atomic_load_explicit(&a->verify_done, memory_order_acquire);
        size_t total = atomic_load_explicit(&a->verify_total, memory_order_acquire);
        char   progress[128];

        snprintf(progress, sizeof progress,
                 "full TLS + HTTPS verification: %zu / %zu finalists  (x cancels)", done, total);
        qn_textn(s, r.x + QN_MAX(r.w - (int)strlen(progress) - 2, 2), r.y, progress,
                 r.w - 4, t->info, t->head_bg, QN_ATTR_BOLD);
    }
    clamp_scroll(a, nrecords, visible);

    for (uint32_t i = 0; i < visible; i++) {
        uint32_t   idx = a->scroll + i;
        int        y   = r.y + 1 + (int)i;
        bool       on  = idx == a->sel;
        uint32_t   bg  = on ? t->sel_bg : t->bg;
        const cf_record *rec;
        char       addr[QN_ADDRSTRLEN];

        qn_fill(s, r.x, y, r.w, 1, ' ', t->fg, bg, 0);
        if (idx >= nrecords)
            continue;

        rec = &records[idx];
        qn_addr_str(&rec->addr, addr, sizeof addr);
        qn_fmt_dur(rec->rtt_med_us, rtt, sizeof rtt);
        qn_fmt_dur(rec->rtt_delta_mean_us, jit, sizeof jit);

        qn_printf(s, r.x + 1, y, on ? t->sel_fg : t->dim, bg, 0, "%3u", idx + 1);
        qn_textn(s, r.x + 5, y, addr, 18, on ? t->sel_fg : t->fg, bg, on ? QN_ATTR_BOLD : 0);
        qn_text(s, r.x + 23, y, rec->verified ? "V" : "P",
                rec->verified ? t->good : t->warn, bg, QN_ATTR_BOLD);
        qn_textn(s, r.x + 25, y,
                 qn_classification_str(qn_cf_record_classification(rec)), 10,
                 verdict_color(rec), bg,
                 QN_ATTR_BOLD);
        qn_printf(s, r.x + 36, y, t->fg, bg, 0, "%9s", rtt);
        qn_printf(s, r.x + 46, y, t->dim, bg, 0, "%9s", jit);
        qn_printf(s, r.x + 56, y, rec->loss_pct ? t->warn : t->faint, bg, 0, "%4u%%", rec->loss_pct);
        qn_textn(s, r.x + 63, y, rec->colo[0] ? rec->colo : "-", 4, t->info, bg, 0);
        qn_printf(s, r.x + 69, y, rec->score ? t->good : t->faint, bg, QN_ATTR_BOLD, "%5u",
                  rec->score);
    }

    if (!nrecords)
        qn_text(s, r.x + 2, r.y + 2, "no reachable edges recorded yet - press s to sweep", t->faint,
                t->bg, 0);
}

static void detail_line(qn_screen *s, const qn_rect *box, int *y, uint32_t color,
                        uint16_t attr, const char *fmt, ...)
{
    char    line[256];
    va_list ap;

    if (*y >= box->y + box->h - 2)
        return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    qn_textn(s, box->x + 2, (*y)++, line, box->w - 4, color, qn_theme_get()->panel, attr);
}

static void draw_cf_detail(qn_app *a)
{
    const qn_theme  *t = qn_theme_get();
    qn_screen       *s = &a->scr;
    const cf_record *records, *rec;
    uint32_t         n;
    qn_rect          box;
    char             addr[QN_ADDRSTRLEN], med[24], min[24], p90[24], delta[24], ci[64];
    int              y;

    if (!a->detail_open || a->view != QN_VIEW_CF)
        return;
    records = cf_display_records(a, &n);
    if (!records || !n || a->sel >= n)
        return;
    if (s->w < 44u || s->h < 15u)
        return;

    rec = &records[a->sel];
    box.w = QN_MIN((int)s->w - 4, 86);
    box.h = QN_MIN((int)s->h - 5, 14);
    box.x = ((int)s->w - box.w) / 2;
    box.y = ((int)s->h - box.h) / 2;
    qn_box(s, box, rec->verified ? "verified evidence" : "preliminary evidence", true);

    qn_addr_str(&rec->addr, addr, sizeof addr);
    qn_fmt_dur(rec->rtt_med_us, med, sizeof med);
    qn_fmt_dur(rec->rtt_min_us, min, sizeof min);
    qn_fmt_dur(rec->rtt_p90_us, p90, sizeof p90);
    qn_fmt_dur(rec->rtt_delta_mean_us, delta, sizeof delta);
    if (rec->rtt_ci90_valid)
        snprintf(ci, sizeof ci, "%u..%u us", rec->rtt_ci90_lo_us, rec->rtt_ci90_hi_us);
    else
        qn_strlcpy(ci, "unavailable (needs >= 5 RTTs)", sizeof ci);

    y = box.y + 1;
    detail_line(s, &box, &y, t->fg, QN_ATTR_BOLD, "%s  %s", addr,
                qn_classification_str(qn_cf_record_classification(rec)));
    detail_line(s, &box, &y, t->dim, 0,
                "RTT median %s  p90 %s  min %s  delta %s", med, p90, min, delta);
    detail_line(s, &box, &y, t->dim, 0, "CI90 %s  samples %u  lost %u  loss %u%%",
                ci, rec->samples.n, rec->samples.lost, rec->loss_pct);
    detail_line(s, &box, &y, t->dim, 0, "origin %s  transport %s  TLS %s  errno %d",
                qn_failure_origin_str((qn_failure_origin)rec->failure_origin),
                qn_result_str((qn_result)rec->transport_result),
                qn_tls_outcome_str((qn_tls_outcome)rec->tls_outcome), rec->sys_errno);
    detail_line(s, &box, &y, t->dim, 0, "TLS version 0x%04x  suite 0x%04x  ALPN %s",
                rec->tls_version, rec->tls_suite, rec->alpn[0] ? rec->alpn : "-");
    detail_line(s, &box, &y, t->dim, 0,
                "HTTP %u  colo %s  handshake %u us  TTFB %u us", rec->http_status,
                rec->colo[0] ? rec->colo : "-", rec->handshake_us, rec->ttfb_us);
    detail_line(s, &box, &y, t->dim, 0,
                "flow %llu bytes  %u kbps  idle %u ms  score %u  confidence %u",
                (unsigned long long)rec->bytes, rec->kbps, rec->idle_held_ms, rec->score,
                rec->confidence);
    detail_line(s, &box, &y, t->info, 0, "%s",
                rec->verify_reason[0] ? rec->verify_reason : "reason: -");
    qn_textn(s, box.x + 2, box.y + box.h - 2, "Enter or Esc closes this evidence pane",
             box.w - 4, t->faint, t->panel, 0);
}

static void draw_ports(qn_app *a, qn_rect r)
{
    const qn_theme *t       = qn_theme_get();
    qn_screen      *s       = &a->scr;
    uint32_t        visible = (uint32_t)QN_MAX(r.h - 1, 0);
    char            rtt[24];

    draw_table_head(a, r, "  PORT   SERVICE           RTT        BANNER");
    clamp_scroll(a, a->ps.nopen, visible);

    for (uint32_t i = 0; i < visible; i++) {
        uint32_t     idx = a->scroll + i;
        int          y   = r.y + 1 + (int)i;
        bool         on  = idx == a->sel;
        uint32_t     bg  = on ? t->sel_bg : t->bg;
        port_record *rec;

        qn_fill(s, r.x, y, r.w, 1, ' ', t->fg, bg, 0);
        if (idx >= a->ps.nopen)
            continue;

        rec = &a->ps.open[idx];
        qn_fmt_dur(rec->rtt_us, rtt, sizeof rtt);

        qn_printf(s, r.x + 1, y, on ? t->sel_fg : t->good, bg, QN_ATTR_BOLD, "%6u", rec->port);
        qn_textn(s, r.x + 9, y, qn_service_name(rec->port), 16, t->accent, bg, 0);
        qn_printf(s, r.x + 26, y, t->fg, bg, 0, "%9s", rtt);
        if (rec->banner_len)
            qn_textn(s, r.x + 37, y, rec->banner, r.w - 39, t->dim, bg, 0);
    }

    if (!a->ps.nopen)
        qn_text(s, r.x + 2, r.y + 2, "no open ports recorded yet", t->faint, t->bg, 0);
}

static void draw_hosts(qn_app *a, qn_rect r)
{
    const qn_theme *t       = qn_theme_get();
    qn_screen      *s       = &a->scr;
    uint32_t        visible = (uint32_t)QN_MAX(r.h - 1, 0);
    char            rtt[24];

    draw_table_head(a, r, "  ADDRESS            RTT         FIRST ANSWER");
    if (a->waiting_bg) {
        qn_text(s, r.x + 2, r.y + 2, "probing ICMP before TCP fallback...", t->faint, t->bg, 0);
        return;
    }
    clamp_scroll(a, a->hd.n, visible);

    for (uint32_t i = 0; i < visible; i++) {
        uint32_t     idx = a->scroll + i;
        int          y   = r.y + 1 + (int)i;
        bool         on  = idx == a->sel;
        uint32_t     bg  = on ? t->sel_bg : t->bg;
        host_record *rec;
        char         addr[QN_ADDRSTRLEN];

        qn_fill(s, r.x, y, r.w, 1, ' ', t->fg, bg, 0);
        if (idx >= a->hd.n)
            continue;

        rec = &a->hd.host[idx];
        qn_addr_str(&rec->addr, addr, sizeof addr);
        qn_fmt_dur(rec->rtt_us, rtt, sizeof rtt);

        qn_textn(s, r.x + 1, y, addr, 18, on ? t->sel_fg : t->fg, bg, QN_ATTR_BOLD);
        qn_printf(s, r.x + 20, y, t->dim, bg, 0, "%9s", rtt);
        if (rec->open_hint)
            qn_printf(s, r.x + 32, y, t->accent, bg, 0, "%u/%s", rec->open_hint,
                      qn_service_name(rec->open_hint));
        else
            qn_text(s, r.x + 32, y, "icmp echo", t->faint, bg, 0);
    }

    if (!a->hd.n)
        qn_text(s, r.x + 2, r.y + 2, "no hosts found yet - press s to sweep the local prefix",
                t->faint, t->bg, 0);
}

static void draw_net(qn_app *a, qn_rect r)
{
    const qn_theme *t = qn_theme_get();
    qn_screen      *s = &a->scr;
    char            buf[128], addr[QN_ADDRSTRLEN];
    int             y;
    qn_rect         top, bot;

    if (!atomic_load(&a->ni_ready) && !atomic_load(&a->bg_busy))
        bg_start(a, BG_NETINFO);

    top = (qn_rect){ r.x, r.y, r.w, QN_MIN(r.h / 2, 12) };
    bot = (qn_rect){ r.x, r.y + top.h, r.w, r.h - top.h };

    if (!atomic_load(&a->ni_ready)) {
        qn_box(s, top, "links", false);
        qn_text(s, top.x + 2, top.y + 1, "probing...", t->faint, t->panel, 0);
        qn_box(s, bot, "path", false);
        qn_text(s, bot.x + 2, bot.y + 1, "probing path...", t->faint, t->panel, 0);
        return;
    }

    qn_box(s, top, "links", false);
    y = top.y + 1;
    for (uint32_t i = 0; i < a->ni.niface && y < top.y + top.h - 1; i++) {
        const qn_iface *f = &a->ni.iface[i];
        bool            primary = a->ni.default_iface[0] && !strcmp(f->name, a->ni.default_iface);

        qn_addr_str(&f->addr, addr, sizeof addr);
        snprintf(buf, sizeof buf, "%-10s %-9s %-16s /%-3u mtu %u", f->name,
                 qn_link_kind_str((qn_link_kind)f->kind), addr, f->prefix_bits, f->mtu);
        qn_textn(s, top.x + 2, y, buf, top.w - 4, primary ? t->fg : t->dim, t->panel,
                 primary ? QN_ATTR_BOLD : 0);
        if (primary)
            qn_text(s, top.x + top.w - 10, y, "default", t->accent, t->panel, 0);
        y++;
    }
    if (!a->ni.niface)
        qn_text(s, top.x + 2, top.y + 1, "no links", t->faint, t->panel, 0);

    qn_box(s, bot, "path", false);
    y = bot.y + 1;

    if (a->ni.has_gateway) {
        char dur[24];

        qn_addr_str(&a->ni.gateway, addr, sizeof addr);
        qn_fmt_dur(a->ni.gw_rtt_us, dur, sizeof dur);
        snprintf(buf, sizeof buf, "%s  (%s)", addr, dur);
        qn_kv(s, bot.x + 2, y++, bot.w - 4, "gateway  ", buf, t->fg);
    }

    for (uint32_t i = 0; i < a->ni.ndns && y < bot.y + bot.h - 1; i++) {
        qn_addr_str(&a->ni.dns[i], addr, sizeof addr);
        snprintf(buf, sizeof buf, "resolver%u", i + 1);
        qn_kv(s, bot.x + 2, y++, bot.w - 4, buf, addr, t->fg);
    }

    if (a->ni.has_public) {
        qn_addr_str(&a->ni.public_v4, addr, sizeof addr);
        snprintf(buf, sizeof buf, "%s  via %s", addr,
                 a->ni.public_colo[0] ? a->ni.public_colo : "?");
        qn_kv(s, bot.x + 2, y++, bot.w - 4, "public   ", buf, t->accent);
    }

    if (a->ni.inet_rtt_us) {
        qn_fmt_dur(a->ni.inet_rtt_us, buf, sizeof buf);
        qn_kv(s, bot.x + 2, y++, bot.w - 4, "internet ", buf, t->info);
    }
    if (a->ni.dns_rtt_us) {
        qn_fmt_dur(a->ni.dns_rtt_us, buf, sizeof buf);
        qn_kv(s, bot.x + 2, y++, bot.w - 4, "dns      ", buf, t->info);
    }

    y++;
    qn_kv(s, bot.x + 2, y++, bot.w - 4, "dns divergence",
          a->ni.dns_state == QN_DIAG_POSITIVE
              ? "observed"
              : (a->ni.dns_state == QN_DIAG_NEGATIVE
                     ? "not observed"
                     : qn_diag_state_str((qn_diag_state)a->ni.dns_state)),
          a->ni.dns_state == QN_DIAG_POSITIVE
              ? t->warn
              : (a->ni.dns_state == QN_DIAG_NEGATIVE ? t->good : t->faint));
    qn_kv(s, bot.x + 2, y++, bot.w - 4, "captive portal",
          a->ni.captive_state == QN_DIAG_POSITIVE
              ? "detected"
              : (a->ni.captive_state == QN_DIAG_NEGATIVE
                     ? "not detected"
                     : qn_diag_state_str((qn_diag_state)a->ni.captive_state)),
          a->ni.captive_state == QN_DIAG_POSITIVE
              ? t->warn
              : (a->ni.captive_state == QN_DIAG_NEGATIVE ? t->good : t->faint));
}

static void draw_help(qn_app *a, qn_rect r)
{
    static const char *lines[] = {
        "NAVIGATION",
        "  1..7 / tab      switch view",
        "  up/down         move selection",
        "  pgup/pgdn       page",
        "  home/end        jump to first/last row",
        "  enter           details, custom value, or plan confirmation",
        "",
        "SCAN",
        "  s               open and validate Scan Plan before Cloudflare scans",
        "  x               stop the running scan",
        "  e               export results to JSON and CSV",
        "  q / ctrl-c      quit",
        "  Scan Plan: arrows choose, type edits, w saves, r restores",
        "  No Cloudflare probe starts before the second Enter confirmation.",
        "",
        "READING THE CLOUDFLARE TABLE",
        "  stable-after-marker   marker observed, then idle hold survived",
        "  flowing-after-marker  marker observed, then flow sample completed",
        "  cf-marker-observed    HTTPS returned Cloudflare application markers",
        "  handshake       TLS completed; identity is not authenticated",
        "  suspected       reserved for corroborated interference evidence",
        "  failures        local, peer, path, protocol and unsupported stay distinct",
        "  tcp             the port answered but supported TLS did not complete",
        "  dead            no answer at all",
        "",
        "  RTT DELTA is the mean absolute delta between consecutive RTT samples.",
        "  SCORE ranks verdict first, then median RTT, RTT delta and loss.",
        "  A failure cannot cross into the TLS-success score band.",
    };
    const qn_theme *t = qn_theme_get();

    for (uint32_t i = 0; i < QN_ARRAY_LEN(lines) && (int)i < r.h; i++) {
        const char *l   = lines[i];
        bool        hdr = l[0] && l[0] != ' ';
        qn_text(&a->scr, r.x + 2, r.y + (int)i, l, hdr ? t->accent : t->dim, t->bg,
                hdr ? QN_ATTR_BOLD : 0);
    }
}

static void do_export(qn_app *a)
{
    const char *j = a->cfg->out_json ? a->cfg->out_json : "qanat-results.json";
    const char *c = a->cfg->out_csv ? a->cfg->out_csv : "qanat-results.csv";
    qn_run_outcome json, csv, outcome;

    if (a->engine_live || atomic_load(&a->bg_busy)) {
        status(a, "wait for active work before exporting");
        return;
    }

    json = qn_export_json(j, &a->cf, &a->ps, &a->hd, &a->ni);
    csv = qn_export_csv(c, &a->cf, &a->ps, &a->hd);
    outcome = qn_run_outcome_worst(json, csv);
    a->outcome = qn_run_outcome_worst(a->outcome, outcome);
    status(a, outcome == QN_RUN_SUCCESS ? "exported to %s and %s"
                                        : "export failed (%s / %s)",
           j, c);
}

static bool do_requested_exports(qn_app *a)
{
    qn_run_outcome outcome = QN_RUN_SUCCESS;

    if (a->cfg->out_json)
        outcome = qn_run_outcome_worst(
            outcome, qn_export_json(a->cfg->out_json, &a->cf, &a->ps,
                                    &a->hd, &a->ni));
    if (a->cfg->out_csv)
        outcome = qn_run_outcome_worst(
            outcome, qn_export_csv(a->cfg->out_csv, &a->cf, &a->ps, &a->hd));
    a->outcome = qn_run_outcome_worst(a->outcome, outcome);
    return outcome == QN_RUN_SUCCESS;
}

static void save_plan_settings(qn_app *a)
{
    char path[1024];
    char error[192];

    if (!qn_scan_settings_default_path(path, sizeof path)) {
        status(a, "HOME or XDG_CONFIG_HOME cannot form a settings path");
        return;
    }
    if (!qn_scan_settings_save(path, &a->cfg->scan, error, sizeof error)) {
        status(a, "settings save failed: %s", error);
        return;
    }
    a->plan_editor.dirty = false;
    status(a, "scan settings saved to %s", path);
}

static void load_plan_settings(qn_app *a)
{
    qn_scan_request loaded;
    char path[1024];
    char error[192];

    if (!qn_scan_settings_default_path(path, sizeof path)) {
        status(a, "HOME or XDG_CONFIG_HOME cannot form a settings path");
        return;
    }
    if (!qn_scan_settings_load(path, &loaded, error, sizeof error)) {
        status(a, "settings load failed: %s", error);
        return;
    }
    discard_unlaunched_plan(a);
    a->cfg->scan = loaded;
    a->plan_editor.preset = qn_scan_preset_detect(&loaded);
    a->plan_editor.dirty = false;
    a->plan_editor.editing = false;
    a->plan_request_changed = true;
    a->plan_confirm_pending = false;
    status(a, "scan settings restored from %s; review the effective plan", path);
}

static void handle_plan_key(qn_app *a, const qn_key *key)
{
    qn_scan_edit_action action;
    bool was_editing = a->plan_editor.editing;
    char message[192] = "";

    if (!a->plan_editor.editing && key->kind == QN_KEY_TAB) {
        a->view = (qn_view)((a->view + 1) % QN_VIEW__COUNT);
        return;
    }
    if (!a->plan_editor.editing && key->kind == QN_KEY_CHAR) {
        if (key->ch == 'w') {
            save_plan_settings(a);
            return;
        }
        if (key->ch == 'r') {
            load_plan_settings(a);
            return;
        }
        if (key->ch == '?') {
            a->view = QN_VIEW_HELP;
            return;
        }
        if (key->ch == 's') {
            a->plan_editor.field = QN_SCAN_FIELD_REVIEW;
            status(a, "review the exact resource plan, then press Enter");
            return;
        }
    }
    action = qn_scan_editor_key(&a->plan_editor, &a->cfg->scan, key,
                                message, sizeof message);
    if (action == QN_SCAN_EDIT_CHANGED) {
        discard_unlaunched_plan(a);
        a->plan_request_changed = true;
        a->plan_confirm_pending = false;
        status(a, "%s", message[0] ? message : "settings changed; review the effective plan");
    } else if (action == QN_SCAN_EDIT_REVIEW) {
        if (a->engine_live || atomic_load(&a->bg_busy))
            status(a, "a scan is already running");
        else
            (void)start_scan(a);
    } else if (action == QN_SCAN_EDIT_CANCELLED && !was_editing) {
        if (a->plan_confirm_pending) {
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
            discard_unlaunched_plan(a);
            status(a, "prepared scan cancelled; no probe was started");
        }
        a->view = QN_VIEW_DASH;
    } else if (message[0]) {
        status(a, "%s", message);
    }
}

static void handle_key(qn_app *a, const qn_key *k)
{
    uint32_t nrows   = rows_in_view(a);
    uint32_t visible = (uint32_t)QN_MAX((int)a->scr.h - 4, 1);

    if (k->kind == QN_KEY_CHAR && k->ctrl && k->ch == 'c') {
        atomic_store_explicit(&a->bg_cancel, true, memory_order_release);
        if (a->engine_live || atomic_load(&a->bg_busy) || a->plan_confirm_pending)
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
        a->quit = true;
        return;
    }
    if (a->view == QN_VIEW_PLAN) {
        if (k->kind == QN_KEY_CHAR && k->ch == 'q' && !a->plan_editor.editing) {
            if (a->plan_confirm_pending)
                a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
            a->quit = true;
            return;
        }
        handle_plan_key(a, k);
        return;
    }

    switch (k->kind) {
    case QN_KEY_UP:   if (a->sel) a->sel--; return;
    case QN_KEY_DOWN: if (a->sel + 1 < nrows) a->sel++; return;
    case QN_KEY_PGUP: a->sel = a->sel > visible ? a->sel - visible : 0; return;
    case QN_KEY_PGDN:
        a->sel = QN_MIN(a->sel + visible, nrows ? nrows - 1 : 0);
        return;
    case QN_KEY_HOME: a->sel = 0; return;
    case QN_KEY_END:  a->sel = nrows ? nrows - 1 : 0; return;
    case QN_KEY_ENTER:
        if (a->view == QN_VIEW_CF && nrows)
            a->detail_open = !a->detail_open;
        return;
    case QN_KEY_TAB:
        a->view = (qn_view)((a->view + 1) % QN_VIEW__COUNT);
        a->sel = a->scroll = 0;
        a->detail_open = false;
        return;
    case QN_KEY_ESC:
        if (a->detail_open)
            a->detail_open = false;
        else
            a->view = QN_VIEW_DASH;
        return;
    default: break;
    }

    if (k->kind != QN_KEY_CHAR)
        return;

    switch (k->ch) {
    case 'q':
        atomic_store_explicit(&a->bg_cancel, true, memory_order_release);
        if (a->engine_live || atomic_load(&a->bg_busy) || a->plan_confirm_pending)
            a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
        a->quit = true;
        break;
    case '1': a->view = QN_VIEW_DASH; break;
    case '2': a->view = QN_VIEW_CF; break;
    case '3': a->view = QN_VIEW_PLAN; break;
    case '4': a->view = QN_VIEW_PORTS; break;
    case '5': a->view = QN_VIEW_HOSTS; break;
    case '6': a->view = QN_VIEW_NET; break;
    case '7':
    case '?': a->view = QN_VIEW_HELP; break;

    case 's':
        if (a->engine_live || atomic_load(&a->bg_busy)) {
            status(a, "a scan is already running");
        } else if (a->cfg->mode == QN_MODE_NONE) {
            status(a, "no mode selected; start with --cf, --ports or --discover");
        } else if (a->cfg->mode == QN_MODE_CF) {
            a->view = QN_VIEW_PLAN;
            if (a->plan_confirm_pending)
                status(a, "plan is ready; use Review / Start and Enter to confirm");
            else
                (void)prepare_cf_scan(a);
        } else {
            (void)start_scan(a);
        }
        break;

    case 'x':
        if (a->engine_live) {
            if (finalize_engine_phase(a, true))
                status(a, "stopped; partial results finalized");
        } else if (atomic_load(&a->bg_busy)) {
            bg_kind kind = (bg_kind)atomic_load_explicit(&a->bg_kind,
                                                         memory_order_acquire);

            if (cf_verifying(a) || kind == BG_ICMP) {
                atomic_store_explicit(&a->bg_cancel, true, memory_order_release);
                status(a, kind == BG_ICMP ? "cancelling ICMP discovery"
                                          : "cancelling full verification");
            } else {
                status(a, "the short background probe cannot be cancelled");
            }
        }
        break;

    case 'e': do_export(a); break;
    default: break;
    }

    if (k->ch >= '1' && k->ch <= '7') {
        a->sel = a->scroll = 0;
        a->detail_open = false;
    }
}

static void render(qn_app *a)
{
    const qn_theme *t = qn_theme_get();
    qn_rect         body;
    bool            records_locked = false;

    if (a->cf.records_lock_live) {
        pthread_mutex_lock(&a->cf.records_lock);
        records_locked = true;
    }
    qn_screen_clear(&a->scr, t->bg);
    draw_header(a);
    draw_tabs(a, 1);

    body = (qn_rect){ 0, 2, (int)a->scr.w, (int)a->scr.h - 3 };

    switch (a->view) {
    case QN_VIEW_CF:    draw_cf(a, body); break;
    case QN_VIEW_PLAN:  draw_plan(a, body); break;
    case QN_VIEW_PORTS: draw_ports(a, body); break;
    case QN_VIEW_HOSTS: draw_hosts(a, body); break;
    case QN_VIEW_NET:   draw_net(a, body); break;
    case QN_VIEW_HELP:  draw_help(a, body); break;
    default:            draw_dash(a, body); break;
    }

    draw_cf_detail(a);

    draw_footer(a);
    if (records_locked)
        pthread_mutex_unlock(&a->cf.records_lock);
    if (!qn_screen_flush(&a->scr, &a->term)) {
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_FAILED);
        status(a, "terminal write failed: %s", strerror(errno ? errno : EIO));
        a->quit = true;
    }
}

static qn_view default_view(qn_mode m)
{
    switch (m) {
    case QN_MODE_CF:       return QN_VIEW_PLAN;
    case QN_MODE_PORTS:    return QN_VIEW_PORTS;
    case QN_MODE_DISCOVER: return QN_VIEW_HOSTS;
    case QN_MODE_NETINFO:  return QN_VIEW_NET;
    default:               return QN_VIEW_DASH;
    }
}

int qn_app_run(qn_config *cfg)
{
    qn_app *a = (qn_app *)calloc(1, sizeof *a);
    int     result;
    bool    requested_exports_ok = true;

    if (!a)
        return qn_run_exit_code(QN_RUN_FAILED);
    a->cfg        = cfg;
    a->t_start_ms = qn_now_ms();
    qn_topology_detect(&a->topo);

    if (!qn_arena_init(&a->arena, ARENA_BYTES)) {
        free(a);
        qn_warn("could not reserve the working arena");
        return qn_run_exit_code(QN_RUN_FAILED);
    }
    if (!qn_term_open(&a->term, !cfg->no_color)) {
        qn_warn("stdout is not a terminal; use --headless for line output");
        qn_arena_free(&a->arena);
        free(a);
        return qn_run_exit_code(QN_RUN_FAILED);
    }

    qn_theme_init(a->term.depth);
    qn_input_init(&a->input);
    qn_scan_editor_init(&a->plan_editor);
    a->plan_editor.preset = qn_scan_preset_detect(&cfg->scan);
    if (!qn_screen_init(&a->scr, a->term.w, a->term.h)) {
        qn_term_close(&a->term);
        qn_arena_free(&a->arena);
        free(a);
        return qn_run_exit_code(QN_RUN_FAILED);
    }

    a->view = default_view(cfg->mode);
    qn_spark_reset(&a->spark);
    status(a, "ready");

    if (cfg->mode == QN_MODE_NETINFO)
        bg_start(a, BG_NETINFO);
    else if (cfg->mode != QN_MODE_NONE && cfg->mode != QN_MODE_CF)
        start_scan(a);
    else if (cfg->mode == QN_MODE_CF)
        status(a, "configure Scan Plan; Review / Start validates resources before confirmation");

    while (!a->quit && !qn_term_interrupted()) {
        struct pollfd pf = { STDIN_FILENO, POLLIN, 0 };
        uint64_t      now;

        if (qn_term_resized(&a->term))
            qn_screen_resize(&a->scr, a->term.w, a->term.h);

        (void)poll(&pf, 1, a->engine_live ? 8 : FRAME_MS);
        {
            qn_key k;

            while (qn_input_poll(&a->input, STDIN_FILENO, &k))
                handle_key(a, &k);
        }

        pump(a);

        now = qn_now_ms();
        if (now - a->last_spark_ms >= 250) {
            qn_engine_snapshot sn;
            if (a->engine_ready) {
                qn_engine_rate_sample(&a->eng);
                qn_engine_stats(&a->eng, &sn);
            } else {
                memset(&sn, 0, sizeof sn);
            }
            qn_spark_push(&a->spark, sn.rate_now);
            a->last_spark_ms = now;
        }
        if (now - a->last_thermal_ms >= 3000) {
            a->thermal_mc        = qn_thermal_read();
            a->last_thermal_ms   = now;
        }

        if (now - a->last_frame_ms >= FRAME_MS) {
            render(a);
            a->last_frame_ms = now;
        }
    }

    if (qn_term_interrupted())
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
    if (a->engine_live) {
        a->outcome = qn_run_outcome_worst(a->outcome, QN_RUN_CANCELLED);
        (void)finalize_engine_phase(a, true);
    }
    atomic_store_explicit(&a->bg_cancel, true, memory_order_release);
    if (a->bg_joinable) {
        pthread_join(a->bg_tid, NULL);
        a->bg_joinable = false;
    }
    if (a->cf_prepared && !a->cf_launched)
        discard_unlaunched_plan(a);
    if (!a->scan_done && cfg->mode != QN_MODE_NONE &&
        cfg->mode != QN_MODE_NETINFO &&
        (cfg->mode != QN_MODE_CF || a->cf_launched))
        finish_scan_results(a);

    if (cfg->out_json || cfg->out_csv)
        requested_exports_ok = do_requested_exports(a);

    qn_screen_free(&a->scr);
    qn_term_close(&a->term);
    if (!requested_exports_ok)
        qn_warn("could not write one or more requested result files");
    /* Restore the terminal before a config export can write to stdout. */
    if (cfg->export_on) {
        qn_run_outcome output =
            qn_export_config(cfg->export_file, cfg->export_fmt, &a->cf);

        if (output != QN_RUN_SUCCESS) {
            qn_warn("could not write the config export");
            a->outcome = qn_run_outcome_worst(a->outcome, output);
        }
    }
    if (a->engine_ready)
        qn_engine_destroy(&a->eng);
    cf_scan_destroy(&a->cf);
    qn_arena_free(&a->arena);
    result = qn_run_exit_code(a->outcome);
    free(a);
    return result;
}
