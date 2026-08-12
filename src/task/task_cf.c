#include "qanat/task.h"
#include "qanat/crypto.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include "qanat/verify.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define CF_RTT_CALIBRATION 3u
#define CF_CALIBRATION_OVERSAMPLE 4u
#define CF_CALIBRATION_EXTRA 32u

const char *cf_phase_str(cf_phase p)
{
    switch (p) {
    case CF_PHASE_SWEEP: return "reach";
    case CF_PHASE_TLS:   return "handshake";
    case CF_PHASE_RTT:   return "measure";
    default:             return "done";
    }
}

/* Lower connect latency is better; a candidate with no sample sorts last. */
static int cf_sweep_better(const void *a, const void *b)
{
    uint32_t ra = qn_samples_min(&((const cf_record *)a)->samples);
    uint32_t rb = qn_samples_min(&((const cf_record *)b)->samples);

    if (!ra)
        ra = 0xFFFFFFFFu;
    if (!rb)
        rb = 0xFFFFFFFFu;
    return ra < rb ? 1 : (ra > rb ? -1 : 0);
}

static qn_task_next cf_next_sweep(void *ctx, uint64_t idx, qn_job *out)
{
    cf_scan *s = (cf_scan *)ctx;
    qn_addr  a;

    uint64_t pick;

    /* Retaining what was asked for is the goal being met, not an early end. */
    if (atomic_load_explicit(&s->full, memory_order_acquire))
        return QN_TASK_STOP_CONDITION;
    if (idx >= s->cfg->scan_plan.planned_addresses)
        return QN_TASK_EXHAUSTED;
    if (s->cfg->scan_plan.exact_full ||
        s->cfg->scan_plan.selection == QN_SELECTION_UNIFORM) {
        pick = qn_perm_apply(&s->uniform, idx);
    } else if (!qn_bandit_next(&s->bandit, idx, &pick)) {
        return QN_TASK_EXHAUSTED;
    }
    /* The scheduler drew from inside the set, so a miss is an internal fault. */
    if (!qn_cidr_set_nth(&s->set, pick, &a))
        return QN_TASK_FATAL;

    out->addr  = a;
    out->port  = 443;
    out->stage = QN_STAGE_TCP;
    out->token = pick;
    return QN_TASK_JOB;
}

static void cf_on_sweep(void *ctx, const qn_event *ev)
{
    cf_scan  *s = (cf_scan *)ctx;

    cf_record cand;

    s->sweep_completed++;

    /* Local failures never train the range scheduler as negative evidence. */
    if (ev->result != QN_R_CANCELLED &&
        (ev->failure_origin == QN_FAIL_NONE || ev->failure_origin == QN_FAIL_PEER ||
         ev->failure_origin == QN_FAIL_PATH))
        qn_bandit_report(&s->bandit, ev->job.token, ev->result == QN_R_OPEN);

    if (ev->result != QN_R_OPEN)
        return;

    /* Late in-flight opens may train scheduling but cannot inflate retained results. */
    s->reached++;
    if (s->limit && s->n >= s->limit) {
        s->late_reachable_discarded++;
        atomic_store_explicit(&s->full, true, memory_order_release);
        return;
    }

    memset(&cand, 0, sizeof cand);
    cand.addr = ev->job.addr;
    cand.highest_rung_reached = QN_RUNG_TCP;
    cand.terminal_outcome = QN_TERM_SUCCESS;
    if (ev->rtt_us)
        qn_samples_add(&cand.samples, ev->rtt_us);

    /* --limit means stop after n reachable candidates, as documented. */
    if (s->limit) {
        s->rec[s->n++] = cand;
        if (s->n >= s->limit)
            atomic_store_explicit(&s->full, true, memory_order_release);
        return;
    }

    /* Otherwise the sweep runs to completion and only the best K survive. */
    {
        bool was_full = qn_topk_full(&s->keep);
        bool kept = qn_topk_offer(&s->keep, &cand);

        if (was_full) {
            s->candidate_truncated = true;
            if (kept)
                s->candidate_replaced++;
            else
                s->candidate_dropped++;
        }
    }
    s->n = s->keep.n;
}

static qn_task_next cf_next_sel(void *ctx, uint64_t idx, qn_job *out, uint8_t stage,
                                uint16_t port)
{
    cf_scan *s = (cf_scan *)ctx;

    if (idx >= s->nactive)
        return QN_TASK_EXHAUSTED;
    out->addr  = s->rec[s->active[idx]].addr;
    out->port  = port;
    out->stage = stage;
    out->token = s->active[idx];
    return QN_TASK_JOB;
}

static qn_task_next cf_next_tls(void *ctx, uint64_t idx, qn_job *out)
{
    return cf_next_sel(ctx, idx, out, QN_STAGE_TLS, 443);
}

static void cf_on_tls(void *ctx, const qn_event *ev)
{
    cf_scan   *s = (cf_scan *)ctx;
    cf_record *r;

    if (ev->job.token >= s->n)
        return;
    r = &s->rec[(uint32_t)ev->job.token];

    if (ev->result == QN_R_CANCELLED)
        return;
    r->failure_origin = ev->failure_origin;
    r->transport_result = ev->result;
    r->tls_outcome = ev->tls;
    r->sys_errno = ev->sys_errno;

    if (ev->failure_origin == QN_FAIL_LOCAL || ev->result == QN_R_ERROR) {
        r->terminal_outcome = QN_TERM_LOCAL_ERROR;
        s->local_errors++;
        return;
    }

    switch (ev->tls) {
    case QN_TLS_SERVERHELLO:
        r->highest_rung_reached = QN_RUNG_TLS;
        r->terminal_outcome = QN_TERM_SUCCESS;
        s->clean++;
        if (ev->rtt_us) {
            qn_samples_add(&r->samples, ev->rtt_us);
            qn_hist_add(&s->hist, ev->rtt_us);
        }
        break;

    case QN_TLS_ALERT:
        r->terminal_outcome = QN_TERM_PEER_REJECTED;
        s->inconclusive++;
        break;

    case QN_TLS_RESET:
        r->terminal_outcome = QN_TERM_RESET;
        s->inconclusive++;
        break;

    case QN_TLS_SILENCE:
        r->terminal_outcome = ev->result == QN_R_TIMEOUT ? QN_TERM_TIMEOUT
                                                         : QN_TERM_INCONCLUSIVE;
        s->inconclusive++;
        break;

    case QN_TLS_GARBAGE:
        r->terminal_outcome = QN_TERM_PROTOCOL_INVALID;
        s->inconclusive++;
        break;

    default:
        if (ev->result == QN_R_UNREACH || ev->failure_origin == QN_FAIL_PATH) {
            r->terminal_outcome = QN_TERM_INCONCLUSIVE;
            s->inconclusive++;
        }
        break;
    }
}

static qn_task_next cf_next_rtt(void *ctx, uint64_t idx, qn_job *out)
{
    cf_scan *s = (cf_scan *)ctx;

    if (idx >= s->nactive)
        return QN_TASK_EXHAUSTED;
    out->addr  = s->rec[s->active[idx]].addr;
    out->port  = 443;
    out->stage = QN_STAGE_RTT;
    out->token = s->active[idx];
    return QN_TASK_JOB;
}

static void cf_on_rtt(void *ctx, const qn_event *ev)
{
    cf_scan   *s = (cf_scan *)ctx;
    cf_record *r;
    uint32_t   idx;

    if (ev->job.token >= s->n)
        return;
    idx = (uint32_t)ev->job.token;
    r = &s->rec[idx];

    if (ev->result == QN_R_CANCELLED)
        return;
    if (ev->failure_origin == QN_FAIL_LOCAL || ev->result == QN_R_ERROR) {
        s->local_errors++;
        return;
    }

    if (ev->result == QN_R_OPEN && ev->rtt_us) {
        qn_samples_add(&r->samples, ev->rtt_us);
        qn_hist_add(&s->hist, ev->rtt_us);

        /* Freeze a three-sample baseline used only for sequential probe allocation. */
        if (!s->rtt_baseline_us[idx]) {
            if (r->samples.n >= CF_RTT_CALIBRATION)
                s->rtt_baseline_us[idx] = qn_samples_median(&r->samples);
            return;
        }
        qn_sprt_push(&s->spr[idx],
                     qn_rtt_within_baseline(s->rtt_baseline_us[idx], ev->rtt_us));
    } else {
        qn_samples_lost(&r->samples);
        qn_sprt_push(&s->spr[idx], false);
    }
}

static bool project_arena_array(uint64_t *used, uint64_t count, size_t item_size,
                                size_t alignment)
{
    uint64_t offset, bytes;

    if (!used || !count || !item_size || !alignment ||
        (alignment & (alignment - 1u)) != 0u ||
        *used > UINT64_MAX - (alignment - 1u))
        return false;
    offset = (*used + alignment - 1u) & ~(uint64_t)(alignment - 1u);
    if (count > UINT64_MAX / item_size)
        return false;
    bytes = count * item_size;
    if (offset > UINT64_MAX - bytes)
        return false;
    *used = offset + bytes;
    return true;
}

static bool scan_environment(qn_scan_environment *environment, const cf_scan *scan)
{
    struct rlimit limit;
    struct sysinfo memory;
    uint64_t projected;
    uint32_t blocks;
    long cpus;

    memset(environment, 0, sizeof *environment);
    environment->total_addresses = scan->set.total;
    environment->input_prefixes = scan->input_prefixes;
    environment->normalized_prefixes = scan->normalized_prefixes;
    environment->input_addresses = scan->input_addresses;
    environment->duplicate_addresses = scan->duplicate_addresses;
    environment->candidate_bytes = sizeof(cf_record) + sizeof(uint32_t) * 4u +
                                   sizeof(qn_sprt);
    environment->candidate_fixed_bytes = 6u * 63u;
    environment->verifier_slot_bytes = qn_verify_slot_bytes();
    environment->verifier_result_bytes = qn_verify_result_bytes();
    environment->verifier_fixed_bytes = qn_verify_fixed_bytes();
    projected = scan->arena ? scan->arena->used : 0u;
    blocks = qn_bandit_block_count(scan->set.total, 256u);
    if (!blocks ||
        !project_arena_array(&projected, blocks, sizeof(qn_block),
                             _Alignof(qn_block)) ||
        (scan->cfg->history &&
         !project_arena_array(&projected, 8192u, sizeof(qn_store_entry),
                              _Alignof(qn_store_entry))))
        return false;
    environment->working_bytes = projected;
    environment->working_capacity_bytes = scan->arena ? scan->arena->cap : 0u;
    {
        long page = sysconf(_SC_PAGESIZE);

        environment->page_size = page > 0 ? (size_t)page : 4096u;
    }
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0)
        environment->fd_limit = limit.rlim_cur == RLIM_INFINITY
                                    ? UINT32_MAX
                                    : (uint64_t)limit.rlim_cur;
    if (sysinfo(&memory) == 0)
        environment->available_memory_bytes =
            (uint64_t)memory.freeram * (uint64_t)memory.mem_unit;
    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    environment->cpu_count = cpus > 0 && (uint64_t)cpus <= UINT32_MAX
                                 ? (uint32_t)cpus
                                 : 1u;
#if defined(__ANDROID__)
    environment->mobile = true;
#endif
    return true;
}

static void *candidate_array(qn_arena *arena, uint32_t count, size_t element)
{
    if (!count || !element || (size_t)count > SIZE_MAX / element)
        return NULL;
    return qn_arena_alloc(arena, (size_t)count * element, 64u);
}

bool cf_scan_init(cf_scan *s, qn_arena *a, qn_config *cfg)
{
    qn_scan_environment environment;
    qn_scan_request request;

    memset(s, 0, sizeof *s);
    if (pthread_mutex_init(&s->records_lock, NULL) != 0)
        return false;
    s->records_lock_live = true;
    s->arena = a;
    s->cfg   = cfg;
    s->step  = -1;
    s->phase = CF_PHASE_SWEEP;

    if (cfg->ranges_file) {
        qn_cidr_report rep;

        /* One snapshot: the file cannot change between sizing and parsing. */
        if (!qn_cidr_set_load_snapshot(&s->set, a, cfg->ranges_file, &rep, AF_INET)) {
            if (rep.bad_line)
                qn_warn("%s line %u: cannot use '%s'", cfg->ranges_file, rep.bad_line,
                        rep.bad_text);
            qn_warn("%s: %u accepted, %u rejected, %u over capacity; refusing to scan a "
                    "narrowed range set",
                    cfg->ranges_file, rep.accepted, rep.rejected, rep.overflow);
            return false;
        }
        memcpy(s->ranges_digest, rep.digest, sizeof s->ranges_digest);
        s->ranges_bytes = rep.bytes;
        s->input_prefixes = rep.accepted;
    } else {
        qn_sha256 digest;

        if (!qn_cidr_set_init(&s->set, a, qn_cf_v4_n))
            return false;
        qn_sha256_init(&digest);
        for (uint32_t i = 0; i < qn_cf_v4_n; i++) {
            size_t length = strlen(qn_cf_v4[i]);

            if (!qn_cidr_set_add_str(&s->set, qn_cf_v4[i]))
                return false;
            qn_sha256_update(&digest, qn_cf_v4[i], length);
            qn_sha256_update(&digest, "\n", 1u);
            s->ranges_bytes += length + 1u;
        }
        qn_sha256_final(&digest, s->ranges_digest);
        s->input_prefixes = qn_cf_v4_n;
    }
    for (uint32_t i = 0u; i < s->set.n; i++) {
        uint64_t count = qn_prefix_usable(&s->set.v[i], false);

        if (s->input_addresses > UINT64_MAX - count)
            return false;
        s->input_addresses += count;
    }
    qn_cidr_set_seal(&s->set, a);
    if (!s->set.total)
        return false;
    s->normalized_prefixes = s->set.n;
    if (s->input_addresses < s->set.total)
        return false;
    s->duplicate_addresses = s->input_addresses - s->set.total;

    request = cfg->scan;
    if (!scan_environment(&environment, s)) {
        qn_warn("range metadata resource arithmetic overflowed");
        return false;
    }
    if (!qn_scan_plan_resolve(&request, &environment, &cfg->scan_plan)) {
        qn_warn("invalid scan plan: %s", cfg->scan_plan.error);
        return false;
    }
    cfg->scan = request;
    cfg->scan_plan_valid = true;
    cfg->concurrency = cfg->scan_plan.scan_concurrency;
    cfg->verify_concurrency = cfg->scan_plan.verify_concurrency;
    cfg->stability_concurrency = cfg->scan_plan.stability_concurrency;

    {
        uint64_t seed = cfg->effective_seed;
        uint64_t exploration;

        if (!cfg->seed_explicit && !seed)
            seed = qn_rng_entropy();
        cfg->effective_seed = seed;

        if (!qn_bandit_init(&s->bandit, a, s->set.total, 256u, 2u,
                            qn_seed_derive(seed, 0x43462D42414E4449ull)))
            return false;
        if (cfg->scan_plan.selection == QN_SELECTION_STRATIFIED) {
            exploration = cfg->scan_plan.planned_addresses;
        } else if (cfg->scan_plan.selection == QN_SELECTION_HYBRID) {
            exploration = cfg->scan_plan.planned_addresses / 100u *
                          cfg->scan_plan.explore_percent;
            exploration += (cfg->scan_plan.planned_addresses % 100u) *
                           cfg->scan_plan.explore_percent / 100u;
            if ((cfg->scan_plan.planned_addresses % 100u) *
                    cfg->scan_plan.explore_percent % 100u)
                exploration++;
            if (cfg->scan_plan.planned_addresses >= s->bandit.n &&
                exploration < s->bandit.n)
                exploration = s->bandit.n;
            if (exploration > cfg->scan_plan.planned_addresses)
                exploration = cfg->scan_plan.planned_addresses;
        } else {
            exploration = QN_MIN(cfg->scan_plan.planned_addresses,
                                 (uint64_t)s->bandit.n);
        }
        if (!qn_bandit_set_explore_total(&s->bandit, exploration))
            return false;
    }
    qn_perm_init(&s->uniform, s->set.total,
                 qn_seed_derive(cfg->effective_seed, 0x43462D554E49464Full));

    s->cap = (uint32_t)cfg->scan_plan.candidate_capacity;
    s->limit = cfg->scan_plan.mode == QN_SCAN_REACHABLE
                   ? (uint32_t)cfg->scan_plan.reachable_target
                   : 0u;
    if (cfg->scan_plan.estimated_candidate_bytes > SIZE_MAX ||
        !qn_arena_init(&s->candidate_arena,
                       (size_t)cfg->scan_plan.estimated_candidate_bytes))
        return false;
    s->candidate_arena_live = true;
    s->rec = (cf_record *)candidate_array(&s->candidate_arena, s->cap, sizeof *s->rec);
    s->finalist = (uint32_t *)candidate_array(&s->candidate_arena, s->cap,
                                              sizeof *s->finalist);
    s->active = (uint32_t *)candidate_array(&s->candidate_arena, s->cap,
                                            sizeof *s->active);
    s->spr = (qn_sprt *)candidate_array(&s->candidate_arena, s->cap, sizeof *s->spr);
    s->rtt_baseline_us =
        (uint32_t *)candidate_array(&s->candidate_arena, s->cap,
                                    sizeof *s->rtt_baseline_us);
    s->selection_scratch =
        (uint32_t *)candidate_array(&s->candidate_arena, s->cap,
                                    sizeof *s->selection_scratch);
    if (!s->rec || !s->finalist || !s->active || !s->spr || !s->rtt_baseline_us ||
        !s->selection_scratch) {
        qn_arena_free(&s->candidate_arena);
        s->candidate_arena_live = false;
        return false;
    }
    memset(s->rtt_baseline_us, 0, (size_t)s->cap * sizeof *s->rtt_baseline_us);
    if (!qn_topk_attach(&s->keep, s->rec, s->cap, (uint32_t)sizeof(cf_record), cf_sweep_better))
        return false;

    {
#if defined(QN_TASK_CF_TESTING)
        qn_strlcpy(s->oper, "offline-test", sizeof s->oper);
#else
        qn_netinfo ni;

        memset(&ni, 0, sizeof ni);
        if (qn_netinfo_ifaces(&ni))
            qn_netinfo_routes(&ni);
        qn_operator_tag(&ni, s->oper);
#endif
    }

    if (cfg->history) {
        if (!qn_store_init(&s->store, a, 8192u))
            return false;
        s->history_writable = qn_store_load(&s->store, cfg->history);
        if (!s->history_writable)
            snprintf(s->io_warn, sizeof s->io_warn, "could not read the history in %s",
                     cfg->history);
    }

    qn_hist_reset(&s->hist);
    return true;
}

static void active_all(cf_scan *s)
{
    s->nactive = 0;
    for (uint32_t i = 0; i < s->n; i++)
        s->active[s->nactive++] = i;
}

static uint32_t ordered_index(const uint32_t *order, uint32_t position)
{
    return order ? order[position] : position;
}

static uint32_t choose_diverse(cf_scan *s, const uint32_t *order, uint32_t count,
                               uint32_t keep, uint32_t *output)
{
    uint32_t selected = 0u;
    uint32_t reserve = QN_MIN(keep, QN_MAX(keep / 4u, 1u));

    for (uint32_t i = 0u; i < s->cap; i++)
        s->selection_scratch[i] = UINT32_MAX;
    memset(s->rtt_baseline_us, 0, (size_t)s->cap * sizeof *s->rtt_baseline_us);
    for (uint32_t i = 0u; i < count && selected < reserve; i++) {
        uint32_t index = ordered_index(order, i);
        uint32_t block, slot;
        bool found = false;

        if (index >= s->n ||
            !qn_classification_has_tls(qn_cf_record_classification(&s->rec[index])) ||
            s->rec[index].addr.af != AF_INET)
            continue;
        block = s->rec[index].addr.u.v4 >> 8u;
        slot = (uint32_t)(((uint64_t)block * UINT64_C(2654435761)) % s->cap);
        for (uint32_t probe = 0u; probe < s->cap; probe++) {
            uint32_t at = slot + probe;

            if (at >= s->cap)
                at -= s->cap;
            if (s->selection_scratch[at] == block) {
                found = true;
                break;
            }
            if (s->selection_scratch[at] == UINT32_MAX) {
                s->selection_scratch[at] = block;
                break;
            }
        }
        if (!found) {
            output[selected++] = index;
            s->rtt_baseline_us[index] = UINT32_MAX;
        }
    }
    for (uint32_t i = 0u; i < count && selected < keep; i++) {
        uint32_t index = ordered_index(order, i);

        if (index >= s->n || s->rtt_baseline_us[index] == UINT32_MAX)
            continue;
        if (qn_classification_has_tls(qn_cf_record_classification(&s->rec[index]))) {
            output[selected++] = index;
            s->rtt_baseline_us[index] = UINT32_MAX;
        }
    }
    for (uint32_t i = 0u; i < selected; i++)
        s->rtt_baseline_us[output[i]] = 0u;
    return selected;
}

static uint32_t calibration_limit(const cf_scan *s)
{
    uint64_t finalists = s->cfg->scan_plan.finalist_limit;
    uint64_t multiplied = finalists > UINT64_MAX / CF_CALIBRATION_OVERSAMPLE
                              ? UINT64_MAX
                              : finalists * CF_CALIBRATION_OVERSAMPLE;
    uint64_t added = finalists > UINT64_MAX - CF_CALIBRATION_EXTRA
                         ? UINT64_MAX
                         : finalists + CF_CALIBRATION_EXTRA;
    uint64_t target = QN_MAX(multiplied, added);

    target = QN_MIN(target, (uint64_t)s->n);
    return (uint32_t)target;
}

static int record_address_order(const cf_record *a, const cf_record *b)
{
    if (a->addr.af != b->addr.af)
        return a->addr.af < b->addr.af ? -1 : 1;
    if (a->addr.af == AF_INET)
        return a->addr.u.v4 < b->addr.u.v4
                   ? -1
                   : (a->addr.u.v4 > b->addr.u.v4 ? 1 : 0);
    return memcmp(a->addr.u.v6, b->addr.u.v6, sizeof a->addr.u.v6);
}

static bool record_index_precedes(const cf_scan *s, uint32_t left, uint32_t right)
{
    const cf_record *a = &s->rec[left];
    const cf_record *b = &s->rec[right];

    return a->score > b->score ||
           (a->score == b->score && record_address_order(a, b) <= 0);
}

static void sort_record_indices(const cf_scan *s, uint32_t *indices, uint32_t count)
{
    for (uint32_t i = 1u; i < count; i++) {
        uint32_t key = indices[i];
        uint32_t lo = 0u, hi = i;

        while (lo < hi) {
            uint32_t mid = lo + ((hi - lo) >> 1u);

            if (record_index_precedes(s, indices[mid], key))
                lo = mid + 1u;
            else
                hi = mid;
        }
        if (lo != i)
            memmove(&indices[lo + 1u], &indices[lo],
                    (size_t)(i - lo) * sizeof *indices);
        indices[lo] = key;
    }
}

static void finalize_calibrated_finalists(cf_scan *s)
{
    uint32_t keep = (uint32_t)s->cfg->scan_plan.finalist_limit;

    if (!s->rtt_ready)
        return;
    for (uint32_t i = 0u; i < s->ncalibration; i++)
        qn_cf_finalize_rank(&s->rec[s->finalist[i]], s->cfg->scan_plan.rank_by);
    memcpy(s->active, s->finalist,
           (size_t)s->ncalibration * sizeof *s->active);
    sort_record_indices(s, s->active, s->ncalibration);
    s->nfinalist = choose_diverse(s, s->active, s->ncalibration, keep,
                                  s->finalist);
    s->nactive = 0u;
    s->rtt_ready = false;
}

bool cf_scan_next_phase(cf_scan *s)
{
    uint32_t samples = s->cfg->samples ? s->cfg->samples : 1u;

    for (;;) {
        s->step++;

        switch (s->step) {
        case 0:
            s->phase = CF_PHASE_SWEEP;
            s->task  = (qn_task){ cf_next_sweep, cf_on_sweep, s,
                                  s->cfg->scan_plan.planned_addresses, "reach" };
            return true;

        case 1:
            if (!s->n)
                continue;
            s->phase = CF_PHASE_TLS;
            active_all(s);
            s->task = (qn_task){ cf_next_tls, cf_on_tls, s, s->nactive, "handshake" };
            return true;

        case 2: {
            uint32_t keep;

            /* Cheap TLS evidence ranks an oversampled calibration cohort. */
            for (uint32_t i = 0; i < s->n; i++)
                qn_cf_finalize_rank(&s->rec[i], s->cfg->scan_plan.rank_by);
            qn_cf_sort(s->rec, s->n);

            keep = calibration_limit(s);
            s->ncalibration = choose_diverse(s, NULL, s->n, keep, s->finalist);
            s->nfinalist = 0u;
            if (!s->ncalibration)
                continue;

            /* RTT calibration starts from a clean sample window. */
            for (uint32_t i = 0; i < s->ncalibration; i++) {
                memset(&s->rec[s->finalist[i]].samples, 0, sizeof(qn_samples));
                s->rtt_baseline_us[s->finalist[i]] = 0u;
            }

            for (uint32_t i = 0; i < s->ncalibration; i++)
                qn_sprt_init(&s->spr[s->finalist[i]], 500, 900, 50, 50, 3,
                             (uint16_t)QN_MIN(QN_MAX_SAMPLES, samples * 2u));

            memcpy(s->active, s->finalist,
                   (size_t)s->ncalibration * sizeof *s->active);
            s->nactive = s->ncalibration;
            qn_hist_reset(&s->hist);
            s->rtt_ready = true;
            s->rtt_round = 1;
            s->phase     = CF_PHASE_RTT;
            s->task      = (qn_task){ cf_next_rtt, cf_on_rtt, s, s->nactive, "measure" };
            return true;
        }

        default:
            if (s->rtt_ready && s->rtt_round < QN_MIN(QN_MAX_SAMPLES, samples * 2u)) {
                uint32_t k = 0;

                /* Sampling budget goes where the decision is still open. */
                for (uint32_t i = 0; i < s->nactive; i++)
                    if (qn_sprt_status(&s->spr[s->active[i]]) == QN_SPRT_CONTINUE)
                        s->active[k++] = s->active[i];
                s->nactive = k;
                if (s->nactive) {
                    s->rtt_round++;
                    s->phase = CF_PHASE_RTT;
                    s->task  = (qn_task){ cf_next_rtt, cf_on_rtt, s, s->nactive, "measure" };
                    return true;
                }
            }
            finalize_calibrated_finalists(s);
            s->phase = CF_PHASE_DONE;
            return false;
        }
    }
}

/* A failure the user never sees is worse than no file at all. */
static void io_failed(cf_scan *s, const char *what, const char *path)
{
    snprintf(s->io_warn, sizeof s->io_warn, "could not write the %s to %s", what, path);
}

/* Sanitize peer/user fields so control bytes cannot forge line-oriented records. */
static void log_field(char *dst, size_t cap, const char *src)
{
    size_t j = 0;

    if (!cap)
        return;
    if (!src)
        src = "-";
    for (size_t i = 0; src[i] && j + 1u < cap; i++) {
        unsigned char c = (unsigned char)src[i];

        dst[j++] = c >= 0x20u && c != 0x7fu && c != '\t' ? (char)c : '_';
    }
    dst[j] = 0;
}

/* Append-only record of what was observed, so a result can be audited. */
static void log_events(cf_scan *s, const qn_verify_result *vr, uint32_t n)
{
    char  ip[QN_ADDRSTRLEN], oper[QN_OPERATOR_TAG_LEN], sni[256];
    FILE *f;

    if (!s->cfg->event_log)
        return;
    f = fopen(s->cfg->event_log, "a");
    if (!f) {
        io_failed(s, "event log", s->cfg->event_log);
        return;
    }

    log_field(oper, sizeof oper, s->oper);
    log_field(sni, sizeof sni, s->cfg->sni);
    fprintf(f, "# seed=%llu operator=%s sni=%s fp=%u flow=%u idle=%u active=%u hold=%u\n",
            (unsigned long long)s->cfg->effective_seed, oper, sni,
            s->cfg->fingerprint, s->cfg->flow_bytes, s->cfg->idle_ms,
            s->cfg->verify_concurrency, s->cfg->stability_concurrency);

    for (uint32_t i = 0; i < n; i++) {
        const qn_verify_result *v = &vr[i];
        const qn_observation *observation = &v->observation;
        char reason[sizeof observation->terminal.reason];
        char cn[sizeof observation->tls.peer_cn];
        char issuer[sizeof observation->tls.peer_issuer];

        if (!observation->completed)
            continue;

        qn_addr_str(&v->addr, ip, sizeof ip);
        log_field(reason, sizeof reason,
                  observation->terminal.reason[0]
                      ? observation->terminal.reason
                      : "-");
        log_field(cn, sizeof cn,
                  observation->tls.peer_cn[0] ? observation->tls.peer_cn : "-");
        log_field(issuer, sizeof issuer,
                  observation->tls.peer_issuer[0]
                      ? observation->tls.peer_issuer
                      : "-");
        fprintf(f, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t0x%04X\t0x%04X\t%u\t%u\t%u\t%llu\t%u\t%u\t%s\t%s\t%s\t%s\n", ip,
                qn_classification_str(v->classification),
                qn_highest_rung_str(v->classification.highest_rung_reached),
                qn_terminal_outcome_str(v->classification.terminal_outcome),
                qn_failure_origin_str(
                    (qn_failure_origin)observation->terminal.origin),
                observation->terminal.sys_errno,
                observation->terminal.protocol_code, observation->tls.version,
                observation->tls.suite, observation->transport.connect_us,
                observation->tls.handshake_us, observation->http.ttfb_us,
                (unsigned long long)observation->bytes, observation->flow.kbps,
                observation->stability.held_ms,
                observation->edge.colo[0] ? observation->edge.colo : "-",
                reason, cn, issuer);
    }
    {
        bool wrote = ferror(f) == 0;

        if (fclose(f) != 0 || !wrote)
            io_failed(s, "event log", s->cfg->event_log);
    }
}

static void apply_verify_result(cf_scan *scan, uint32_t finalist_index,
                                const qn_verify_result *value, bool have_wall,
                                uint64_t wall_now)
{
    cf_record *record = &scan->rec[scan->finalist[finalist_index]];
    const qn_observation *observation = &value->observation;

    if (!observation->completed)
        return;
    record->highest_rung_reached = (uint8_t)value->classification.highest_rung_reached;
    record->terminal_outcome = (uint8_t)value->classification.terminal_outcome;
    record->tls_version = observation->tls.version;
    record->tls_suite = observation->tls.suite;
    record->handshake_us = observation->tls.handshake_us;
    record->ttfb_us = observation->http.ttfb_us;
    record->bytes = observation->bytes;
    record->kbps = observation->flow.kbps;
    record->idle_held_ms = observation->stability.held_ms;
    record->http_status = observation->http.status;
    memcpy(record->colo, observation->edge.colo, sizeof record->colo);
    qn_strlcpy(record->alpn, observation->tls.alpn, sizeof record->alpn);
    qn_strlcpy(record->verify_reason, observation->terminal.reason,
               sizeof record->verify_reason);
    record->sys_errno = observation->terminal.sys_errno;
    record->failure_origin = observation->terminal.origin;
    record->transport_result = observation->transport.result;
    record->tls_outcome = observation->tls.outcome;
    record->verified = 1u;
    if (scan->cfg->history && scan->history_writable && have_wall)
        record->confidence =
            (uint16_t)qn_store_confidence(&scan->store, &value->addr, wall_now);
}

static void recount_verified(cf_scan *scan)
{
    scan->suspected = 0u;
    scan->inconclusive = 0u;
    scan->local_errors = 0u;
    scan->clean = 0u;
    scan->edges = 0u;
    for (uint32_t i = 0; i < scan->n; i++) {
        qn_classification classification = qn_cf_record_classification(&scan->rec[i]);

        if (classification.terminal_outcome == QN_TERM_INTERFERENCE)
            scan->suspected++;
        if (classification.terminal_outcome != QN_TERM_SUCCESS &&
            classification.terminal_outcome != QN_TERM_LOCAL_ERROR)
            scan->inconclusive++;
        if (classification.terminal_outcome == QN_TERM_LOCAL_ERROR)
            scan->local_errors++;
        if (qn_classification_has_tls(classification))
            scan->clean++;
        if (qn_classification_has_marker(classification))
            scan->edges++;
    }
}

bool cf_scan_verify(cf_scan *s)
{
    qn_verify_cfg cfg;
    qn_addr *addresses = NULL;
    qn_verify_result *results = NULL;
    uint32_t total = s->nfinalist;
    uint32_t batch = s->cfg->scan_plan.verification_batch_size;
    uint64_t wall_now = 0u;
    size_t address_bytes;
    size_t result_bytes;
    bool have_wall;

    if (s->verified)
        return true;
    if (!total) {
        s->verified = true;
        s->verify_state = (uint8_t)QN_VERIFY_COMPLETE;
        return true;
    }
    if (!batch || batch > total)
        batch = total;
    if (!qn_size_mul((size_t)batch, sizeof *addresses, &address_bytes) ||
        !qn_size_mul((size_t)batch, sizeof *results, &result_bytes)) {
        s->verify_errno = EOVERFLOW;
        s->verify_state = (uint8_t)QN_VERIFY_INFRA_FAILURE;
        return false;
    }
    addresses = (qn_addr *)malloc(address_bytes);
    results = (qn_verify_result *)calloc(1u, result_bytes);
    if (!addresses || !results) {
        free(addresses);
        free(results);
        s->verify_errno = ENOMEM;
        s->verify_state = (uint8_t)QN_VERIFY_INFRA_FAILURE;
        return false;
    }

    qn_verify_defaults(&cfg);
    cfg.seed = s->cfg->effective_seed;
    cfg.deterministic = s->cfg->seed_explicit;
    cfg.sni = s->cfg->sni;
    cfg.fp = (qn_tls_fp)s->cfg->fingerprint;
    cfg.profile = s->cfg->profile_instance;
    cfg.cert_strict = s->cfg->cert_strict;
    cfg.timeout_ms = s->cfg->timeout_ms;
    cfg.concurrency = QN_MAX(s->cfg->verify_concurrency, 1u);
    cfg.stability_concurrency = s->cfg->stability_concurrency;
    cfg.want_bytes = s->cfg->deep ? s->cfg->flow_bytes : 0u;
    cfg.idle_ms = s->cfg->deep ? s->cfg->idle_ms : 0u;
    cfg.cancel = s->cancel;
    cfg.progress_done = s->verify_done;
    cfg.progress_total = s->verify_total;
    cfg.progress_grand_total = total;
    have_wall = qn_wall_now(&wall_now);

    for (uint32_t offset = 0u; offset < total;) {
        uint32_t count = QN_MIN(batch, total - offset);
        qn_verify_status status;

        memset(results, 0, (size_t)count * sizeof *results);
        for (uint32_t i = 0u; i < count; i++) {
            uint32_t selected = s->finalist[offset + i];

            if (selected >= s->n) {
                s->verify_errno = EINVAL;
                s->verify_state = (uint8_t)QN_VERIFY_INFRA_FAILURE;
                free(addresses);
                free(results);
                return false;
            }
            addresses[i] = s->rec[selected].addr;
        }
        cfg.progress_base = offset;
        status = qn_verify_run(&cfg, addresses, count, results);
        s->verify_state = (uint8_t)status.state;
        s->verify_attempted += status.attempted;
        s->verify_completed += status.completed;
        s->verify_errno = status.fatal_errno;
        if (status.state != QN_VERIFY_COMPLETE) {
            free(addresses);
            free(results);
            return false;
        }
        log_events(s, results, count);
        if (s->records_lock_live)
            pthread_mutex_lock(&s->records_lock);
        for (uint32_t i = 0u; i < count; i++) {
            const qn_observation *observation = &results[i].observation;
            qn_failure_origin origin =
                (qn_failure_origin)observation->terminal.origin;

            if (s->cfg->history && s->history_writable && have_wall &&
                observation->completed &&
                (origin == QN_FAIL_NONE || origin == QN_FAIL_PEER ||
                 origin == QN_FAIL_PATH))
                qn_store_observe(&s->store, &results[i].addr, s->oper,
                                 qn_classification_has_marker(results[i].classification),
                                 observation->tls.handshake_us, wall_now);
            apply_verify_result(s, offset + i, &results[i], have_wall, wall_now);
        }
        if (s->records_lock_live)
            pthread_mutex_unlock(&s->records_lock);
        offset += count;
    }
    if (s->cfg->history && s->history_writable && have_wall &&
        !qn_store_save(&s->store, s->cfg->history))
        io_failed(s, "history", s->cfg->history);
    if (s->records_lock_live)
        pthread_mutex_lock(&s->records_lock);
    recount_verified(s);
    if (s->records_lock_live)
        pthread_mutex_unlock(&s->records_lock);
    s->verified = true;
    s->verify_state = (uint8_t)QN_VERIFY_COMPLETE;
    free(addresses);
    free(results);
    return true;
}

void cf_scan_finish(cf_scan *s)
{
    if (s->records_lock_live)
        pthread_mutex_lock(&s->records_lock);
    for (uint32_t i = 0; i < s->n; i++)
        qn_cf_finalize_rank(&s->rec[i], s->cfg->scan_plan.rank_by);
    qn_cf_sort(s->rec, s->n);
    s->phase = CF_PHASE_DONE;
    if (s->records_lock_live)
        pthread_mutex_unlock(&s->records_lock);
}

void cf_scan_account_phase(cf_scan *s, const qn_engine_finalization *finalization)
{
    if (!s || !finalization || s->phase != CF_PHASE_SWEEP)
        return;
    s->sweep_stats = finalization->stats;
}

void cf_scan_destroy(cf_scan *s)
{
    if (!s)
        return;
    if (s->candidate_arena_live)
        qn_arena_free(&s->candidate_arena);
    if (s->records_lock_live)
        pthread_mutex_destroy(&s->records_lock);
    s->candidate_arena_live = false;
    s->records_lock_live = false;
    s->rec = NULL;
    s->finalist = NULL;
    s->active = NULL;
    s->spr = NULL;
    s->rtt_baseline_us = NULL;
    s->selection_scratch = NULL;
}
