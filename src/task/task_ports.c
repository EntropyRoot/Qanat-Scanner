#include "qanat/task.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

const char *port_phase_str(port_phase p)
{
    switch (p) {
    case PORT_PHASE_SWEEP:  return "sweep";
    case PORT_PHASE_RETRY:  return "confirm";
    case PORT_PHASE_BANNER: return "banner";
    default:                return "done";
    }
}

bool qn_parse_ports(const char *spec, uint16_t *out, uint32_t cap, uint32_t *n)
{
    uint8_t     seen[65536u / 8u];
    const char *p = spec;

    *n = 0;
    if (!spec || !*spec || !strcmp(spec, "-") || !strcmp(spec, "all")) {
        if (cap < 65535u)
            return false;
        for (uint32_t v = 1; v <= 65535; v++)
            out[(*n)++] = (uint16_t)v;
        return true;
    }
    if (!strcmp(spec, "top")) {
        uint32_t        cnt;
        const uint16_t *t = qn_top_ports(&cnt);
        if (cap < cnt)
            return false;
        for (uint32_t i = 0; i < cnt; i++)
            out[(*n)++] = t[i];
        return true;
    }

    memset(seen, 0, sizeof seen);
    while (*p) {
        char         *end;
        unsigned long lo, hi;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p < '0' || *p > '9')
            return false;

        errno = 0;
        lo = strtoul(p, &end, 10);
        if (end == p || errno == ERANGE || lo < 1u || lo > 65535u)
            return false;
        p = end;
        while (*p == ' ' || *p == '\t')
            p++;

        hi = lo;
        if (*p == '-') {
            /* Open-ended or whitespace-split ranges are ambiguous and unsafe. */
            p++;
            if (*p < '0' || *p > '9')
                return false;
            errno = 0;
            hi = strtoul(p, &end, 10);
            if (end == p || errno == ERANGE || hi < lo || hi > 65535u)
                return false;
            p = end;
            while (*p == ' ' || *p == '\t')
                p++;
        }

        for (unsigned long v = lo; v <= hi; v++) {
            uint8_t mask = (uint8_t)(1u << (v & 7u));

            if (seen[v >> 3] & mask)
                continue;
            if (*n >= cap)
                return false;
            seen[v >> 3] |= mask;
            out[(*n)++] = (uint16_t)v;
        }

        if (!*p)
            break;
        if (*p++ != ',')
            return false;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            return false;
    }

    return *n != 0u;
}

static qn_task_next ps_next_sweep(void *ctx, uint64_t idx, qn_job *out)
{
    port_scan *s = (port_scan *)ctx;

    if (idx >= s->nports)
        return QN_TASK_EXHAUSTED;
    out->addr  = s->target;
    /* Permutation avoids an ascending burst pattern. */
    out->port  = s->ports[qn_perm_apply(&s->perm, idx)];
    out->stage = QN_STAGE_TCP;
    return QN_TASK_JOB;
}

static void ps_record_open(port_scan *s, uint16_t port, uint32_t rtt_us)
{
    port_record *r;

    if (s->nopen >= s->opencap)
        return;
    r = &s->open[s->nopen++];
    memset(r, 0, sizeof *r);
    r->port   = port;
    r->result = QN_R_OPEN;
    r->rtt_us = rtt_us;
}

static void ps_on_result(void *ctx, const qn_event *ev)
{
    port_scan *s    = (port_scan *)ctx;
    uint16_t   port = ev->job.port;
    uint8_t    prev = s->pstate[port];

    if (ev->result == QN_R_CANCELLED) {
        if (prev == PORT_ST_UNKNOWN)
            s->pstate[port] = PORT_ST_CANCELLED;
        s->cancelled++;
        return;
    }
    s->scanned++;

    switch (ev->result) {
    case QN_R_OPEN:
        if (prev != PORT_ST_OPEN) {
            s->pstate[port] = PORT_ST_OPEN;
            ps_record_open(s, port, ev->rtt_us);
            if (prev == PORT_ST_FILTERED && s->filtered)
                s->filtered--;
        }
        if (ev->rtt_us)
            qn_hist_add(&s->hist, ev->rtt_us);
        break;

    case QN_R_REFUSED:
        if (prev != PORT_ST_CLOSED) {
            if (prev == PORT_ST_FILTERED && s->filtered)
                s->filtered--;
            s->pstate[port] = PORT_ST_CLOSED;
            s->refused++;
        }
        /* Refusal still proves host liveness. */
        if (ev->rtt_us)
            qn_hist_add(&s->hist, ev->rtt_us);
        break;

    case QN_R_TIMEOUT:
        if (prev == PORT_ST_UNKNOWN) {
            s->pstate[port] = PORT_ST_FILTERED;
            s->filtered++;
        }
        break;

    case QN_R_UNREACH:
        if (prev == PORT_ST_UNKNOWN || prev == PORT_ST_FILTERED) {
            if (prev == PORT_ST_FILTERED && s->filtered)
                s->filtered--;
            s->pstate[port] = PORT_ST_UNREACHABLE;
            s->unreachable++;
        }
        break;

    case QN_R_RESET:
        if (prev == PORT_ST_UNKNOWN || prev == PORT_ST_FILTERED) {
            if (prev == PORT_ST_FILTERED && s->filtered)
                s->filtered--;
            s->pstate[port] = PORT_ST_RESET;
            s->reset++;
        }
        break;

    default:
        if (prev == PORT_ST_UNKNOWN || prev == PORT_ST_FILTERED) {
            if (prev == PORT_ST_FILTERED && s->filtered)
                s->filtered--;
            s->pstate[port] = PORT_ST_LOCAL_ERROR;
            s->local_errors++;
        }
        break;
    }
}

static qn_task_next ps_next_retry(void *ctx, uint64_t idx, qn_job *out)
{
    port_scan *s = (port_scan *)ctx;

    if (idx >= s->nretry)
        return QN_TASK_EXHAUSTED;
    out->addr  = s->target;
    out->port  = s->retry[idx];
    out->stage = QN_STAGE_TCP;
    return QN_TASK_JOB;
}

static qn_task_next ps_next_banner(void *ctx, uint64_t idx, qn_job *out)
{
    port_scan *s = (port_scan *)ctx;

    if (idx >= s->nopen)
        return QN_TASK_EXHAUSTED;
    out->addr  = s->target;
    out->port  = s->open[idx].port;
    out->stage = QN_STAGE_BANNER;
    out->token = (uint32_t)idx;
    return QN_TASK_JOB;
}

static void ps_on_banner(void *ctx, const qn_event *ev)
{
    port_scan   *s = (port_scan *)ctx;
    port_record *r;
    uint32_t     n;

    if (ev->job.token >= s->nopen || !ev->blen)
        return;
    r = &s->open[ev->job.token];
    n = QN_MIN(ev->blen, (uint16_t)(sizeof r->banner - 1));

    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = ev->body[i];
        if (c == '\r' || c == '\n') {
            n = i;
            break;
        }
        r->banner[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
    }
    r->banner[n]  = '\0';
    r->banner_len = (uint8_t)n;
}

bool port_scan_init(port_scan *s, qn_arena *a, const qn_config *cfg)
{
    uint16_t *scratch;

    memset(s, 0, sizeof *s);
    s->cfg   = cfg;
    s->step  = -1;
    s->phase = PORT_PHASE_SWEEP;

    if (!cfg->target || !qn_resolve(cfg->target, cfg->v6, &s->target))
        return false;
    qn_addr_str(&s->target, s->target_str, sizeof s->target_str);

    scratch = QN_ARENA_ARRAY(a, uint16_t, 65536);
    if (!scratch)
        return false;
    if (!qn_parse_ports(cfg->port_spec, scratch, 65536, &s->nports))
        return false;

    s->ports  = scratch;
    s->pstate = QN_ARENA_ARRAY(a, uint8_t, 65536);
    s->retry  = QN_ARENA_ARRAY(a, uint16_t, 65536);
    if (!s->pstate || !s->retry)
        return false;

    memset(s->pstate, 0, 65536u * sizeof *s->pstate);
    {
        uint32_t unique = 0;

        for (uint32_t i = 0; i < s->nports; i++) {
            uint16_t port = s->ports[i];
            if (!s->pstate[port]) {
                s->pstate[port] = 1;
                s->ports[unique++] = port;
            }
        }
        s->nports = unique;
        memset(s->pstate, 0, 65536u * sizeof *s->pstate);
    }

    s->opencap = s->nports;
    s->open    = QN_ARENA_ARRAY(a, port_record, s->opencap);
    if (!s->open)
        return false;

    {
        uint64_t master = cfg->effective_seed;

        if (!cfg->seed_explicit && !master)
            master = qn_rng_entropy();
        qn_perm_init(&s->perm, s->nports,
                     qn_seed_derive(master, 0x504F52542D4F5244ull));
    }
    qn_hist_reset(&s->hist);
    return true;
}

static void ps_build_retry(port_scan *s)
{
    s->nretry = 0;
    for (uint32_t i = 0; i < s->nports; i++) {
        uint16_t port = s->ports[i];
        if (s->pstate[port] == PORT_ST_FILTERED)
            s->retry[s->nretry++] = port;
    }
}

bool port_scan_next_phase(port_scan *s)
{
    for (;;) {
        s->step++;

        if (s->step == 0) {
            s->phase        = PORT_PHASE_SWEEP;
            s->task = (qn_task){ ps_next_sweep, ps_on_result, s, s->nports, "sweep" };
            return true;
        }

        if (s->retry_round < s->cfg->retries) {
            s->retry_round++;
            ps_build_retry(s);
            if (!s->nretry)
                continue;
            s->phase        = PORT_PHASE_RETRY;
            s->task = (qn_task){ ps_next_retry, ps_on_result, s, s->nretry, "confirm" };
            return true;
        }

        if (s->phase != PORT_PHASE_BANNER && s->nopen) {
            s->phase        = PORT_PHASE_BANNER;
            s->task = (qn_task){ ps_next_banner, ps_on_banner, s, s->nopen, "banner" };
            return true;
        }

        s->phase = PORT_PHASE_DONE;
        return false;
    }
}

static int port_cmp(const void *a, const void *b)
{
    uint16_t x = ((const port_record *)a)->port;
    uint16_t y = ((const port_record *)b)->port;
    return (x > y) - (x < y);
}

void port_scan_finish(port_scan *s)
{
    if (s->nopen > 1)
        qsort(s->open, s->nopen, sizeof *s->open, port_cmp);
    s->phase = PORT_PHASE_DONE;
}
