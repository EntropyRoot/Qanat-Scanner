#include "qanat/stats.h"

#include "qanat/util.h"

#include <string.h>
#include <sys/socket.h>

void qn_samples_add(qn_samples *s, uint32_t rtt_us)
{
    if (s && s->n < QN_MAX_SAMPLES)
        s->rtt_us[s->n++] = rtt_us;
}

void qn_samples_lost(qn_samples *s)
{
    if (s && s->lost < 255)
        s->lost++;
}

static uint32_t sorted_copy(const qn_samples *s, uint32_t *out)
{
    uint32_t n;

    if (!s || !out)
        return 0;
    n = QN_MIN((uint32_t)s->n, (uint32_t)QN_MAX_SAMPLES);

    memcpy(out, s->rtt_us, n * sizeof *out);
    for (uint32_t i = 1; i < n; i++) { /* n <= 12: insertion sort wins */
        uint32_t v = out[i];
        uint32_t j = i;
        while (j && out[j - 1] > v) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = v;
    }
    return n;
}

uint32_t qn_samples_min(const qn_samples *s)
{
    uint32_t m = 0;

    if (!s)
        return 0;
    for (uint32_t i = 0; i < s->n; i++)
        if (!m || s->rtt_us[i] < m)
            m = s->rtt_us[i];
    return m;
}

uint32_t qn_samples_median(const qn_samples *s)
{
    uint32_t v[QN_MAX_SAMPLES];
    uint32_t n = sorted_copy(s, v);

    if (!n)
        return 0;
    return (n & 1u) ? v[n / 2] : (uint32_t)(((uint64_t)v[n / 2 - 1] + v[n / 2]) / 2u);
}

uint32_t qn_samples_p90(const qn_samples *s)
{
    uint32_t v[QN_MAX_SAMPLES];
    uint32_t n = sorted_copy(s, v);

    if (!n)
        return 0;
    /* Nearest-rank P90: ceil(0.9*n), converted to a zero-based index. */
    return v[(n * 9u - 1u) / 10u];
}

uint32_t qn_samples_delta_mean(const qn_samples *s)
{
    uint64_t acc = 0;

    if (!s || s->n < 2)
        return 0;
    for (uint32_t i = 1; i < s->n; i++) {
        uint32_t a = s->rtt_us[i - 1], b = s->rtt_us[i];
        acc += (a > b) ? (a - b) : (b - a);
    }
    return (uint32_t)(acc / (s->n - 1u));
}

uint8_t qn_samples_loss_pct(const qn_samples *s)
{
    uint32_t total;

    if (!s)
        return 100;
    total = (uint32_t)s->n + s->lost;
    if (!total)
        return 100;
    return (uint8_t)((s->lost * 100u) / total);
}

uint32_t qn_cf_score_policy(cf_record *r, qn_rank_policy policy)
{
    uint32_t edge = 0u, latency = 0u, stability = 0u, confidence, throughput;
    uint32_t tunnel = 0u;
    uint32_t median_quality, p90_quality, jitter_quality, loss_quality;

    if (!r)
        return 0u;
    r->score_version = QN_SCORE_VERSION;
    r->score_edge = r->score_latency = r->score_stability = 0u;
    r->score_confidence = r->score_throughput = r->score_tunnel = 0u;
    if (r->terminal_outcome != QN_TERM_SUCCESS)
        return 0u;
    switch ((qn_highest_rung)r->highest_rung_reached) {
    case QN_RUNG_STABLE:  edge = 4000u; break;
    case QN_RUNG_FLOWING: edge = 3700u; break;
    case QN_RUNG_EDGE:    edge = 3400u; break;
    case QN_RUNG_HTTP:    edge = 2800u; break;
    case QN_RUNG_TLS:     edge = 2200u; break;
    case QN_RUNG_TCP:     edge = 800u; break;
    default:              return 0u;
    }
    if (r->verified && r->colo[0])
        edge += 500u;
    median_quality = !r->rtt_med_us || r->rtt_med_us >= 600000u
                         ? 0u
                         : 1500u - (uint32_t)((uint64_t)r->rtt_med_us * 1500u / 600000u);
    p90_quality = !r->rtt_p90_us || r->rtt_p90_us >= 900000u
                      ? 0u
                      : 1000u - (uint32_t)((uint64_t)r->rtt_p90_us * 1000u / 900000u);
    latency = median_quality + p90_quality;
    jitter_quality = r->rtt_delta_mean_us >= 150000u
                         ? 0u
                         : 750u - (uint32_t)((uint64_t)r->rtt_delta_mean_us * 750u / 150000u);
    loss_quality = r->loss_pct >= 100u ? 0u : (uint32_t)(100u - r->loss_pct) * 7u;
    stability = jitter_quality + loss_quality;
    if (r->highest_rung_reached == QN_RUNG_STABLE && r->idle_held_ms)
        stability += 50u;
    confidence = r->confidence > 1000u ? 1000u : r->confidence;
    throughput = r->kbps >= 100000u ? 1000u : r->kbps / 100u;
    if (r->tunnel_state == QN_TUNNEL_PASSED)
        tunnel = 30000u;
    else if (qn_tunnel_state_failed((qn_tunnel_state)r->tunnel_state))
        tunnel = 0u;
    else
        tunnel = 15000u;
    r->score_edge = (uint16_t)edge;
    r->score_latency = (uint16_t)latency;
    r->score_stability = (uint16_t)stability;
    r->score_confidence = (uint16_t)confidence;
    r->score_throughput = (uint16_t)throughput;
    r->score_tunnel = (uint16_t)tunnel;
    switch (policy) {
    case QN_RANK_LATENCY:
        return tunnel + edge + latency * 2u + stability / 2u + confidence / 2u;
    case QN_RANK_STABILITY:
        return tunnel + edge + stability * 2u + latency / 2u + confidence;
    case QN_RANK_THROUGHPUT:
        return tunnel + edge + throughput * 3u + latency / 2u + stability / 2u;
    case QN_RANK_BALANCED:
    default:
        return tunnel + edge + latency + stability + confidence + throughput;
    }
}

uint32_t qn_cf_score(const cf_record *r)
{
    cf_record copy;

    if (!r)
        return 0u;
    copy = *r;
    return qn_cf_score_policy(&copy, QN_RANK_BALANCED);
}

bool qn_samples_median_ci90(const qn_samples *s, uint32_t *lo_us, uint32_t *hi_us)
{
    /* Narrowest order-statistic interval with binomial coverage >= 90%. */
    static const uint8_t rank[QN_MAX_SAMPLES + 1] = { 0, 0, 0, 0, 0, 1, 1,
                                                      1, 2, 2, 2, 3, 3 };
    uint32_t v[QN_MAX_SAMPLES];
    uint32_t n;
    uint8_t  k;

    if (!lo_us || !hi_us)
        return false;
    *lo_us = 0;
    *hi_us = 0;
    n = sorted_copy(s, v);
    if (n < 5u)
        return false;

    k      = rank[n];
    *lo_us = v[k - 1u];
    *hi_us = v[n - k];
    return true;
}

bool qn_rtt_within_baseline(uint32_t baseline_us, uint32_t sample_us)
{
    uint64_t ceiling;

    if (!baseline_us || !sample_us)
        return false;
    ceiling = (uint64_t)baseline_us + baseline_us / 2u + 5000u;
    return sample_us <= ceiling;
}

void qn_cf_finalize(cf_record *r)
{
    qn_cf_finalize_rank(r, QN_RANK_BALANCED);
}

void qn_cf_finalize_rank(cf_record *r, qn_rank_policy policy)
{
    if (!r)
        return;
    r->rtt_min_us = qn_samples_min(&r->samples);
    r->rtt_med_us = qn_samples_median(&r->samples);
    r->rtt_p90_us = qn_samples_p90(&r->samples);
    r->rtt_ci90_valid = qn_samples_median_ci90(&r->samples, &r->rtt_ci90_lo_us,
                                               &r->rtt_ci90_hi_us);
    r->rtt_delta_mean_us = qn_samples_delta_mean(&r->samples);
    r->loss_pct          = qn_samples_loss_pct(&r->samples);
    r->score             = qn_cf_score_policy(r, policy);
}

static int address_order(const qn_addr *a, const qn_addr *b)
{
    if (a->af != b->af)
        return a->af < b->af ? -1 : 1;
    if (a->af == AF_INET)
        return a->u.v4 < b->u.v4 ? -1 : (a->u.v4 > b->u.v4 ? 1 : 0);
    return memcmp(a->u.v6, b->u.v6, sizeof a->u.v6);
}

void qn_cf_sort(cf_record *v, uint32_t n)
{
    for (uint32_t i = 1; i < n; i++) {
        cf_record key = v[i];
        uint32_t  lo = 0, hi = i;

        while (lo < hi) {
            uint32_t mid = lo + ((hi - lo) >> 1);
            if (v[mid].score > key.score ||
                (v[mid].score == key.score &&
                 address_order(&v[mid].addr, &key.addr) <= 0))
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo != i)
            memmove(&v[lo + 1], &v[lo], (i - lo) * sizeof *v);
        v[lo] = key;
    }
}

void qn_hist_reset(qn_hist *h)
{
    if (h)
        memset(h, 0, sizeof *h);
}

/* Log-spaced from 1 ms with finer low-end buckets. */
static uint32_t hist_bin(uint32_t rtt_us)
{
    uint32_t ms = rtt_us / 1000u;
    uint32_t b;

    if (ms < 2u)
        return ms;
    b = (uint32_t)(31 - __builtin_clz(ms)) * 2u;
    if (ms >= (3u << (b / 2u - 1u)))
        b++;
    return b >= QN_HIST_BINS ? QN_HIST_BINS - 1 : b;
}

void qn_hist_add(qn_hist *h, uint32_t rtt_us)
{
    uint32_t b = hist_bin(rtt_us);

    if (!h)
        return;
    h->bin[b]++;
    h->total++;
    if (h->bin[b] > h->max_bin)
        h->max_bin = h->bin[b];
}

void qn_hist_bin_range(uint32_t bin, uint32_t *lo_us, uint32_t *hi_us)
{
    uint32_t lo_ms, hi_ms;

    if (!lo_us || !hi_us)
        return;
    *lo_us = 0;
    *hi_us = 0;
    if (bin >= QN_HIST_BINS)
        return;
    lo_ms = (bin < 2) ? bin : ((bin & 1u) ? (3u << (bin / 2u - 1u)) : (1u << (bin / 2u)));
    hi_ms = (bin + 1 < 2) ? (bin + 1)
                                    : (((bin + 1) & 1u) ? (3u << ((bin + 1) / 2u - 1u))
                                                        : (1u << ((bin + 1) / 2u)));
    *lo_us = lo_ms * 1000u;
    *hi_us = hi_ms * 1000u;
}

void qn_spark_reset(qn_spark *s)
{
    memset(s, 0, sizeof *s);
}

void qn_spark_push(qn_spark *s, uint32_t v)
{
    s->v[s->head] = v;
    s->head       = (s->head + 1u) % QN_SPARK_LEN;
}

uint32_t qn_spark_at(const qn_spark *s, uint32_t i)
{
    return s->v[(s->head + i) % QN_SPARK_LEN];
}
