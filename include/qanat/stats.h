#ifndef QANAT_STATS_H
#define QANAT_STATS_H

#include "qanat/qanat.h"

void     qn_samples_add(qn_samples *s, uint32_t rtt_us);
void     qn_samples_lost(qn_samples *s);
uint32_t qn_samples_min(const qn_samples *s);
uint32_t qn_samples_median(const qn_samples *s);
uint32_t qn_samples_p90(const qn_samples *s);
/* Mean absolute delta between consecutive RTT observations. */
uint32_t qn_samples_delta_mean(const qn_samples *s);
uint8_t  qn_samples_loss_pct(const qn_samples *s);

/* Distribution-free two-sided median CI90; unavailable below five observations. */
bool qn_samples_median_ci90(const qn_samples *s, uint32_t *lo_us, uint32_t *hi_us);

/* Fixed-baseline predicate used only by the sequential RTT budget gate. */
bool qn_rtt_within_baseline(uint32_t baseline_us, uint32_t sample_us);

/* Versioned component score using evidence, latency, stability, confidence and flow. */
uint32_t qn_cf_score(const cf_record *r);
uint32_t qn_cf_score_policy(cf_record *record, qn_rank_policy policy);

void qn_cf_finalize(cf_record *r);
void qn_cf_finalize_rank(cf_record *record, qn_rank_policy policy);

/* Descending by score; stable for equal scores. */
void qn_cf_sort(cf_record *v, uint32_t n);

#define QN_HIST_BINS 24

/* Log-spaced RTT histogram, 1ms..4s. */
typedef struct {
    uint32_t bin[QN_HIST_BINS];
    uint32_t total;
    uint32_t max_bin;
} qn_hist;

void qn_hist_reset(qn_hist *h);
void qn_hist_add(qn_hist *h, uint32_t rtt_us);
void qn_hist_bin_range(uint32_t bin, uint32_t *lo_us, uint32_t *hi_us);

#define QN_SPARK_LEN 64

typedef struct {
    uint32_t v[QN_SPARK_LEN];
    uint32_t head;
} qn_spark;

void qn_spark_reset(qn_spark *s);
void qn_spark_push(qn_spark *s, uint32_t v);
uint32_t qn_spark_at(const qn_spark *s, uint32_t i);

#endif /* QANAT_STATS_H */
