#ifndef QANAT_NET_FLOWMETER_H
#define QANAT_NET_FLOWMETER_H

#include "qanat/util.h"

/* Measured transfer behavior stays separate from the request and exposes stalls. */
typedef struct {
    uint64_t requested;         /* bytes the request asked for; 0 means no flow */
    uint64_t received;          /* bytes that actually arrived */
    uint64_t span_ns;           /* request sent until the connection ended */
    uint64_t since_progress_ns; /* end minus the last byte that advanced it */
} qn_flow_sample;

typedef struct {
    uint32_t kbps;         /* only ever set for a completed transfer */
    uint32_t partial_kbps; /* rate over what did arrive, always labelled */
    uint32_t stall_us;
    bool     completed;
    bool     attempted;
} qn_flow_report;

#define QN_FLOW_MIN_SPAN_NS 1000000ull

static inline uint32_t qn_flow_rate_kbps(uint64_t bytes, uint64_t span_ns)
{
    if (span_ns <= QN_FLOW_MIN_SPAN_NS)
        return 0u;
    return (uint32_t)QN_MIN((bytes * 8ull * 1000000ull) / span_ns, (uint64_t)UINT32_MAX);
}

static inline void qn_flow_report_of(const qn_flow_sample *s, qn_flow_report *out)
{
    memset(out, 0, sizeof *out);
    if (!s->requested)
        return;

    out->attempted = true;
    out->completed = s->received >= s->requested;

    if (out->completed) {
        out->kbps = qn_flow_rate_kbps(s->received, s->span_ns);
        return;
    }

    out->partial_kbps = qn_flow_rate_kbps(s->received, s->span_ns);
    out->stall_us     = (uint32_t)QN_MIN(
        (s->since_progress_ns ? s->since_progress_ns : s->span_ns) / 1000ull,
        (uint64_t)UINT32_MAX);
}

#endif /* QANAT_NET_FLOWMETER_H */
