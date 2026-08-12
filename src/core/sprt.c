/* Wald SPRT in fixed point, so no libm and no floats on the hot path. */

#include "qanat/sprt.h"

#include <string.h>

#define LN2_Q16 45426

static int64_t ln_q16(uint32_t v)
{
    int     k;
    int64_t m, t, t2, s;

    if (v == 0)
        return -(int64_t)20 * 65536;

    k = 31 - __builtin_clz(v);
    m = ((int64_t)v << 16) >> k; /* Q16 mantissa in [1,2) */

    /* ln(m) = 2*atanh((m-1)/(m+1)); |t| <= 1/3 so three terms suffice */
    t  = ((m - 65536) << 16) / (m + 65536);
    t2 = (t * t) >> 16;
    s  = t;
    t  = (t * t2) >> 16;
    s += t / 3;
    t  = (t * t2) >> 16;
    s += t / 5;

    return (int64_t)k * LN2_Q16 + 2 * s;
}

static int32_t ln_ratio_milli(uint32_t num, uint32_t den)
{
    int64_t d = ln_q16(num) - ln_q16(den);
    return (int32_t)((d * 1000) >> 16);
}

void qn_sprt_init(qn_sprt *s, uint32_t p0, uint32_t p1, uint32_t alpha, uint32_t beta,
                  uint16_t nmin, uint16_t nmax)
{
    memset(s, 0, sizeof *s);

    p0    = QN_CLAMP(p0, 1u, 999u);
    p1    = QN_CLAMP(p1, 1u, 999u);
    alpha = QN_CLAMP(alpha, 1u, 499u);
    beta  = QN_CLAMP(beta, 1u, 499u);
    if (p1 <= p0)
        p1 = p0 + 1u > 999u ? 999u : p0 + 1u;

    s->up     = ln_ratio_milli(p1, p0);
    s->down   = ln_ratio_milli(1000u - p1, 1000u - p0);
    s->accept = ln_ratio_milli(1000u - beta, alpha);
    s->reject = ln_ratio_milli(beta, 1000u - alpha);

    s->nmin = nmin ? nmin : 1u;
    s->nmax = nmax > s->nmin ? nmax : s->nmin;
}

qn_sprt_state qn_sprt_status(const qn_sprt *s)
{
    if (s->n < s->nmin)
        return QN_SPRT_CONTINUE;
    if (s->llr >= s->accept)
        return QN_SPRT_ACCEPT;
    if (s->llr <= s->reject)
        return QN_SPRT_REJECT;
    if (s->n >= s->nmax)
        return s->llr >= 0 ? QN_SPRT_ACCEPT : QN_SPRT_REJECT;
    return QN_SPRT_CONTINUE;
}

qn_sprt_state qn_sprt_push(qn_sprt *s, bool good)
{
    if (s->n < 0xFFFFu)
        s->n++;
    if (good && s->good < 0xFFFFu)
        s->good++;

    s->llr += good ? s->up : s->down;

    /* bound the walk so a long run cannot wrap the accumulator */
    s->llr = QN_CLAMP(s->llr, -1000000, 1000000);

    return qn_sprt_status(s);
}

const char *qn_sprt_state_str(qn_sprt_state st)
{
    switch (st) {
    case QN_SPRT_ACCEPT: return "accept";
    case QN_SPRT_REJECT: return "reject";
    default:             return "continue";
    }
}
