#ifndef QANAT_SPRT_H
#define QANAT_SPRT_H

#include "qanat/util.h"

/* Wald SPRT: spend samples where the decision is still open. */

typedef enum {
    QN_SPRT_CONTINUE = 0,
    QN_SPRT_ACCEPT, /* behaves like the good hypothesis */
    QN_SPRT_REJECT  /* behaves like the bad one */
} qn_sprt_state;

typedef struct {
    int32_t  llr; /* milli-nats */
    int32_t  up, down;
    int32_t  accept, reject;
    uint16_t n, good;
    uint16_t nmin, nmax;
} qn_sprt;

/* Probabilities and error rates are per mille. */
void          qn_sprt_init(qn_sprt *s, uint32_t p0, uint32_t p1, uint32_t alpha, uint32_t beta,
                           uint16_t nmin, uint16_t nmax);
qn_sprt_state qn_sprt_push(qn_sprt *s, bool good);
qn_sprt_state qn_sprt_status(const qn_sprt *s);
const char   *qn_sprt_state_str(qn_sprt_state st);

#endif /* QANAT_SPRT_H */
