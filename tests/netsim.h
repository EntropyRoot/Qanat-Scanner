#ifndef QANAT_NETSIM_H
#define QANAT_NETSIM_H

#include <stdint.h>
#include <stdlib.h>

/* The shapes a censored path actually takes, reproduced on loopback. */
typedef enum {
    QN_NETSIM_RST_ON_CONNECT = 0, /* SYN answered, then killed */
    QN_NETSIM_ACCEPT_SILENT,      /* connects, then says nothing */
    QN_NETSIM_RST_AFTER_BYTES,    /* the common one: dies mid-handshake */
    QN_NETSIM_EOF_AFTER_BYTES,    /* clean close, which is not interference */
    QN_NETSIM_GARBAGE,            /* answers a ClientHello with non-TLS */
    QN_NETSIM_DRIP                /* one byte at a time */
} qn_netsim_mode;

typedef struct qn_netsim qn_netsim;

qn_netsim *qn_netsim_start(qn_netsim_mode mode, uint32_t after_bytes);
uint16_t   qn_netsim_port(const qn_netsim *s);
uint32_t   qn_netsim_accepted(qn_netsim *s);
void       qn_netsim_stop(qn_netsim *s);

#endif /* QANAT_NETSIM_H */
