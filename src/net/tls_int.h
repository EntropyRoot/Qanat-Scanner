#ifndef QANAT_TLS_INT_H
#define QANAT_TLS_INT_H

#include "qanat/tls.h"

#include "certscan.h"

#define REC_HDR 5

#define RT_CCS   20
#define RT_ALERT 21
#define RT_HS    22
#define RT_APP   23

#define HS_SERVER_HELLO  2
#define HS_NEW_TICKET    4
#define HS_ENCRYPTED_EXT 8
#define HS_CERT          11
#define HS_SERVER_KX     12
#define HS_CERT_REQ      13
#define HS_HELLO_DONE    14
#define HS_CERT_VERIFY   15
#define HS_CLIENT_KX     16
#define HS_FINISHED      20
#define HS_KEY_UPDATE    24

enum {
    T12_EXPECT_CERT = 0,
    T12_EXPECT_SERVER_KX,
    T12_EXPECT_REQ_OR_DONE,
    T12_FLIGHT_DONE
};

/* tls12.c */
bool      qn_tls12_suite(uint16_t suite, qn_hash_id *h, qn_aead_id *a);
qn_tls_rc qn_tls12_setup(qn_tls_session *s);
qn_tls_rc qn_tls12_dispatch(qn_tls_session *s, qn_tls_io *io);
qn_tls_rc qn_tls13_dispatch(qn_tls_session *s, qn_tls_io *io);
qn_tls_rc qn_tls12_open(qn_tls_session *s, uint8_t type, size_t *plen);
int       qn_tls12_seal(qn_tls_session *s, uint8_t type, const uint8_t *data, size_t len,
                        uint8_t *out, size_t cap);
void      qn_tls12_on_ccs(qn_tls_session *s);

#endif /* QANAT_TLS_INT_H */
