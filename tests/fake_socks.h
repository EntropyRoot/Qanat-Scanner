#ifndef QANAT_TEST_FAKE_SOCKS_H
#define QANAT_TEST_FAKE_SOCKS_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    QN_FAKE_SOCKS_SUCCESS = 0,
    QN_FAKE_SOCKS_AUTH,
    QN_FAKE_SOCKS_SHORT,
    QN_FAKE_SOCKS_FRAGMENTED,
    QN_FAKE_SOCKS_CONNECT_ERROR,
    QN_FAKE_SOCKS_MIDCLOSE,
    QN_FAKE_SOCKS_OVERSIZED
} qn_fake_socks_mode;

typedef struct qn_fake_socks qn_fake_socks;

qn_fake_socks *qn_fake_socks_start(qn_fake_socks_mode mode);
uint16_t qn_fake_socks_port(const qn_fake_socks *server);
bool qn_fake_socks_greeting_ok(const qn_fake_socks *server);
bool qn_fake_socks_connect_ok(const qn_fake_socks *server);
void qn_fake_socks_stop(qn_fake_socks *server);

#endif
