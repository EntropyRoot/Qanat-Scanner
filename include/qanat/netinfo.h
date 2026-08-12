#ifndef QANAT_NETINFO_H
#define QANAT_NETINFO_H

#include "qanat/qanat.h"

#define QN_MAX_IFACES 12
#define QN_MAX_DNS    4

typedef enum {
    QN_LINK_UNKNOWN = 0,
    QN_LINK_WIFI,
    QN_LINK_CELL,
    QN_LINK_VPN,
    QN_LINK_LOOPBACK,
    QN_LINK_ETHER
} qn_link_kind;

const char *qn_link_kind_str(qn_link_kind k);

typedef enum {
    QN_DIAG_NOT_RUN = 0,
    QN_DIAG_POSITIVE,
    QN_DIAG_NEGATIVE,
    QN_DIAG_INCONCLUSIVE
} qn_diag_state;

const char *qn_diag_state_str(qn_diag_state state);

typedef struct {
    char     name[16];
    qn_addr  addr;
    qn_addr  netmask;
    uint8_t  prefix_bits;
    uint8_t  kind;
    uint8_t  up;
    uint8_t  has_v4;
    uint32_t mtu;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
} qn_iface;

typedef struct {
    qn_iface iface[QN_MAX_IFACES];
    uint32_t niface;

    qn_addr  gateway;
    bool     has_gateway;
    char     default_iface[16];

    qn_addr  dns[QN_MAX_DNS];
    uint32_t ndns;

    qn_addr  public_v4;
    bool     has_public;
    char     public_colo[4];

    uint32_t gw_rtt_us;
    uint32_t dns_rtt_us;
    uint32_t inet_rtt_us;

    bool dns_divergent;
    bool captive_portal;
    uint8_t gateway_state;
    uint8_t internet_state;
    uint8_t public_state;
    uint8_t dns_state;
    uint8_t captive_state;
} qn_netinfo;

#define QN_OPERATOR_TAG_LEN 24

/* Stable label for the path a run was taken on, from local signals only. */
void qn_operator_tag(const qn_netinfo *ni, char out[QN_OPERATOR_TAG_LEN]);

bool qn_netinfo_ifaces(qn_netinfo *ni);
bool qn_netinfo_routes(qn_netinfo *ni);
bool qn_netinfo_dns(qn_netinfo *ni);
void qn_netinfo_probe(qn_netinfo *ni, uint32_t timeout_ms);
void qn_netinfo_collect(qn_netinfo *ni, uint32_t timeout_ms);

/* The interface carrying the default route, or NULL. */
const qn_iface *qn_netinfo_primary(const qn_netinfo *ni);

/* Derives the local /24-or-wider sweep range from the primary link. */
bool qn_netinfo_local_prefix(const qn_netinfo *ni, char *out, size_t cap);

#endif /* QANAT_NETINFO_H */
