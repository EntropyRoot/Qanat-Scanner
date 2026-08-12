#ifndef QANAT_PROFILE_H
#define QANAT_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "qanat/tls.h"

#define QN_PROFILE_MAX_H2_SETTINGS 6u
#define QN_PROFILE_MAX_HEADERS     12u
#define QN_PROFILE_INSTANCE_VERSION 2u

typedef qn_tls_fp qn_tls_hello_profile;

typedef struct {
    uint16_t id;
    uint32_t value;
} qn_h2_setting;

typedef struct {
    qn_h2_setting setting[QN_PROFILE_MAX_H2_SETTINGS];
    uint8_t       nsettings;
    uint32_t      connection_window;
} qn_h2_settings_profile;

typedef enum {
    QN_PSEUDO_METHOD = 0,
    QN_PSEUDO_AUTHORITY,
    QN_PSEUDO_SCHEME,
    QN_PSEUDO_PATH
} qn_pseudo_header;

typedef enum {
    QN_HEADER_CONNECTION = 0,
    QN_HEADER_USER_AGENT,
    QN_HEADER_ACCEPT,
    QN_HEADER_ACCEPT_ENCODING,
    QN_HEADER_ACCEPT_LANGUAGE,
    QN_HEADER_UPGRADE_INSECURE,
    QN_HEADER_SEC_FETCH_DEST,
    QN_HEADER_SEC_FETCH_MODE,
    QN_HEADER_SEC_FETCH_SITE,
    QN_HEADER_SEC_FETCH_USER,
    QN_HEADER_SEC_CH_UA,
    QN_HEADER_SEC_CH_UA_MOBILE,
    QN_HEADER_SEC_CH_UA_PLATFORM,
    QN_HEADER_PRIORITY,
    QN_HEADER_TE
} qn_regular_header;

typedef struct {
    const char *user_agent;
    const char *accept;
    const char *accept_encoding;
    const char *accept_language;
    const char *sec_fetch_site;
    const char *sec_ch_ua;
    uint8_t     pseudo_order[4];
    uint8_t     header_order[QN_PROFILE_MAX_HEADERS];
    uint8_t     nheaders;
} qn_http_header_profile;

typedef struct qn_client_profile {
    qn_tls_hello_profile   tls;
    qn_h2_settings_profile h2;
    qn_http_header_profile http;
    const char            *name;
    const char            *browser;
    const char            *platform;
    const char            *version;
} qn_client_profile;

typedef enum {
    QN_PROFILE_EXACT = 0,
    QN_PROFILE_CAPABILITY_CONSTRAINED,
    QN_PROFILE_UNSUPPORTED
} qn_profile_support;

typedef struct qn_profile_instance {
    uint32_t                  version;
    qn_tls_fp                 requested;
    qn_tls_fp                 resolved;
    qn_profile_support        support;
    const qn_client_profile  *profile;
    uint64_t                  seed;
    uint64_t                  grease_seed;
    char                      sni[254];
    qn_h2_setting             h2_settings[QN_PROFILE_MAX_H2_SETTINGS];
    size_t                    h2_settings_n;
    uint32_t                  h2_connection_window;
    uint8_t                   h2_pseudo_order[4];
    uint8_t                   http1_header_order[QN_PROFILE_MAX_HEADERS];
    size_t                    http1_header_order_n;
    bool                      allow_tls12;
    bool                      cert_strict;
} qn_profile_instance;

const qn_client_profile *qn_client_profile_get(qn_tls_fp profile);
bool qn_client_profile_parse(const char *name, qn_tls_fp *profile);
bool qn_profile_h2_shape(const qn_client_profile *profile, uint64_t seed,
                         qn_h2_setting *settings, size_t settings_cap,
                         size_t *settings_n, uint32_t *connection_window);
bool qn_profile_http_shape(const qn_client_profile *profile, uint64_t seed,
                           uint8_t pseudo_order[4],
                           uint8_t header_order[QN_PROFILE_MAX_HEADERS],
                           size_t *header_order_n);

bool qn_profile_instance_init(qn_profile_instance *instance, qn_tls_fp requested,
                              uint64_t seed, const char *sni, bool allow_tls12,
                              bool cert_strict);
uint64_t qn_profile_seed_from_run(uint64_t run_seed);
uint64_t qn_profile_wire_seed(uint64_t run_seed, uint64_t index);
const char *qn_profile_support_str(qn_profile_support support);
int qn_profile_instance_http1_get(const qn_profile_instance *instance,
                                  const char *host, const char *path,
                                  uint8_t *out, size_t cap);

int qn_profile_http1_get(const qn_client_profile *profile, uint64_t seed,
                         const char *host, const char *path,
                         uint8_t *out, size_t cap);

#endif /* QANAT_PROFILE_H */
