#ifndef QANAT_TUNNEL_H
#define QANAT_TUNNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "qanat/outcome.h"

struct qn_profile_instance;

#define QN_TUNNEL_LINK_MAX         4096u
#define QN_TUNNEL_SECRET_MAX        255u
#define QN_TUNNEL_HOST_MAX          253u
#define QN_TUNNEL_PATH_MAX          767u
#define QN_TUNNEL_SERVICE_MAX       255u
#define QN_TUNNEL_ALPN_MAX          127u
#define QN_TUNNEL_CONFIG_MAX      32768u
#define QN_TUNNEL_XRAY_PATH_MAX    1023u
#define QN_TUNNEL_REASON_MAX         31u

typedef enum {
    QN_TUNNEL_PROTOCOL_VLESS = 0,
    QN_TUNNEL_PROTOCOL_TROJAN,
    QN_TUNNEL_PROTOCOL_VMESS,
    QN_TUNNEL_PROTOCOL_COUNT
} qn_tunnel_protocol;

typedef enum {
    QN_TUNNEL_NETWORK_WS = 0,
    QN_TUNNEL_NETWORK_GRPC,
    QN_TUNNEL_NETWORK_XHTTP,
    QN_TUNNEL_NETWORK_TCP,
    QN_TUNNEL_NETWORK_COUNT
} qn_tunnel_network;

typedef enum {
    QN_TUNNEL_SECURITY_NONE = 0,
    QN_TUNNEL_SECURITY_TLS,
    QN_TUNNEL_SECURITY_COUNT
} qn_tunnel_security;

typedef struct {
    qn_tunnel_protocol protocol;
    qn_tunnel_network  network;
    qn_tunnel_security security;
    uint16_t           port;
    bool               grpc_multi;
    char               secret[QN_TUNNEL_SECRET_MAX + 1u];
    char               address[QN_TUNNEL_HOST_MAX + 1u];
    char               sni[QN_TUNNEL_HOST_MAX + 1u];
    char               host[QN_TUNNEL_HOST_MAX + 1u];
    char               path[QN_TUNNEL_PATH_MAX + 1u];
    char               flow[64];
    char               alpn[QN_TUNNEL_ALPN_MAX + 1u];
    char               fingerprint[32];
    char               service_name[QN_TUNNEL_SERVICE_MAX + 1u];
    char               mode[32];
} qn_tunnel_link;

typedef enum {
    QN_TUNNEL_PARSE_OK = 0,
    QN_TUNNEL_PARSE_EMPTY,
    QN_TUNNEL_PARSE_TOO_LONG,
    QN_TUNNEL_PARSE_UTF8,
    QN_TUNNEL_PARSE_SCHEME,
    QN_TUNNEL_PARSE_ENCODING,
    QN_TUNNEL_PARSE_SYNTAX,
    QN_TUNNEL_PARSE_DUPLICATE,
    QN_TUNNEL_PARSE_UNSUPPORTED_FIELD,
    QN_TUNNEL_PARSE_UNSUPPORTED_VALUE,
    QN_TUNNEL_PARSE_CREDENTIAL,
    QN_TUNNEL_PARSE_ADDRESS,
    QN_TUNNEL_PARSE_PORT,
    QN_TUNNEL_PARSE_JSON,
    QN_TUNNEL_PARSE_COUNT
} qn_tunnel_parse_code;

qn_tunnel_parse_code qn_tunnel_link_parse(const uint8_t *input, size_t length,
                                           qn_tunnel_link *out);
qn_tunnel_parse_code qn_tunnel_link_parse_cstr(const char *input,
                                                qn_tunnel_link *out);
const char *qn_tunnel_parse_str(qn_tunnel_parse_code code);
const char *qn_tunnel_protocol_str(qn_tunnel_protocol protocol);
const char *qn_tunnel_network_str(qn_tunnel_network network);
const char *qn_tunnel_security_str(qn_tunnel_security security);
void qn_tunnel_link_clear(qn_tunnel_link *link);

typedef enum {
    QN_TUNNEL_CONFIG_LIVE = 0,
    QN_TUNNEL_CONFIG_REDACTED,
    QN_TUNNEL_CONFIG_TEMPLATE
} qn_tunnel_config_mode;

typedef enum {
    QN_TUNNEL_CONFIG_OK = 0,
    QN_TUNNEL_CONFIG_ARGUMENT,
    QN_TUNNEL_CONFIG_CANDIDATE,
    QN_TUNNEL_CONFIG_SECRET,
    QN_TUNNEL_CONFIG_OVERFLOW
} qn_tunnel_config_code;

typedef struct {
    const qn_tunnel_link *link;
    const char           *candidate;
    uint16_t              socks_port;
    qn_tunnel_config_mode mode;
} qn_tunnel_config_request;

qn_tunnel_config_code qn_tunnel_config_build(const qn_tunnel_config_request *request,
                                              char *output, size_t capacity,
                                              size_t *length);
const char *qn_tunnel_config_str(qn_tunnel_config_code code);

typedef enum {
    QN_SOCKS5_ERROR_NONE = 0,
    QN_SOCKS5_ERROR_ARGUMENT,
    QN_SOCKS5_ERROR_VERSION,
    QN_SOCKS5_ERROR_AUTH,
    QN_SOCKS5_ERROR_CONNECT,
    QN_SOCKS5_ERROR_ADDRESS,
    QN_SOCKS5_ERROR_RESERVED,
    QN_SOCKS5_ERROR_OVERFLOW,
    QN_SOCKS5_ERROR_TRUNCATED
} qn_socks5_error;

typedef enum {
    QN_SOCKS5_NEED_INPUT = 0,
    QN_SOCKS5_SEND_CONNECT,
    QN_SOCKS5_READY,
    QN_SOCKS5_FAILED
} qn_socks5_action;

typedef struct {
    uint8_t phase;
    uint8_t response[263];
    size_t  response_length;
    size_t  response_needed;
    uint8_t host_length;
    uint16_t port;
    char    host[256];
    qn_socks5_error error;
} qn_socks5_client;

bool qn_socks5_init(qn_socks5_client *client, const char *host, uint16_t port);
size_t qn_socks5_greeting(uint8_t output[3]);
qn_socks5_action qn_socks5_feed(qn_socks5_client *client,
                                const uint8_t *input, size_t length,
                                size_t *consumed, uint8_t *output,
                                size_t output_capacity, size_t *output_length);
qn_socks5_action qn_socks5_eof(qn_socks5_client *client);
const char *qn_socks5_error_str(qn_socks5_error error);

typedef enum {
    QN_TUNNEL_UNTESTED = 0,
    QN_TUNNEL_QUEUED,
    QN_TUNNEL_PASSED,
    QN_TUNNEL_BINARY_MISSING,
    QN_TUNNEL_CONFIG_INVALID,
    QN_TUNNEL_START_FAILED,
    QN_TUNNEL_SOCKS_FAILED,
    QN_TUNNEL_PROBE_FAILED,
    QN_TUNNEL_NO_MARKER,
    QN_TUNNEL_CANCELLED,
    QN_TUNNEL_STATE_COUNT
} qn_tunnel_state;

static inline bool qn_tunnel_state_terminal(qn_tunnel_state state)
{
    return state >= QN_TUNNEL_PASSED && state < QN_TUNNEL_STATE_COUNT;
}

static inline bool qn_tunnel_state_failed(qn_tunnel_state state)
{
    return state == QN_TUNNEL_CONFIG_INVALID ||
           state == QN_TUNNEL_START_FAILED ||
           state == QN_TUNNEL_SOCKS_FAILED ||
           state == QN_TUNNEL_PROBE_FAILED ||
           state == QN_TUNNEL_NO_MARKER;
}

static inline bool qn_tunnel_state_skipped(qn_tunnel_state state)
{
    return state == QN_TUNNEL_BINARY_MISSING ||
           state == QN_TUNNEL_CANCELLED;
}

static inline const char *qn_tunnel_state_str(qn_tunnel_state state)
{
    static const char *const names[] = {
        "untested", "queued", "passed", "binary-missing",
        "config-invalid", "start-failed", "socks-failed",
        "probe-failed", "no-marker", "cancelled"
    };

    return state < QN_TUNNEL_STATE_COUNT ? names[state] : "invalid";
}

typedef enum {
    QN_XRAY_FOUND = 0,
    QN_XRAY_NOT_FOUND,
    QN_XRAY_INVALID_PATH,
    QN_XRAY_PATH_OVERFLOW
} qn_xray_find_code;

qn_xray_find_code qn_xray_find(const char *requested, char *resolved,
                                size_t capacity);
const char *qn_xray_find_str(qn_xray_find_code code);

typedef enum {
    QN_XRAY_INSTALL_OK = 0,
    QN_XRAY_INSTALL_UNSUPPORTED,
    QN_XRAY_INSTALL_TOOL_MISSING,
    QN_XRAY_INSTALL_DOWNLOAD_FAILED,
    QN_XRAY_INSTALL_DIGEST_INVALID,
    QN_XRAY_INSTALL_ARCHIVE_INVALID,
    QN_XRAY_INSTALL_TARGET_FAILED
} qn_xray_install_code;

qn_xray_install_code qn_xray_install(char *installed, size_t capacity);
bool qn_xray_install_target(char *target, size_t capacity);
const char *qn_xray_install_str(qn_xray_install_code code);

typedef struct {
    qn_tunnel_state state;
    uint8_t         attempts;
    uint32_t        ttfb_us;
    uint32_t        kbps;
    char            reason[QN_TUNNEL_REASON_MAX + 1u];
} qn_tunnel_result;

typedef struct {
    const qn_tunnel_link *link;
    const char           *xray_path;
    const char           *candidate;
    const char           *probe_host;
    const char           *probe_path;
    const struct qn_profile_instance *profile;
    uint8_t               fingerprint;
    bool                  allow_tls12;
    bool                  cert_strict;
    uint32_t              timeout_ms;
    uint32_t              idle_ms;
    uint32_t              want_bytes;
    uint8_t               max_attempts;
    uint64_t              seed;
    const _Atomic bool   *cancel;
} qn_tunnel_run_config;

qn_run_outcome qn_tunnel_run(const qn_tunnel_run_config *config,
                              qn_tunnel_result *result);

#if defined(QN_TUNNEL_TESTING)
typedef enum {
    QN_TUNNEL_TEST_NONE = 0,
    QN_TUNNEL_TEST_TEMP_CREATE,
    QN_TUNNEL_TEST_TEMP_WRITE,
    QN_TUNNEL_TEST_CONFIG_REJECT,
    QN_TUNNEL_TEST_CHILD_START
} qn_tunnel_test_fault;

void qn_tunnel_test_set_fault(qn_tunnel_test_fault fault);
const char *qn_tunnel_test_last_temp(void);
#endif

#endif
