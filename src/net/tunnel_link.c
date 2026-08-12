#include "qanat/tunnel.h"
#include "qanat/util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

enum {
    F_NETWORK = 1u << 0,
    F_SECURITY = 1u << 1,
    F_SNI = 1u << 2,
    F_HOST = 1u << 3,
    F_PATH = 1u << 4,
    F_FLOW = 1u << 5,
    F_ALPN = 1u << 6,
    F_FP = 1u << 7,
    F_SERVICE = 1u << 8,
    F_MODE = 1u << 9,
    F_MULTI = 1u << 10,
    F_ADDRESS = 1u << 11,
    F_PORT = 1u << 12,
    F_SECRET = 1u << 13,
    F_VERSION = 1u << 14,
    F_AID = 1u << 15,
    F_CIPHER = 1u << 16,
    F_LABEL = 1u << 17,
    F_HEADER = 1u << 18,
    F_ALLOW_INSECURE = 1u << 19
};

static void clear_bytes(void *memory, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)memory;

    while (length--)
        *p++ = 0u;
}

void qn_tunnel_link_clear(qn_tunnel_link *link)
{
    if (link)
        clear_bytes(link, sizeof *link);
}

const char *qn_tunnel_protocol_str(qn_tunnel_protocol protocol)
{
    static const char *const names[] = { "vless", "trojan", "vmess" };

    return protocol < QN_TUNNEL_PROTOCOL_COUNT ? names[protocol] : "invalid";
}

const char *qn_tunnel_network_str(qn_tunnel_network network)
{
    static const char *const names[] = { "ws", "grpc", "xhttp", "tcp" };

    return network < QN_TUNNEL_NETWORK_COUNT ? names[network] : "invalid";
}

const char *qn_tunnel_security_str(qn_tunnel_security security)
{
    static const char *const names[] = { "none", "tls" };

    return security < QN_TUNNEL_SECURITY_COUNT ? names[security] : "invalid";
}

const char *qn_tunnel_parse_str(qn_tunnel_parse_code code)
{
    static const char *const names[] = {
        "ok", "empty", "too-long", "invalid-utf8", "unsupported-scheme",
        "invalid-encoding", "invalid-syntax", "duplicate-field",
        "unsupported-field", "unsupported-value", "invalid-credential",
        "invalid-address", "invalid-port", "invalid-json"
    };

    return code < QN_TUNNEL_PARSE_COUNT ? names[code] : "invalid";
}

static bool utf8_valid(const uint8_t *input, size_t length)
{
    size_t i = 0u;

    while (i < length) {
        uint8_t c = input[i++];
        uint32_t value;
        uint32_t minimum;
        size_t need;

        if (c == 0u || c < 0x20u || c == 0x7fu)
            return false;
        if (c < 0x80u)
            continue;
        if (c >= 0xc2u && c <= 0xdfu) {
            value = (uint32_t)(c & 0x1fu);
            minimum = 0x80u;
            need = 1u;
        } else if (c >= 0xe0u && c <= 0xefu) {
            value = (uint32_t)(c & 0x0fu);
            minimum = 0x800u;
            need = 2u;
        } else if (c >= 0xf0u && c <= 0xf4u) {
            value = (uint32_t)(c & 0x07u);
            minimum = 0x10000u;
            need = 3u;
        } else {
            return false;
        }
        if (length - i < need)
            return false;
        for (size_t n = 0u; n < need; n++) {
            uint8_t part = input[i++];

            if ((part & 0xc0u) != 0x80u)
                return false;
            value = (value << 6) | (uint32_t)(part & 0x3fu);
        }
        if (value < minimum || value > 0x10ffffu ||
            (value >= 0xd800u && value <= 0xdfffu))
            return false;
    }
    return true;
}

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A') + 10;
    return -1;
}

static bool percent_decode(const char *input, size_t length,
                           char *output, size_t capacity)
{
    size_t used = 0u;

    if (!capacity)
        return false;
    for (size_t i = 0u; i < length; i++) {
        unsigned char c = (unsigned char)input[i];

        if (c == '%') {
            int high, low;

            if (length - i < 3u)
                return false;
            high = hex_value((unsigned char)input[i + 1u]);
            low = hex_value((unsigned char)input[i + 2u]);
            if (high < 0 || low < 0)
                return false;
            c = (unsigned char)((unsigned)high * 16u + (unsigned)low);
            i += 2u;
        }
        if (c == 0u || c < 0x20u || c == 0x7fu || used + 1u >= capacity)
            return false;
        output[used++] = (char)c;
    }
    output[used] = '\0';
    return utf8_valid((const uint8_t *)output, used);
}

static bool copy_text(char *output, size_t capacity, const char *value)
{
    size_t length = strlen(value);

    if (length >= capacity)
        return false;
    memcpy(output, value, length + 1u);
    return true;
}

static bool ascii_token(const char *value, bool comma, bool slash)
{
    const unsigned char *p = (const unsigned char *)value;

    if (!*p)
        return false;
    while (*p) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
            (comma && *p == ',') || (slash && *p == '/')) {
            p++;
            continue;
        }
        return false;
    }
    return true;
}

static bool valid_uuid(const char *value)
{
    static const size_t dash[] = { 8u, 13u, 18u, 23u };

    if (strlen(value) != 36u)
        return false;
    for (size_t i = 0u; i < 36u; i++) {
        bool is_dash = false;

        for (size_t n = 0u; n < sizeof dash / sizeof dash[0]; n++)
            if (dash[n] == i)
                is_dash = true;
        if (is_dash) {
            if (value[i] != '-')
                return false;
        } else if (!isxdigit((unsigned char)value[i])) {
            return false;
        }
    }
    return true;
}

static bool valid_endpoint_host(const char *value)
{
    qn_addr address;

    return qn_addr_parse(value, &address) || qn_valid_hostname(value);
}

static bool parse_port(const char *text, uint16_t *port)
{
    uint32_t value = 0u;

    if (!*text)
        return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (!isdigit(*p))
            return false;
        value = value * 10u + (uint32_t)(*p - '0');
        if (value > 65535u)
            return false;
    }
    if (!value)
        return false;
    *port = (uint16_t)value;
    return true;
}

static qn_tunnel_parse_code set_once(uint32_t *seen, uint32_t field)
{
    if ((*seen & field) != 0u)
        return QN_TUNNEL_PARSE_DUPLICATE;
    *seen |= field;
    return QN_TUNNEL_PARSE_OK;
}

static qn_tunnel_parse_code set_network(qn_tunnel_link *link, const char *value)
{
    if (!strcmp(value, "ws") || !strcmp(value, "websocket"))
        link->network = QN_TUNNEL_NETWORK_WS;
    else if (!strcmp(value, "grpc"))
        link->network = QN_TUNNEL_NETWORK_GRPC;
    else if (!strcmp(value, "xhttp") || !strcmp(value, "splithttp"))
        link->network = QN_TUNNEL_NETWORK_XHTTP;
    else if (!strcmp(value, "tcp") || !strcmp(value, "raw"))
        link->network = QN_TUNNEL_NETWORK_TCP;
    else
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    return QN_TUNNEL_PARSE_OK;
}

static qn_tunnel_parse_code set_security(qn_tunnel_link *link, const char *value)
{
    if (!strcmp(value, "tls"))
        link->security = QN_TUNNEL_SECURITY_TLS;
    else if (!*value || !strcmp(value, "none"))
        link->security = QN_TUNNEL_SECURITY_NONE;
    else
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    return QN_TUNNEL_PARSE_OK;
}

static bool false_value(const char *value)
{
    return !*value || !strcmp(value, "0") || !strcmp(value, "false");
}

static bool true_value(const char *value)
{
    return !strcmp(value, "1") || !strcmp(value, "true");
}

static qn_tunnel_parse_code apply_field(qn_tunnel_link *link, const char *key,
                                        const char *value, uint32_t *seen,
                                        bool vmess)
{
    qn_tunnel_parse_code code;
    uint32_t field;

    if (!strcmp(key, "net") || !strcmp(key, "network") ||
        (!vmess && !strcmp(key, "type"))) {
        field = F_NETWORK;
        code = set_once(seen, field);
        return code == QN_TUNNEL_PARSE_OK ? set_network(link, value) : code;
    }
    if (!strcmp(key, "security") || (vmess && !strcmp(key, "tls"))) {
        field = F_SECURITY;
        code = set_once(seen, field);
        return code == QN_TUNNEL_PARSE_OK ? set_security(link, value) : code;
    }
    if (!strcmp(key, "sni") || !strcmp(key, "serverName")) {
        field = F_SNI;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->sni, sizeof link->sni, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "host") || !strcmp(key, "authority")) {
        field = F_HOST;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->host, sizeof link->host, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "path")) {
        field = F_PATH;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->path, sizeof link->path, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "flow")) {
        field = F_FLOW;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->flow, sizeof link->flow, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "alpn")) {
        field = F_ALPN;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->alpn, sizeof link->alpn, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "fp") || !strcmp(key, "fingerprint")) {
        field = F_FP;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->fingerprint, sizeof link->fingerprint, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "serviceName") || !strcmp(key, "service_name")) {
        field = F_SERVICE;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->service_name, sizeof link->service_name, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "mode")) {
        field = F_MODE;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->mode, sizeof link->mode, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!strcmp(key, "multiMode")) {
        field = F_MULTI;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        if (!false_value(value) && !true_value(value))
            return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
        link->grpc_multi = true_value(value);
        return QN_TUNNEL_PARSE_OK;
    }
    if (!strcmp(key, "encryption") || !strcmp(key, "scy")) {
        field = F_CIPHER;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        if (link->protocol == QN_TUNNEL_PROTOCOL_VLESS)
            return !strcmp(value, "none") ? QN_TUNNEL_PARSE_OK
                                           : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
        return (!*value || !strcmp(value, "auto") || !strcmp(value, "none"))
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    }
    if (!strcmp(key, "headerType") || (vmess && !strcmp(key, "type"))) {
        field = F_HEADER;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return (!*value || !strcmp(value, "none")) ? QN_TUNNEL_PARSE_OK
                                                    : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    }
    if (!strcmp(key, "allowInsecure")) {
        field = F_ALLOW_INSECURE;
        code = set_once(seen, field);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return false_value(value) ? QN_TUNNEL_PARSE_OK
                                  : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    }
    if (vmess && !strcmp(key, "add")) {
        code = set_once(seen, F_ADDRESS);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->address, sizeof link->address, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (vmess && !strcmp(key, "port")) {
        code = set_once(seen, F_PORT);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return parse_port(value, &link->port) ? QN_TUNNEL_PARSE_OK
                                              : QN_TUNNEL_PARSE_PORT;
    }
    if (vmess && !strcmp(key, "id")) {
        code = set_once(seen, F_SECRET);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return copy_text(link->secret, sizeof link->secret, value)
                   ? QN_TUNNEL_PARSE_OK : QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (vmess && !strcmp(key, "v")) {
        code = set_once(seen, F_VERSION);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return !strcmp(value, "2") ? QN_TUNNEL_PARSE_OK
                                    : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    }
    if (vmess && !strcmp(key, "aid")) {
        code = set_once(seen, F_AID);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        return (!*value || !strcmp(value, "0")) ? QN_TUNNEL_PARSE_OK
                                                 : QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    }
    if (vmess && !strcmp(key, "ps"))
        return set_once(seen, F_LABEL);
    return QN_TUNNEL_PARSE_UNSUPPORTED_FIELD;
}

static bool valid_alpn_list(const char *value)
{
    bool have = false;

    for (const unsigned char *p = (const unsigned char *)value;; p++) {
        if (*p == ',' || *p == '\0') {
            if (!have)
                return false;
            if (!*p)
                return true;
            have = false;
        } else {
            have = true;
        }
    }
}

static qn_tunnel_parse_code finish_link(qn_tunnel_link *link, uint32_t seen)
{
    qn_addr literal;

    if (!valid_endpoint_host(link->address))
        return QN_TUNNEL_PARSE_ADDRESS;
    if (!link->port)
        return QN_TUNNEL_PARSE_PORT;
    if (link->protocol != QN_TUNNEL_PROTOCOL_TROJAN && !valid_uuid(link->secret))
        return QN_TUNNEL_PARSE_CREDENTIAL;
    if (link->protocol == QN_TUNNEL_PROTOCOL_TROJAN && !link->secret[0])
        return QN_TUNNEL_PARSE_CREDENTIAL;

    if (!link->sni[0]) {
        const char *name = qn_valid_hostname(link->host)
                               ? link->host : link->address;

        if (qn_valid_hostname(name) &&
            !copy_text(link->sni, sizeof link->sni, name))
            return QN_TUNNEL_PARSE_TOO_LONG;
    }
    if (!link->host[0] && link->sni[0] &&
        !copy_text(link->host, sizeof link->host, link->sni))
        return QN_TUNNEL_PARSE_TOO_LONG;
    if (link->security == QN_TUNNEL_SECURITY_TLS &&
        (!link->sni[0] || !qn_valid_hostname(link->sni)))
        return QN_TUNNEL_PARSE_ADDRESS;
    if (link->host[0] && !qn_valid_hostname(link->host) &&
        !qn_addr_parse(link->host, &literal))
        return QN_TUNNEL_PARSE_ADDRESS;

    if ((link->network == QN_TUNNEL_NETWORK_WS ||
         link->network == QN_TUNNEL_NETWORK_XHTTP) && !link->path[0] &&
        !copy_text(link->path, sizeof link->path, "/"))
        return QN_TUNNEL_PARSE_TOO_LONG;
    if ((link->network == QN_TUNNEL_NETWORK_WS ||
         link->network == QN_TUNNEL_NETWORK_XHTTP) && link->path[0] != '/')
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->network == QN_TUNNEL_NETWORK_GRPC && !link->service_name[0] &&
        link->path[0]) {
        const char *service = link->path[0] == '/' ? link->path + 1 : link->path;

        if (!copy_text(link->service_name, sizeof link->service_name, service))
            return QN_TUNNEL_PARSE_TOO_LONG;
        clear_bytes(link->path, sizeof link->path);
    }
    if (link->network == QN_TUNNEL_NETWORK_TCP && link->path[0])
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->network != QN_TUNNEL_NETWORK_GRPC &&
        ((seen & F_SERVICE) || (seen & F_MULTI)))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->network == QN_TUNNEL_NETWORK_GRPC &&
        link->path[0] && (seen & F_SERVICE))
        return QN_TUNNEL_PARSE_DUPLICATE;
    if ((seen & (F_ALPN | F_FP)) &&
        link->security != QN_TUNNEL_SECURITY_TLS)
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if ((seen & F_FLOW) && link->flow[0] &&
        (link->protocol != QN_TUNNEL_PROTOCOL_VLESS ||
         link->network != QN_TUNNEL_NETWORK_TCP ||
         link->security != QN_TUNNEL_SECURITY_TLS))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->flow[0] && !ascii_token(link->flow, false, false))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->alpn[0] &&
        (!ascii_token(link->alpn, true, true) ||
         !valid_alpn_list(link->alpn)))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->fingerprint[0] && !ascii_token(link->fingerprint, false, false))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (!link->fingerprint[0] &&
        !copy_text(link->fingerprint, sizeof link->fingerprint, "chrome"))
        return QN_TUNNEL_PARSE_TOO_LONG;
    if (!link->mode[0] && !copy_text(link->mode, sizeof link->mode, "auto"))
        return QN_TUNNEL_PARSE_TOO_LONG;
    if (link->network == QN_TUNNEL_NETWORK_XHTTP &&
        strcmp(link->mode, "auto") && strcmp(link->mode, "packet-up") &&
        strcmp(link->mode, "stream-up") && strcmp(link->mode, "stream-one"))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    if (link->network != QN_TUNNEL_NETWORK_XHTTP && strcmp(link->mode, "auto"))
        return QN_TUNNEL_PARSE_UNSUPPORTED_VALUE;
    return QN_TUNNEL_PARSE_OK;
}

static qn_tunnel_parse_code parse_authority(qn_tunnel_link *link, char *authority)
{
    char *port_text;

    if (authority[0] == '[') {
        char *close = strchr(authority, ']');

        if (!close || close[1] != ':' || !close[2])
            return QN_TUNNEL_PARSE_SYNTAX;
        *close = '\0';
        port_text = close + 2;
        if (!copy_text(link->address, sizeof link->address, authority + 1))
            return QN_TUNNEL_PARSE_TOO_LONG;
    } else {
        char *colon = strrchr(authority, ':');

        if (!colon || colon == authority || strchr(authority, ':') != colon)
            return QN_TUNNEL_PARSE_SYNTAX;
        *colon = '\0';
        port_text = colon + 1;
        if (!copy_text(link->address, sizeof link->address, authority))
            return QN_TUNNEL_PARSE_TOO_LONG;
    }
    return parse_port(port_text, &link->port) ? QN_TUNNEL_PARSE_OK
                                               : QN_TUNNEL_PARSE_PORT;
}

static qn_tunnel_parse_code parse_query(qn_tunnel_link *link, char *query,
                                        uint32_t *seen)
{
    char *part = query;

    while (*part) {
        char *next = strchr(part, '&');
        char *equals;
        char key[64];
        char value[1024];
        qn_tunnel_parse_code code;

        if (next)
            *next = '\0';
        if (!*part)
            return QN_TUNNEL_PARSE_SYNTAX;
        equals = strchr(part, '=');
        if (!equals || strchr(equals + 1, '='))
            return QN_TUNNEL_PARSE_SYNTAX;
        *equals = '\0';
        if (!percent_decode(part, strlen(part), key, sizeof key) ||
            !percent_decode(equals + 1, strlen(equals + 1), value, sizeof value))
            return QN_TUNNEL_PARSE_ENCODING;
        code = apply_field(link, key, value, seen, false);
        clear_bytes(value, sizeof value);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        if (!next)
            break;
        part = next + 1;
    }
    return QN_TUNNEL_PARSE_OK;
}

static qn_tunnel_parse_code parse_uri(char *text, qn_tunnel_link *link)
{
    char *rest;
    char *fragment;
    char *query;
    char *at;
    qn_tunnel_parse_code code;
    uint32_t seen = 0u;
    char decoded_fragment[1024];

    if (!strncmp(text, "vless://", 8u)) {
        link->protocol = QN_TUNNEL_PROTOCOL_VLESS;
        rest = text + 8;
    } else if (!strncmp(text, "trojan://", 9u)) {
        link->protocol = QN_TUNNEL_PROTOCOL_TROJAN;
        link->security = QN_TUNNEL_SECURITY_TLS;
        rest = text + 9;
    } else {
        return QN_TUNNEL_PARSE_SCHEME;
    }
    fragment = strchr(rest, '#');
    if (fragment) {
        if (strchr(fragment + 1, '#') ||
            !percent_decode(fragment + 1, strlen(fragment + 1),
                            decoded_fragment, sizeof decoded_fragment))
            return QN_TUNNEL_PARSE_ENCODING;
        clear_bytes(decoded_fragment, sizeof decoded_fragment);
        *fragment = '\0';
    }
    query = strchr(rest, '?');
    if (query)
        *query++ = '\0';
    at = strrchr(rest, '@');
    if (!at || at == rest || strchr(rest, '@') != at)
        return QN_TUNNEL_PARSE_SYNTAX;
    *at = '\0';
    if (!percent_decode(rest, strlen(rest), link->secret, sizeof link->secret))
        return QN_TUNNEL_PARSE_ENCODING;
    code = parse_authority(link, at + 1);
    if (code != QN_TUNNEL_PARSE_OK)
        return code;
    if (query && *query) {
        code = parse_query(link, query, &seen);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
    } else if (query) {
        return QN_TUNNEL_PARSE_SYNTAX;
    }
    return finish_link(link, seen);
}

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return (int)(c - 'A');
    if (c >= 'a' && c <= 'z')
        return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9')
        return (int)(c - '0') + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

static bool base64_decode(const char *input, size_t length,
                          uint8_t *output, size_t capacity, size_t *output_length)
{
    size_t used = 0u;
    size_t padded;
    const char *first_pad;

    if (!length || length % 4u == 1u)
        return false;
    first_pad = memchr(input, '=', length);
    if (first_pad) {
        size_t pad_at = (size_t)(first_pad - input);

        if (length % 4u || length - pad_at > 2u)
            return false;
        for (size_t i = pad_at; i < length; i++)
            if (input[i] != '=')
                return false;
    }
    padded = (length + 3u) & ~(size_t)3u;
    for (size_t i = 0u; i < padded; i += 4u) {
        int value[4];
        unsigned pad = 0u;

        for (size_t n = 0u; n < 4u; n++) {
            size_t index = i + n;

            if (index >= length || input[index] == '=') {
                value[n] = 0;
                pad++;
            } else {
                if (pad)
                    return false;
                value[n] = base64_value((unsigned char)input[index]);
                if (value[n] < 0)
                    return false;
            }
        }
        if (pad > 2u || (i + 4u < padded && pad))
            return false;
        if ((pad == 2u && ((unsigned)value[1] & 15u)) ||
            (pad == 1u && ((unsigned)value[2] & 3u)))
            return false;
        if (used + 3u - pad > capacity)
            return false;
        output[used++] = (uint8_t)((unsigned)value[0] << 2 |
                                   (unsigned)value[1] >> 4);
        if (pad < 2u)
            output[used++] = (uint8_t)(((unsigned)value[1] & 15u) << 4 |
                                       (unsigned)value[2] >> 2);
        if (!pad)
            output[used++] = (uint8_t)(((unsigned)value[2] & 3u) << 6 |
                                       (unsigned)value[3]);
    }
    *output_length = used;
    return true;
}

static void skip_space(const uint8_t *json, size_t length, size_t *offset)
{
    while (*offset < length && (json[*offset] == ' ' || json[*offset] == '\t' ||
                                json[*offset] == '\n' || json[*offset] == '\r'))
        (*offset)++;
}

static bool append_codepoint(char *output, size_t capacity, size_t *used,
                             uint32_t value)
{
    uint8_t encoded[4];
    size_t count;

    if (!value || value > 0x10ffffu || (value >= 0xd800u && value <= 0xdfffu))
        return false;
    if (value < 0x80u) {
        encoded[0] = (uint8_t)value;
        count = 1u;
    } else if (value < 0x800u) {
        encoded[0] = (uint8_t)(0xc0u | value >> 6);
        encoded[1] = (uint8_t)(0x80u | (value & 0x3fu));
        count = 2u;
    } else if (value < 0x10000u) {
        encoded[0] = (uint8_t)(0xe0u | value >> 12);
        encoded[1] = (uint8_t)(0x80u | (value >> 6 & 0x3fu));
        encoded[2] = (uint8_t)(0x80u | (value & 0x3fu));
        count = 3u;
    } else {
        encoded[0] = (uint8_t)(0xf0u | value >> 18);
        encoded[1] = (uint8_t)(0x80u | (value >> 12 & 0x3fu));
        encoded[2] = (uint8_t)(0x80u | (value >> 6 & 0x3fu));
        encoded[3] = (uint8_t)(0x80u | (value & 0x3fu));
        count = 4u;
    }
    if (*used + count >= capacity)
        return false;
    for (size_t i = 0u; i < count; i++)
        output[(*used)++] = (char)encoded[i];
    return true;
}

static bool json_hex4(const uint8_t *json, size_t length, size_t *offset,
                      uint32_t *value)
{
    uint32_t result = 0u;

    if (length - *offset < 4u)
        return false;
    for (size_t i = 0u; i < 4u; i++) {
        int digit = hex_value(json[(*offset)++]);

        if (digit < 0)
            return false;
        result = result * 16u + (uint32_t)digit;
    }
    *value = result;
    return true;
}

static bool json_string(const uint8_t *json, size_t length, size_t *offset,
                        char *output, size_t capacity)
{
    size_t used = 0u;

    if (*offset >= length || json[(*offset)++] != '"')
        return false;
    while (*offset < length) {
        uint8_t c = json[(*offset)++];

        if (c == '"') {
            output[used] = '\0';
            return utf8_valid((const uint8_t *)output, used);
        }
        if (c < 0x20u || c == 0x7fu)
            return false;
        if (c != '\\') {
            if (used + 1u >= capacity)
                return false;
            output[used++] = (char)c;
            continue;
        }
        if (*offset >= length)
            return false;
        c = json[(*offset)++];
        if (c == '"' || c == '\\' || c == '/') {
            if (used + 1u >= capacity)
                return false;
            output[used++] = (char)c;
        } else if (c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't') {
            return false;
        } else if (c == 'u') {
            uint32_t value;

            if (!json_hex4(json, length, offset, &value))
                return false;
            if (value >= 0xd800u && value <= 0xdbffu) {
                uint32_t low;

                if (length - *offset < 6u || json[*offset] != '\\' ||
                    json[*offset + 1u] != 'u')
                    return false;
                *offset += 2u;
                if (!json_hex4(json, length, offset, &low) ||
                    low < 0xdc00u || low > 0xdfffu)
                    return false;
                value = 0x10000u + ((value - 0xd800u) << 10) + (low - 0xdc00u);
            }
            if (!append_codepoint(output, capacity, &used, value))
                return false;
        } else {
            return false;
        }
    }
    return false;
}

typedef enum {
    JSON_SCALAR_STRING = 0,
    JSON_SCALAR_NUMBER,
    JSON_SCALAR_BOOLEAN
} json_scalar_kind;

static bool json_number_valid(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (*p == '-')
        p++;
    if (*p == '0') {
        p++;
        if (isdigit(*p))
            return false;
    } else {
        if (*p < '1' || *p > '9')
            return false;
        while (isdigit(*p))
            p++;
    }
    if (*p == '.') {
        p++;
        if (!isdigit(*p))
            return false;
        while (isdigit(*p))
            p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!isdigit(*p))
            return false;
        while (isdigit(*p))
            p++;
    }
    return *p == '\0';
}

static bool json_scalar(const uint8_t *json, size_t length, size_t *offset,
                        char *output, size_t capacity,
                        json_scalar_kind *kind)
{
    size_t start = *offset;
    size_t count;

    if (!kind)
        return false;
    if (*offset < length && json[*offset] == '"') {
        *kind = JSON_SCALAR_STRING;
        return json_string(json, length, offset, output, capacity);
    }
    while (*offset < length && json[*offset] != ',' && json[*offset] != '}' &&
           json[*offset] != ' ' && json[*offset] != '\t' &&
           json[*offset] != '\n' && json[*offset] != '\r')
        (*offset)++;
    count = *offset - start;
    if (!count || count >= capacity)
        return false;
    for (size_t i = 0u; i < count; i++)
        output[i] = (char)json[start + i];
    output[count] = '\0';
    if (!strcmp(output, "true") || !strcmp(output, "false")) {
        *kind = JSON_SCALAR_BOOLEAN;
        return true;
    }
    *kind = JSON_SCALAR_NUMBER;
    return json_number_valid(output);
}

static bool vmess_scalar_type_valid(const char *key, json_scalar_kind kind)
{
    if (!strcmp(key, "port") || !strcmp(key, "aid"))
        return kind == JSON_SCALAR_STRING || kind == JSON_SCALAR_NUMBER;
    if (!strcmp(key, "multiMode"))
        return kind == JSON_SCALAR_STRING || kind == JSON_SCALAR_BOOLEAN;
    return kind == JSON_SCALAR_STRING;
}

static qn_tunnel_parse_code parse_vmess_json(const uint8_t *json, size_t length,
                                              qn_tunnel_link *link)
{
    size_t offset = 0u;
    uint32_t seen = 0u;
    bool have_field = false;

    if (!utf8_valid(json, length))
        return QN_TUNNEL_PARSE_UTF8;
    skip_space(json, length, &offset);
    if (offset >= length || json[offset++] != '{')
        return QN_TUNNEL_PARSE_JSON;
    for (;;) {
        char key[64];
        char value[1024];
        qn_tunnel_parse_code code;
        json_scalar_kind kind;

        skip_space(json, length, &offset);
        if (offset < length && json[offset] == '}') {
            offset++;
            break;
        }
        if (have_field) {
            if (offset >= length || json[offset++] != ',')
                return QN_TUNNEL_PARSE_JSON;
            skip_space(json, length, &offset);
        }
        if (!json_string(json, length, &offset, key, sizeof key))
            return QN_TUNNEL_PARSE_JSON;
        skip_space(json, length, &offset);
        if (offset >= length || json[offset++] != ':')
            return QN_TUNNEL_PARSE_JSON;
        skip_space(json, length, &offset);
        if (!json_scalar(json, length, &offset, value, sizeof value, &kind) ||
            !vmess_scalar_type_valid(key, kind))
            return QN_TUNNEL_PARSE_JSON;
        code = apply_field(link, key, value, &seen, true);
        clear_bytes(value, sizeof value);
        if (code != QN_TUNNEL_PARSE_OK)
            return code;
        have_field = true;
    }
    skip_space(json, length, &offset);
    if (offset != length ||
        (seen & (F_ADDRESS | F_PORT | F_SECRET | F_VERSION)) !=
            (F_ADDRESS | F_PORT | F_SECRET | F_VERSION))
        return QN_TUNNEL_PARSE_JSON;
    return finish_link(link, seen);
}

static qn_tunnel_parse_code parse_vmess(const char *text, size_t length,
                                        qn_tunnel_link *link)
{
    uint8_t decoded[3072] = { 0 };
    size_t decoded_length = 0u;
    qn_tunnel_parse_code code;
    const char *encoded;
    const char *fragment;
    size_t encoded_length;
    char decoded_fragment[1024];

    if (length <= 8u || strncmp(text, "vmess://", 8u))
        return QN_TUNNEL_PARSE_SCHEME;
    link->protocol = QN_TUNNEL_PROTOCOL_VMESS;
    encoded = text + 8;
    encoded_length = length - 8u;
    fragment = memchr(encoded, '#', encoded_length);
    if (fragment) {
        size_t fragment_length = encoded_length -
                                 (size_t)(fragment + 1 - encoded);

        if (memchr(fragment + 1, '#', fragment_length) ||
            !percent_decode(fragment + 1, fragment_length, decoded_fragment,
                            sizeof decoded_fragment))
            return QN_TUNNEL_PARSE_ENCODING;
        clear_bytes(decoded_fragment, sizeof decoded_fragment);
        encoded_length = (size_t)(fragment - encoded);
    }
    if (!base64_decode(encoded, encoded_length, decoded, sizeof decoded,
                       &decoded_length))
        return QN_TUNNEL_PARSE_ENCODING;
    code = parse_vmess_json(decoded, decoded_length, link);
    clear_bytes(decoded, sizeof decoded);
    return code;
}

qn_tunnel_parse_code qn_tunnel_link_parse(const uint8_t *input, size_t length,
                                           qn_tunnel_link *out)
{
    char text[QN_TUNNEL_LINK_MAX + 1u];
    qn_tunnel_link parsed;
    qn_tunnel_parse_code code;

    if (out)
        qn_tunnel_link_clear(out);
    if (!input || !out || !length)
        return QN_TUNNEL_PARSE_EMPTY;
    if (length > QN_TUNNEL_LINK_MAX)
        return QN_TUNNEL_PARSE_TOO_LONG;
    if (!utf8_valid(input, length))
        return QN_TUNNEL_PARSE_UTF8;
    memcpy(text, input, length);
    text[length] = '\0';
    memset(&parsed, 0, sizeof parsed);
    parsed.network = QN_TUNNEL_NETWORK_TCP;
    parsed.security = QN_TUNNEL_SECURITY_NONE;
    if (!strncmp(text, "vmess://", 8u))
        code = parse_vmess(text, length, &parsed);
    else
        code = parse_uri(text, &parsed);
    clear_bytes(text, sizeof text);
    if (code != QN_TUNNEL_PARSE_OK) {
        qn_tunnel_link_clear(&parsed);
        return code;
    }
    *out = parsed;
    qn_tunnel_link_clear(&parsed);
    return QN_TUNNEL_PARSE_OK;
}

qn_tunnel_parse_code qn_tunnel_link_parse_cstr(const char *input,
                                                qn_tunnel_link *out)
{
    size_t length = 0u;

    if (!input)
        return QN_TUNNEL_PARSE_EMPTY;
    while (length <= QN_TUNNEL_LINK_MAX && input[length])
        length++;
    if (length > QN_TUNNEL_LINK_MAX) {
        if (out)
            qn_tunnel_link_clear(out);
        return QN_TUNNEL_PARSE_TOO_LONG;
    }
    return qn_tunnel_link_parse((const uint8_t *)input, length, out);
}
