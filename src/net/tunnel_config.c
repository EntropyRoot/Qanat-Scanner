#include "qanat/tunnel.h"
#include "qanat/util.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char   *data;
    size_t  capacity;
    size_t  used;
    bool    failed;
} json_buffer;

static void append_raw(json_buffer *buffer, const char *text)
{
    size_t length;

    if (buffer->failed)
        return;
    length = strlen(text);
    if (length >= buffer->capacity - buffer->used) {
        buffer->failed = true;
        return;
    }
    memcpy(buffer->data + buffer->used, text, length);
    buffer->used += length;
    buffer->data[buffer->used] = '\0';
}

static void append_format(json_buffer *buffer, const char *format, ...)
{
    va_list arguments;
    int written;

    if (buffer->failed)
        return;
    va_start(arguments, format);
    written = vsnprintf(buffer->data + buffer->used,
                        buffer->capacity - buffer->used, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= buffer->capacity - buffer->used) {
        buffer->failed = true;
        return;
    }
    buffer->used += (size_t)written;
}

static void append_string(json_buffer *buffer, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    append_raw(buffer, "\"");
    while (*p && !buffer->failed) {
        char encoded[7];

        if (*p == '"' || *p == '\\') {
            encoded[0] = '\\';
            encoded[1] = (char)*p;
            encoded[2] = '\0';
            append_raw(buffer, encoded);
        } else if (*p < 0x20u || *p == 0x7fu) {
            (void)snprintf(encoded, sizeof encoded, "\\u%04x", (unsigned)*p);
            append_raw(buffer, encoded);
        } else {
            encoded[0] = (char)*p;
            encoded[1] = '\0';
            append_raw(buffer, encoded);
        }
        p++;
    }
    append_raw(buffer, "\"");
}

static bool candidate_valid(const char *candidate, bool *is_ip)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t length;

    if (!candidate || !*candidate || !is_ip)
        return false;
    length = strnlen(candidate, QN_TUNNEL_HOST_MAX + 1u);
    if (!length || length > QN_TUNNEL_HOST_MAX)
        return false;
    if (inet_pton(AF_INET, candidate, &ipv4) == 1 ||
        inet_pton(AF_INET6, candidate, &ipv6) == 1) {
        *is_ip = true;
        return true;
    }
    *is_ip = false;
    return qn_valid_hostname(candidate);
}

static bool link_strings_terminated(const qn_tunnel_link *link)
{
    return memchr(link->secret, '\0', sizeof link->secret) &&
           memchr(link->address, '\0', sizeof link->address) &&
           memchr(link->sni, '\0', sizeof link->sni) &&
           memchr(link->host, '\0', sizeof link->host) &&
           memchr(link->path, '\0', sizeof link->path) &&
           memchr(link->flow, '\0', sizeof link->flow) &&
           memchr(link->alpn, '\0', sizeof link->alpn) &&
           memchr(link->fingerprint, '\0', sizeof link->fingerprint) &&
           memchr(link->service_name, '\0', sizeof link->service_name) &&
           memchr(link->mode, '\0', sizeof link->mode);
}

static bool mode_valid(const qn_tunnel_link *link)
{
    if (link->network == QN_TUNNEL_NETWORK_XHTTP)
        return !strcmp(link->mode, "auto") || !strcmp(link->mode, "packet-up") ||
               !strcmp(link->mode, "stream-up") ||
               !strcmp(link->mode, "stream-one");
    return !strcmp(link->mode, "auto");
}

static bool transport_fields_valid(const qn_tunnel_link *link)
{
    if (link->network == QN_TUNNEL_NETWORK_WS)
        return link->path[0] == '/' && !link->service_name[0] &&
               !link->grpc_multi;
    if (link->network == QN_TUNNEL_NETWORK_GRPC)
        return !link->path[0];
    if (link->network == QN_TUNNEL_NETWORK_XHTTP)
        return link->path[0] == '/' && !link->service_name[0] &&
               !link->grpc_multi;
    return !link->path[0] && !link->service_name[0] && !link->grpc_multi;
}

static bool link_valid(const qn_tunnel_link *link,
                       qn_tunnel_config_mode mode)
{
    return link && link->protocol < QN_TUNNEL_PROTOCOL_COUNT &&
           link->network < QN_TUNNEL_NETWORK_COUNT &&
           link->security < QN_TUNNEL_SECURITY_COUNT &&
           link_strings_terminated(link) && link->port != 0u &&
           link->address[0] != '\0' &&
           (link->security != QN_TUNNEL_SECURITY_TLS ||
            (link->sni[0] && (mode == QN_TUNNEL_CONFIG_TEMPLATE ||
                              qn_valid_hostname(link->sni)))) &&
           transport_fields_valid(link) && mode_valid(link) &&
           (!link->flow[0] ||
            (link->protocol == QN_TUNNEL_PROTOCOL_VLESS &&
             link->network == QN_TUNNEL_NETWORK_TCP &&
             link->security == QN_TUNNEL_SECURITY_TLS));
}

static void append_alpn(json_buffer *buffer, const char *alpn)
{
    char part[QN_TUNNEL_ALPN_MAX + 1u];
    size_t used = 0u;
    bool first = true;

    append_raw(buffer, "[");
    for (const char *p = alpn;; p++) {
        if (*p == ',' || *p == '\0') {
            if (used) {
                part[used] = '\0';
                if (!first)
                    append_raw(buffer, ",");
                append_string(buffer, part);
                first = false;
                used = 0u;
            }
            if (!*p)
                break;
        } else if (used < sizeof part - 1u) {
            part[used++] = *p;
        } else {
            buffer->failed = true;
            break;
        }
    }
    append_raw(buffer, "]");
}

static bool verify_names(const qn_tunnel_link *link, char *output, size_t capacity)
{
    int written;

    output[0] = '\0';
    if (link->host[0]) {
        written = snprintf(output, capacity, "%s", link->host);
        if (written < 0 || (size_t)written >= capacity)
            return false;
    }
    if (link->sni[0] && strcmp(link->host, link->sni)) {
        size_t used = strlen(output);

        written = snprintf(output + used, capacity - used, "%s%s",
                           used ? "," : "", link->sni);
        if (written < 0 || (size_t)written >= capacity - used)
            return false;
    }
    return output[0] != '\0';
}

static void append_user(json_buffer *buffer, const qn_tunnel_link *link,
                        const char *candidate, const char *secret)
{
    if (link->protocol == QN_TUNNEL_PROTOCOL_TROJAN) {
        append_raw(buffer, "{\"servers\":[{\"address\":");
        append_string(buffer, candidate);
        append_format(buffer, ",\"port\":%u,\"password\":", link->port);
        append_string(buffer, secret);
        append_raw(buffer, "}]}");
        return;
    }

    append_raw(buffer, "{\"vnext\":[{\"address\":");
    append_string(buffer, candidate);
    append_format(buffer, ",\"port\":%u,\"users\":[{\"id\":", link->port);
    append_string(buffer, secret);
    if (link->protocol == QN_TUNNEL_PROTOCOL_VLESS)
        append_raw(buffer, ",\"encryption\":\"none\"");
    else
        append_raw(buffer, ",\"security\":\"auto\"");
    if (link->flow[0]) {
        append_raw(buffer, ",\"flow\":");
        append_string(buffer, link->flow);
    }
    append_raw(buffer, "}]}]}");
}

static void append_tls(json_buffer *buffer, const qn_tunnel_link *link, bool is_ip)
{
    char names[QN_TUNNEL_HOST_MAX * 2u + 2u];

    if (link->security != QN_TUNNEL_SECURITY_TLS)
        return;
    append_raw(buffer, ",\"tlsSettings\":{\"serverName\":");
    append_string(buffer, link->sni);
    append_raw(buffer, ",\"fingerprint\":");
    append_string(buffer, link->fingerprint);
    if (link->alpn[0]) {
        append_raw(buffer, ",\"alpn\":");
        append_alpn(buffer, link->alpn);
    }
    if (is_ip && (link->host[0] || link->sni[0])) {
        if (!verify_names(link, names, sizeof names)) {
            buffer->failed = true;
            return;
        }
        append_raw(buffer, ",\"verifyPeerCertByName\":");
        append_string(buffer, names);
    }
    append_raw(buffer, "}");
}

static void append_transport(json_buffer *buffer, const qn_tunnel_link *link)
{
    switch (link->network) {
    case QN_TUNNEL_NETWORK_WS:
        append_raw(buffer, ",\"wsSettings\":{\"path\":");
        append_string(buffer, link->path);
        if (link->host[0]) {
            append_raw(buffer, ",\"host\":");
            append_string(buffer, link->host);
            append_raw(buffer, ",\"headers\":{\"Host\":");
            append_string(buffer, link->host);
            append_raw(buffer, "}");
        }
        append_raw(buffer, "}");
        break;
    case QN_TUNNEL_NETWORK_GRPC:
        append_raw(buffer, ",\"grpcSettings\":{\"serviceName\":");
        append_string(buffer, link->service_name);
        append_raw(buffer, ",\"authority\":");
        append_string(buffer, link->host);
        append_format(buffer, ",\"multiMode\":%s}",
                      link->grpc_multi ? "true" : "false");
        break;
    case QN_TUNNEL_NETWORK_XHTTP:
        append_raw(buffer, ",\"xhttpSettings\":{\"host\":");
        append_string(buffer, link->host);
        append_raw(buffer, ",\"path\":");
        append_string(buffer, link->path);
        append_raw(buffer, ",\"mode\":");
        append_string(buffer, link->mode);
        append_raw(buffer, "}");
        break;
    case QN_TUNNEL_NETWORK_TCP:
    case QN_TUNNEL_NETWORK_COUNT:
        break;
    }
}

qn_tunnel_config_code qn_tunnel_config_build(const qn_tunnel_config_request *request,
                                              char *output, size_t capacity,
                                              size_t *length)
{
    json_buffer buffer;
    const qn_tunnel_link *link;
    const char *secret;
    bool is_ip;

    if (!request || !output || !capacity || !length ||
        !link_valid(request->link, request->mode) ||
        request->mode > QN_TUNNEL_CONFIG_TEMPLATE || request->socks_port == 0u)
        return QN_TUNNEL_CONFIG_ARGUMENT;
    if (!candidate_valid(request->candidate, &is_ip))
        return QN_TUNNEL_CONFIG_CANDIDATE;
    link = request->link;
    if (request->mode == QN_TUNNEL_CONFIG_LIVE) {
        if (!link->secret[0])
            return QN_TUNNEL_CONFIG_SECRET;
        secret = link->secret;
    } else if (request->mode == QN_TUNNEL_CONFIG_REDACTED) {
        secret = "<redacted>";
    } else {
        secret = link->protocol == QN_TUNNEL_PROTOCOL_TROJAN
                     ? "REPLACE_PASSWORD" : "REPLACE_UUID";
    }

    buffer = (json_buffer){ output, capacity, 0u, false };
    output[0] = '\0';
    append_raw(&buffer, "{\"log\":{\"loglevel\":\"none\"},\"inbounds\":[{");
    append_format(&buffer,
                  "\"tag\":\"socks-in\",\"listen\":\"127.0.0.1\",\"port\":%u,"
                  "\"protocol\":\"socks\",\"settings\":{\"auth\":\"noauth\","
                  "\"udp\":false},\"sniffing\":{\"enabled\":false}}],"
                  "\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":",
                  request->socks_port);
    append_string(&buffer, qn_tunnel_protocol_str(link->protocol));
    append_raw(&buffer, ",\"settings\":");
    append_user(&buffer, link, request->candidate, secret);
    append_raw(&buffer, ",\"streamSettings\":{\"network\":");
    append_string(&buffer, qn_tunnel_network_str(link->network));
    append_raw(&buffer, ",\"security\":");
    append_string(&buffer, qn_tunnel_security_str(link->security));
    append_tls(&buffer, link, is_ip);
    append_transport(&buffer, link);
    append_raw(&buffer,
               "}},{\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{}}],"
               "\"routing\":{\"domainStrategy\":\"AsIs\",\"rules\":[{\"type\":\"field\","
               "\"network\":\"tcp,udp\",\"outboundTag\":\"proxy\"}]}}");
    if (buffer.failed)
        return QN_TUNNEL_CONFIG_OVERFLOW;
    *length = buffer.used;
    return QN_TUNNEL_CONFIG_OK;
}

const char *qn_tunnel_config_str(qn_tunnel_config_code code)
{
    static const char *const names[] = {
        "ok", "invalid-argument", "invalid-candidate", "missing-secret", "overflow"
    };

    return code <= QN_TUNNEL_CONFIG_OVERFLOW ? names[code] : "invalid";
}
