#include "qanat/tunnel.h"
#include "fake_socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); failures++; \
} } while (0)

static char *read_snapshot(const char *path)
{
    FILE *file = fopen(path, "rb");
    char *buffer;
    long end;
    size_t length;

    if (!file)
        return NULL;
    if (fseek(file, 0, SEEK_END) != 0 || (end = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        return NULL;
    }
    length = (size_t)end;
    buffer = (char *)malloc(length + 1u);
    if (!buffer) {
        (void)fclose(file);
        return NULL;
    }
    if (fread(buffer, 1u, length, file) != length || fclose(file) != 0) {
        free(buffer);
        return NULL;
    }
    while (length && (buffer[length - 1u] == '\n' ||
                      buffer[length - 1u] == '\r'))
        length--;
    buffer[length] = '\0';
    return buffer;
}

static void test_vless(void)
{
    const char *uri =
        "vless://123e4567-e89b-12d3-a456-426614174000@origin.example:443"
        "?type=ws&security=tls&sni=sni.example&host=host.example&path=%2Fedge"
        "&flow=&alpn=h2%2Chttp%2F1.1&fp=chrome";
    qn_tunnel_link link;

    CHECK(qn_tunnel_link_parse_cstr(uri, &link) == QN_TUNNEL_PARSE_OK);
    CHECK(link.protocol == QN_TUNNEL_PROTOCOL_VLESS);
    CHECK(link.network == QN_TUNNEL_NETWORK_WS);
    CHECK(link.security == QN_TUNNEL_SECURITY_TLS);
    CHECK(!strcmp(link.address, "origin.example"));
    CHECK(link.port == 443u);
    CHECK(!strcmp(link.sni, "sni.example"));
    CHECK(!strcmp(link.host, "host.example"));
    CHECK(!strcmp(link.path, "/edge"));
    CHECK(!strcmp(link.alpn, "h2,http/1.1"));
    qn_tunnel_link_clear(&link);
}

static void test_trojan(void)
{
    qn_tunnel_link link;

    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://p%40ss@origin.example:8443?type=grpc&security=tls&"
              "sni=sni.example&host=authority.example&serviceName=svc&multiMode=true",
              &link) == QN_TUNNEL_PARSE_OK);
    CHECK(link.protocol == QN_TUNNEL_PROTOCOL_TROJAN);
    CHECK(!strcmp(link.secret, "p@ss"));
    CHECK(link.network == QN_TUNNEL_NETWORK_GRPC);
    CHECK(link.grpc_multi);
    CHECK(!strcmp(link.service_name, "svc"));
    qn_tunnel_link_clear(&link);

    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@origin.example:443?type=tcp",
              &link) == QN_TUNNEL_PARSE_OK);
    CHECK(link.security == QN_TUNNEL_SECURITY_TLS);
    CHECK(!strcmp(link.sni, "origin.example"));
    CHECK(!strcmp(link.host, "origin.example"));
    qn_tunnel_link_clear(&link);
}

static void test_vmess(void)
{
    const char *uri =
        "vmess://eyJ2IjoiMiIsImFkZCI6Im9yaWdpbi5leGFtcGxlIiwicG9ydCI6IjQ0MyIs"
        "ImlkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiYWlkIjoi"
        "MCIsIm5ldCI6InhodHRwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiaG9zdC5leGFtcGxl"
        "IiwicGF0aCI6Ii94IiwidGxzIjoidGxzIiwic25pIjoic25pLmV4YW1wbGUiLCJhbHBu"
        "IjoiaDIsaHR0cC8xLjEiLCJmcCI6ImNocm9tZSIsIm1vZGUiOiJzdHJlYW0tdXAifQ==";
    qn_tunnel_link link;

    CHECK(qn_tunnel_link_parse_cstr(uri, &link) == QN_TUNNEL_PARSE_OK);
    CHECK(link.protocol == QN_TUNNEL_PROTOCOL_VMESS);
    CHECK(link.network == QN_TUNNEL_NETWORK_XHTTP);
    CHECK(link.security == QN_TUNNEL_SECURITY_TLS);
    CHECK(!strcmp(link.path, "/x"));
    CHECK(!strcmp(link.mode, "stream-up"));
    qn_tunnel_link_clear(&link);
    {
        char with_fragment[2048];

        CHECK(snprintf(with_fragment, sizeof with_fragment, "%s#node%%20one",
                       uri) > 0);
        CHECK(qn_tunnel_link_parse_cstr(with_fragment, &link) ==
              QN_TUNNEL_PARSE_OK);
        qn_tunnel_link_clear(&link);
    }
}

static void test_bad_links(void)
{
    qn_tunnel_link link;
    char oversized[QN_TUNNEL_LINK_MAX + 2u];
    uint8_t invalid_utf8[] = { 'v', 'l', 'e', 's', 's', ':', '/', '/', 0xc0u, 0xafu };

    memset(&link, 0xa5, sizeof link);
    CHECK(qn_tunnel_link_parse_cstr("", &link) == QN_TUNNEL_PARSE_EMPTY);
    CHECK(link.secret[0] == '\0');
    CHECK(qn_tunnel_link_parse_cstr("vless://x", &link) == QN_TUNNEL_PARSE_SYNTAX);
    CHECK(qn_tunnel_link_parse_cstr(
              "vless://123e4567-e89b-12d3-a456-426614174000@a.example:443?"
              "type=ws&type=tcp",
              &link) == QN_TUNNEL_PARSE_DUPLICATE);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443?path=%zz",
              &link) == QN_TUNNEL_PARSE_ENCODING);
    CHECK(qn_tunnel_link_parse(invalid_utf8, sizeof invalid_utf8, &link) ==
          QN_TUNNEL_PARSE_UTF8);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443?unknown=x",
              &link) == QN_TUNNEL_PARSE_UNSUPPORTED_FIELD);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://bad@secret@a.example:443",
              &link) == QN_TUNNEL_PARSE_SYNTAX);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443#bad%zz",
              &link) == QN_TUNNEL_PARSE_ENCODING);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443?type=tcp&path=%2Fx",
              &link) == QN_TUNNEL_PARSE_UNSUPPORTED_VALUE);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443?type=ws&serviceName=ignored",
              &link) == QN_TUNNEL_PARSE_UNSUPPORTED_VALUE);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@a.example:443?type=ws&security=none&fp=chrome",
              &link) == QN_TUNNEL_PARSE_UNSUPPORTED_VALUE);
    CHECK(qn_tunnel_link_parse_cstr(
              "vmess://eyJhZGQiOiJhLmV4YW1wbGUiLCJwb3J0IjoiNDQzIiwiaWQiOiIx"
              "MjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAifQ==",
              &link) == QN_TUNNEL_PARSE_JSON);
    CHECK(qn_tunnel_link_parse_cstr("vmess://YWJ=", &link) ==
          QN_TUNNEL_PARSE_ENCODING);
    CHECK(qn_tunnel_link_parse_cstr(
              "trojan://secret@198.51.100.2:443?type=ws&security=tls&"
              "host=front.example&path=%2Fedge",
              &link) == QN_TUNNEL_PARSE_OK);
    CHECK(!strcmp(link.sni, "front.example"));
    qn_tunnel_link_clear(&link);
    memset(oversized, 'x', sizeof oversized);
    oversized[sizeof oversized - 1u] = '\0';
    CHECK(qn_tunnel_link_parse_cstr(oversized, &link) ==
          QN_TUNNEL_PARSE_TOO_LONG);
    CHECK(link.secret[0] == '\0');
}

static qn_tunnel_link sample_link(qn_tunnel_network network,
                                  qn_tunnel_security security)
{
    qn_tunnel_link link;

    memset(&link, 0, sizeof link);
    link.protocol = QN_TUNNEL_PROTOCOL_VLESS;
    link.network = network;
    link.security = security;
    link.port = 443u;
    memcpy(link.secret, "123e4567-e89b-12d3-a456-426614174000", 37u);
    memcpy(link.address, "origin.example", 15u);
    memcpy(link.sni, "sni.example", 12u);
    memcpy(link.host, "host.example", 13u);
    memcpy(link.alpn, "h2,http/1.1", 12u);
    memcpy(link.fingerprint, "chrome", 7u);
    if (network == QN_TUNNEL_NETWORK_WS ||
        network == QN_TUNNEL_NETWORK_XHTTP)
        memcpy(link.path, "/edge", 6u);
    if (network == QN_TUNNEL_NETWORK_GRPC)
        memcpy(link.service_name, "svc", 4u);
    memcpy(link.mode, network == QN_TUNNEL_NETWORK_XHTTP
                          ? "stream-up" : "auto",
           network == QN_TUNNEL_NETWORK_XHTTP ? 10u : 5u);
    return link;
}

static void test_builder(void)
{
    static const char *const snapshots[QN_TUNNEL_NETWORK_COUNT]
                                                [QN_TUNNEL_SECURITY_COUNT] = {
        { "tests/snapshots/xray-vless-ws-none.json",
          "tests/snapshots/xray-vless-ws-tls.json" },
        { "tests/snapshots/xray-vless-grpc-none.json",
          "tests/snapshots/xray-vless-grpc-tls.json" },
        { "tests/snapshots/xray-vless-xhttp-none.json",
          "tests/snapshots/xray-vless-xhttp-tls.json" },
        { "tests/snapshots/xray-vless-tcp-none.json",
          "tests/snapshots/xray-vless-tcp-tls.json" }
    };
    char config[QN_TUNNEL_CONFIG_MAX];
    size_t length;

    for (unsigned network = 0u; network < QN_TUNNEL_NETWORK_COUNT; network++) {
        for (unsigned security = 0u; security < QN_TUNNEL_SECURITY_COUNT; security++) {
            qn_tunnel_link link = sample_link((qn_tunnel_network)network,
                                              (qn_tunnel_security)security);
            qn_tunnel_config_request request = {
                &link, "203.0.113.8", 21080u, QN_TUNNEL_CONFIG_LIVE
            };

            CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
                  QN_TUNNEL_CONFIG_OK);
            {
                char *snapshot = read_snapshot(snapshots[network][security]);

                CHECK(snapshot != NULL);
                if (snapshot) {
                    CHECK(strcmp(config, snapshot) == 0);
                    free(snapshot);
                }
            }
            CHECK(length == strlen(config));
            CHECK(strstr(config, "\"address\":\"203.0.113.8\"") != NULL);
            CHECK(strstr(config, "origin.example") == NULL);
            CHECK(strstr(config, "123e4567-e89b-12d3-a456-426614174000") != NULL);
            if (security == QN_TUNNEL_SECURITY_TLS) {
                CHECK(strstr(config, "sni.example") != NULL);
                CHECK(strstr(config, "\"verifyPeerCertByName\":"
                                     "\"host.example,sni.example\"") != NULL);
            } else {
                CHECK(strstr(config, "sni.example") == NULL);
                CHECK(strstr(config, "verifyPeerCertByName") == NULL);
            }
            if (network != QN_TUNNEL_NETWORK_TCP)
                CHECK(strstr(config, "host.example") != NULL);
            qn_tunnel_link_clear(&link);
        }
    }
}

static void test_builder_secret_policy(void)
{
    qn_tunnel_link link = sample_link(QN_TUNNEL_NETWORK_WS,
                                      QN_TUNNEL_SECURITY_TLS);
    qn_tunnel_config_request request = {
        &link, "candidate.example", 21080u, QN_TUNNEL_CONFIG_REDACTED
    };
    char config[QN_TUNNEL_CONFIG_MAX];
    size_t length;

    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_OK);
    CHECK(strstr(config, "123e4567-e89b-12d3-a456-426614174000") == NULL);
    CHECK(strstr(config, "<redacted>") != NULL);
    CHECK(strstr(config, "verifyPeerCertByName") == NULL);
    request.candidate = "198.51.100.4";
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_OK);
    CHECK(strstr(config, "\"verifyPeerCertByName\":"
                         "\"host.example,sni.example\"") != NULL);
    qn_tunnel_link_clear(&link);
}

static void test_builder_protocol_shapes(void)
{
    qn_tunnel_link link = sample_link(QN_TUNNEL_NETWORK_WS,
                                      QN_TUNNEL_SECURITY_TLS);
    qn_tunnel_config_request request = {
        &link, "203.0.113.8", 21080u, QN_TUNNEL_CONFIG_LIVE
    };
    char config[QN_TUNNEL_CONFIG_MAX];
    size_t length;

    link.protocol = QN_TUNNEL_PROTOCOL_TROJAN;
    memcpy(link.secret, "correct horse battery staple", 29u);
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_OK);
    CHECK(strstr(config, "\"protocol\":\"trojan\"") != NULL);
    CHECK(strstr(config, "\"servers\":[{") != NULL);
    CHECK(strstr(config, "\"password\":") != NULL);
    CHECK(strstr(config, "\"vnext\":") == NULL);

    link.protocol = QN_TUNNEL_PROTOCOL_VMESS;
    memcpy(link.secret, "123e4567-e89b-12d3-a456-426614174000", 37u);
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_OK);
    CHECK(strstr(config, "\"protocol\":\"vmess\"") != NULL);
    CHECK(strstr(config, "\"security\":\"auto\"") != NULL);
    CHECK(strstr(config, "\"encryption\":\"none\"") == NULL);
    qn_tunnel_link_clear(&link);
}

static void test_builder_rejects_ignored_fields(void)
{
    qn_tunnel_link link = sample_link(QN_TUNNEL_NETWORK_TCP,
                                      QN_TUNNEL_SECURITY_TLS);
    qn_tunnel_config_request request = {
        &link, "198.51.100.4", 21080u, QN_TUNNEL_CONFIG_LIVE
    };
    char config[QN_TUNNEL_CONFIG_MAX];
    size_t length;

    memcpy(link.path, "/ignored", 9u);
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_ARGUMENT);
    link.path[0] = '\0';
    memcpy(link.service_name, "ignored", 8u);
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_ARGUMENT);
    link.service_name[0] = '\0';
    link.grpc_multi = true;
    CHECK(qn_tunnel_config_build(&request, config, sizeof config, &length) ==
          QN_TUNNEL_CONFIG_ARGUMENT);
    qn_tunnel_link_clear(&link);
}

static void test_socks_success_fragmented(void)
{
    qn_socks5_client client;
    uint8_t greeting[3];
    uint8_t request[300];
    uint8_t method[] = { 0x05u, 0x00u };
    uint8_t reply[] = { 0x05u, 0x00u, 0x00u, 0x03u, 0x09u,
                        'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x01u, 0xbbu };
    size_t consumed, output_length;

    CHECK(qn_socks5_init(&client, "www.cloudflare.com", 443u));
    CHECK(qn_socks5_greeting(greeting) == 3u);
    CHECK(!memcmp(greeting, (uint8_t[]){ 0x05u, 0x01u, 0x00u }, 3u));
    CHECK(qn_socks5_feed(&client, method, 1u, &consumed, request,
                         sizeof request, &output_length) == QN_SOCKS5_NEED_INPUT);
    CHECK(qn_socks5_feed(&client, method + 1u, 1u, &consumed, request,
                         sizeof request, &output_length) == QN_SOCKS5_SEND_CONNECT);
    CHECK(output_length == 25u);
    CHECK(!memcmp(request, (uint8_t[]){ 0x05u, 0x01u, 0x00u, 0x03u, 18u }, 5u));
    for (size_t i = 0u; i < sizeof reply; i++) {
        qn_socks5_action action = qn_socks5_feed(
            &client, reply + i, 1u, &consumed, request, sizeof request, &output_length);

        CHECK(action == (i + 1u == sizeof reply ? QN_SOCKS5_READY
                                                 : QN_SOCKS5_NEED_INPUT));
    }
}

static void test_socks_failures(void)
{
    qn_socks5_client client;
    uint8_t output[300];
    size_t consumed, output_length;

    CHECK(qn_socks5_init(&client, "example.com", 443u));
    CHECK(qn_socks5_feed(&client, (uint8_t[]){ 0x05u, 0x02u }, 2u,
                         &consumed, output, sizeof output, &output_length) ==
          QN_SOCKS5_FAILED);
    CHECK(client.error == QN_SOCKS5_ERROR_AUTH);

    CHECK(qn_socks5_init(&client, "example.com", 443u));
    CHECK(qn_socks5_feed(&client, (uint8_t[]){ 0x05u }, 1u,
                         &consumed, output, sizeof output, &output_length) ==
          QN_SOCKS5_NEED_INPUT);
    CHECK(qn_socks5_eof(&client) == QN_SOCKS5_FAILED);
    CHECK(client.error == QN_SOCKS5_ERROR_TRUNCATED);

    CHECK(qn_socks5_init(&client, "example.com", 443u));
    CHECK(qn_socks5_feed(&client, (uint8_t[]){ 0x05u, 0x00u }, 2u,
                         &consumed, output, sizeof output, &output_length) ==
          QN_SOCKS5_SEND_CONNECT);
    CHECK(qn_socks5_feed(&client,
                         (uint8_t[]){ 0x05u, 0x05u, 0x00u, 0x01u }, 4u,
                         &consumed, output, sizeof output, &output_length) ==
          QN_SOCKS5_FAILED);
    CHECK(client.error == QN_SOCKS5_ERROR_CONNECT);

    CHECK(qn_socks5_init(&client, "example.com", 443u));
    CHECK(qn_socks5_feed(&client,
                         (uint8_t[]){ 0x05u, 0x00u, 0xffu }, 3u,
                         &consumed, output, sizeof output, &output_length) ==
          QN_SOCKS5_FAILED);
    CHECK(client.error == QN_SOCKS5_ERROR_OVERFLOW);
}

static qn_socks5_action socket_socks_client(qn_fake_socks_mode mode,
                                             qn_socks5_error *error)
{
    qn_fake_socks *server = qn_fake_socks_start(mode);
    qn_socks5_client client;
    struct sockaddr_in address;
    uint8_t input[300];
    uint8_t output[300];
    uint8_t greeting[3];
    qn_socks5_action action = QN_SOCKS5_FAILED;
    int fd = -1;

    CHECK(server != NULL);
    if (!server)
        return action;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    if (fd < 0)
        goto out;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(qn_fake_socks_port(server));
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof address) == 0);
    CHECK(qn_socks5_init(&client, "www.cloudflare.com", 443u));
    {
        size_t greeting_length = qn_socks5_greeting(greeting);

        CHECK(write(fd, greeting, greeting_length) ==
              (ssize_t)greeting_length);
    }
    for (;;) {
        ssize_t got = read(fd, input, sizeof input);
        size_t consumed = 0u;
        size_t output_length = 0u;

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            action = qn_socks5_eof(&client);
            break;
        }
        action = qn_socks5_feed(&client, input, (size_t)got, &consumed,
                                output, sizeof output, &output_length);
        if (action != QN_SOCKS5_FAILED)
            CHECK(consumed == (size_t)got);
        if (action == QN_SOCKS5_SEND_CONNECT) {
            CHECK(write(fd, output, output_length) == (ssize_t)output_length);
            continue;
        }
        if (action == QN_SOCKS5_NEED_INPUT)
            continue;
        break;
    }
    if (error)
        *error = client.error;
out:
    if (fd >= 0)
        (void)close(fd);
    qn_fake_socks_stop(server);
    return action;
}

static void test_socks_loopback_server(void)
{
    qn_socks5_error error = QN_SOCKS5_ERROR_NONE;

    CHECK(socket_socks_client(QN_FAKE_SOCKS_SUCCESS, &error) == QN_SOCKS5_READY);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_FRAGMENTED, &error) ==
          QN_SOCKS5_READY);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_AUTH, &error) == QN_SOCKS5_FAILED);
    CHECK(error == QN_SOCKS5_ERROR_AUTH);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_SHORT, &error) == QN_SOCKS5_FAILED);
    CHECK(error == QN_SOCKS5_ERROR_TRUNCATED);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_CONNECT_ERROR, &error) ==
          QN_SOCKS5_FAILED);
    CHECK(error == QN_SOCKS5_ERROR_CONNECT);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_MIDCLOSE, &error) ==
          QN_SOCKS5_FAILED);
    CHECK(error == QN_SOCKS5_ERROR_TRUNCATED);
    CHECK(socket_socks_client(QN_FAKE_SOCKS_OVERSIZED, &error) ==
          QN_SOCKS5_FAILED);
    CHECK(error == QN_SOCKS5_ERROR_OVERFLOW);
}

int main(void)
{
    test_vless();
    test_trojan();
    test_vmess();
    test_bad_links();
    test_builder();
    test_builder_secret_policy();
    test_builder_protocol_shapes();
    test_builder_rejects_ignored_fields();
    test_socks_success_fragmented();
    test_socks_failures();
    test_socks_loopback_server();
    if (failures) {
        fprintf(stderr, "tunnel tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("tunnel tests: ok");
    return 0;
}
