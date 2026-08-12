#include "qanat/tunnel.h"

#include <string.h>

enum {
    SOCKS_PHASE_METHOD = 0,
    SOCKS_PHASE_CONNECT,
    SOCKS_PHASE_READY,
    SOCKS_PHASE_FAILED
};

bool qn_socks5_init(qn_socks5_client *client, const char *host, uint16_t port)
{
    size_t length;

    if (!client || !host || !port)
        return false;
    length = strnlen(host, 256u);
    if (!length || length >= 256u)
        return false;
    for (size_t i = 0u; i < length; i++) {
        unsigned char c = (unsigned char)host[i];

        if (c <= 0x20u || c >= 0x7fu)
            return false;
    }
    memset(client, 0, sizeof *client);
    memcpy(client->host, host, length + 1u);
    client->host_length = (uint8_t)length;
    client->port = port;
    client->phase = SOCKS_PHASE_METHOD;
    client->response_needed = 2u;
    return true;
}

size_t qn_socks5_greeting(uint8_t output[3])
{
    if (!output)
        return 0u;
    output[0] = 0x05u;
    output[1] = 0x01u;
    output[2] = 0x00u;
    return 3u;
}

static qn_socks5_action fail(qn_socks5_client *client, qn_socks5_error error)
{
    client->phase = SOCKS_PHASE_FAILED;
    client->error = error;
    return QN_SOCKS5_FAILED;
}

static qn_socks5_action method_complete(qn_socks5_client *client,
                                        uint8_t *output, size_t capacity,
                                        size_t *output_length)
{
    size_t need = 7u + client->host_length;

    if (client->response[0] != 0x05u)
        return fail(client, QN_SOCKS5_ERROR_VERSION);
    if (client->response[1] != 0x00u)
        return fail(client, QN_SOCKS5_ERROR_AUTH);
    if (!output || capacity < need)
        return fail(client, QN_SOCKS5_ERROR_OVERFLOW);
    output[0] = 0x05u;
    output[1] = 0x01u;
    output[2] = 0x00u;
    output[3] = 0x03u;
    output[4] = client->host_length;
    memcpy(output + 5u, client->host, client->host_length);
    output[5u + client->host_length] = (uint8_t)(client->port >> 8);
    output[6u + client->host_length] = (uint8_t)client->port;
    *output_length = need;
    client->phase = SOCKS_PHASE_CONNECT;
    client->response_length = 0u;
    client->response_needed = 4u;
    return QN_SOCKS5_SEND_CONNECT;
}

static qn_socks5_action connect_header(qn_socks5_client *client)
{
    if (client->response[0] != 0x05u)
        return fail(client, QN_SOCKS5_ERROR_VERSION);
    if (client->response[1] != 0x00u)
        return fail(client, QN_SOCKS5_ERROR_CONNECT);
    if (client->response[2] != 0x00u)
        return fail(client, QN_SOCKS5_ERROR_RESERVED);
    switch (client->response[3]) {
    case 0x01u:
        client->response_needed = 10u;
        break;
    case 0x03u:
        client->response_needed = 5u;
        break;
    default:
        return fail(client, QN_SOCKS5_ERROR_ADDRESS);
    }
    return QN_SOCKS5_NEED_INPUT;
}

static qn_socks5_action connect_complete(qn_socks5_client *client)
{
    client->phase = SOCKS_PHASE_READY;
    client->error = QN_SOCKS5_ERROR_NONE;
    return QN_SOCKS5_READY;
}

qn_socks5_action qn_socks5_feed(qn_socks5_client *client,
                                const uint8_t *input, size_t length,
                                size_t *consumed, uint8_t *output,
                                size_t output_capacity, size_t *output_length)
{
    qn_socks5_action action = QN_SOCKS5_NEED_INPUT;

    if (consumed)
        *consumed = 0u;
    if (output_length)
        *output_length = 0u;
    if (!client || (!input && length) || !consumed || !output_length)
        return client ? fail(client, QN_SOCKS5_ERROR_ARGUMENT) : QN_SOCKS5_FAILED;
    if (client->phase == SOCKS_PHASE_READY)
        return length ? fail(client, QN_SOCKS5_ERROR_OVERFLOW) : QN_SOCKS5_READY;
    if (client->phase == SOCKS_PHASE_FAILED)
        return QN_SOCKS5_FAILED;

    while (*consumed < length) {
        if (client->response_length >= sizeof client->response)
            return fail(client, QN_SOCKS5_ERROR_OVERFLOW);
        client->response[client->response_length++] = input[(*consumed)++];
        if (client->response_length < client->response_needed)
            continue;
        if (client->phase == SOCKS_PHASE_METHOD) {
            action = method_complete(client, output, output_capacity, output_length);
            if (action != QN_SOCKS5_NEED_INPUT)
                return *consumed < length ? fail(client, QN_SOCKS5_ERROR_OVERFLOW)
                                          : action;
        } else if (client->response_needed == 4u) {
            action = connect_header(client);
            if (action == QN_SOCKS5_FAILED)
                return action;
        }
        if (client->phase == SOCKS_PHASE_CONNECT &&
            client->response[3] == 0x03u && client->response_needed == 5u &&
            client->response_length == 5u) {
            client->response_needed = 7u + client->response[4];
            if (client->response_needed > sizeof client->response ||
                client->response[4] == 0u)
                return fail(client, QN_SOCKS5_ERROR_ADDRESS);
        }
        if (client->phase == SOCKS_PHASE_CONNECT &&
            client->response_length == client->response_needed &&
            client->response_needed > 5u) {
            action = connect_complete(client);
            return *consumed < length ? fail(client, QN_SOCKS5_ERROR_OVERFLOW)
                                      : action;
        }
    }
    return action;
}

qn_socks5_action qn_socks5_eof(qn_socks5_client *client)
{
    if (!client)
        return QN_SOCKS5_FAILED;
    if (client->phase == SOCKS_PHASE_READY)
        return QN_SOCKS5_READY;
    return fail(client, QN_SOCKS5_ERROR_TRUNCATED);
}

const char *qn_socks5_error_str(qn_socks5_error error)
{
    static const char *const names[] = {
        "none", "argument", "version", "auth", "connect", "address",
        "reserved", "overflow", "truncated"
    };

    return error <= QN_SOCKS5_ERROR_TRUNCATED ? names[error] : "invalid";
}
