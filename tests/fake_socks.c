#include "fake_socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct qn_fake_socks {
    int fd;
    uint16_t port;
    qn_fake_socks_mode mode;
    pthread_t thread;
    _Atomic bool greeting_ok;
    _Atomic bool connect_ok;
};

static bool read_exact(int fd, uint8_t *buffer, size_t length)
{
    size_t used = 0u;

    while (used < length) {
        ssize_t got = read(fd, buffer + used, length - used);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        used += (size_t)got;
    }
    return true;
}

static bool write_exact(int fd, const uint8_t *buffer, size_t length)
{
    size_t used = 0u;

    while (used < length) {
        ssize_t wrote = write(fd, buffer + used, length - used);

        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return false;
        used += (size_t)wrote;
    }
    return true;
}

static void fragmented_write(int fd, const uint8_t *buffer, size_t length)
{
    for (size_t i = 0u; i < length; i++) {
        if (!write_exact(fd, buffer + i, 1u))
            break;
        (void)usleep(1000u);
    }
}

static void *serve(void *argument)
{
    qn_fake_socks *server = (qn_fake_socks *)argument;
    uint8_t greeting[3];
    uint8_t header[5];
    uint8_t tail[257];
    static const uint8_t method_ok[] = { 0x05u, 0x00u };
    static const uint8_t connect_ok[] = {
        0x05u, 0x00u, 0x00u, 0x01u, 127u, 0u, 0u, 1u, 0x52u, 0x58u
    };
    int client = accept(server->fd, NULL, NULL);

    if (client < 0)
        return NULL;
    if (!read_exact(client, greeting, sizeof greeting))
        goto out;
    atomic_store_explicit(&server->greeting_ok,
                          memcmp(greeting,
                                 (uint8_t[]){ 0x05u, 0x01u, 0x00u }, 3u) == 0,
                          memory_order_release);
    if (server->mode == QN_FAKE_SOCKS_AUTH) {
        (void)write_exact(client, (uint8_t[]){ 0x05u, 0x02u }, 2u);
        goto out;
    }
    if (server->mode == QN_FAKE_SOCKS_SHORT) {
        (void)write_exact(client, (uint8_t[]){ 0x05u }, 1u);
        goto out;
    }
    if (server->mode == QN_FAKE_SOCKS_OVERSIZED) {
        (void)write_exact(client,
                          (uint8_t[]){ 0x05u, 0x00u, 0xffu }, 3u);
        goto out;
    }
    if (server->mode == QN_FAKE_SOCKS_FRAGMENTED)
        fragmented_write(client, method_ok, sizeof method_ok);
    else if (!write_exact(client, method_ok, sizeof method_ok))
        goto out;
    if (!read_exact(client, header, sizeof header) || header[0] != 0x05u ||
        header[1] != 0x01u || header[2] != 0x00u || header[3] != 0x03u ||
        header[4] == 0u)
        goto out;
    if (!read_exact(client, tail, (size_t)header[4] + 2u))
        goto out;
    atomic_store_explicit(&server->connect_ok, true, memory_order_release);
    if (server->mode == QN_FAKE_SOCKS_MIDCLOSE)
        goto out;
    if (server->mode == QN_FAKE_SOCKS_CONNECT_ERROR) {
        (void)write_exact(client,
                          (uint8_t[]){ 0x05u, 0x05u, 0x00u, 0x01u,
                                       0u, 0u, 0u, 0u, 0u, 0u }, 10u);
        goto out;
    }
    if (server->mode == QN_FAKE_SOCKS_FRAGMENTED)
        fragmented_write(client, connect_ok, sizeof connect_ok);
    else
        (void)write_exact(client, connect_ok, sizeof connect_ok);
out:
    (void)close(client);
    return NULL;
}

qn_fake_socks *qn_fake_socks_start(qn_fake_socks_mode mode)
{
    qn_fake_socks *server = (qn_fake_socks *)calloc(1u, sizeof *server);
    struct sockaddr_in address;
    socklen_t address_length = sizeof address;

    if (!server)
        return NULL;
    server->fd = -1;
    server->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server->fd < 0)
        goto fail;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server->fd, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(server->fd, 1) != 0 ||
        getsockname(server->fd, (struct sockaddr *)&address,
                    &address_length) != 0)
        goto fail;
    server->mode = mode;
    server->port = ntohs(address.sin_port);
    if (pthread_create(&server->thread, NULL, serve, server) != 0)
        goto fail;
    return server;
fail:
    if (server->fd >= 0)
        (void)close(server->fd);
    free(server);
    return NULL;
}

uint16_t qn_fake_socks_port(const qn_fake_socks *server)
{
    return server ? server->port : 0u;
}

bool qn_fake_socks_greeting_ok(const qn_fake_socks *server)
{
    return server && atomic_load_explicit(&server->greeting_ok,
                                           memory_order_acquire);
}

bool qn_fake_socks_connect_ok(const qn_fake_socks *server)
{
    return server && atomic_load_explicit(&server->connect_ok,
                                           memory_order_acquire);
}

void qn_fake_socks_stop(qn_fake_socks *server)
{
    if (!server)
        return;
    (void)shutdown(server->fd, SHUT_RDWR);
    (void)close(server->fd);
    (void)pthread_join(server->thread, NULL);
    free(server);
}
