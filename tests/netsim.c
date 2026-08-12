/* An adversarial peer on loopback: the failure modes a censor produces. */

#include "netsim.h"

#include <errno.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct qn_netsim {
    int             fd;
    uint16_t        port;
    qn_netsim_mode  mode;
    uint32_t        after_bytes;
    uint32_t        delay_ms;
    pthread_t       tid;
    _Atomic int     stop;
    _Atomic int     accepted;
};

static void hard_reset(int fd)
{
    /* Zero linger turns close() into an RST rather than a FIN. */
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
}

static void *serve(void *arg)
{
    qn_netsim *s = (qn_netsim *)arg;

    while (!atomic_load_explicit(&s->stop, memory_order_acquire)) {
        uint8_t buf[4096];
        int     c = accept(s->fd, NULL, NULL);
        ssize_t n;
        uint32_t seen = 0;

        if (c < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        atomic_fetch_add_explicit(&s->accepted, 1, memory_order_relaxed);

        switch (s->mode) {
        case QN_NETSIM_RST_ON_CONNECT:
            hard_reset(c);
            continue;

        case QN_NETSIM_ACCEPT_SILENT:
            /* Hold it open and say nothing, so the client must time out. */
            while (!atomic_load_explicit(&s->stop, memory_order_acquire) && seen < 100u) {
                usleep(10000);
                seen++;
            }
            close(c);
            continue;

        case QN_NETSIM_RST_AFTER_BYTES:
            while (!atomic_load_explicit(&s->stop, memory_order_acquire) &&
                   seen < s->after_bytes) {
                n = read(c, buf, sizeof buf);
                if (n <= 0)
                    break;
                seen += (uint32_t)n;
            }
            hard_reset(c);
            continue;

        case QN_NETSIM_EOF_AFTER_BYTES:
            while (!atomic_load_explicit(&s->stop, memory_order_acquire) &&
                   seen < s->after_bytes) {
                n = read(c, buf, sizeof buf);
                if (n <= 0)
                    break;
                seen += (uint32_t)n;
            }
            close(c); /* FIN rather than RST, so the two are told apart */
            continue;

        case QN_NETSIM_GARBAGE:
            /* Answer a ClientHello with something that is not TLS at all. */
            n = read(c, buf, sizeof buf);
            if (n > 0) {
                static const char junk[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                ssize_t written = write(c, junk, sizeof junk - 1u);
                if (written < 0 && errno == EINTR)
                    written = write(c, junk, sizeof junk - 1u);
                (void)written;
            }
            close(c);
            continue;

        case QN_NETSIM_DRIP:
            /* One byte at a time, to exercise partial reads. */
            n = read(c, buf, sizeof buf);
            if (n > 0) {
                static const uint8_t rec[] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0 };
                size_t               i;
                for (i = 0; i < sizeof rec &&
                            !atomic_load_explicit(&s->stop, memory_order_acquire);
                     i++) {
                    if (write(c, rec + i, 1) != 1)
                        break;
                    usleep(1000);
                }
            }
            close(c);
            continue;

        default:
            close(c);
            continue;
        }
    }
    return NULL;
}

qn_netsim *qn_netsim_start(qn_netsim_mode mode, uint32_t after_bytes)
{
    struct sockaddr_in sa;
    socklen_t          sl = sizeof sa;
    qn_netsim         *s  = (qn_netsim *)calloc(1, sizeof *s);
    int                one = 1;

    if (!s)
        return NULL;

    s->mode        = mode;
    s->after_bytes = after_bytes ? after_bytes : 1u;
    s->fd          = socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0) {
        free(s);
        return NULL;
    }
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7F000001u);
    sa.sin_port        = 0; /* let the kernel pick */

    if (bind(s->fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(s->fd, 64) != 0 ||
        getsockname(s->fd, (struct sockaddr *)&sa, &sl) != 0) {
        close(s->fd);
        free(s);
        return NULL;
    }
    s->port = ntohs(sa.sin_port);

    if (pthread_create(&s->tid, NULL, serve, s) != 0) {
        close(s->fd);
        free(s);
        return NULL;
    }
    return s;
}

uint16_t qn_netsim_port(const qn_netsim *s)
{
    return s ? s->port : 0;
}

uint32_t qn_netsim_accepted(qn_netsim *s)
{
    return s ? (uint32_t)atomic_load_explicit(&s->accepted, memory_order_relaxed) : 0;
}

void qn_netsim_stop(qn_netsim *s)
{
    if (!s)
        return;
    atomic_store_explicit(&s->stop, 1, memory_order_release);
    shutdown(s->fd, SHUT_RDWR);
    close(s->fd);
    pthread_join(s->tid, NULL);
    free(s);
}
