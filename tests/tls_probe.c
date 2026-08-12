/* Drives a real handshake against a peer. Used by scripts/test_tls_local.sh. */

#include "qanat/tls.h"
#include "qanat/util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dial(const char *ip, uint16_t port)
{
    struct sockaddr_in sa;
    int                fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0)
            return false;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return true;
}

int main(int argc, char **argv)
{
    static uint8_t inbuf[16384], outbuf[32768], appbuf[262144], hello[4096];
    qn_tls_session s;
    qn_tls_config  cfg;
    qn_tls_io      io;
    const char    *ip   = argc > 1 ? argv[1] : "127.0.0.1";
    uint16_t       port = (uint16_t)(argc > 2 ? atoi(argv[2]) : 4443);
    const char    *sni  = argc > 3 ? argv[3] : "localhost";
    qn_tls_fp      fp   = QN_TLS_FP_CHROME;
    int            fd, n;
    size_t         total_app = 0;
    bool           shook     = false;

    if (argc > 4 && !qn_tls_fp_parse(argv[4], &fp)) {
        fprintf(stderr, "bad fingerprint %s\n", argv[4]);
        return 2;
    }

    memset(&cfg, 0, sizeof cfg);
    cfg.sni         = sni;
    cfg.fp          = fp;
    cfg.allow_tls12 = argc > 5 && !strcmp(argv[5], "tls12");

    qn_tls_init(&s, &cfg);

    fd = dial(ip, port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    n = qn_tls_start(&s, hello, sizeof hello);
    if (n < 0 || !write_all(fd, hello, (size_t)n)) {
        fprintf(stderr, "hello failed\n");
        return 1;
    }
    printf("hello: %d bytes, fingerprint=%s\n", n, qn_tls_fp_str(fp));
    printf("ja3: %s\nja4: %s\n", s.ja3, s.ja4);

    for (;;) {
        ssize_t   r = read(fd, inbuf, sizeof inbuf);
        qn_tls_rc rc;

        if (r <= 0) {
            fprintf(stderr, "peer closed before completion\n");
            return 1;
        }

        memset(&io, 0, sizeof io);
        io.in     = inbuf;
        io.inlen  = (size_t)r;
        io.out    = outbuf;
        io.outcap = sizeof outbuf;
        io.app    = appbuf + total_app;
        io.appcap = sizeof appbuf - total_app;

        rc = qn_tls_recv(&s, &io);
        if (io.outlen && !write_all(fd, io.out, io.outlen)) {
            fprintf(stderr, "write failed\n");
            return 1;
        }
        total_app += io.applen;

        if (rc == QN_TLS_RC_DONE && !shook) {
            static const char *req_fmt = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
            char               req[256];
            int                rl;

            shook = true;
            printf("handshake: ok version=0x%04X suite=0x%04X ems=%d cn=%s issuer=%s\n", s.version, s.suite,
                   (int)s.ems, s.peer_cn[0] ? s.peer_cn : "-",
                   s.peer_issuer[0] ? s.peer_issuer : "-");

            rl = snprintf(req, sizeof req, req_fmt, sni);
            n  = qn_tls_send_app(&s, (const uint8_t *)req, (size_t)rl, outbuf, sizeof outbuf);
            if (n < 0 || !write_all(fd, outbuf, (size_t)n)) {
                fprintf(stderr, "app write failed\n");
                return 1;
            }
            continue;
        }

        if (rc == QN_TLS_RC_MORE || rc == QN_TLS_RC_DONE)
            continue;
        if (rc == QN_TLS_RC_ALERT && shook && total_app)
            break;

        fprintf(stderr,
                "handshake failed: %s (state=%u hs=%u suite=0x%04X alert=%u)\n",
                qn_tls_rc_str(rc), s.st, s.hs_type, s.suite, s.alert_desc);
        return 1;
    }

    printf("app: %zu bytes\n", total_app);
    if (total_app >= 12 && memcmp(appbuf, "HTTP/1.", 7) == 0) {
        char line[80];
        size_t i;
        for (i = 0; i < sizeof line - 1 && i < total_app && appbuf[i] != '\r'; i++)
            line[i] = (char)appbuf[i];
        line[i] = 0;
        printf("status: %s\n", line);
        return 0;
    }
    fprintf(stderr, "no HTTP response seen\n");
    return 1;
}
