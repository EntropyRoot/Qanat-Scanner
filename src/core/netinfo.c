#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/netinfo.h"

#include "qanat/probe.h"
#include "qanat/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

const char *qn_diag_state_str(qn_diag_state state)
{
    switch (state) {
    case QN_DIAG_NOT_RUN:      return "not-run";
    case QN_DIAG_POSITIVE:     return "positive";
    case QN_DIAG_NEGATIVE:     return "negative";
    case QN_DIAG_INCONCLUSIVE: return "inconclusive";
    default:                   return "invalid";
    }
}

#if defined(__has_include)
#if __has_include(<sys/system_properties.h>)
#include <sys/system_properties.h>
#define QN_HAVE_PROPS 1
#endif
#endif

#define CONTROL_DOMAIN "example.com"
#define TRACE_HOST     "1.1.1.1"

const char *qn_link_kind_str(qn_link_kind k)
{
    switch (k) {
    case QN_LINK_WIFI:     return "wifi";
    case QN_LINK_CELL:     return "cellular";
    case QN_LINK_VPN:      return "vpn";
    case QN_LINK_LOOPBACK: return "loopback";
    case QN_LINK_ETHER:    return "ethernet";
    default:               return "unknown";
    }
}

static qn_link_kind kind_of(const char *name)
{
    if (!strncmp(name, "lo", 2))
        return QN_LINK_LOOPBACK;
    if (!strncmp(name, "wlan", 4) || !strncmp(name, "ap", 2) || !strncmp(name, "swlan", 5))
        return QN_LINK_WIFI;
    if (!strncmp(name, "rmnet", 5) || !strncmp(name, "ccmni", 5) || !strncmp(name, "pdp", 3) ||
        !strncmp(name, "seth", 4) || !strncmp(name, "v4-rmnet", 8))
        return QN_LINK_CELL;
    if (!strncmp(name, "tun", 3) || !strncmp(name, "ppp", 3) || !strncmp(name, "wg", 2) ||
        !strncmp(name, "ipsec", 5))
        return QN_LINK_VPN;
    if (!strncmp(name, "eth", 3) || !strncmp(name, "en", 2))
        return QN_LINK_ETHER;
    return QN_LINK_UNKNOWN;
}

static bool mask_to_bits(uint32_t mask, uint8_t *bits)
{
    uint32_t inverse = ~mask;

    /* A valid IPv4 netmask is a run of ones followed only by zeroes. */
    if (!bits || (inverse & (inverse + 1u)) != 0u)
        return false;
    *bits = (uint8_t)__builtin_popcount(mask);
    return true;
}

static void read_iface_counters(qn_netinfo *ni)
{
    FILE *f = fopen("/proc/net/dev", "r");
    char  line[512];

    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        char             *colon = strchr(line, ':');
        char             *name;
        unsigned long long rx = 0, tx = 0, d;

        if (!colon)
            continue;
        *colon = '\0';
        name   = line;
        while (*name == ' ')
            name++;

        if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", &rx, &d, &d, &d, &d,
                   &d, &d, &d, &tx) < 9)
            continue;

        for (uint32_t i = 0; i < ni->niface; i++) {
            if (!strcmp(ni->iface[i].name, name)) {
                ni->iface[i].rx_bytes = rx;
                ni->iface[i].tx_bytes = tx;
                break;
            }
        }
    }
    fclose(f);
}

bool qn_netinfo_ifaces(qn_netinfo *ni)
{
    struct ifaddrs *list = NULL, *it;
    int             s;

    if (!ni)
        return false;
    ni->niface = 0;
    memset(ni->iface, 0, sizeof ni->iface);
    if (getifaddrs(&list) != 0)
        return false;

    s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    for (it = list; it; it = it->ifa_next) {
        qn_iface *f = NULL;

        if (!it->ifa_name || !it->ifa_addr || it->ifa_addr->sa_family != AF_INET)
            continue;

        for (uint32_t i = 0; i < ni->niface; i++)
            if (!strcmp(ni->iface[i].name, it->ifa_name)) {
                f = &ni->iface[i];
                break;
            }
        if (!f) {
            if (ni->niface >= QN_MAX_IFACES)
                continue;
            f = &ni->iface[ni->niface++];
            memset(f, 0, sizeof *f);
            qn_strlcpy(f->name, it->ifa_name, sizeof f->name);
            f->kind = (uint8_t)kind_of(f->name);
        }
        f->up = f->up || ((it->ifa_flags & IFF_UP) && (it->ifa_flags & IFF_RUNNING));

        /* Keep one deterministic primary IPv4 address per interface. */
        if (!f->has_v4) {
            f->addr.af   = AF_INET;
            f->addr.u.v4 = ntohl(((struct sockaddr_in *)(void *)it->ifa_addr)->sin_addr.s_addr);
            f->has_v4    = 1;

            if (it->ifa_netmask) {
                uint32_t m = ntohl(((struct sockaddr_in *)(void *)it->ifa_netmask)->sin_addr.s_addr);
                uint8_t  bits;

                if (mask_to_bits(m, &bits)) {
                    f->netmask.af   = AF_INET;
                    f->netmask.u.v4 = m;
                    f->prefix_bits  = bits;
                }
            }
        }

        if (s >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof ifr);
            qn_strlcpy(ifr.ifr_name, f->name, sizeof ifr.ifr_name);
            if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
                f->mtu = (uint32_t)ifr.ifr_mtu;
        }
    }

    if (s >= 0)
        close(s);
    freeifaddrs(list);
    read_iface_counters(ni);
    return ni->niface > 0;
}

/* 1 up, 0 down, -1 unknown. Table and scope would need rtnetlink. */
static int iface_is_up(const char *name)
{
    char  path[64], state[16];
    FILE *f;
    int   up = -1;

    if (snprintf(path, sizeof path, "/sys/class/net/%s/operstate", name) <= 0)
        return -1;
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fgets(state, sizeof state, f)) {
        if (!strncmp(state, "up", 2))
            up = 1;
        else if (!strncmp(state, "down", 4))
            up = 0;
    }
    fclose(f);
    return up;
}

bool qn_netinfo_routes(qn_netinfo *ni)
{
    FILE *f = fopen("/proc/net/route", "r");
    char  line[256];
    bool  got = false;

    if (!ni)
        return false;
    memset(&ni->gateway, 0, sizeof ni->gateway);
    ni->has_gateway = false;
    ni->default_iface[0] = '\0';

    if (!f)
        return false;

    if (!fgets(line, sizeof line, f)) { /* header */
        fclose(f);
        return false;
    }
    {
        unsigned best_metric = 0;
        int      best_up = -1;

        while (fgets(line, sizeof line, f)) {
            char     name[32];
            unsigned dest, gw, flags, refcnt, use, metric;
            int      up;

            if (sscanf(line, "%31s %X %X %X %u %u %u", name, &dest, &gw, &flags,
                       &refcnt, &use, &metric) != 7)
                continue;
            if (dest != 0 || !(flags & 0x1u))
                continue;

            up = iface_is_up(name);
            /* Lowest metric wins; a live interface beats a down one at equal cost. */
            if (got && (up < best_up || (up == best_up && metric >= best_metric)))
                continue;

            /* /proc/net/route stores IPv4 words in little-endian hex. */
            ni->has_gateway = false;
            if (gw) {
                ni->gateway.af   = AF_INET;
                ni->gateway.u.v4 = ntohl(gw);
                ni->has_gateway  = true;
            }
            qn_strlcpy(ni->default_iface, name, sizeof ni->default_iface);
            best_metric = metric;
            best_up     = up;
            got         = true;
        }
    }
    fclose(f);
    return got;
}

bool qn_netinfo_dns(qn_netinfo *ni)
{
    FILE *f;
    char  line[256];

    if (!ni)
        return false;
    ni->ndns = 0;
    memset(ni->dns, 0, sizeof ni->dns);

    f = fopen("/etc/resolv.conf", "r");
    if (f) {
        while (fgets(line, sizeof line, f) && ni->ndns < QN_MAX_DNS) {
            char addr[64];
            if (sscanf(line, "nameserver %63s", addr) == 1) {
                qn_addr parsed;
                bool    duplicate = false;

                if (!qn_addr_parse(addr, &parsed))
                    continue;
                for (uint32_t i = 0; i < ni->ndns; i++)
                    if (qn_addr_eq(&ni->dns[i], &parsed)) {
                        duplicate = true;
                        break;
                    }
                if (!duplicate)
                    ni->dns[ni->ndns++] = parsed;
            }
        }
        fclose(f);
    }

#ifdef QN_HAVE_PROPS
    /* Android exposes resolvers through system properties. */
    if (!ni->ndns) {
        static const char *keys[] = { "net.dns1", "net.dns2", "net.dns3", "net.dns4" };
        for (unsigned i = 0; i < QN_ARRAY_LEN(keys) && ni->ndns < QN_MAX_DNS; i++) {
            char v[PROP_VALUE_MAX];
            if (__system_property_get(keys[i], v) > 0 && qn_addr_parse(v, &ni->dns[ni->ndns]))
                ni->ndns++;
        }
    }
#endif
    return ni->ndns > 0;
}

const qn_iface *qn_netinfo_primary(const qn_netinfo *ni)
{
    const qn_iface *best = NULL;

    if (!ni)
        return NULL;
    for (uint32_t i = 0; i < ni->niface; i++) {
        const qn_iface *f = &ni->iface[i];
        if (f->kind == QN_LINK_LOOPBACK || !f->has_v4)
            continue;
        if (ni->default_iface[0] && !strcmp(f->name, ni->default_iface))
            return f;
        if (!best && f->up)
            best = f;
    }
    return best;
}

bool qn_netinfo_local_prefix(const qn_netinfo *ni, char *out, size_t cap)
{
    const qn_iface *f = qn_netinfo_primary(ni);
    uint8_t         bits;
    char            ip[16];
    char            prefix[32];
    int             n;

    if (!out || !cap || !f || !f->has_v4)
        return false;

    /* Avoid sweeping carrier aggregates inferred from broad routes. */
    bits = f->prefix_bits ? f->prefix_bits : 24;
    if (bits < 22)
        bits = 24;

    qn_ipv4_str(f->addr.u.v4 & (uint32_t)(0xFFFFFFFFu << (32 - bits)), ip);
    n = snprintf(prefix, sizeof prefix, "%s/%u", ip, bits);
    if (n <= 0 || (size_t)n >= sizeof prefix)
        return false;
    return qn_strlcpy(out, prefix, cap) < cap;
}

static int poll_until(int fd, short events, uint64_t deadline_ms)
{
    for (;;) {
        struct pollfd pf = { fd, events, 0 };
        uint64_t      now = qn_now_ms();
        uint64_t      remain;
        int           timeout, rc;

        if (now >= deadline_ms) {
            errno = ETIMEDOUT;
            return 0;
        }
        remain = deadline_ms - now;
        timeout = remain > (uint64_t)INT_MAX ? INT_MAX : (int)remain;
        rc = poll(&pf, 1, timeout);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc == 0)
            errno = ETIMEDOUT;
        if (rc > 0 && (pf.revents & POLLNVAL)) {
            errno = EBADF;
            return -1;
        }
        return rc;
    }
}

static bool peer_replied(int error)
{
    return error == ECONNREFUSED || error == ECONNRESET || error == ECONNABORTED;
}

static int connect_timed(const qn_addr *a, uint16_t port, uint32_t timeout_ms,
                         uint32_t *rtt_us, bool *reachable)
{
    struct sockaddr_in sa;
    uint64_t           t0;
    int                fd, err = 0;
    socklen_t          sl = sizeof err;

    uint64_t deadline;
    int      cr;

    if (rtt_us)
        *rtt_us = 0;
    if (reachable)
        *reachable = false;
    if (!a || a->af != AF_INET || !port) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(a->u.v4);

    t0 = qn_now_ns();
    cr = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (cr != 0 && errno != EINPROGRESS) {
        int saved = errno;

        if (peer_replied(saved) && rtt_us)
            *rtt_us = (uint32_t)((qn_now_ns() - t0) / 1000ull);
        if (reachable && peer_replied(saved))
            *reachable = true;
        close(fd);
        errno = saved;
        return -1;
    }

    if (cr != 0) {
        int wait_rc;

        deadline = qn_now_ms() + timeout_ms;
        wait_rc = poll_until(fd, POLLOUT, deadline);
        if (wait_rc <= 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (rtt_us)
        *rtt_us = (uint32_t)((qn_now_ns() - t0) / 1000ull);

    if (err) {
        if (reachable && peer_replied(err))
            *reachable = true;
        close(fd);
        errno = err;
        return -1;
    }
    if (reachable)
        *reachable = true;
    return fd;
}

static bool send_timed(int fd, const uint8_t *buf, size_t len, uint64_t deadline_ms)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && qn_errno_would_block(errno)) {
            uint64_t now = qn_now_ms();

            if (now >= deadline_ms || poll_until(fd, POLLOUT, deadline_ms) <= 0)
                return false;
            continue;
        }
        return false;
    }
    return true;
}

static ssize_t http_get(const qn_addr *a, uint16_t port, const char *host, const char *path,
                        uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    uint8_t req[512];
    int     rlen;
    int     fd;
    size_t  got = 0;
    uint64_t deadline;

    if (!a || !host || !path || !buf || cap < 2u) {
        errno = EINVAL;
        return -1;
    }
    fd = connect_timed(a, port, timeout_ms, NULL, NULL);
    if (fd < 0)
        return -1;

    deadline = qn_now_ms() + timeout_ms;
    rlen = qn_http_build_get(req, sizeof req, host, path);
    if (rlen <= 0 || !send_timed(fd, req, (size_t)rlen, deadline)) {
        int saved = rlen <= 0 ? EINVAL : errno;
        close(fd);
        errno = saved;
        return -1;
    }

    while (got + 1 < cap) {
        uint64_t      now = qn_now_ms();
        ssize_t       n;

        if (now >= deadline || poll_until(fd, POLLIN, deadline) <= 0)
            break;
        n = recv(fd, buf + got, cap - got - 1, 0);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && qn_errno_would_block(errno))
            continue;
        if (n <= 0)
            break;
    }
    close(fd);
    buf[got] = '\0';
    return (ssize_t)got;
}

static int dns_build(uint8_t *b, size_t cap, const char *name, uint16_t id)
{
    size_t      o = 12;
    const char *p = name;

    if (cap < 12 + strlen(name) + 6)
        return -1;

    b[0] = (uint8_t)(id >> 8);
    b[1] = (uint8_t)id;
    b[2] = 0x01; /* recursion desired */
    b[3] = 0x00;
    b[4] = 0x00;
    b[5] = 0x01; /* qdcount */
    memset(b + 6, 0, 6);

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t      len = dot ? (size_t)(dot - p) : strlen(p);

        if (!len || len > 63 || o + len + 1 >= cap)
            return -1;
        b[o++] = (uint8_t)len;
        memcpy(b + o, p, len);
        o += len;
        if (!dot)
            break;
        p = dot + 1;
    }
    b[o++] = 0x00;
    b[o++] = 0x00;
    b[o++] = 0x01; /* A */
    b[o++] = 0x00;
    b[o++] = 0x01; /* IN */
    return (int)o;
}

static bool dns_skip_name(const uint8_t *b, size_t len, size_t o, size_t *next)
{
    size_t pos = o, wire_end = 0, expanded = 0;
    bool   jumped = false;

    if (!b || !next || o >= len)
        return false;
    for (size_t steps = 0; steps <= len; steps++) {
        uint8_t l;

        if (pos >= len)
            return false;
        l = b[pos];
        if (!l) {
            *next = jumped ? wire_end : pos + 1u;
            return true;
        }
        if ((l & 0xC0u) == 0xC0u) {
            uint16_t target;

            if (pos + 1u >= len)
                return false;
            target = (uint16_t)(((uint16_t)(l & 0x3Fu) << 8) | b[pos + 1u]);
            /* RFC 1035 backward compression targets also rule out pointer cycles. */
            if ((size_t)target >= pos)
                return false;
            if (!jumped) {
                wire_end = pos + 2u;
                jumped = true;
            }
            pos = target;
            continue;
        }
        if ((l & 0xC0u) != 0u || l > 63u || (size_t)l > len - pos - 1u ||
            expanded + (size_t)l + 1u > 255u)
            return false;
        expanded += (size_t)l + 1u;
        pos += (size_t)l + 1u;
    }
    return false;
}

static uint32_t dns_answers(const uint8_t *b, size_t len, uint32_t *out, uint32_t cap)
{
    uint16_t qd, an;
    size_t   o = 12;
    uint32_t n = 0;

    if (!b || !out || !cap || len < 12)
        return 0;
    qd = (uint16_t)((b[4] << 8) | b[5]);
    an = (uint16_t)((b[6] << 8) | b[7]);

    if (qd != 1u || !dns_skip_name(b, len, o, &o) || o > len || len - o < 4u)
        return 0;
    o += 4u;

    for (uint16_t i = 0; i < an; i++) {
        uint16_t type, class_, rdlen;

        if (!dns_skip_name(b, len, o, &o))
            return 0;
        if (o + 10 > len)
            return 0;
        type  = (uint16_t)((b[o] << 8) | b[o + 1]);
        class_ = (uint16_t)((b[o + 2] << 8) | b[o + 3]);
        rdlen = (uint16_t)((b[o + 8] << 8) | b[o + 9]);
        o += 10;
        if (o + rdlen > len)
            return 0;
        if (type == 1u && class_ == 1u && rdlen == 4u && n < cap)
            out[n++] = ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) |
                       ((uint32_t)b[o + 2] << 8) | b[o + 3];
        o += rdlen;
    }
    return n;
}

static uint32_t dns_query(const qn_addr *server, const char *name, uint32_t *out, uint32_t cap,
                          uint32_t timeout_ms, uint32_t *rtt_us)
{
    struct sockaddr_storage ss;
    socklen_t               sslen;
    uint8_t            q[512], r[1024];
    uint64_t           t0;
    uint64_t           deadline;
    uint16_t           id;
    int                fd, qlen;
    ssize_t            n;
    uint32_t           found = 0;

    if (!server || (server->af != AF_INET && server->af != AF_INET6))
        return 0;

    id   = (uint16_t)qn_rng_entropy();
    qlen = dns_build(q, sizeof q, name, id);
    if (qlen <= 0)
        return 0;

    fd = socket(server->af, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;

    memset(&ss, 0, sizeof ss);
    if (server->af == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)(void *)&ss;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(53);
        sa->sin_addr.s_addr = htonl(server->u.v4);
        sslen = sizeof *sa;
    } else {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)(void *)&ss;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(53);
        memcpy(&sa6->sin6_addr, server->u.v6, sizeof sa6->sin6_addr);
        sslen = sizeof *sa6;
    }

    if (connect(fd, (struct sockaddr *)(void *)&ss, sslen) != 0) {
        close(fd);
        return 0;
    }
    t0 = qn_now_ns();
    deadline = qn_now_ms() + timeout_ms;
    if (!send_timed(fd, q, (size_t)qlen, deadline)) {
        close(fd);
        return 0;
    }

    if (poll_until(fd, POLLIN, deadline) > 0) {
        do {
            n = recv(fd, r, sizeof r, 0);
        } while (n < 0 && errno == EINTR);
        if (n >= 12 && r[0] == (uint8_t)(id >> 8) && r[1] == (uint8_t)id &&
            (r[2] & 0x80u) && !(r[2] & 0x7Au) && !(r[3] & 0x0Fu) &&
            r[4] == 0u && r[5] == 1u) {
            found = dns_answers(r, (size_t)n, out, cap);
            if (found && rtt_us)
                *rtt_us = (uint32_t)((qn_now_ns() - t0) / 1000ull);
        }
    }
    close(fd);
    return found;
}

static bool dns_resolve_v4(const qn_netinfo *ni, const char *name, uint32_t timeout_ms,
                           qn_addr *out)
{
    uint32_t answer[1];
    uint64_t deadline;

    if (!ni || !name || !out)
        return false;
    memset(out, 0, sizeof *out);
    deadline = qn_now_ms() + timeout_ms;
    for (uint32_t i = 0; i < ni->ndns; i++) {
        uint64_t now = qn_now_ms();
        uint32_t remain;

        if (now >= deadline)
            break;
        remain = (uint32_t)QN_MIN(deadline - now, (uint64_t)UINT32_MAX);
        if (dns_query(&ni->dns[i], name, answer, QN_ARRAY_LEN(answer), remain, NULL)) {
            out->af = AF_INET;
            out->u.v4 = answer[0];
            return true;
        }
    }
    return false;
}

static bool trace_value(const uint8_t *body, size_t len, const char *key,
                        char *out, size_t cap)
{
    size_t key_len, pos = 0;

    if (!body || !key || !out || !cap)
        return false;
    out[0] = '\0';
    key_len = strlen(key);
    while (pos < len) {
        size_t end = pos, value_len;

        while (end < len && body[end] != '\n' && body[end] != '\r')
            end++;
        if (end > pos + key_len && body[pos + key_len] == '=' &&
            memcmp(body + pos, key, key_len) == 0) {
            value_len = end - pos - key_len - 1u;
            if (!value_len || value_len >= cap)
                return false;
            memcpy(out, body + pos + key_len + 1u, value_len);
            out[value_len] = '\0';
            return true;
        }
        while (end < len && (body[end] == '\n' || body[end] == '\r'))
            end++;
        pos = end;
    }
    return false;
}

void qn_netinfo_probe(qn_netinfo *ni, uint32_t timeout_ms)
{
    qn_addr anchor;
    uint8_t body[2048];
    ssize_t trace_n;

    if (!ni)
        return;

    memset(&ni->public_v4, 0, sizeof ni->public_v4);
    ni->has_public = false;
    memset(ni->public_colo, 0, sizeof ni->public_colo);
    ni->gw_rtt_us = 0;
    ni->dns_rtt_us = 0;
    ni->inet_rtt_us = 0;
    ni->dns_divergent = false;
    ni->captive_portal = false;
    ni->gateway_state = QN_DIAG_NOT_RUN;
    ni->internet_state = QN_DIAG_NOT_RUN;
    ni->public_state = QN_DIAG_NOT_RUN;
    ni->dns_state = QN_DIAG_NOT_RUN;
    ni->captive_state = QN_DIAG_NOT_RUN;

    if (ni->has_gateway) {
        bool reached = false;
        int  fd = connect_timed(&ni->gateway, 80, timeout_ms, &ni->gw_rtt_us, &reached);
        if (fd >= 0 || reached) {
            ni->gateway_state = QN_DIAG_POSITIVE;
            if (fd >= 0)
                close(fd);
        } else {
            ni->gateway_state = QN_DIAG_INCONCLUSIVE;
        }
    }

    if (qn_addr_parse(TRACE_HOST, &anchor)) {
        bool reached = false;
        int  fd = connect_timed(&anchor, 443, timeout_ms, &ni->inet_rtt_us, &reached);
        if (fd >= 0 || reached) {
            ni->internet_state = QN_DIAG_POSITIVE;
            if (fd >= 0)
                close(fd);
        } else {
            ni->internet_state = QN_DIAG_INCONCLUSIVE;
        }

        trace_n = http_get(&anchor, 80, "1.1.1.1", "/cdn-cgi/trace", body,
                           sizeof body, timeout_ms);
        if (trace_n > 0) {
            qn_http_reply reply;
            long          hend = qn_find_headers_end(body, (size_t)trace_n);

            if (hend > 0 && qn_http_parse(body, (size_t)trace_n, &reply) && reply.complete &&
                reply.status == 200u) {
                char tmp[48];

                if (trace_value(body + hend, (size_t)trace_n - (size_t)hend, "ip", tmp,
                                sizeof tmp)) {
                qn_addr parsed;
                if (qn_addr_parse(tmp, &parsed) && parsed.af == AF_INET) {
                    ni->public_v4 = parsed;
                    ni->has_public = true;
                }
            }
                if (reply.colo[0])
                    memcpy(ni->public_colo, reply.colo, sizeof ni->public_colo);
            }
            ni->public_state = ni->has_public ? QN_DIAG_POSITIVE : QN_DIAG_INCONCLUSIVE;
        } else {
            ni->public_state = QN_DIAG_INCONCLUSIVE;
        }

        {
            qn_addr gstatic;
            if (dns_resolve_v4(ni, "connectivitycheck.gstatic.com", timeout_ms, &gstatic)) {
                ssize_t n = http_get(&gstatic, 80, "connectivitycheck.gstatic.com",
                                     "/generate_204", body, sizeof body, timeout_ms);
                qn_http_reply reply;

                if (n <= 0 || !qn_http_parse(body, (size_t)n, &reply) || !reply.complete) {
                    ni->captive_state = QN_DIAG_INCONCLUSIVE;
                } else if (reply.status != 204u) {
                    ni->captive_portal = true;
                    ni->captive_state = QN_DIAG_POSITIVE;
                } else {
                    ni->captive_state = QN_DIAG_NEGATIVE;
                }
            } else {
                ni->captive_state = QN_DIAG_INCONCLUSIVE;
            }
        }
    }

    /* Divergence is a signal, not proof of DNS manipulation. */
    if (ni->ndns) {
        uint32_t local[8], ref[8];
        uint32_t nl = 0, nr;
        uint64_t local_deadline = qn_now_ms() + timeout_ms;

        for (uint32_t i = 0; i < ni->ndns && !nl; i++) {
            uint64_t now = qn_now_ms();
            uint32_t remain;

            if (now >= local_deadline)
                break;
            remain = (uint32_t)QN_MIN(local_deadline - now, (uint64_t)UINT32_MAX);
            nl = dns_query(&ni->dns[i], CONTROL_DOMAIN, local, QN_ARRAY_LEN(local),
                           remain, &ni->dns_rtt_us);
        }
        if (qn_addr_parse("1.1.1.1", &anchor)) {
            nr = dns_query(&anchor, CONTROL_DOMAIN, ref, QN_ARRAY_LEN(ref), timeout_ms, NULL);
            if (nl && nr) {
                bool overlap = false;
                for (uint32_t i = 0; i < nl && !overlap; i++)
                    for (uint32_t j = 0; j < nr; j++)
                        if (local[i] == ref[j]) {
                            overlap = true;
                            break;
                        }
                ni->dns_divergent = !overlap;
                ni->dns_state = ni->dns_divergent ? QN_DIAG_POSITIVE : QN_DIAG_NEGATIVE;
            } else {
                ni->dns_state = QN_DIAG_INCONCLUSIVE;
            }
        } else {
            ni->dns_state = QN_DIAG_INCONCLUSIVE;
        }
    }
}

void qn_netinfo_collect(qn_netinfo *ni, uint32_t timeout_ms)
{
    if (!ni)
        return;
    memset(ni, 0, sizeof *ni);
    qn_netinfo_ifaces(ni);
    qn_netinfo_routes(ni);
    qn_netinfo_dns(ni);
    qn_netinfo_probe(ni, timeout_ms);
}

/* Local-only path tags distinguish cellular assignments and Wi-Fi LANs across runs. */
void qn_operator_tag(const qn_netinfo *ni, char out[QN_OPERATOR_TAG_LEN])
{
    const qn_iface *best = NULL;
    uint32_t        i;

    qn_strlcpy(out, "unknown", QN_OPERATOR_TAG_LEN);
    if (!ni)
        return;

    for (i = 0; i < ni->niface; i++) {
        const qn_iface *f = &ni->iface[i];

        if (f->kind == QN_LINK_LOOPBACK || !f->up || !f->has_v4)
            continue;
        if (ni->default_iface[0] && !strcmp(f->name, ni->default_iface)) {
            best = f;
            break;
        }
        if (!best || f->kind == QN_LINK_CELL)
            best = f;
    }
    if (!best)
        return;

    if (ni->has_public)
        snprintf(out, QN_OPERATOR_TAG_LEN, "%s/%u.%u", qn_link_kind_str((qn_link_kind)best->kind),
                 (ni->public_v4.u.v4 >> 24) & 0xFFu, (ni->public_v4.u.v4 >> 16) & 0xFFu);
    else
        snprintf(out, QN_OPERATOR_TAG_LEN, "%s/%u.%u.local",
                 qn_link_kind_str((qn_link_kind)best->kind), (best->addr.u.v4 >> 24) & 0xFFu,
                 (best->addr.u.v4 >> 16) & 0xFFu);
}
