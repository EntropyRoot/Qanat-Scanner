#include "qanat/tunnel.h"

#include "qanat/profile.h"
#include "qanat/util.h"
#include "qanat/verify.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define XRAY_CHECK_TIMEOUT_MS 5000u
#define XRAY_STOP_GRACE_MS     250u
#define XRAY_READY_LIMIT_MS    5000u
#define XRAY_PORT_FIRST      21080u
#define XRAY_PORT_SPAN       20000u

static _Atomic uint32_t port_sequence = XRAY_PORT_FIRST;

#if defined(QN_TUNNEL_TESTING)
static qn_tunnel_test_fault runtime_fault;
static char runtime_last_temp[PATH_MAX];

void qn_tunnel_test_set_fault(qn_tunnel_test_fault fault)
{
    runtime_fault = fault;
    runtime_last_temp[0] = '\0';
}

const char *qn_tunnel_test_last_temp(void)
{
    return runtime_last_temp;
}
#endif

static bool cancelled(const _Atomic bool *cancel)
{
    return cancel && atomic_load_explicit(cancel, memory_order_acquire);
}

static void clear_bytes(void *memory, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)memory;

    while (length--)
        *p++ = 0u;
}

static bool copy_path(char *output, size_t capacity, const char *path)
{
    size_t length;

    if (!output || !capacity || !path)
        return false;
    length = strlen(path);
    if (!length || length >= capacity)
        return false;
    memcpy(output, path, length + 1u);
    return true;
}

static bool executable_file(const char *path)
{
    struct stat status;

    return path && strchr(path, '/') && stat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && access(path, X_OK) == 0;
}

qn_xray_find_code qn_xray_find(const char *requested, char *resolved,
                                size_t capacity)
{
    const char *path;

    if (!resolved || !capacity)
        return QN_XRAY_INVALID_PATH;
    resolved[0] = '\0';
    if (requested && *requested && strcmp(requested, "auto")) {
        char absolute[PATH_MAX];

        if (requested[0] == '/') {
            if (!copy_path(absolute, sizeof absolute, requested))
                return QN_XRAY_PATH_OVERFLOW;
        } else if (!realpath(requested, absolute)) {
            return QN_XRAY_INVALID_PATH;
        }
        if (!executable_file(absolute))
            return QN_XRAY_INVALID_PATH;
        return copy_path(resolved, capacity, absolute) ? QN_XRAY_FOUND
                                                       : QN_XRAY_PATH_OVERFLOW;
    }

    path = getenv("PATH");
    if (!path)
        return QN_XRAY_NOT_FOUND;
    while (*path) {
        const char *end = strchr(path, ':');
        size_t length = end ? (size_t)(end - path) : strlen(path);
        char candidate[PATH_MAX];
        int written;

        if (length && path[0] == '/' && length < sizeof candidate) {
            written = snprintf(candidate, sizeof candidate, "%.*s/xray",
                               (int)length, path);
            if (written > 0 && (size_t)written < sizeof candidate &&
                executable_file(candidate))
                return copy_path(resolved, capacity, candidate) ? QN_XRAY_FOUND
                                                                 : QN_XRAY_PATH_OVERFLOW;
        }
        if (!end)
            break;
        path = end + 1;
    }
    return QN_XRAY_NOT_FOUND;
}

const char *qn_xray_find_str(qn_xray_find_code code)
{
    static const char *const names[] = {
        "found", "not-found", "invalid-path", "path-overflow"
    };

    return code <= QN_XRAY_PATH_OVERFLOW ? names[code] : "invalid";
}

typedef struct {
    int fd;
    uint16_t port;
} port_lease;

static bool reserve_port(port_lease *lease)
{
    struct sockaddr_in address;

    memset(lease, 0, sizeof *lease);
    lease->fd = -1;
    for (uint32_t attempt = 0u; attempt < XRAY_PORT_SPAN; attempt++) {
        uint32_t sequence = atomic_fetch_add_explicit(&port_sequence, 1u,
                                                       memory_order_relaxed);
        uint16_t port = (uint16_t)(XRAY_PORT_FIRST +
                                   (sequence - XRAY_PORT_FIRST) % XRAY_PORT_SPAN);
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

        if (fd < 0)
            return false;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *)&address, sizeof address) == 0) {
            lease->fd = fd;
            lease->port = port;
            return true;
        }
        {
            int bind_error = errno;

            close(fd);
            errno = bind_error;
        }
        if (errno != EADDRINUSE)
            return false;
    }
    errno = EADDRINUSE;
    return false;
}

static void release_port(port_lease *lease)
{
    if (lease->fd >= 0)
        close(lease->fd);
    lease->fd = -1;
}

static bool write_all(int fd, const char *data, size_t length)
{
    size_t offset = 0u;

    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        offset += (size_t)written;
    }
    return true;
}

static bool create_private_config(const char *data, size_t length,
                                  char *path, size_t capacity)
{
    const char *directory = getenv("TMPDIR");
    int fd;
    int written;
    bool ok;

    if (!directory || directory[0] != '/')
        directory = "/tmp";
    written = snprintf(path, capacity, "%s/qanat-xray-XXXXXX", directory);
    if (written <= 0 || (size_t)written >= capacity) {
        errno = ENAMETOOLONG;
        return false;
    }
#if defined(QN_TUNNEL_TESTING)
    if (runtime_fault == QN_TUNNEL_TEST_TEMP_CREATE) {
        errno = EIO;
        return false;
    }
#endif
    fd = mkostemp(path, O_CLOEXEC);
    if (fd < 0)
        return false;
#if defined(QN_TUNNEL_TESTING)
    qn_strlcpy(runtime_last_temp, path, sizeof runtime_last_temp);
#endif
    ok = fchmod(fd, S_IRUSR | S_IWUSR) == 0;
#if defined(QN_TUNNEL_TESTING)
    if (runtime_fault == QN_TUNNEL_TEST_TEMP_WRITE) {
        errno = EIO;
        ok = false;
    }
#endif
    if (ok)
        ok = write_all(fd, data, length) && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (!ok) {
        int saved = errno ? errno : EIO;

        (void)unlink(path);
        path[0] = '\0';
        errno = saved;
    }
    return ok;
}

static void close_child_fds(void)
{
    struct rlimit limit;
    rlim_t maximum = 1024u;

    if (getrlimit(RLIMIT_NOFILE, &limit) == 0)
        maximum = limit.rlim_cur == RLIM_INFINITY ? 65536u
                                                  : limit.rlim_cur;
    if (maximum > 65536u)
        maximum = 65536u;
    for (int fd = 3; (rlim_t)fd < maximum; fd++)
        close(fd);
}

static pid_t spawn_xray(const char *xray, const char *config, bool check)
{
    pid_t child;

#if defined(QN_TUNNEL_TESTING)
    if (runtime_fault == QN_TUNNEL_TEST_CHILD_START) {
        errno = EAGAIN;
        return -1;
    }
#endif
    child = fork();
    if (child != 0)
        return child;
    {
        int null_fd = open("/dev/null", O_RDWR);

        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            (void)dup2(null_fd, STDOUT_FILENO);
            (void)dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO)
                close(null_fd);
        }
    }
    close_child_fds();
    if (check)
        execl(xray, xray, "run", "-test", "-c", config, (char *)NULL);
    else
        execl(xray, xray, "run", "-c", config, (char *)NULL);
    _exit(127);
}

static bool reap_until(pid_t child, uint32_t timeout_ms,
                       const _Atomic bool *cancel, int *status)
{
    uint64_t deadline = qn_now_ms() + timeout_ms;

    for (;;) {
        pid_t waited = waitpid(child, status, WNOHANG);

        if (waited == child)
            return true;
        if (waited < 0 && errno != EINTR)
            return false;
        if (cancelled(cancel) || qn_now_ms() >= deadline)
            return false;
        (void)usleep(10000u);
    }
}

static void stop_child(pid_t child, bool immediate)
{
    int status;

    if (child <= 0)
        return;
    if (waitpid(child, &status, WNOHANG) == child)
        return;
    if (!immediate) {
        (void)kill(child, SIGTERM);
        if (reap_until(child, XRAY_STOP_GRACE_MS, NULL, &status))
            return;
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR)
        ;
}

static void set_result(qn_tunnel_result *result, qn_tunnel_state state,
                       const char *reason);

static bool config_check(const char *xray, const char *path,
                         const _Atomic bool *cancel)
{
    int status = 0;
    pid_t child;

#if defined(QN_TUNNEL_TESTING)
    if (runtime_fault == QN_TUNNEL_TEST_CONFIG_REJECT)
        return false;
#endif
    child = spawn_xray(xray, path, true);
    if (child < 0)
        return false;
    if (!reap_until(child, XRAY_CHECK_TIMEOUT_MS, cancel, &status)) {
        stop_child(child, true);
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool socks_ready(pid_t *child, uint16_t port, uint32_t timeout_ms,
                        const _Atomic bool *cancel, qn_tunnel_result *result)
{
    uint64_t deadline = qn_now_ms() + QN_MIN(timeout_ms, XRAY_READY_LIMIT_MS);

    for (;;) {
        struct sockaddr_in address;
        int status;
        pid_t waited = waitpid(*child, &status, WNOHANG);

        if (waited == *child) {
            *child = -1;
            set_result(result, QN_TUNNEL_START_FAILED, "xray-exit");
            return false;
        }
        if (waited < 0 && errno != EINTR) {
            set_result(result, QN_TUNNEL_START_FAILED, "xray-wait");
            return false;
        }
        if (cancelled(cancel)) {
            set_result(result, QN_TUNNEL_CANCELLED, "cancelled");
            return false;
        }
        {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

            if (fd >= 0) {
                memset(&address, 0, sizeof address);
                address.sin_family = AF_INET;
                address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                address.sin_port = htons(port);
                if (connect(fd, (struct sockaddr *)&address,
                            sizeof address) == 0) {
                    close(fd);
                    return true;
                }
                close(fd);
            }
        }
        if (qn_now_ms() >= deadline) {
            set_result(result, QN_TUNNEL_START_FAILED, "socks-readiness");
            return false;
        }
        (void)usleep(10000u);
    }
}

static void set_result(qn_tunnel_result *result, qn_tunnel_state state,
                       const char *reason)
{
    result->state = state;
    qn_strlcpy(result->reason, reason, sizeof result->reason);
}

static qn_tunnel_state classify_probe(const qn_verify_result *verify,
                                      char *reason, size_t capacity)
{
    const char *why = verify->observation.terminal.reason;

    if (!strncmp(why, "socks-", 6u)) {
        qn_strlcpy(reason, why, capacity);
        return QN_TUNNEL_SOCKS_FAILED;
    }
    if (verify->observation.http.status < 200u ||
        verify->observation.http.status >= 300u) {
        qn_strlcpy(reason, "http-not-2xx", capacity);
        return QN_TUNNEL_PROBE_FAILED;
    }
    if (!verify->observation.http.colo[0]) {
        qn_strlcpy(reason, "colo-missing", capacity);
        return QN_TUNNEL_NO_MARKER;
    }
    qn_strlcpy(reason, "verified", capacity);
    return QN_TUNNEL_PASSED;
}

static qn_tunnel_state run_attempt(const qn_tunnel_run_config *config,
                                   qn_tunnel_result *result)
{
    port_lease lease;
    qn_tunnel_config_request build;
    qn_tunnel_config_code build_code;
    char *json = NULL;
    size_t json_length = 0u;
    char path[PATH_MAX] = { 0 };
    pid_t child = -1;
    qn_tunnel_state state = QN_TUNNEL_START_FAILED;

    if (!reserve_port(&lease)) {
        set_result(result, QN_TUNNEL_START_FAILED, "port-reservation");
        return QN_TUNNEL_START_FAILED;
    }
    json = (char *)malloc(QN_TUNNEL_CONFIG_MAX);
    if (!json) {
        release_port(&lease);
        set_result(result, QN_TUNNEL_START_FAILED, "config-memory");
        return QN_TUNNEL_START_FAILED;
    }
    build = (qn_tunnel_config_request){
        config->link, config->candidate, lease.port, QN_TUNNEL_CONFIG_LIVE
    };
    build_code = qn_tunnel_config_build(&build, json, QN_TUNNEL_CONFIG_MAX,
                                        &json_length);
    if (build_code != QN_TUNNEL_CONFIG_OK) {
        set_result(result, QN_TUNNEL_CONFIG_INVALID,
                   qn_tunnel_config_str(build_code));
        state = QN_TUNNEL_CONFIG_INVALID;
        goto out;
    }
    if (!create_private_config(json, json_length, path, sizeof path)) {
        set_result(result, QN_TUNNEL_START_FAILED, "config-temp");
        goto out;
    }
    clear_bytes(json, QN_TUNNEL_CONFIG_MAX);
    if (!config_check(config->xray_path, path, config->cancel)) {
        set_result(result, cancelled(config->cancel) ? QN_TUNNEL_CANCELLED
                                                     : QN_TUNNEL_CONFIG_INVALID,
                   cancelled(config->cancel) ? "cancelled" : "xray-config");
        state = result->state;
        goto out;
    }
    release_port(&lease);
    child = spawn_xray(config->xray_path, path, false);
    if (child < 0) {
        set_result(result, QN_TUNNEL_START_FAILED, "xray-spawn");
        goto out;
    }
    if (!socks_ready(&child, lease.port, config->timeout_ms, config->cancel,
                     result)) {
        state = result->state;
        goto out;
    }
    {
        qn_verify_cfg verify_config;
        qn_verify_result verify_result;
        qn_verify_status verify_status;
        qn_addr candidate_address;

        memset(&verify_result, 0, sizeof verify_result);
        qn_verify_defaults(&verify_config);
        if (!qn_addr_parse(config->candidate, &candidate_address)) {
            set_result(result, QN_TUNNEL_CONFIG_INVALID, "candidate-address");
            state = QN_TUNNEL_CONFIG_INVALID;
            goto out;
        }
        verify_config.profile = config->profile;
        verify_config.sni = config->probe_host;
        verify_config.trace_path = config->probe_path;
        verify_config.fp = (qn_tls_fp)config->fingerprint;
        verify_config.allow_tls12 = config->allow_tls12;
        verify_config.cert_strict = config->cert_strict;
        verify_config.concurrency = 1u;
        verify_config.stability_concurrency = config->idle_ms ? 1u : 0u;
        verify_config.timeout_ms = config->timeout_ms;
        verify_config.idle_ms = config->idle_ms;
        verify_config.want_bytes = config->want_bytes;
        verify_config.seed = config->seed;
        verify_config.deterministic = true;
        verify_config.cancel = config->cancel;
        verify_config.socks_enabled = true;
        (void)qn_addr_parse("127.0.0.1", &verify_config.socks_address);
        verify_config.socks_port = lease.port;
        verify_config.socks_target_host = config->probe_host;
        verify_config.socks_target_port = 443u;
        verify_status = qn_verify_run(&verify_config, &candidate_address, 1u,
                                      &verify_result);
        if (verify_status.state == QN_VERIFY_CANCELLED) {
            set_result(result, QN_TUNNEL_CANCELLED, "cancelled");
            state = QN_TUNNEL_CANCELLED;
        } else if (verify_status.state == QN_VERIFY_INFRA_FAILURE) {
            set_result(result, QN_TUNNEL_PROBE_FAILED, "verifier-infra");
            state = QN_TUNNEL_PROBE_FAILED;
        } else {
            state = classify_probe(&verify_result, result->reason,
                                   sizeof result->reason);
            result->state = state;
            result->ttfb_us = verify_result.observation.http.ttfb_us;
            result->kbps = verify_result.observation.flow.kbps;
        }
    }

out:
    stop_child(child, cancelled(config->cancel));
    if (path[0])
        (void)unlink(path);
    release_port(&lease);
    if (json) {
        clear_bytes(json, QN_TUNNEL_CONFIG_MAX);
        free(json);
    }
    clear_bytes(path, sizeof path);
    return state;
}

qn_run_outcome qn_tunnel_run(const qn_tunnel_run_config *config,
                              qn_tunnel_result *result)
{
    char resolved[QN_TUNNEL_XRAY_PATH_MAX + 1u];
    qn_tunnel_run_config effective;
    qn_xray_find_code find_code;
    uint8_t attempts;

    if (!config || !result || !config->link || !config->candidate ||
        !config->probe_host || !config->probe_path || !config->timeout_ms ||
        !config->max_attempts || config->max_attempts > 2u) {
        if (result) {
            memset(result, 0, sizeof *result);
            set_result(result, QN_TUNNEL_CONFIG_INVALID, "run-argument");
        }
        return QN_RUN_FAILED;
    }
    memset(result, 0, sizeof *result);
    find_code = qn_xray_find(config->xray_path, resolved, sizeof resolved);
    if (find_code != QN_XRAY_FOUND) {
        set_result(result,
                   find_code == QN_XRAY_NOT_FOUND ? QN_TUNNEL_BINARY_MISSING
                                                  : QN_TUNNEL_CONFIG_INVALID,
                   qn_xray_find_str(find_code));
        return find_code == QN_XRAY_NOT_FOUND ? QN_RUN_INCOMPLETE
                                              : QN_RUN_FAILED;
    }
    effective = *config;
    effective.xray_path = resolved;
    attempts = config->max_attempts;
    for (uint8_t attempt = 1u; attempt <= attempts; attempt++) {
        qn_tunnel_state state;

        memset(result, 0, sizeof *result);
        result->attempts = attempt;
        if (cancelled(config->cancel)) {
            set_result(result, QN_TUNNEL_CANCELLED, "cancelled");
            return QN_RUN_CANCELLED;
        }
        state = run_attempt(&effective, result);
        if (state == QN_TUNNEL_PASSED)
            return QN_RUN_SUCCESS;
        if (state == QN_TUNNEL_CONFIG_INVALID || state == QN_TUNNEL_CANCELLED)
            break;
    }
    if (result->state == QN_TUNNEL_CANCELLED)
        return QN_RUN_CANCELLED;
    return QN_RUN_INCOMPLETE;
}
