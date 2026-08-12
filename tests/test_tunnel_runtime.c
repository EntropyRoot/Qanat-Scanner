#include "qanat/tunnel.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static uint64_t monotonic_ms(void);

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); failures++; \
} } while (0)

static void write_script(const char *path, const char *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    size_t used = 0u;
    size_t length = strlen(body);

    CHECK(fd >= 0);
    if (fd < 0)
        return;
    while (used < length) {
        ssize_t wrote = write(fd, body + used, length - used);

        CHECK(wrote > 0);
        if (wrote <= 0)
            break;
        used += (size_t)wrote;
    }
    CHECK(close(fd) == 0);
}

static qn_tunnel_link sample_link(void)
{
    qn_tunnel_link link;

    memset(&link, 0, sizeof link);
    link.protocol = QN_TUNNEL_PROTOCOL_VLESS;
    link.network = QN_TUNNEL_NETWORK_WS;
    link.security = QN_TUNNEL_SECURITY_TLS;
    link.port = 443u;
    memcpy(link.secret, "123e4567-e89b-12d3-a456-426614174000", 37u);
    memcpy(link.address, "origin.example", 15u);
    memcpy(link.sni, "sni.example", 12u);
    memcpy(link.host, "host.example", 13u);
    memcpy(link.path, "/edge", 6u);
    memcpy(link.fingerprint, "chrome", 7u);
    memcpy(link.mode, "auto", 5u);
    return link;
}

static qn_tunnel_run_config run_config(const qn_tunnel_link *link,
                                       const char *script,
                                       const _Atomic bool *cancel)
{
    qn_tunnel_run_config config;

    memset(&config, 0, sizeof config);
    config.link = link;
    config.xray_path = script;
    config.candidate = "198.51.100.8";
    config.probe_host = "www.cloudflare.com";
    config.probe_path = "/cdn-cgi/trace";
    config.timeout_ms = 100u;
    config.max_attempts = 1u;
    config.cancel = cancel;
    return config;
}

static void check_temp_removed(void)
{
    const char *path = qn_tunnel_test_last_temp();

    if (*path)
        CHECK(access(path, F_OK) != 0 && errno == ENOENT);
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    size_t count = 0u;

    if (!directory)
        return SIZE_MAX;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            count++;
    (void)closedir(directory);
    return count;
}

static void test_fault_cleanup(const char *script)
{
    qn_tunnel_link link = sample_link();
    qn_tunnel_run_config config = run_config(&link, script, NULL);
    qn_tunnel_result result;
    static const qn_tunnel_test_fault faults[] = {
        QN_TUNNEL_TEST_TEMP_CREATE,
        QN_TUNNEL_TEST_TEMP_WRITE,
        QN_TUNNEL_TEST_CONFIG_REJECT,
        QN_TUNNEL_TEST_CHILD_START
    };

    for (size_t i = 0u; i < sizeof faults / sizeof faults[0]; i++) {
        qn_tunnel_test_set_fault(faults[i]);
        CHECK(qn_tunnel_run(&config, &result) != QN_RUN_SUCCESS);
        check_temp_removed();
        CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    }
    qn_tunnel_test_set_fault(QN_TUNNEL_TEST_NONE);
    {
        memset(&result, 0xa5, sizeof result);
        config.max_attempts = 3u;
        CHECK(qn_tunnel_run(&config, &result) == QN_RUN_FAILED);
        CHECK(result.state == QN_TUNNEL_CONFIG_INVALID);
        CHECK(result.attempts == 0u);
        CHECK(result.ttfb_us == 0u);
        CHECK(result.kbps == 0u);
    }
    qn_tunnel_link_clear(&link);
}

static void test_cancel_and_fd_pressure(const char *script)
{
    qn_tunnel_link link = sample_link();
    _Atomic bool cancel = true;
    qn_tunnel_run_config config = run_config(&link, script, &cancel);
    qn_tunnel_result result;
    struct rlimit old_limit;
    struct rlimit limited;
    size_t before = fd_count();

    CHECK(qn_tunnel_run(&config, &result) == QN_RUN_CANCELLED);
    CHECK(result.state == QN_TUNNEL_CANCELLED);
    check_temp_removed();
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    atomic_store(&cancel, false);
    CHECK(getrlimit(RLIMIT_NOFILE, &old_limit) == 0);
    limited = old_limit;
    if (limited.rlim_cur > 64u)
        limited.rlim_cur = 64u;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    for (unsigned i = 0u; i < 64u; i++) {
        qn_tunnel_test_set_fault(QN_TUNNEL_TEST_CONFIG_REJECT);
        CHECK(qn_tunnel_run(&config, &result) != QN_RUN_SUCCESS);
        check_temp_removed();
    }
    CHECK(setrlimit(RLIMIT_NOFILE, &old_limit) == 0);
    CHECK(fd_count() == before);
    qn_tunnel_test_set_fault(QN_TUNNEL_TEST_NONE);
    qn_tunnel_link_clear(&link);
}

static void *cancel_after_start(void *opaque)
{
    _Atomic bool *cancel = (_Atomic bool *)opaque;

    (void)usleep(50000u);
    atomic_store(cancel, true);
    return NULL;
}

static void test_active_cancel(const char *script)
{
    qn_tunnel_link link = sample_link();
    _Atomic bool cancel = false;
    qn_tunnel_run_config config = run_config(&link, script, &cancel);
    qn_tunnel_result result;
    pthread_t thread;
    uint64_t started = monotonic_ms();

    config.timeout_ms = 3000u;
    CHECK(pthread_create(&thread, NULL, cancel_after_start, &cancel) == 0);
    CHECK(qn_tunnel_run(&config, &result) == QN_RUN_CANCELLED);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(result.state == QN_TUNNEL_CANCELLED);
    CHECK(monotonic_ms() - started < 1000u);
    check_temp_removed();
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    qn_tunnel_link_clear(&link);
}

static uint64_t monotonic_ms(void)
{
    struct timespec value;

    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000u +
           (uint64_t)value.tv_nsec / 1000000u;
}

static void test_unruly_child(const char *script)
{
    qn_tunnel_link link = sample_link();
    qn_tunnel_run_config config = run_config(&link, script, NULL);
    qn_tunnel_result result;
    uint64_t started = monotonic_ms();

    CHECK(qn_tunnel_run(&config, &result) == QN_RUN_INCOMPLETE);
    CHECK(result.state == QN_TUNNEL_START_FAILED);
    CHECK(monotonic_ms() - started < 2000u);
    check_temp_removed();
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    qn_tunnel_link_clear(&link);
}

static void test_path_discovery(const char *directory)
{
    qn_tunnel_link link = sample_link();
    qn_tunnel_run_config config = run_config(&link, "auto", NULL);
    qn_tunnel_result result;
    char absolute[PATH_MAX];
    char resolved[PATH_MAX];
    const char *current = getenv("PATH");
    char *saved = current ? strdup(current) : NULL;

    CHECK(realpath(directory, absolute) != NULL);
    CHECK(setenv("PATH", absolute, 1) == 0);
    CHECK(qn_xray_find("auto", resolved, sizeof resolved) == QN_XRAY_FOUND);
    CHECK(qn_tunnel_run(&config, &result) == QN_RUN_INCOMPLETE);
    CHECK(result.state == QN_TUNNEL_START_FAILED);
    CHECK(!strcmp(result.reason, "xray-exit"));
    if (saved) {
        CHECK(setenv("PATH", saved, 1) == 0);
        free(saved);
    } else {
        CHECK(unsetenv("PATH") == 0);
    }
    check_temp_removed();
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    qn_tunnel_link_clear(&link);
}

static void run_fixture_case(const char *fixture, const char *mode,
                             qn_tunnel_state expected,
                             qn_run_outcome expected_outcome)
{
    qn_tunnel_link link = sample_link();
    qn_tunnel_run_config config = run_config(&link, fixture, NULL);
    qn_tunnel_result result;

    config.timeout_ms = 3000u;
    config.allow_tls12 = true;
    CHECK(setenv("QN_FAKE_XRAY_MODE", mode, 1) == 0);
    CHECK(qn_tunnel_run(&config, &result) == expected_outcome);
    CHECK(result.state == expected);
    CHECK(result.attempts == 1u);
    if (expected == QN_TUNNEL_PASSED)
        CHECK(result.ttfb_us > 0u);
    check_temp_removed();
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    qn_tunnel_link_clear(&link);
}

static void test_loopback_pipeline(void)
{
    const char *fixture = getenv("QN_TUNNEL_LIVE_FIXTURE");

    if (!fixture || !*fixture)
        return;
    run_fixture_case(fixture, "success", QN_TUNNEL_PASSED,
                     QN_RUN_SUCCESS);
    run_fixture_case(fixture, "no-marker", QN_TUNNEL_NO_MARKER,
                     QN_RUN_INCOMPLETE);
    run_fixture_case(fixture, "socks-auth", QN_TUNNEL_SOCKS_FAILED,
                     QN_RUN_INCOMPLETE);
}

int main(void)
{
    char directory[] = "qanat-tunnel-runtime-XXXXXX";
    char script[256];
    char stubborn[256];
    char *made = mkdtemp(directory);

    CHECK(made != NULL);
    if (!made)
        return 1;
    CHECK(snprintf(script, sizeof script, "%s/xray", made) > 0);
    CHECK(snprintf(stubborn, sizeof stubborn, "%s/xray-stubborn", made) > 0);
    write_script(script, "#!/bin/sh\nexit 0\n");
    write_script(stubborn,
                 "#!/bin/sh\nif [ \"$2\" = \"-test\" ]; then exit 0; fi\n"
                 "trap '' TERM\nwhile :; do sleep 1; done\n");
    test_fault_cleanup(script);
    test_cancel_and_fd_pressure(script);
    test_active_cancel(stubborn);
    test_unruly_child(stubborn);
    test_path_discovery(made);
    test_loopback_pipeline();
    CHECK(unlink(script) == 0);
    CHECK(unlink(stubborn) == 0);
    CHECK(rmdir(made) == 0);
    if (failures) {
        fprintf(stderr, "tunnel runtime tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("tunnel runtime tests: ok");
    return 0;
}
