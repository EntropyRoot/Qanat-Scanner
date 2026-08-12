#include "qanat/tunnel.h"

#include "qanat/crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define XRAY_ASSET "Xray-android-arm64-v8a.zip"
#define XRAY_RELEASE "https://github.com/XTLS/Xray-core/releases/latest/download/"

static bool path_tool(const char *name, char *output, size_t capacity)
{
    const char *path = getenv("PATH");

    if (!path || strchr(name, '/'))
        return false;
    while (*path) {
        const char *end = strchr(path, ':');
        size_t length = end ? (size_t)(end - path) : strlen(path);
        int written;

        if (length && path[0] == '/') {
            written = snprintf(output, capacity, "%.*s/%s", (int)length,
                               path, name);
            if (written > 0 && (size_t)written < capacity &&
                access(output, X_OK) == 0)
                return true;
        }
        if (!end)
            break;
        path = end + 1;
    }
    return false;
}

static bool wait_success(pid_t child)
{
    int status;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool download(const char *curl, const char *url, const char *path)
{
    pid_t child = fork();

    if (child < 0)
        return false;
    if (!child) {
        execl(curl, curl, "--fail", "--location", "--silent",
              "--show-error", "--proto", "=https", "--tlsv1.2",
              "--connect-timeout", "15", "--max-time", "300",
              "--output", path, url, (char *)NULL);
        _exit(127);
    }
    return wait_success(child);
}

static bool sha256_file(const char *path, uint8_t output[32])
{
    qn_sha256 context;
    uint8_t buffer[32768];
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return false;
    qn_sha256_init(&context);
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof buffer);

        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            close(fd);
            return false;
        }
        if (!got)
            break;
        qn_sha256_update(&context, buffer, (size_t)got);
    }
    close(fd);
    qn_sha256_final(&context, output);
    memset(buffer, 0, sizeof buffer);
    return true;
}

static int hex_digit(int value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    value = tolower(value);
    return value >= 'a' && value <= 'f' ? value - 'a' + 10 : -1;
}

static bool digest_file(const char *path, uint8_t expected[32])
{
    FILE *file = fopen(path, "rb");
    char line[512];

    if (!file)
        return false;
    while (fgets(line, sizeof line, file)) {
        char *equals = strchr(line, '=');
        char *hex;

        if (!equals || !strstr(line, "SHA2-256"))
            continue;
        hex = equals + 1;
        while (*hex == ' ' || *hex == '\t')
            hex++;
        if (strlen(hex) < 64u) {
            fclose(file);
            return false;
        }
        for (size_t i = 0u; i < 32u; i++) {
            int high = hex_digit((unsigned char)hex[i * 2u]);
            int low = hex_digit((unsigned char)hex[i * 2u + 1u]);

            if (high < 0 || low < 0) {
                fclose(file);
                return false;
            }
            expected[i] = (uint8_t)((unsigned)high * 16u + (unsigned)low);
        }
        if (hex[64] && hex[64] != '\r' && hex[64] != '\n' &&
            !isspace((unsigned char)hex[64])) {
            fclose(file);
            return false;
        }
        fclose(file);
        return true;
    }
    fclose(file);
    return false;
}

static bool extract_xray(const char *unzip, const char *archive,
                         const char *output)
{
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    posix_spawn_file_actions_t actions;
    char *const arguments[] = {
        (char *)(uintptr_t)unzip, (char *)"-p",
        (char *)(uintptr_t)archive, (char *)"xray", NULL
    };
    pid_t child = -1;
    int spawn_error;

    if (fd < 0)
        return false;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(fd);
        return false;
    }
    spawn_error = posix_spawn_file_actions_adddup2(&actions, fd,
                                                    STDOUT_FILENO);
    if (!spawn_error)
        spawn_error = posix_spawn_file_actions_addclose(&actions, fd);
    if (!spawn_error)
        spawn_error = posix_spawn(&child, unzip, &actions, NULL,
                                  arguments, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    close(fd);
    return !spawn_error && wait_success(child);
}

static bool install_directory(char *directory, size_t capacity, bool create)
{
    const char *prefix = getenv("PREFIX");
    const char *home = getenv("HOME");
    int written;

    if (prefix && prefix[0] == '/')
        written = snprintf(directory, capacity, "%s/bin", prefix);
    else if (home && home[0] == '/') {
        char local[PATH_MAX];
        int local_written = snprintf(local, sizeof local, "%s/.local", home);

        if (local_written <= 0 || (size_t)local_written >= sizeof local)
            return false;
        if (create && mkdir(local, 0700) != 0 && errno != EEXIST)
            return false;
        written = snprintf(directory, capacity, "%s/bin", local);
    } else {
        return false;
    }
    if (written <= 0 || (size_t)written >= capacity)
        return false;
    if (create && mkdir(directory, 0700) != 0 && errno != EEXIST)
        return false;
    return true;
}

bool qn_xray_install_target(char *target, size_t capacity)
{
    char directory[PATH_MAX];
    int written;

    if (!target || !capacity ||
        !install_directory(directory, sizeof directory, false))
        return false;
    written = snprintf(target, capacity, "%s/xray", directory);
    if (written <= 0 || (size_t)written >= capacity)
        return false;
    return true;
}

static bool write_all(int fd, const uint8_t *buffer, size_t length)
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

static bool install_target(const char *source, char *target, size_t capacity)
{
    char directory[PATH_MAX], temporary[PATH_MAX];
    uint8_t buffer[32768];
    int source_fd = -1, target_fd = -1, written;
    bool ok = false;

    if (!install_directory(directory, sizeof directory, true))
        return false;
    written = snprintf(target, capacity, "%s/xray", directory);
    if (written <= 0 || (size_t)written >= capacity)
        return false;
    written = snprintf(temporary, sizeof temporary,
                       "%s/.qanat-xray-XXXXXX", directory);
    if (written <= 0 || (size_t)written >= sizeof temporary)
        return false;
    source_fd = open(source, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0)
        goto out;
    target_fd = mkstemp(temporary);
    if (target_fd < 0)
        goto out;
    if (fcntl(target_fd, F_SETFD, FD_CLOEXEC) != 0 ||
        fchmod(target_fd, 0700) != 0)
        goto out;
    for (;;) {
        ssize_t got = read(source_fd, buffer, sizeof buffer);

        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            goto out;
        if (!got)
            break;
        if (!write_all(target_fd, buffer, (size_t)got))
            goto out;
    }
    if (fsync(target_fd) != 0)
        goto out;
    {
        int closing = target_fd;

        target_fd = -1;
        if (close(closing) != 0)
            goto out;
    }
    {
        int closing = source_fd;

        source_fd = -1;
        if (close(closing) != 0)
            goto out;
    }
    if (rename(temporary, target) != 0)
        goto out;
    temporary[0] = '\0';
    {
        int directory_fd = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY);

        if (directory_fd < 0)
            goto out;
        ok = fsync(directory_fd) == 0;
        if (close(directory_fd) != 0)
            ok = false;
    }
out:
    memset(buffer, 0, sizeof buffer);
    if (source_fd >= 0)
        (void)close(source_fd);
    if (target_fd >= 0)
        (void)close(target_fd);
    if (temporary[0])
        (void)unlink(temporary);
    return ok;
}

static bool regular_nonempty(const char *path)
{
    struct stat status;

    return stat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_size > 0;
}

qn_xray_install_code qn_xray_install(char *installed, size_t capacity)
{
    struct utsname machine;
    char curl[PATH_MAX], unzip[PATH_MAX];
    char directory[PATH_MAX];
    char archive[PATH_MAX] = { 0 };
    char digest[PATH_MAX] = { 0 };
    char binary[PATH_MAX] = { 0 };
    char target[PATH_MAX], target_directory[PATH_MAX];
    char archive_url[512], digest_url[512];
    const char *temporary_root;
    uint8_t expected[32], actual[32];
    qn_xray_install_code result = QN_XRAY_INSTALL_DOWNLOAD_FAILED;
    int directory_written;

    if (!installed || !capacity || uname(&machine) != 0 ||
        strcmp(machine.machine, "aarch64"))
        return QN_XRAY_INSTALL_UNSUPPORTED;
    installed[0] = '\0';
    if (!path_tool("curl", curl, sizeof curl) ||
        !path_tool("unzip", unzip, sizeof unzip))
        return QN_XRAY_INSTALL_TOOL_MISSING;
    if (!qn_xray_install_target(target, sizeof target))
        return QN_XRAY_INSTALL_TARGET_FAILED;
    temporary_root = getenv("TMPDIR");
    if (!temporary_root || temporary_root[0] != '/')
        temporary_root = "/tmp";
    directory_written = snprintf(directory, sizeof directory,
                                 "%s/qanat-xray-install-XXXXXX",
                                 temporary_root);
    if (directory_written <= 0 ||
        (size_t)directory_written >= sizeof directory ||
        !mkdtemp(directory)) {
        if (strlen(target) >= sizeof target_directory)
            return QN_XRAY_INSTALL_TARGET_FAILED;
        strcpy(target_directory, target);
        {
            char *slash = strrchr(target_directory, '/');

            if (!slash)
                return QN_XRAY_INSTALL_TARGET_FAILED;
            *slash = '\0';
        }
        if (!install_directory(target_directory, sizeof target_directory, true))
            return QN_XRAY_INSTALL_TARGET_FAILED;
        directory_written = snprintf(directory, sizeof directory,
                                     "%s/.qanat-xray-install-XXXXXX",
                                     target_directory);
        if (directory_written <= 0 ||
            (size_t)directory_written >= sizeof directory ||
            !mkdtemp(directory))
            return QN_XRAY_INSTALL_TARGET_FAILED;
    }
    (void)chmod(directory, 0700);
    {
        int archive_written = snprintf(archive, sizeof archive, "%s/%s",
                                       directory, XRAY_ASSET);
        int digest_written = snprintf(digest, sizeof digest, "%s/%s.dgst",
                                      directory, XRAY_ASSET);
        int binary_written = snprintf(binary, sizeof binary, "%s/xray",
                                      directory);
        int archive_url_written = snprintf(archive_url, sizeof archive_url,
                                           "%s%s", XRAY_RELEASE, XRAY_ASSET);
        int digest_url_written = snprintf(digest_url, sizeof digest_url,
                                          "%s%s.dgst", XRAY_RELEASE,
                                          XRAY_ASSET);

        if (archive_written <= 0 || (size_t)archive_written >= sizeof archive ||
            digest_written <= 0 || (size_t)digest_written >= sizeof digest ||
            binary_written <= 0 || (size_t)binary_written >= sizeof binary ||
            archive_url_written <= 0 ||
            (size_t)archive_url_written >= sizeof archive_url ||
            digest_url_written <= 0 ||
            (size_t)digest_url_written >= sizeof digest_url)
            goto out;
    }
    if (!download(curl, archive_url, archive) ||
        !download(curl, digest_url, digest))
        goto out;
    if (!digest_file(digest, expected) || !sha256_file(archive, actual) ||
        memcmp(expected, actual, sizeof expected)) {
        result = QN_XRAY_INSTALL_DIGEST_INVALID;
        goto out;
    }
    if (!extract_xray(unzip, archive, binary) || !regular_nonempty(binary)) {
        result = QN_XRAY_INSTALL_ARCHIVE_INVALID;
        goto out;
    }
    if (!install_target(binary, installed, capacity)) {
        result = QN_XRAY_INSTALL_TARGET_FAILED;
        goto out;
    }
    result = QN_XRAY_INSTALL_OK;
out:
    if (binary[0])
        (void)unlink(binary);
    if (digest[0])
        (void)unlink(digest);
    if (archive[0])
        (void)unlink(archive);
    (void)rmdir(directory);
    memset(expected, 0, sizeof expected);
    memset(actual, 0, sizeof actual);
    return result;
}

const char *qn_xray_install_str(qn_xray_install_code code)
{
    static const char *const names[] = {
        "installed", "unsupported-platform", "curl-or-unzip-missing",
        "download-failed", "digest-invalid", "archive-invalid",
        "target-failed"
    };

    return code <= QN_XRAY_INSTALL_TARGET_FAILED ? names[code] : "invalid";
}
