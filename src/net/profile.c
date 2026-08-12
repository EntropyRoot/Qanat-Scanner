#include "qanat/profile.h"

#include "qanat/util.h"

#include <stdbool.h>
#include <string.h>

#define H2_HEADER_TABLE_SIZE 0x1u
#define H2_ENABLE_PUSH       0x2u
#define H2_INITIAL_WINDOW    0x4u
#define H2_MAX_FRAME_SIZE    0x5u
#define H2_MAX_HEADER_LIST   0x6u

static const qn_client_profile PROFILES[] = {
    {
        QN_TLS_FP_CHROME,
        { { { H2_HEADER_TABLE_SIZE, 0u },
              { H2_ENABLE_PUSH, 0u },
              { H2_INITIAL_WINDOW, 16u << 20 },
              { H2_MAX_HEADER_LIST, 8192u } },
          4u, 16u << 20 },
        { "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
          "*/*", "identity",
          { QN_PSEUDO_METHOD, QN_PSEUDO_AUTHORITY,
            QN_PSEUDO_SCHEME, QN_PSEUDO_PATH },
          { QN_HEADER_USER_AGENT, QN_HEADER_ACCEPT,
            QN_HEADER_ACCEPT_ENCODING } },
        "chrome-android-126", "Chrome", "Android", "126"
    },
    {
        QN_TLS_FP_FIREFOX,
        { { { H2_HEADER_TABLE_SIZE, 0u },
              { H2_INITIAL_WINDOW, 131072u },
              { H2_MAX_FRAME_SIZE, 16384u },
              { H2_ENABLE_PUSH, 0u },
              { H2_MAX_HEADER_LIST, 8192u } },
          5u, 16u << 20 },
        { "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 "
          "Firefox/127.0",
          "*/*", "identity",
          { QN_PSEUDO_METHOD, QN_PSEUDO_PATH,
            QN_PSEUDO_AUTHORITY, QN_PSEUDO_SCHEME },
          { QN_HEADER_ACCEPT, QN_HEADER_ACCEPT_ENCODING,
            QN_HEADER_USER_AGENT } },
        "firefox-android-127", "Firefox", "Android", "127"
    },
    {
        QN_TLS_FP_SAFARI,
        { { { H2_ENABLE_PUSH, 0u },
              { H2_HEADER_TABLE_SIZE, 0u },
              { H2_INITIAL_WINDOW, 65535u },
              { H2_MAX_HEADER_LIST, 8192u } },
          4u, 16u << 20 },
        { "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
          "Mobile/15E148 Safari/604.1",
          "*/*", "identity",
          { QN_PSEUDO_METHOD, QN_PSEUDO_SCHEME,
            QN_PSEUDO_PATH, QN_PSEUDO_AUTHORITY },
          { QN_HEADER_ACCEPT_ENCODING, QN_HEADER_ACCEPT,
            QN_HEADER_USER_AGENT } },
        "safari-ios-17", "Safari", "iOS", "17"
    },
    {
        QN_TLS_FP_RANDOM,
        { { { H2_HEADER_TABLE_SIZE, 0u },
              { H2_ENABLE_PUSH, 0u },
              { H2_INITIAL_WINDOW, 16u << 20 },
              { H2_MAX_HEADER_LIST, 8192u } },
          4u, 16u << 20 },
        { "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
          "*/*", "identity",
          { QN_PSEUDO_METHOD, QN_PSEUDO_AUTHORITY,
            QN_PSEUDO_SCHEME, QN_PSEUDO_PATH },
          { QN_HEADER_USER_AGENT, QN_HEADER_ACCEPT,
            QN_HEADER_ACCEPT_ENCODING } },
        "random", "Randomized", "dynamic", "seeded"
    }
};

static uint64_t shape_next(uint64_t *state)
{
    uint64_t z;

    *state += UINT64_C(0x9E3779B97F4A7C15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void shuffle_u8(uint8_t *values, size_t n, uint64_t *state)
{
    size_t i;

    for (i = n; i > 1u; i--) {
        size_t j = (size_t)(shape_next(state) % i);
        uint8_t tmp = values[i - 1u];

        values[i - 1u] = values[j];
        values[j] = tmp;
    }
}

static void shuffle_h2(qn_h2_setting *values, size_t n, uint64_t *state)
{
    size_t i;

    for (i = n; i > 1u; i--) {
        size_t j = (size_t)(shape_next(state) % i);
        qn_h2_setting tmp = values[i - 1u];

        values[i - 1u] = values[j];
        values[j] = tmp;
    }
}

const qn_client_profile *qn_client_profile_get(qn_tls_fp profile)
{
    if (profile < QN_TLS_FP_CHROME || profile >= QN_TLS_FP_COUNT)
        return NULL;
    return &PROFILES[(size_t)profile];
}

const char *qn_profile_support_str(qn_profile_support support)
{
    switch (support) {
    case QN_PROFILE_EXACT:                  return "exact";
    case QN_PROFILE_CAPABILITY_CONSTRAINED: return "capability-constrained";
    case QN_PROFILE_UNSUPPORTED:            return "unsupported";
    default:                                return "invalid";
    }
}

uint64_t qn_profile_seed_from_run(uint64_t run_seed)
{
    return qn_seed_derive(run_seed, UINT64_C(0x43462D50524F4649));
}

uint64_t qn_profile_wire_seed(uint64_t run_seed, uint64_t index)
{
    uint64_t verify_seed = qn_seed_derive(run_seed, UINT64_C(0x43462D4445455000));

    return qn_seed_derive(verify_seed, UINT64_C(0x5645524946590000) ^ index);
}

bool qn_profile_instance_init(qn_profile_instance *instance, qn_tls_fp requested,
                              uint64_t seed, const char *sni, bool allow_tls12,
                              bool cert_strict)
{
    qn_tls_fp resolved = requested;
    const qn_client_profile *profile;

    if (!instance || !qn_valid_hostname(sni) || requested < QN_TLS_FP_CHROME ||
        requested >= QN_TLS_FP_COUNT)
        return false;
    if (requested == QN_TLS_FP_RANDOM)
        resolved = (qn_tls_fp)(qn_seed_derive(seed, UINT64_C(0x50524F46494C4500)) %
                               (uint64_t)QN_TLS_FP_RANDOM);
    profile = qn_client_profile_get(resolved);
    if (!profile)
        return false;
    memset(instance, 0, sizeof *instance);
    instance->version = QN_PROFILE_INSTANCE_VERSION;
    instance->requested = requested;
    instance->resolved = resolved;
    instance->support = QN_PROFILE_CAPABILITY_CONSTRAINED;
    instance->profile = profile;
    instance->seed = seed;
    instance->grease_seed = qn_seed_derive(seed, UINT64_C(0x4752454153450000));
    instance->allow_tls12 = allow_tls12;
    instance->cert_strict = cert_strict;
    if (qn_strlcpy(instance->sni, sni, sizeof instance->sni) >= sizeof instance->sni ||
        !qn_profile_h2_shape(profile, instance->seed, instance->h2_settings,
                             QN_PROFILE_MAX_H2_SETTINGS, &instance->h2_settings_n,
                             &instance->h2_connection_window) ||
        !qn_profile_http_shape(profile, instance->seed, instance->h2_pseudo_order,
                               instance->http1_header_order)) {
        memset(instance, 0, sizeof *instance);
        return false;
    }
    return true;
}

const char *qn_tls_fp_str(qn_tls_fp profile)
{
    const qn_client_profile *value = qn_client_profile_get(profile);

    return value ? value->name : "invalid";
}

bool qn_client_profile_parse(const char *name, qn_tls_fp *profile)
{
    size_t i;

    if (!name || !profile)
        return false;
    for (i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++) {
        if (!strcmp(name, PROFILES[i].name)) {
            *profile = (qn_tls_fp)i;
            return true;
        }
    }
    if (!strcmp(name, "chrome"))
        *profile = QN_TLS_FP_CHROME;
    else if (!strcmp(name, "firefox"))
        *profile = QN_TLS_FP_FIREFOX;
    else if (!strcmp(name, "safari"))
        *profile = QN_TLS_FP_SAFARI;
    else
        return false;
    return true;
}

bool qn_tls_fp_parse(const char *name, qn_tls_fp *profile)
{
    return qn_client_profile_parse(name, profile);
}

bool qn_profile_h2_shape(const qn_client_profile *profile, uint64_t seed,
                         qn_h2_setting *settings, size_t settings_cap,
                         size_t *settings_n, uint32_t *connection_window)
{
    size_t n;

    if (!profile || !settings || !settings_n || !connection_window ||
        profile->h2.nsettings > QN_PROFILE_MAX_H2_SETTINGS)
        return false;
    n = profile->h2.nsettings;
    if (settings_cap < n)
        return false;
    memcpy(settings, profile->h2.setting, n * sizeof settings[0]);
    *connection_window = profile->h2.connection_window;
    if (profile->tls == QN_TLS_FP_RANDOM) {
        uint64_t state = seed ^ UINT64_C(0x48322D5345545449);

        shuffle_h2(settings, n, &state);
        for (size_t i = 0; i < n; i++) {
            if (settings[i].id == H2_INITIAL_WINDOW) {
                settings[i].value = 65535u +
                                    (uint32_t)(shape_next(&state) % (4u << 20));
            }
        }
    }
    *settings_n = n;
    return true;
}

bool qn_profile_http_shape(const qn_client_profile *profile, uint64_t seed,
                           uint8_t pseudo_order[4], uint8_t header_order[3])
{
    if (!profile || !pseudo_order || !header_order)
        return false;
    memcpy(pseudo_order, profile->http.pseudo_order, 4u);
    memcpy(header_order, profile->http.header_order, 3u);
    if (profile->tls == QN_TLS_FP_RANDOM) {
        uint64_t state = seed ^ UINT64_C(0x48322D4845414445);

        shuffle_u8(pseudo_order, 4u, &state);
        shuffle_u8(header_order, 3u, &state);
    }
    return true;
}

typedef struct {
    uint8_t *out;
    size_t   cap;
    size_t   n;
    bool     failed;
} request_writer;

static void request_put(request_writer *writer, const char *text)
{
    size_t n = strlen(text);

    if (writer->failed || n > writer->cap - writer->n) {
        writer->failed = true;
        return;
    }
    memcpy(writer->out + writer->n, text, n);
    writer->n += n;
}

static void request_header(request_writer *writer,
                           const qn_http_header_profile *profile,
                           uint8_t header)
{
    switch ((qn_regular_header)header) {
    case QN_HEADER_USER_AGENT:
        request_put(writer, "User-Agent: ");
        request_put(writer, profile->user_agent);
        break;
    case QN_HEADER_ACCEPT:
        request_put(writer, "Accept: ");
        request_put(writer, profile->accept);
        break;
    case QN_HEADER_ACCEPT_ENCODING:
        request_put(writer, "Accept-Encoding: ");
        request_put(writer, profile->accept_encoding);
        break;
    default:
        writer->failed = true;
        return;
    }
    request_put(writer, "\r\n");
}

int qn_profile_http1_get(const qn_client_profile *profile, uint64_t seed,
                         const char *host, const char *path,
                         uint8_t *out, size_t cap)
{
    request_writer writer = { out, cap, 0u, false };
    uint8_t pseudo_order[4];
    uint8_t order[3];

    if (!profile || !out || !cap || !qn_valid_field(host, 253u) ||
        !qn_valid_field(path, 1024u))
        return -1;
    if (!qn_profile_http_shape(profile, seed, pseudo_order, order))
        return -1;

    request_put(&writer, "GET ");
    request_put(&writer, path);
    request_put(&writer, " HTTP/1.1\r\nHost: ");
    request_put(&writer, host);
    request_put(&writer, "\r\n");
    for (size_t i = 0; i < sizeof order; i++)
        request_header(&writer, &profile->http, order[i]);
    request_put(&writer, "Connection: keep-alive\r\n\r\n");
    if (writer.failed || writer.n >= cap || writer.n > (size_t)INT32_MAX)
        return -1;
    out[writer.n] = 0u;
    return (int)writer.n;
}

int qn_profile_instance_http1_get(const qn_profile_instance *instance,
                                  const char *host, const char *path,
                                  uint8_t *out, size_t cap)
{
    request_writer writer = { out, cap, 0u, false };

    if (!instance || instance->version != QN_PROFILE_INSTANCE_VERSION ||
        !instance->profile || !out || !cap || !qn_valid_field(host, 253u) ||
        !qn_valid_field(path, 1024u))
        return -1;
    request_put(&writer, "GET ");
    request_put(&writer, path);
    request_put(&writer, " HTTP/1.1\r\nHost: ");
    request_put(&writer, host);
    request_put(&writer, "\r\n");
    for (size_t i = 0; i < QN_ARRAY_LEN(instance->http1_header_order); i++)
        request_header(&writer, &instance->profile->http,
                       instance->http1_header_order[i]);
    request_put(&writer, "Connection: keep-alive\r\n\r\n");
    if (writer.failed || writer.n >= cap || writer.n > (size_t)INT32_MAX)
        return -1;
    out[writer.n] = 0u;
    return (int)writer.n;
}
