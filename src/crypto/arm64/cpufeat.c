/* Thread-safe runtime feature detection and reproducible backend controls. */

#include "backend.h"
#include "qanat/crypto.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__)
#include <sys/auxv.h>

#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (UINT64_C(1) << 1)
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (UINT64_C(1) << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (UINT64_C(1) << 4)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (UINT64_C(1) << 6)
#endif
#ifndef HWCAP_SHA512
#define HWCAP_SHA512 (UINT64_C(1) << 21)
#endif
#endif

#define BACKEND_BIT(b) (UINT32_C(1) << (unsigned)(b))

static pthread_once_t controls_once = PTHREAD_ONCE_INIT;
static uint32_t       available_mask;
static uint32_t       disabled_mask;
static uint32_t       forced_mask;
static uint32_t       forced_missing_mask;

typedef struct {
    const char *disable;
    const char *force;
} backend_env;

static const backend_env backend_controls[QN_BACKEND_COUNT] = {
    [QN_BACKEND_AES_CE]        = { "QN_DISABLE_AES_CE", "QN_FORCE_AES_CE" },
    [QN_BACKEND_GHASH_CE]      = { "QN_DISABLE_GHASH_CE", "QN_FORCE_GHASH_CE" },
    [QN_BACKEND_AES_GCM_FUSED] = { "QN_DISABLE_AES_GCM_FUSED", "QN_FORCE_AES_GCM_FUSED" },
    [QN_BACKEND_SHA256_CE]     = { "QN_DISABLE_SHA256_CE", "QN_FORCE_SHA256_CE" },
    [QN_BACKEND_CHACHA_NEON]   = { "QN_DISABLE_CHACHA_NEON", "QN_FORCE_CHACHA_NEON" },
    [QN_BACKEND_POLY1305_ASM]  = { "QN_DISABLE_POLY1305_ASM", "QN_FORCE_POLY1305_ASM" },
    [QN_BACKEND_X25519_ASM]    = { "QN_DISABLE_X25519_ASM", "QN_FORCE_X25519_ASM" },
    [QN_BACKEND_SHA512_CE]     = { "QN_DISABLE_SHA512_CE", "QN_FORCE_SHA512_CE" },
};

static bool env_true(const char *name)
{
    const char *value = getenv(name);

    if (!value || !*value)
        return false;
    return strcmp(value, "0") != 0 && strcmp(value, "false") != 0 &&
           strcmp(value, "no") != 0 && strcmp(value, "off") != 0;
}

static void detect_controls(void)
{
    unsigned i;

#if defined(__aarch64__)
    {
        unsigned long hwcap = getauxval(AT_HWCAP);

        if ((hwcap & HWCAP_AES) != 0ul)
            available_mask |= BACKEND_BIT(QN_BACKEND_AES_CE);
        if ((hwcap & HWCAP_PMULL) != 0ul)
            available_mask |= BACKEND_BIT(QN_BACKEND_GHASH_CE);
        if ((hwcap & HWCAP_SHA2) != 0ul)
            available_mask |= BACKEND_BIT(QN_BACKEND_SHA256_CE);
        if ((hwcap & HWCAP_ASIMD) != 0ul)
            available_mask |= BACKEND_BIT(QN_BACKEND_CHACHA_NEON);
#if defined(__SIZEOF_INT128__) && !defined(QN_NO_INT128)
        available_mask |= BACKEND_BIT(QN_BACKEND_POLY1305_ASM);
#endif
        if ((available_mask & (BACKEND_BIT(QN_BACKEND_AES_CE) |
                               BACKEND_BIT(QN_BACKEND_GHASH_CE))) ==
            (BACKEND_BIT(QN_BACKEND_AES_CE) | BACKEND_BIT(QN_BACKEND_GHASH_CE)))
            available_mask |= BACKEND_BIT(QN_BACKEND_AES_GCM_FUSED);
        if ((hwcap & HWCAP_SHA512) != 0ul)
            available_mask |= BACKEND_BIT(QN_BACKEND_SHA512_CE);
        /* X25519 has no callable assembly backend. */
    }
#endif

    if (env_true("QN_NO_ASM"))
        disabled_mask = UINT32_MAX;

    for (i = 0; i < QN_BACKEND_COUNT; i++) {
        uint32_t bit = BACKEND_BIT(i);

        if (env_true(backend_controls[i].disable))
            disabled_mask |= bit;
        if (env_true(backend_controls[i].force)) {
            forced_mask |= bit;
            if ((available_mask & bit) != 0u)
                disabled_mask &= ~bit;
            else
                forced_missing_mask |= bit;
        }
    }

    {
        uint32_t fused = BACKEND_BIT(QN_BACKEND_AES_GCM_FUSED);
        uint32_t deps  = BACKEND_BIT(QN_BACKEND_AES_CE) |
                        BACKEND_BIT(QN_BACKEND_GHASH_CE);

        if ((forced_mask & fused) != 0u && (available_mask & fused) != 0u)
            disabled_mask &= ~(fused | deps);
        else if ((disabled_mask & deps) != 0u)
            disabled_mask |= fused;
    }
}

static void ensure_controls(void)
{
    (void)pthread_once(&controls_once, detect_controls);
}

bool qn_crypto_backend_available(qn_crypto_backend backend)
{
    if ((unsigned)backend >= QN_BACKEND_COUNT)
        return false;
    ensure_controls();
    return (available_mask & BACKEND_BIT(backend)) != 0u;
}

bool qn_crypto_backend_enabled(qn_crypto_backend backend)
{
    uint32_t bit;

    if ((unsigned)backend >= QN_BACKEND_COUNT)
        return false;
    ensure_controls();
    bit = BACKEND_BIT(backend);
    return (available_mask & bit) != 0u && (disabled_mask & bit) == 0u;
}

bool qn_crypto_backend_forced(qn_crypto_backend backend)
{
    if ((unsigned)backend >= QN_BACKEND_COUNT)
        return false;
    ensure_controls();
    return (forced_mask & BACKEND_BIT(backend)) != 0u;
}

const char *qn_crypto_backend_name(qn_crypto_backend backend)
{
    static const char *const names[QN_BACKEND_COUNT] = {
        [QN_BACKEND_AES_CE]        = "aes-ce",
        [QN_BACKEND_GHASH_CE]      = "ghash-pmull",
        [QN_BACKEND_AES_GCM_FUSED] = "aes-gcm-fused",
        [QN_BACKEND_SHA256_CE]     = "sha256-ce",
        [QN_BACKEND_CHACHA_NEON]   = "chacha-neon",
        [QN_BACKEND_POLY1305_ASM]  = "poly1305-asm",
        [QN_BACKEND_X25519_ASM]    = "x25519-asm",
        [QN_BACKEND_SHA512_CE]     = "sha512-ce",
    };

    if ((unsigned)backend >= QN_BACKEND_COUNT)
        return "unknown";
    return names[backend];
}

const char *qn_crypto_backend_control_error(void)
{
    ensure_controls();
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_AES_CE)) != 0u)
        return "QN_FORCE_AES_CE requested, but AES CE is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_GHASH_CE)) != 0u)
        return "QN_FORCE_GHASH_CE requested, but PMULL GHASH is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_AES_GCM_FUSED)) != 0u)
        return "QN_FORCE_AES_GCM_FUSED requested, but AES or PMULL is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_SHA256_CE)) != 0u)
        return "QN_FORCE_SHA256_CE requested, but SHA2 CE is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_CHACHA_NEON)) != 0u)
        return "QN_FORCE_CHACHA_NEON requested, but NEON is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_POLY1305_ASM)) != 0u)
        return "QN_FORCE_POLY1305_ASM requested, but the AArch64 backend is unavailable";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_X25519_ASM)) != 0u)
        return "QN_FORCE_X25519_ASM requested, but no X25519 assembly backend is compiled";
    if ((forced_missing_mask & BACKEND_BIT(QN_BACKEND_SHA512_CE)) != 0u)
        return "QN_FORCE_SHA512_CE requested, but no SHA-512 CE backend is compiled";
    return NULL;
}

bool qn_cpu_has_aes(void)
{
    return qn_crypto_backend_enabled(QN_BACKEND_AES_CE);
}

bool qn_cpu_has_pmull(void)
{
    return qn_crypto_backend_enabled(QN_BACKEND_GHASH_CE);
}

bool qn_cpu_has_sha2(void)
{
    return qn_crypto_backend_enabled(QN_BACKEND_SHA256_CE);
}

bool qn_cpu_has_neon(void)
{
    return qn_crypto_backend_enabled(QN_BACKEND_CHACHA_NEON);
}
