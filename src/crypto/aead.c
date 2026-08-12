/* AEAD dispatch shared by the TLS 1.2 and 1.3 record layers. */

#include "aead_impl.h"

#include <string.h>

/* Zero for an unknown id: a default of 32 would hand callers a phantom key. */
size_t qn_aead_key_len(qn_aead_id id)
{
    switch (id) {
    case QN_AEAD_AES128GCM:        return 16u;
    case QN_AEAD_AES256GCM:        return 32u;
    case QN_AEAD_CHACHA20POLY1305: return 32u;
    default:                       return 0u;
    }
}

bool qn_aead_init(qn_aead *a, qn_aead_id id, const uint8_t *key)
{
    bool ok;

    if (!a)
        return false;
    memset(a, 0, sizeof *a);
    if (!key || !qn_aead_key_len(id))
        return false;

    switch (id) {
    case QN_AEAD_AES128GCM:
        ok = qn_aes_gcm_setkey(&a->u.gcm, key, 16u);
        break;
    case QN_AEAD_AES256GCM:
        ok = qn_aes_gcm_setkey(&a->u.gcm, key, 32u);
        break;
    case QN_AEAD_CHACHA20POLY1305:
        memcpy(a->u.chacha, key, 32u);
        ok = true;
        break;
    default:
        return false;
    }

    /* Publish the id only after the key schedule is installed. */
    if (!ok) {
        memset(a, 0, sizeof *a);
        return false;
    }
    a->id    = id;
    a->ready = true;
    return true;
}

bool qn_aead_seal(const qn_aead *a, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                  size_t aadlen, const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    if (!a || !a->ready || !iv || !out || (aadlen && !aad) || (ptlen && !pt))
        return false;
    switch (a->id) {
    case QN_AEAD_AES128GCM:
    case QN_AEAD_AES256GCM:
        return qn_aes_gcm_seal(&a->u.gcm, iv, aad, aadlen, pt, ptlen, out);
    case QN_AEAD_CHACHA20POLY1305:
        return qn_chacha20poly1305_seal(a->u.chacha, iv, aad, aadlen, pt, ptlen, out);
    default:
        return false;
    }
}

bool qn_aead_open(const qn_aead *a, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                  size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    if (!a || !a->ready || !iv || !ct || !out || (aadlen && !aad))
        return false;
    switch (a->id) {
    case QN_AEAD_AES128GCM:
    case QN_AEAD_AES256GCM:
        return qn_aes_gcm_open(&a->u.gcm, iv, aad, aadlen, ct, ctlen, out);
    case QN_AEAD_CHACHA20POLY1305:
        return qn_chacha20poly1305_open(a->u.chacha, iv, aad, aadlen, ct, ctlen, out);
    default:
        return false;
    }
}
