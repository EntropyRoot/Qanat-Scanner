#ifndef QANAT_RANGES_H
#define QANAT_RANGES_H

#include "qanat/qanat.h"

#define QN_CF_RANGES_URL "https://www.cloudflare.com/ips-v4"
#define QN_PATH_CAP       1024u

typedef struct {
    char     path[QN_PATH_CAP];
    char     error[192];
    uint32_t prefixes;
    uint64_t candidates;
} qn_cf_ranges_info;

bool qn_cf_ranges_default_path(char *out, size_t outsz);
bool qn_cf_ranges_inspect(const char *path, qn_cf_ranges_info *out);
bool qn_cf_ranges_cached(qn_cf_ranges_info *out);
bool qn_cf_ranges_update(qn_cf_ranges_info *out);

#endif /* QANAT_RANGES_H */
