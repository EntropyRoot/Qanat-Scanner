#include "qanat/task.h"

/* Published ranges; --ranges overrides this snapshot. */
const char *const qn_cf_v4[] = {
    "173.245.48.0/20",  "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18",  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",    "172.64.0.0/13",   "131.0.72.0/22",
};
const uint32_t qn_cf_v4_n = (uint32_t)(sizeof qn_cf_v4 / sizeof qn_cf_v4[0]);

const char *const qn_cf_updated = "2026-08-08";
