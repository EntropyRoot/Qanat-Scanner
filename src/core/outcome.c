#include "qanat/outcome.h"

#include <stdint.h>

const char *qn_run_outcome_str(qn_run_outcome outcome)
{
    switch (outcome) {
    case QN_RUN_SUCCESS:    return "success";
    case QN_RUN_CANCELLED:  return "cancelled";
    case QN_RUN_INCOMPLETE: return "incomplete";
    default:                return "failed";
    }
}

int qn_run_exit_code(qn_run_outcome outcome)
{
    switch (outcome) {
    case QN_RUN_SUCCESS:    return 0;
    case QN_RUN_CANCELLED:  return 130;
    case QN_RUN_INCOMPLETE: return 4;
    default:                return 3;
    }
}

qn_run_outcome qn_run_outcome_worst(qn_run_outcome a, qn_run_outcome b)
{
    static const uint8_t rank[] = { 0u, 2u, 1u, 3u };

    if ((unsigned)a >= sizeof rank / sizeof rank[0] ||
        (unsigned)b >= sizeof rank / sizeof rank[0])
        return QN_RUN_FAILED;
    return rank[(unsigned)a] >= rank[(unsigned)b] ? a : b;
}
