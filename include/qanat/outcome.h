#ifndef QANAT_OUTCOME_H
#define QANAT_OUTCOME_H

/* One run-outcome contract is shared by every subsystem and front end. */
typedef enum {
    QN_RUN_SUCCESS = 0,
    QN_RUN_CANCELLED,
    QN_RUN_INCOMPLETE,
    QN_RUN_FAILED
} qn_run_outcome;

const char *qn_run_outcome_str(qn_run_outcome outcome);
int qn_run_exit_code(qn_run_outcome outcome);
qn_run_outcome qn_run_outcome_worst(qn_run_outcome left,
                                    qn_run_outcome right);

#endif
