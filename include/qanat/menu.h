#ifndef QANAT_MENU_H
#define QANAT_MENU_H

#include "qanat/qanat.h"

typedef enum {
    QN_MENU_ERROR = -1,
    QN_MENU_EXIT = 0,
    QN_MENU_START = 1
} qn_menu_result;

/* Numeric launcher used only when both standard input and output are TTYs. */
qn_menu_result qn_menu_run(qn_config *cfg);

#endif /* QANAT_MENU_H */
