#include "qanat/verify.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static qn_addr test_address(void)
{
    qn_addr address;

    memset(&address, 0, sizeof address);
    address.af = AF_INET;
    address.u.v4 = 0xC0000201u;
    return address;
}

static qn_verify_status run_fault(qn_verify_test_fault fault,
                                  qn_verify_result *result)
{
    qn_verify_cfg config;
    qn_addr address = test_address();

    qn_verify_defaults(&config);
    config.sni = "example.com";
    config.concurrency = 1u;
    config.stability_concurrency = 1u;
    config.idle_ms = 0u;
    config.want_bytes = 0u;
    qn_verify_test_set_fault(fault);
    return qn_verify_run(&config, &address, 1u, result);
}

static void expect_startup_fault(qn_verify_test_fault fault, int error,
                                 uint32_t attempted)
{
    qn_verify_result result, before;
    qn_verify_status status;

    memset(&result, 0xA5, sizeof result);
    before = result;
    status = run_fault(fault, &result);
    CHECK(status.state == QN_VERIFY_INFRA_FAILURE);
    CHECK(status.fatal_errno == error);
    CHECK(status.attempted == attempted);
    CHECK(status.attempted + status.unattempted == 1u);
    CHECK(status.completed + status.cancelled == status.attempted);
    CHECK(memcmp(&result, &before, sizeof result) == 0);
}

static void test_transactional_startup_faults(void)
{
    expect_startup_fault(QN_VERIFY_TEST_WORK_ALLOC, ENOMEM, 0u);
    expect_startup_fault(QN_VERIFY_TEST_EPOLL_CREATE, EMFILE, 0u);
    expect_startup_fault(QN_VERIFY_TEST_SLOT_ALLOC, ENOMEM, 0u);
    expect_startup_fault(QN_VERIFY_TEST_INBUF_ALLOC, ENOMEM, 0u);
    expect_startup_fault(QN_VERIFY_TEST_APPBUF_ALLOC, ENOMEM, 0u);
    expect_startup_fault(QN_VERIFY_TEST_SOCKET, EMFILE, 1u);
    expect_startup_fault(QN_VERIFY_TEST_EPOLL_CTL, EIO, 1u);
    expect_startup_fault(QN_VERIFY_TEST_EPOLL_WAIT, EIO, 1u);
    expect_startup_fault(QN_VERIFY_TEST_READ, EIO, 1u);
}

static void test_short_write_is_completed_before_reading(void)
{
    qn_verify_result result;
    qn_verify_status status;

    memset(&result, 0, sizeof result);
    status = run_fault(QN_VERIFY_TEST_SHORT_WRITE, &result);
    CHECK(qn_verify_test_short_write_seen());
    CHECK(status.state == QN_VERIFY_COMPLETE);
    CHECK(status.fatal_errno == 0);
    CHECK(status.attempted == 1u && status.completed == 1u);
    CHECK(status.unattempted == 0u && status.cancelled == 0u);
    CHECK(result.observation.completed);
    CHECK(result.observation.transport.connected);
    CHECK(result.classification.terminal_outcome == QN_TERM_PEER_REJECTED);
}

static void test_pool_planning_is_bounded(void)
{
    qn_verify_pool_plan plan;

    CHECK(qn_verify_plan_pools(32u, 512u, 5000u, 1024u, 64u, &plan));
    CHECK(plan.active == 32u);
    CHECK(plan.stability == 32u);
    CHECK(plan.total == 64u);
    CHECK(plan.total < 1024u);
    CHECK(qn_verify_plan_pools(32u, 512u, 0u, 1024u, 64u, &plan));
    CHECK(plan.active == 32u && plan.stability == 0u && plan.total == 32u);
}

static void test_verifier_state_uses_run_outcome_contract(void)
{
    CHECK(qn_verify_run_outcome(QN_VERIFY_COMPLETE) == QN_RUN_SUCCESS);
    CHECK(qn_verify_run_outcome(QN_VERIFY_PARTIAL) == QN_RUN_INCOMPLETE);
    CHECK(qn_verify_run_outcome(QN_VERIFY_CANCELLED) == QN_RUN_CANCELLED);
    CHECK(qn_verify_run_outcome(QN_VERIFY_INFRA_FAILURE) == QN_RUN_FAILED);
    CHECK(qn_verify_run_outcome((qn_verify_state)99) == QN_RUN_FAILED);
}

int main(void)
{
    test_transactional_startup_faults();
    test_short_write_is_completed_before_reading();
    test_pool_planning_is_bounded();
    test_verifier_state_uses_run_outcome_contract();
    qn_verify_test_set_fault(QN_VERIFY_TEST_NONE);

    if (failures) {
        fprintf(stderr, "verify fault tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("verify fault tests: ok\n");
    return 0;
}
