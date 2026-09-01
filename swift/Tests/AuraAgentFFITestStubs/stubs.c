#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// macOS Swift tests exercise language-evidence code without loading the iOS
// XCFramework. Weak symbols satisfy the test linker while allowing a real
// native library to win whenever one is available. Any accidental runtime use
// aborts instead of producing a false-positive test result.

#define AURA_TEST_STUB __attribute__((weak))

typedef struct {
    uint8_t *ptr;
    size_t len;
} AuraBuffer;

static void aura_unavailable_in_host_test(void) __attribute__((noreturn));

static void aura_unavailable_in_host_test(void) {
    abort();
}

AURA_TEST_STUB void *aura_agent_init(const uint8_t *config_ptr, size_t config_len) {
    (void)config_ptr;
    (void)config_len;
    aura_unavailable_in_host_test();
}

#define AURA_BUFFER_OPERATION(name)                                                        \
    AURA_TEST_STUB bool name(void *handle, const uint8_t *request_ptr, size_t request_len, \
                             AuraBuffer *out) {                                            \
        (void)handle;                                                                      \
        (void)request_ptr;                                                                 \
        (void)request_len;                                                                 \
        (void)out;                                                                         \
        aura_unavailable_in_host_test();                                                    \
    }

AURA_BUFFER_OPERATION(aura_attest_runtime_artifacts)
AURA_BUFFER_OPERATION(aura_apply_execution_policy)
AURA_BUFFER_OPERATION(aura_analyze_canonical_safety)
AURA_BUFFER_OPERATION(aura_analyze_local_decision)
AURA_BUFFER_OPERATION(aura_apply_safety_case_lifecycle)
AURA_BUFFER_OPERATION(aura_activate_safety_case_successor)
AURA_BUFFER_OPERATION(aura_remove_safety_case_account)
AURA_BUFFER_OPERATION(aura_export_guardian_report_snapshot)
AURA_BUFFER_OPERATION(aura_export_guardian_report_account_snapshot)
AURA_BUFFER_OPERATION(aura_flush_deferred_guardian_report)
AURA_BUFFER_OPERATION(aura_confirm_guardian_report_prepared)
AURA_BUFFER_OPERATION(aura_suppress_guardian_report)
AURA_BUFFER_OPERATION(aura_acknowledge_guardian_report)

AURA_TEST_STUB bool aura_acknowledge_source_checkpoint(
    void *handle,
    const uint8_t *request_ptr,
    size_t request_len
) {
    (void)handle;
    (void)request_ptr;
    (void)request_len;
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB bool aura_export_context(void *handle, AuraBuffer *out) {
    (void)handle;
    (void)out;
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB bool aura_import_context(
    void *handle,
    const uint8_t *request_ptr,
    size_t request_len
) {
    (void)handle;
    (void)request_ptr;
    (void)request_len;
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB bool aura_export_safety_case_state(
    void *handle,
    const uint8_t *account_key_ptr,
    size_t account_key_len,
    AuraBuffer *out
) {
    (void)handle;
    (void)account_key_ptr;
    (void)account_key_len;
    (void)out;
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB bool aura_import_safety_case_state(
    void *handle,
    const uint8_t *account_key_ptr,
    size_t account_key_len,
    const uint8_t *state_ptr,
    size_t state_len
) {
    (void)handle;
    (void)account_key_ptr;
    (void)account_key_len;
    (void)state_ptr;
    (void)state_len;
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB const char *aura_agent_version(void) {
    aura_unavailable_in_host_test();
}

AURA_TEST_STUB char *aura_last_error(void) {
    return NULL;
}

AURA_TEST_STUB void aura_free(void *handle) {
    (void)handle;
}

AURA_TEST_STUB void aura_free_string(char *ptr) {
    (void)ptr;
}

AURA_TEST_STUB void aura_free_buffer(AuraBuffer buffer) {
    (void)buffer;
}
