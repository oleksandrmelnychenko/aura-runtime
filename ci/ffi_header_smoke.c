#include "include/aura_ffi.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(AuraBuffer) >= sizeof(void*) + sizeof(size_t), "AuraBuffer layout changed unexpectedly");
#endif

static void use_exports(void) {
    AuraBuffer buf = {0};
    void *handle = 0;
    const uint8_t *bytes = 0;
    size_t len = 0;

    (void)aura_agent_init(bytes, len);
    (void)aura_attest_runtime_artifacts(handle, bytes, len, &buf);
    (void)aura_apply_execution_policy(handle, bytes, len, &buf);
    (void)aura_analyze_canonical_safety(handle, bytes, len, &buf);
    (void)aura_apply_safety_case_lifecycle(handle, bytes, len, &buf);
    (void)aura_activate_safety_case_successor(handle, bytes, len, &buf);
    (void)aura_remove_safety_case_account(handle, bytes, len, &buf);
    (void)aura_export_guardian_report_snapshot(handle, bytes, len, &buf);
    (void)aura_export_guardian_report_account_snapshot(handle, bytes, len, &buf);
    (void)aura_flush_deferred_guardian_report(handle, bytes, len, &buf);
    (void)aura_confirm_guardian_report_prepared(handle, bytes, len, &buf);
    (void)aura_suppress_guardian_report(handle, bytes, len, &buf);
    (void)aura_acknowledge_guardian_report(handle, bytes, len, &buf);
    (void)aura_export_context(handle, &buf);
    (void)aura_import_context(handle, bytes, len);
    (void)aura_export_safety_case_state(handle, bytes, len, &buf);
    (void)aura_import_safety_case_state(handle, bytes, len, bytes, len);
    (void)aura_agent_version();
    (void)aura_last_error();
    aura_free(handle);
    aura_free_string(0);
    aura_free_buffer(buf);
}

int main(void) {
    use_exports();
    return 0;
}
