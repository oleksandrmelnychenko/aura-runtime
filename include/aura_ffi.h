#ifndef AURA_FFI_H
#define AURA_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;
    size_t len;
} AuraBuffer;

/// Initialize AURA with protobuf AuraConfig bytes. Returns opaque handle or NULL.
/// Symbol exported as `aura_agent_init` to avoid colliding with
/// aura-protected-protocol's `aura_init` when co-linked.
void *aura_agent_init(const uint8_t *config_ptr, size_t config_len);

/// Attest the exact artifacts active in this runtime using a protobuf
/// RuntimeArtifactAttestationRequest/Response challenge exchange.
bool aura_attest_runtime_artifacts(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Verify a protobuf AuraExecutionPolicyApplyRequest against the compile-time
/// Ed25519 trust keyring, atomically advance the account-scoped native monotonic
/// floor, and return an exact application receipt.
bool aura_apply_execution_policy(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Analyze protobuf CanonicalSafetyAnalyzeRequest exactly once. Writes protobuf CanonicalSafetyAnalyzeResponse into out.
bool aura_analyze_canonical_safety(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf SafetyCaseLifecycleCommandRequest. Writes protobuf SafetyCaseLifecycleCommandResponse into out.
bool aura_apply_safety_case_lifecycle(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Explicitly activate protobuf SafetyCaseSuccessorActivationRequest. Writes SafetyCaseSuccessorActivationResponse into out.
bool aura_activate_safety_case_successor(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Purge protobuf SafetyCaseAccountRemovalRequest. Writes protobuf SafetyCaseAccountRemovalResponse into out.
bool aura_remove_safety_case_account(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Export protobuf GuardianReportSnapshotRequest. Writes a content-free GuardianReportSnapshotResponse into out.
bool aura_export_guardian_report_snapshot(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Export protobuf GuardianReportAccountSnapshotRequest. Writes GuardianReportAccountSnapshotResponse into out.
bool aura_export_guardian_report_account_snapshot(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf GuardianReportFlushRequest. Writes the resulting GuardianReportSnapshotResponse into out.
bool aura_flush_deferred_guardian_report(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf GuardianReportPreparationRequest. Writes GuardianReportPreparationResponse into out.
bool aura_confirm_guardian_report_prepared(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf GuardianReportSuppressionRequest. Writes GuardianReportSuppressionResponse into out.
bool aura_suppress_guardian_report(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf GuardianReportAcknowledgementRequest. Writes GuardianReportAcknowledgementResponse into out.
bool aura_acknowledge_guardian_report(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Export context state. Writes protobuf ExportContextResponse into out.
bool aura_export_context(void *handle, AuraBuffer *out);

/// Import context state from protobuf ImportContextRequest.
bool aura_import_context(void *handle, const uint8_t *request_ptr, size_t request_len);

/// Export one account's content-free Safety Case runtime state as UTF-8 JSON. The host must encrypt it at rest.
bool aura_export_safety_case_state(void *handle, const uint8_t *account_key_ptr, size_t account_key_len, AuraBuffer *out);

/// Import one account's bounded UTF-8 JSON Safety Case runtime state after host decryption.
bool aura_import_safety_case_state(void *handle, const uint8_t *account_key_ptr, size_t account_key_len, const uint8_t *state_ptr, size_t state_len);

/// Get AURA version string. Do NOT free the returned pointer.
/// Symbol exported as `aura_agent_version` to avoid colliding with
/// aura-protected-protocol's `aura_version` when co-linked.
const char *aura_agent_version(void);

/// Returns the last error message, or NULL if no error occurred.
/// Caller must free with aura_free_string.
char *aura_last_error(void);

/// Free an AURA analyzer handle.
void aura_free(void *handle);

/// Free a string returned by aura_last_error.
void aura_free_string(char *ptr);

/// Free a protobuf buffer returned by AURA bytes APIs.
void aura_free_buffer(AuraBuffer buf);

#endif /* AURA_FFI_H */
