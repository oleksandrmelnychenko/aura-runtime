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

/// Analyze protobuf MessageInput. Writes protobuf AnalysisResult into out.
bool aura_analyze(void *handle, const uint8_t *message_ptr, size_t message_len, AuraBuffer *out);

/// Analyze protobuf AnalyzeContextRequest. Writes protobuf AnalysisResult into out.
bool aura_analyze_context(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Analyze protobuf CanonicalSafetyAnalyzeRequest exactly once. Writes protobuf CanonicalSafetyAnalyzeResponse into out.
bool aura_analyze_canonical_safety(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Apply protobuf SafetyCaseLifecycleCommandRequest. Writes protobuf SafetyCaseLifecycleCommandResponse into out.
bool aura_apply_safety_case_lifecycle(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Explicitly activate protobuf SafetyCaseSuccessorActivationRequest. Writes SafetyCaseSuccessorActivationResponse into out.
bool aura_activate_safety_case_successor(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Purge protobuf SafetyCaseAccountRemovalRequest. Writes protobuf SafetyCaseAccountRemovalResponse into out.
bool aura_remove_safety_case_account(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Analyze protobuf BatchAnalyzeRequest. Writes protobuf BatchAnalyzeResponse into out.
bool aura_analyze_batch(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Build protobuf ShadowModeBundle from protobuf BuildShadowModeBundleRequest. Writes protobuf ShadowModeBundle into out.
bool aura_build_shadow_bundle(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Update runtime config from protobuf AuraConfig bytes.
bool aura_update_config(void *handle, const uint8_t *config_ptr, size_t config_len);

/// Reload patterns from protobuf ReloadPatternsRequest. Writes protobuf StatusResponse into out.
bool aura_reload_patterns(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Export context state. Writes protobuf ExportContextResponse into out.
bool aura_export_context(void *handle, AuraBuffer *out);

/// Import context state from protobuf ImportContextRequest.
bool aura_import_context(void *handle, const uint8_t *request_ptr, size_t request_len);

/// Export one account's content-free Safety Case runtime state as UTF-8 JSON. The host must encrypt it at rest.
bool aura_export_safety_case_state(void *handle, const uint8_t *account_key_ptr, size_t account_key_len, AuraBuffer *out);

/// Import one account's bounded UTF-8 JSON Safety Case runtime state after host decryption.
bool aura_import_safety_case_state(void *handle, const uint8_t *account_key_ptr, size_t account_key_len, const uint8_t *state_ptr, size_t state_len);

/// Cleanup old context data. Returns true on success.
bool aura_cleanup_context(void *handle, uint64_t now_ms);

/// Get all contacts sorted by risk score. Writes protobuf ContactsByRiskResponse into out.
bool aura_get_contacts_by_risk(void *handle, AuraBuffer *out);

/// Get specific contact profile from protobuf ContactProfileRequest. Writes protobuf ContactProfileResponse into out.
bool aura_get_contact_profile(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Mark a contact as trusted from protobuf MarkContactTrustedRequest.
bool aura_mark_contact_trusted(void *handle, const uint8_t *request_ptr, size_t request_len);

/// Perform a lightweight safety check on raw UTF-8 text. Writes protobuf StatusResponse into out.
bool aura_quick_check(void *handle, const uint8_t *text_ptr, size_t text_len, AuraBuffer *out);

/// Check a raw UTF-8 URL for suspicious or blocked patterns. Writes protobuf StatusResponse into out.
bool aura_detect_suspicious_url(void *handle, const uint8_t *url_ptr, size_t url_len, AuraBuffer *out);

/// Get conversation summary overview. Writes protobuf ConversationSummaryResponse into out.
bool aura_get_conversation_summary(void *handle, AuraBuffer *out);

/// Get initialized runtime capabilities. Writes protobuf RuntimeCapabilities into out.
bool aura_get_runtime_capabilities(void *handle, AuraBuffer *out);

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
