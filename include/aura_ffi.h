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
void *aura_init(const uint8_t *config_ptr, size_t config_len);

/// Analyze protobuf MessageInput. Writes protobuf AnalysisResult into out.
bool aura_analyze(void *handle, const uint8_t *message_ptr, size_t message_len, AuraBuffer *out);

/// Analyze protobuf AnalyzeContextRequest. Writes protobuf AnalysisResult into out.
bool aura_analyze_context(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Analyze protobuf BatchAnalyzeRequest. Writes protobuf BatchAnalyzeResponse into out.
bool aura_analyze_batch(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Update runtime config from protobuf AuraConfig bytes.
bool aura_update_config(void *handle, const uint8_t *config_ptr, size_t config_len);

/// Reload patterns from protobuf ReloadPatternsRequest. Writes protobuf StatusResponse into out.
bool aura_reload_patterns(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Export context state. Writes protobuf ExportContextResponse into out.
bool aura_export_context(void *handle, AuraBuffer *out);

/// Import context state from protobuf ImportContextRequest.
bool aura_import_context(void *handle, const uint8_t *request_ptr, size_t request_len);

/// Cleanup old context data. Returns true on success.
bool aura_cleanup_context(void *handle, uint64_t now_ms);

/// Get all contacts sorted by risk score. Writes protobuf ContactsByRiskResponse into out.
bool aura_get_contacts_by_risk(void *handle, AuraBuffer *out);

/// Get specific contact profile from protobuf ContactProfileRequest. Writes protobuf ContactProfileResponse into out.
bool aura_get_contact_profile(void *handle, const uint8_t *request_ptr, size_t request_len, AuraBuffer *out);

/// Mark a contact as trusted from protobuf MarkContactTrustedRequest.
bool aura_mark_contact_trusted(void *handle, const uint8_t *request_ptr, size_t request_len);

/// Get conversation summary overview. Writes protobuf ConversationSummaryResponse into out.
bool aura_get_conversation_summary(void *handle, AuraBuffer *out);

/// Get AURA version string. Do NOT free the returned pointer.
const char *aura_version(void);

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
