#ifndef AURA_FFI_H
#define AURA_FFI_H

#include <stdint.h>
#include <stdbool.h>

/// Initialize AURA with JSON config. Returns opaque handle or NULL.
void *aura_init(const char *config_json);

/// Analyze text message. Returns JSON string (caller must free with aura_free_string).
char *aura_analyze(void *handle, const char *text, const char *sender_id, const char *conversation_id);

/// Analyze from structured JSON message input. Returns JSON string.
char *aura_analyze_json(void *handle, const char *message_json);

/// Analyze with context tracking. Returns JSON string.
char *aura_analyze_context(void *handle, const char *message_json, uint64_t timestamp_ms);

/// Batch analysis of multiple messages. Returns JSON array string.
char *aura_analyze_batch(void *handle, const char *messages_json);

/// Update analyzer config at runtime. Returns true on success.
bool aura_update_config(void *handle, const char *config_json);

/// Reload patterns from a file path. Returns JSON status string.
char *aura_reload_patterns(void *handle, const char *patterns_path);

/// Export context state as JSON string.
char *aura_export_context(void *handle);

/// Import context state from JSON. Returns true on success.
bool aura_import_context(void *handle, const char *state_json);

/// Cleanup old context data. Returns true on success.
bool aura_cleanup_context(void *handle, uint64_t now_ms);

/// Get all contacts sorted by risk score. Returns JSON string.
char *aura_get_contacts_by_risk(void *handle);

/// Get specific contact profile. Returns JSON string.
char *aura_get_contact_profile(void *handle, const char *sender_id);

/// Mark a contact as trusted. Returns true on success.
bool aura_mark_contact_trusted(void *handle, const char *sender_id);

/// Get conversation summary overview. Returns JSON string.
char *aura_get_conversation_summary(void *handle);

/// Get AURA version string. Do NOT free the returned pointer.
const char *aura_version(void);

/// Returns the last error message, or NULL if no error occurred.
/// Caller must free with aura_free_string.
char *aura_last_error(void);

/// Free an AURA analyzer handle.
void aura_free(void *handle);

/// Free a JSON string returned by AURA analysis functions.
void aura_free_string(char *ptr);

#endif /* AURA_FFI_H */
