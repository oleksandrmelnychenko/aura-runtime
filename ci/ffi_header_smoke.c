#include "include/aura_ffi.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(AuraBuffer) >= sizeof(void*) + sizeof(size_t), "AuraBuffer layout changed unexpectedly");
#endif

static void use_exports(void) {
    AuraBuffer buf = {0};
    void *handle = 0;
    const uint8_t *bytes = 0;
    size_t len = 0;
    uint64_t now_ms = 0;

    (void)aura_init(bytes, len);
    (void)aura_analyze(handle, bytes, len, &buf);
    (void)aura_analyze_context(handle, bytes, len, &buf);
    (void)aura_analyze_batch(handle, bytes, len, &buf);
    (void)aura_update_config(handle, bytes, len);
    (void)aura_reload_patterns(handle, bytes, len, &buf);
    (void)aura_export_context(handle, &buf);
    (void)aura_import_context(handle, bytes, len);
    (void)aura_cleanup_context(handle, now_ms);
    (void)aura_get_contacts_by_risk(handle, &buf);
    (void)aura_get_contact_profile(handle, bytes, len, &buf);
    (void)aura_mark_contact_trusted(handle, bytes, len);
    (void)aura_get_conversation_summary(handle, &buf);
    (void)aura_version();
    (void)aura_last_error();
    aura_free(handle);
    aura_free_string(0);
    aura_free_buffer(buf);
}

int main(void) {
    use_exports();
    return 0;
}
