import Foundation

internal struct NativeAuraAgentBuffer {
    var ptr: UnsafeMutablePointer<UInt8>?
    var len: Int
}

@_silgen_name("aura_agent_init")
internal func native_aura_agent_init(
    _ configPtr: UnsafePointer<UInt8>?,
    _ configLen: Int
) -> UnsafeMutableRawPointer?

@_silgen_name("aura_analyze_context")
internal func native_aura_agent_analyze_context(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_analyze_canonical_safety")
internal func native_aura_agent_analyze_canonical_safety(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_apply_safety_case_lifecycle")
internal func native_aura_agent_apply_safety_case_lifecycle(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_activate_safety_case_successor")
internal func native_aura_agent_activate_safety_case_successor(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_remove_safety_case_account")
internal func native_aura_agent_remove_safety_case_account(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_analyze")
internal func native_aura_agent_analyze(
    _ handle: UnsafeMutableRawPointer?,
    _ messagePtr: UnsafePointer<UInt8>?,
    _ messageLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_analyze_batch")
internal func native_aura_agent_analyze_batch(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_build_shadow_bundle")
internal func native_aura_agent_build_shadow_bundle(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_export_context")
internal func native_aura_agent_export_context(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_import_context")
internal func native_aura_agent_import_context(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int
) -> Bool

@_silgen_name("aura_export_safety_case_state")
internal func native_aura_agent_export_safety_case_state(
    _ handle: UnsafeMutableRawPointer?,
    _ accountKeyPtr: UnsafePointer<UInt8>?,
    _ accountKeyLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_import_safety_case_state")
internal func native_aura_agent_import_safety_case_state(
    _ handle: UnsafeMutableRawPointer?,
    _ accountKeyPtr: UnsafePointer<UInt8>?,
    _ accountKeyLen: Int,
    _ statePtr: UnsafePointer<UInt8>?,
    _ stateLen: Int
) -> Bool

@_silgen_name("aura_cleanup_context")
internal func native_aura_agent_cleanup_context(
    _ handle: UnsafeMutableRawPointer?,
    _ nowMilliseconds: UInt64
) -> Bool

@_silgen_name("aura_update_config")
internal func native_aura_agent_update_config(
    _ handle: UnsafeMutableRawPointer?,
    _ configPtr: UnsafePointer<UInt8>?,
    _ configLen: Int
) -> Bool

@_silgen_name("aura_reload_patterns")
internal func native_aura_agent_reload_patterns(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_contacts_by_risk")
internal func native_aura_agent_get_contacts_by_risk(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_contact_profile")
internal func native_aura_agent_get_contact_profile(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_mark_contact_trusted")
internal func native_aura_agent_mark_contact_trusted(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int
) -> Bool

@_silgen_name("aura_quick_check")
internal func native_aura_agent_quick_check(
    _ handle: UnsafeMutableRawPointer?,
    _ textPtr: UnsafePointer<UInt8>?,
    _ textLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_detect_suspicious_url")
internal func native_aura_agent_detect_suspicious_url(
    _ handle: UnsafeMutableRawPointer?,
    _ urlPtr: UnsafePointer<UInt8>?,
    _ urlLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_conversation_summary")
internal func native_aura_agent_get_conversation_summary(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_runtime_capabilities")
internal func native_aura_agent_get_runtime_capabilities(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_free")
internal func native_aura_agent_free(_ handle: UnsafeMutableRawPointer?)

@_silgen_name("aura_free_string")
internal func native_aura_agent_free_string(_ ptr: UnsafeMutablePointer<CChar>?)

@_silgen_name("aura_free_buffer")
internal func native_aura_agent_free_buffer(_ buffer: NativeAuraAgentBuffer)

@_silgen_name("aura_agent_version")
internal func native_aura_agent_version() -> UnsafePointer<CChar>?

@_silgen_name("aura_last_error")
internal func native_aura_agent_last_error() -> UnsafeMutablePointer<CChar>?
