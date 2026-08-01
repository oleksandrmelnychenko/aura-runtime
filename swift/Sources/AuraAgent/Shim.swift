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

@_silgen_name("aura_attest_runtime_artifacts")
internal func native_aura_agent_attest_runtime_artifacts(
    _ handle: UnsafeMutableRawPointer?,
    _ request: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_apply_execution_policy")
internal func native_aura_agent_apply_execution_policy(
    _ handle: UnsafeMutableRawPointer?,
    _ request: UnsafePointer<UInt8>?,
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

@_silgen_name("aura_analyze_local_decision")
internal func native_aura_agent_analyze_local_decision(
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

@_silgen_name("aura_export_guardian_report_snapshot")
internal func native_aura_agent_export_guardian_report_snapshot(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_export_guardian_report_account_snapshot")
internal func native_aura_agent_export_guardian_report_account_snapshot(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_flush_deferred_guardian_report")
internal func native_aura_agent_flush_deferred_guardian_report(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_confirm_guardian_report_prepared")
internal func native_aura_agent_confirm_guardian_report_prepared(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_suppress_guardian_report")
internal func native_aura_agent_suppress_guardian_report(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_acknowledge_guardian_report")
internal func native_aura_agent_acknowledge_guardian_report(
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
