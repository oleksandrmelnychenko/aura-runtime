import Foundation

internal struct NativeAuraAgentBuffer {
    var ptr: UnsafeMutablePointer<UInt8>?
    var len: Int
}

@_silgen_name("aura_init")
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

@_silgen_name("aura_analyze_for_relay")
internal func native_aura_agent_analyze_for_relay(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_record_relay_response")
internal func native_aura_agent_record_relay_response(
    _ handle: UnsafeMutableRawPointer?,
    _ requestPtr: UnsafePointer<UInt8>?,
    _ requestLen: Int
) -> Bool

@_silgen_name("aura_export_context")
internal func native_aura_agent_export_context(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_contacts_by_risk")
internal func native_aura_agent_get_contacts_by_risk(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_get_conversation_summary")
internal func native_aura_agent_get_conversation_summary(
    _ handle: UnsafeMutableRawPointer?,
    _ out: UnsafeMutablePointer<NativeAuraAgentBuffer>?
) -> Bool

@_silgen_name("aura_free")
internal func native_aura_agent_free(_ handle: UnsafeMutableRawPointer?)

@_silgen_name("aura_free_string")
internal func native_aura_agent_free_string(_ ptr: UnsafeMutablePointer<CChar>?)

@_silgen_name("aura_free_buffer")
internal func native_aura_agent_free_buffer(_ buffer: NativeAuraAgentBuffer)

@_silgen_name("aura_version")
internal func native_aura_agent_version() -> UnsafePointer<CChar>?

@_silgen_name("aura_last_error")
internal func native_aura_agent_last_error() -> UnsafeMutablePointer<CChar>?
