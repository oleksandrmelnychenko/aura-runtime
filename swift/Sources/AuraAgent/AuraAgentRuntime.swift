import Foundation

public final class AuraAgentRuntime: @unchecked Sendable {
    private let handle: UnsafeMutableRawPointer

    public init(configBytes: Data) throws {
        guard !configBytes.isEmpty else {
            throw AuraAgentError.invalidInput("configBytes must not be empty")
        }

        let createdHandle = try Self.withBytePointer(configBytes) { ptr, count in
            native_aura_agent_init(ptr, count)
        }

        guard let createdHandle else {
            throw AuraAgentError.initializationFailed(Self.consumeLastError())
        }

        handle = createdHandle
    }

    deinit {
        native_aura_agent_free(handle)
    }

    public static var version: String {
        native_aura_agent_version().map { String(cString: $0) } ?? "unknown"
    }

    public func analyzeContext(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_analyze_context(handle, ptr, count, out)
            }
        }
    }

    public func analyzeForRelay(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_analyze_for_relay(handle, ptr, count, out)
            }
        }
    }

    public func recordRelayResponse(requestBytes: Data) throws {
        let ok = try Self.withBytePointer(requestBytes) { ptr, count in
            native_aura_agent_record_relay_response(handle, ptr, count)
        }
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    public func exportContext() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_export_context(handle, out)
        }
    }

    public func contactsByRisk() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_get_contacts_by_risk(handle, out)
        }
    }

    public func conversationSummary() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_get_conversation_summary(handle, out)
        }
    }

    private func withOutputBuffer(
        _ body: (UnsafeMutablePointer<NativeAuraAgentBuffer>) throws -> Bool
    ) throws -> Data {
        var buffer = NativeAuraAgentBuffer(ptr: nil, len: 0)
        let ok = try body(&buffer)
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
        defer { native_aura_agent_free_buffer(buffer) }

        guard let ptr = buffer.ptr, buffer.len > 0 else {
            return Data()
        }
        return Data(bytes: ptr, count: buffer.len)
    }

    private static func withBytePointer<T>(
        _ data: Data,
        _ body: (UnsafePointer<UInt8>, Int) throws -> T
    ) throws -> T {
        if data.isEmpty {
            var byte: UInt8 = 0
            return try withUnsafePointer(to: &byte) { ptr in
                try body(ptr, 0)
            }
        }

        return try data.withUnsafeBytes { rawBuffer in
            guard let ptr = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                throw AuraAgentError.invalidInput("bytes have no base address")
            }
            return try body(ptr, data.count)
        }
    }

    private static func consumeLastError() -> String {
        guard let ptr = native_aura_agent_last_error() else {
            return "unknown error"
        }
        defer { native_aura_agent_free_string(ptr) }
        return String(cString: ptr)
    }
}
