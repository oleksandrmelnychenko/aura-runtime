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

    /// Canonically analyzes one event revision and updates Safety Case state at
    /// most once. The request and response are protobuf encoded.
    public func analyzeCanonicalSafety(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_analyze_canonical_safety(handle, ptr, count, out)
            }
        }
    }

    /// Applies an account-scoped resolve or dismiss command encoded as protobuf.
    public func applySafetyCaseLifecycle(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_apply_safety_case_lifecycle(handle, ptr, count, out)
            }
        }
    }

    /// Explicitly activates one successor generation. Product policy decides
    /// whether and when to call this operation.
    public func activateSafetyCaseSuccessor(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_activate_safety_case_successor(handle, ptr, count, out)
            }
        }
    }

    /// Purges one account partition from native Safety Case memory.
    public func removeSafetyCaseAccount(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_remove_safety_case_account(handle, ptr, count, out)
            }
        }
    }

    public func analyze(messageBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(messageBytes) { ptr, count in
                native_aura_agent_analyze(handle, ptr, count, out)
            }
        }
    }

    public func analyzeBatch(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_analyze_batch(handle, ptr, count, out)
            }
        }
    }

    public func buildShadowBundle(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_build_shadow_bundle(handle, ptr, count, out)
            }
        }
    }

    public func exportContext() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_export_context(handle, out)
        }
    }

    public func importContext(requestBytes: Data) throws {
        let ok = try Self.withBytePointer(requestBytes) { ptr, count in
            native_aura_agent_import_context(handle, ptr, count)
        }
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    /// Returns versioned, content-free Safety Case JSON for host encryption.
    public func exportSafetyCaseState(accountKey: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(accountKey) { ptr, count in
                native_aura_agent_export_safety_case_state(handle, ptr, count, out)
            }
        }
    }

    /// Restores host-decrypted Safety Case JSON after native bounded validation.
    public func importSafetyCaseState(accountKey: Data, stateBytes: Data) throws {
        let ok = try Self.withBytePointer(accountKey) { accountPtr, accountCount in
            try Self.withBytePointer(stateBytes) { statePtr, stateCount in
                native_aura_agent_import_safety_case_state(
                    handle,
                    accountPtr,
                    accountCount,
                    statePtr,
                    stateCount
                )
            }
        }
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    public func cleanupContext(nowMilliseconds: UInt64) throws {
        guard native_aura_agent_cleanup_context(handle, nowMilliseconds) else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    public func updateConfig(configBytes: Data) throws {
        let ok = try Self.withBytePointer(configBytes) { ptr, count in
            native_aura_agent_update_config(handle, ptr, count)
        }
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    public func reloadPatterns(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_reload_patterns(handle, ptr, count, out)
            }
        }
    }

    public func contactsByRisk() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_get_contacts_by_risk(handle, out)
        }
    }

    public func contactProfile(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_get_contact_profile(handle, ptr, count, out)
            }
        }
    }

    public func markContactTrusted(requestBytes: Data) throws {
        let ok = try Self.withBytePointer(requestBytes) { ptr, count in
            native_aura_agent_mark_contact_trusted(handle, ptr, count)
        }
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }
    }

    public func quickCheck(textBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(textBytes) { ptr, count in
                native_aura_agent_quick_check(handle, ptr, count, out)
            }
        }
    }

    public func detectSuspiciousURL(urlBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(urlBytes) { ptr, count in
                native_aura_agent_detect_suspicious_url(handle, ptr, count, out)
            }
        }
    }

    public func conversationSummary() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_get_conversation_summary(handle, out)
        }
    }

    /// Returns a protobuf-encoded RuntimeCapabilities snapshot.
    public func runtimeCapabilities() throws -> Data {
        try withOutputBuffer { out in
            native_aura_agent_get_runtime_capabilities(handle, out)
        }
    }

    private func withOutputBuffer(
        _ body: (UnsafeMutablePointer<NativeAuraAgentBuffer>) throws -> Bool
    ) throws -> Data {
        var buffer = NativeAuraAgentBuffer(ptr: nil, len: 0)
        defer { native_aura_agent_free_buffer(buffer) }

        let ok = try body(&buffer)
        guard ok else {
            throw AuraAgentError.callFailed(Self.consumeLastError())
        }

        guard buffer.len > 0 else {
            return Data()
        }
        guard let ptr = buffer.ptr else {
            throw AuraAgentError.callFailed(
                "native call returned a null buffer with a non-zero length"
            )
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
