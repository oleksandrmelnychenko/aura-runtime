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

    /// Canonically analyzes one event revision and updates Safety Case state at
    /// most once. The request and response are protobuf encoded.
    public func analyzeCanonicalSafety(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_analyze_canonical_safety(handle, ptr, count, out)
            }
        }
    }

    /// Returns the native canonical artifact attestation response bytes.
    public func attestRuntimeArtifacts(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { request, count in
                native_aura_agent_attest_runtime_artifacts(handle, request, count, out)
            }
        }
    }

    /// Applies one exact signed execution-policy wire against the native floor.
    public func applyExecutionPolicy(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { request, count in
                native_aura_agent_apply_execution_policy(handle, request, count, out)
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

    /// Returns the native reducer's account-scoped, content-free report
    /// projection. The request and response are protobuf encoded.
    public func exportGuardianReportSnapshot(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_export_guardian_report_snapshot(handle, ptr, count, out)
            }
        }
    }

    /// Returns every pending or deferred report projection in one account.
    public func exportGuardianReportAccountSnapshot(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_export_guardian_report_account_snapshot(
                    handle,
                    ptr,
                    count,
                    out
                )
            }
        }
    }

    /// Flushes one exact eligible deferred report and returns its new snapshot.
    public func flushDeferredGuardianReport(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_flush_deferred_guardian_report(
                    handle,
                    ptr,
                    count,
                    out
                )
            }
        }
    }

    /// Locks one exact pending report after its complete encrypted recipient
    /// fanout has been atomically persisted by the host.
    public func confirmGuardianReportPrepared(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_confirm_guardian_report_prepared(
                    handle,
                    ptr,
                    count,
                    out
                )
            }
        }
    }

    /// Suppresses one exact unprepared report under verified host policy.
    public func suppressGuardianReport(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_suppress_guardian_report(
                    handle,
                    ptr,
                    count,
                    out
                )
            }
        }
    }

    /// Records one exact report as delivered after the complete device fanout
    /// has authenticated durable-enqueue receipts.
    public func acknowledgeGuardianReport(requestBytes: Data) throws -> Data {
        try withOutputBuffer { out in
            try Self.withBytePointer(requestBytes) { ptr, count in
                native_aura_agent_acknowledge_guardian_report(handle, ptr, count, out)
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
