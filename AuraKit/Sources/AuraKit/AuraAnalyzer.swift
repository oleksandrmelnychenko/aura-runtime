import AuraFFI
import Foundation

/// Wrapper to make the opaque FFI handle sendable.
/// Safety: the Rust side wraps the instance in a Mutex.
private struct AuraHandle: @unchecked Sendable {
    let raw: UnsafeMutableRawPointer
}

/// Main AURA analyzer — thread-safe wrapper over the Rust core.
///
/// Create with ``init(config:)`` and call ``analyze(text:senderId:conversationId:)``
/// or ``analyzeWithContext(message:timestampMs:)`` to analyze messages.
public final class AuraAnalyzer: Sendable {

    private let handle: AuraHandle
    private let queue = DispatchQueue(label: "com.ecliptix.aura.analyzer", qos: .userInitiated)

    // MARK: - Lifecycle

    /// Initialize AURA analyzer with the given config.
    public init(config: AuraConfig) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(config)
        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw AuraError.initializationFailed
        }

        guard let h = jsonString.withCString({ aura_init($0) }) else {
            let detail = Self.consumeLastError()
            throw AuraError.initializationFailedWithDetail(detail ?? "unknown error")
        }
        self.handle = AuraHandle(raw: h)
    }

    deinit {
        aura_free(handle.raw)
    }

    // MARK: - Analysis

    /// Analyze a text message (stateless, no context tracking).
    public func analyze(
        text: String,
        senderId: String,
        conversationId: String
    ) async throws -> AnalysisResult {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [handle] in
                let handle = handle.raw
                let json = text.withCString { textPtr in
                    senderId.withCString { senderPtr in
                        conversationId.withCString { convPtr in
                            FFIBridge.consumeCString(
                                aura_analyze(handle, textPtr, senderPtr, convPtr)
                            )
                        }
                    }
                }
                do {
                    guard let json else { throw AuraError.nullPointer }
                    let result: AnalysisResult = try FFIBridge.decodeResult(json)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Analyze a structured message input (stateless).
    public func analyze(message: MessageInput) async throws -> AnalysisResult {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [handle] in
                let handle = handle.raw
                do {
                    let json = try FFIBridge.withJSONCString(message) { ptr in
                        FFIBridge.consumeCString(aura_analyze_json(handle, ptr))
                    }
                    guard let json else { throw AuraError.nullPointer }
                    let result: AnalysisResult = try FFIBridge.decodeResult(json)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Analyze with context tracking — builds conversation history for
    /// multi-message threat detection (grooming, bullying patterns).
    public func analyzeWithContext(
        message: MessageInput,
        timestampMs: UInt64
    ) async throws -> AnalysisResult {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [handle] in
                let handle = handle.raw
                do {
                    let json = try FFIBridge.withJSONCString(message) { ptr in
                        FFIBridge.consumeCString(aura_analyze_context(handle, ptr, timestampMs))
                    }
                    guard let json else { throw AuraError.nullPointer }
                    let result: AnalysisResult = try FFIBridge.decodeResult(json)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Batch analyze multiple messages in one call.
    public func analyzeBatch(messages: [BatchItem]) async throws -> [AnalysisResult] {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [handle] in
                let handle = handle.raw
                do {
                    let json = try FFIBridge.withJSONCString(messages) { ptr in
                        FFIBridge.consumeCString(aura_analyze_batch(handle, ptr))
                    }
                    guard let json else { throw AuraError.nullPointer }
                    let results: [AnalysisResult] = try FFIBridge.decodeResult(json)
                    continuation.resume(returning: results)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Configuration

    /// Update the analyzer config at runtime. Returns true on success.
    @discardableResult
    public func updateConfig(_ config: AuraConfig) throws -> Bool {
        try FFIBridge.withJSONCString(config) { ptr in
            aura_update_config(self.handle.raw, ptr)
        }
    }

    /// Reload patterns from a file path at runtime.
    /// Returns true on success, false on error.
    @discardableResult
    public func reloadPatterns(fromPath path: String) -> Bool {
        let result = path.withCString { ptr in
            FFIBridge.consumeCString(aura_reload_patterns(self.handle.raw, ptr))
        }
        guard let json = result else { return false }
        return json.contains("\"ok\":true")
    }

    // MARK: - Context Management

    /// Export the full conversation context state as a JSON string.
    /// Use this to persist state between app sessions.
    public func exportContext() throws -> String {
        guard let json = FFIBridge.consumeCString(aura_export_context(handle.raw)) else {
            throw AuraError.nullPointer
        }
        return json
    }

    /// Import previously exported context state.
    @discardableResult
    public func importContext(_ stateJSON: String) -> Bool {
        stateJSON.withCString { ptr in
            aura_import_context(self.handle.raw, ptr)
        }
    }

    /// Remove conversation data older than the analysis window.
    @discardableResult
    public func cleanupContext(nowMs: UInt64) -> Bool {
        aura_cleanup_context(handle.raw, nowMs)
    }

    // MARK: - Contacts

    /// Get all contacts sorted by risk score (highest first).
    public func contactsByRisk() throws -> [ContactProfile] {
        guard let json = FFIBridge.consumeCString(aura_get_contacts_by_risk(handle.raw)) else {
            throw AuraError.nullPointer
        }
        return try FFIBridge.decodeResult(json)
    }

    /// Get a specific contact profile by sender ID.
    /// Returns nil if the contact is not found.
    public func contactProfile(senderId: String) throws -> ContactProfile? {
        let result = senderId.withCString { ptr in
            FFIBridge.consumeCString(aura_get_contact_profile(self.handle.raw, ptr))
        }
        guard let json = result else { throw AuraError.nullPointer }

        // Rust returns {"error":false,"message":"contact not found"} for missing contacts
        if json.contains("\"message\":\"contact not found\"") {
            return nil
        }
        return try FFIBridge.decodeResult(json)
    }

    /// Mark a contact as trusted (reduces their risk score).
    @discardableResult
    public func markContactTrusted(senderId: String) -> Bool {
        senderId.withCString { ptr in
            aura_mark_contact_trusted(self.handle.raw, ptr)
        }
    }

    // MARK: - Conversations

    /// Get an overview of all tracked conversations.
    public func conversationSummary() throws -> ConversationOverview {
        guard let json = FFIBridge.consumeCString(aura_get_conversation_summary(handle.raw)) else {
            throw AuraError.nullPointer
        }
        return try FFIBridge.decodeResult(json)
    }

    // MARK: - Version

    /// AURA Core version string.
    public static var version: String {
        String(cString: aura_version())
    }

    // MARK: - Error introspection

    /// Retrieve and consume the last FFI error, if any.
    public static func consumeLastError() -> String? {
        guard let ptr = aura_last_error() else { return nil }
        let msg = String(cString: ptr)
        aura_free_string(ptr)
        return msg
    }
}
