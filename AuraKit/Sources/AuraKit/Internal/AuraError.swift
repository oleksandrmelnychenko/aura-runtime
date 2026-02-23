import Foundation

public enum AuraError: Error, Sendable {
    case initializationFailed
    case initializationFailedWithDetail(String)
    case nullPointer
    case invalidJSON(String)
    case ffiError(code: Int, message: String)
    case unknown(String)
}

extension AuraError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .initializationFailed:
            return "Failed to initialize AURA analyzer"
        case .initializationFailedWithDetail(let detail):
            return "Failed to initialize AURA analyzer: \(detail)"
        case .nullPointer:
            return "AURA FFI returned null pointer"
        case .invalidJSON(let detail):
            return "Invalid JSON: \(detail)"
        case .ffiError(let code, let message):
            return "AURA FFI error \(code): \(message)"
        case .unknown(let detail):
            return "Unknown AURA error: \(detail)"
        }
    }
}
