import Foundation

public enum AuraAgentError: Error, LocalizedError, Sendable {
    case invalidInput(String)
    case invalidResponse(String)
    case initializationFailed(String)
    case callFailed(String)
    case missingHandle

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let message):
            return "Invalid Aura Agent input: \(message)"
        case .invalidResponse(let message):
            return "Invalid Aura Agent response: \(message)"
        case .initializationFailed(let message):
            return "Aura Agent initialization failed: \(message)"
        case .callFailed(let message):
            return "Aura Agent call failed: \(message)"
        case .missingHandle:
            return "Aura Agent runtime handle is unavailable"
        }
    }
}
