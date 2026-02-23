import Foundation

public enum Confidence: String, Codable, Sendable, Comparable {
    case low
    case medium
    case high

    private var sortOrder: Int {
        switch self {
        case .low: return 0
        case .medium: return 1
        case .high: return 2
        }
    }

    public static func < (lhs: Confidence, rhs: Confidence) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}
