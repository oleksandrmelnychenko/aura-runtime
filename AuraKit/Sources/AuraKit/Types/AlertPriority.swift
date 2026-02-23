import Foundation

public enum AlertPriority: String, Codable, Sendable, Comparable {
    case none
    case low
    case medium
    case high
    case urgent

    private var sortOrder: Int {
        switch self {
        case .none: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .urgent: return 4
        }
    }

    public static func < (lhs: AlertPriority, rhs: AlertPriority) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}
