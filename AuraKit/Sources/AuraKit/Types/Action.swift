import Foundation

public enum Action: String, Codable, Sendable, Comparable {
    case allow
    case mark
    case blur
    case warn
    case block

    private var sortOrder: Int {
        switch self {
        case .allow: return 0
        case .mark: return 1
        case .blur: return 2
        case .warn: return 3
        case .block: return 4
        }
    }

    public static func < (lhs: Action, rhs: Action) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}
