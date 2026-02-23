import Foundation

public enum ConversationType: String, Codable, Sendable {
    case direct
    case groupChat = "group_chat"
    case group
}
