import Foundation

public struct ConversationOverview: Codable, Sendable {
    public let totalConversations: Int
    public let conversations: [ConversationSummary]

    enum CodingKeys: String, CodingKey {
        case totalConversations = "total_conversations"
        case conversations
    }
}

public struct ConversationSummary: Codable, Sendable, Identifiable {
    public var id: String { conversationId }

    public let conversationId: String
    public let totalEvents: Int
    public let uniqueSenders: [String]
    public let threatEventCount: Int
    public let latestEventMs: UInt64

    enum CodingKeys: String, CodingKey {
        case conversationId = "conversation_id"
        case totalEvents = "total_events"
        case uniqueSenders = "unique_senders"
        case threatEventCount = "threat_event_count"
        case latestEventMs = "latest_event_ms"
    }
}
