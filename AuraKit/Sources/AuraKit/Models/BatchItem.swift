import Foundation

public struct BatchItem: Encodable, Sendable {
    public let text: String?
    public let senderId: String?
    public let conversationId: String?
    public let language: String?
    public let timestampMs: UInt64?
    public let conversationType: ConversationType?
    public let memberCount: UInt32?

    enum CodingKeys: String, CodingKey {
        case text
        case senderId = "sender_id"
        case conversationId = "conversation_id"
        case language
        case timestampMs = "timestamp_ms"
        case conversationType = "conversation_type"
        case memberCount = "member_count"
    }

    public init(
        text: String?,
        senderId: String? = nil,
        conversationId: String? = nil,
        language: String? = nil,
        timestampMs: UInt64? = nil,
        conversationType: ConversationType? = nil,
        memberCount: UInt32? = nil
    ) {
        self.text = text
        self.senderId = senderId
        self.conversationId = conversationId
        self.language = language
        self.timestampMs = timestampMs
        self.conversationType = conversationType
        self.memberCount = memberCount
    }
}
