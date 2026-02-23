import Foundation

public struct MessageInput: Encodable, Sendable {
    public let text: String?
    public let senderId: String
    public let conversationId: String
    public let language: String?
    public let conversationType: ConversationType?
    public let memberCount: UInt32?

    enum CodingKeys: String, CodingKey {
        case text
        case senderId = "sender_id"
        case conversationId = "conversation_id"
        case language
        case conversationType = "conversation_type"
        case memberCount = "member_count"
    }

    public init(
        text: String?,
        senderId: String,
        conversationId: String,
        language: String? = nil,
        conversationType: ConversationType = .direct,
        memberCount: UInt32? = nil
    ) {
        self.text = text
        self.senderId = senderId
        self.conversationId = conversationId
        self.language = language
        self.conversationType = conversationType
        self.memberCount = memberCount
    }
}
