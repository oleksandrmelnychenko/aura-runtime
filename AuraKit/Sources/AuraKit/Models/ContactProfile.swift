import Foundation

public struct ContactProfile: Codable, Sendable, Identifiable {
    public var id: String { senderId }

    public let senderId: String
    public let riskScore: Float
    public let firstSeenMs: UInt64
    public let lastSeenMs: UInt64
    public let totalMessages: UInt64
    public let groomingEvents: UInt64
    public let bullyingEvents: UInt64
    public let manipulationEvents: UInt64
    public let isTrusted: Bool
    public let isNewContact: Bool
    public let conversationCount: Int
    public let averageSeverity: Float

    enum CodingKeys: String, CodingKey {
        case senderId = "sender_id"
        case riskScore = "risk_score"
        case firstSeenMs = "first_seen_ms"
        case lastSeenMs = "last_seen_ms"
        case totalMessages = "total_messages"
        case groomingEvents = "grooming_events"
        case bullyingEvents = "bullying_events"
        case manipulationEvents = "manipulation_events"
        case isTrusted = "is_trusted"
        case isNewContact = "is_new_contact"
        case conversationCount = "conversation_count"
        case averageSeverity = "average_severity"
    }
}
