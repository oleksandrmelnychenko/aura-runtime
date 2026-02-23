import Foundation

public struct ActionRecommendation: Codable, Sendable {
    public let parentAlert: AlertPriority
    public let followUps: [FollowUpAction]
    public let crisisResources: Bool

    enum CodingKeys: String, CodingKey {
        case parentAlert = "parent_alert"
        case followUps = "follow_ups"
        case crisisResources = "crisis_resources"
    }
}
