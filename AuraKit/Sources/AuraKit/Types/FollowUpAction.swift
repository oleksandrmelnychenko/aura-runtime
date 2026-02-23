import Foundation

public enum FollowUpAction: String, Codable, Sendable {
    case monitorConversation = "monitor_conversation"
    case blockSuggested = "block_suggested"
    case reviewContactProfile = "review_contact_profile"
    case reportToAuthorities = "report_to_authorities"
}
