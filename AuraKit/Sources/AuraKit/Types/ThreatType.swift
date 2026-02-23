import Foundation

public enum ThreatType: String, Codable, Sendable, CaseIterable {
    case none
    case bullying
    case grooming
    case explicit
    case threat
    case selfHarm = "self_harm"
    case spam
    case scam
    case phishing
    case manipulation
    case nsfw
    case hateSpeech = "hate_speech"
    case doxxing
}
