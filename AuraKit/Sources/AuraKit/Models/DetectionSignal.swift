import Foundation

public struct DetectionSignal: Codable, Sendable {
    public let threatType: ThreatType
    public let score: Float
    public let confidence: Confidence
    public let layer: DetectionLayer
    public let explanation: String

    enum CodingKeys: String, CodingKey {
        case threatType = "threat_type"
        case score, confidence, layer, explanation
    }
}
