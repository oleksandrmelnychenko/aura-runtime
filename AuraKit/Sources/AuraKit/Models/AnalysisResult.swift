import Foundation

public struct AnalysisResult: Sendable {
    public let threatType: ThreatType
    public let confidence: Confidence
    public let action: Action
    public let score: Float
    public let explanation: String
    public let detectedThreats: [(ThreatType, Float)]
    public let signals: [DetectionSignal]
    public let recommendedAction: ActionRecommendation?
    public let analysisTimeUs: UInt64

    public var isThreat: Bool { threatType != .none }
    public var needsCrisisResources: Bool { threatType == .selfHarm }
}

extension AnalysisResult: Decodable {
    enum CodingKeys: String, CodingKey {
        case threatType = "threat_type"
        case confidence, action, score, explanation
        case detectedThreats = "detected_threats"
        case signals
        case recommendedAction = "recommended_action"
        case analysisTimeUs = "analysis_time_us"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        threatType = try container.decode(ThreatType.self, forKey: .threatType)
        confidence = try container.decode(Confidence.self, forKey: .confidence)
        action = try container.decode(Action.self, forKey: .action)
        score = try container.decode(Float.self, forKey: .score)
        explanation = try container.decode(String.self, forKey: .explanation)
        signals = try container.decode([DetectionSignal].self, forKey: .signals)
        recommendedAction = try container.decodeIfPresent(ActionRecommendation.self, forKey: .recommendedAction)
        analysisTimeUs = try container.decode(UInt64.self, forKey: .analysisTimeUs)

        // detected_threats comes as [[string, number]] from Rust
        var threatsContainer = try container.nestedUnkeyedContainer(forKey: .detectedThreats)
        var threats: [(ThreatType, Float)] = []
        while !threatsContainer.isAtEnd {
            var pair = try threatsContainer.nestedUnkeyedContainer()
            let type = try pair.decode(ThreatType.self)
            let pairScore = try pair.decode(Float.self)
            threats.append((type, pairScore))
        }
        detectedThreats = threats
    }
}
