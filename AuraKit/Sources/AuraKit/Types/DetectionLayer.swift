import Foundation

public enum DetectionLayer: String, Codable, Sendable {
    case patternMatching = "pattern_matching"
    case mlClassification = "ml_classification"
    case contextAnalysis = "context_analysis"
}
