import Foundation

/// Builds bounded, content-free language evidence for native detector routing.
///
/// The release producer accepts only a caller-declared language. Uncalibrated
/// language classifiers and span inference remain test-only until independent
/// open-set evaluation approves them for production routing.
public struct AuraLanguageEvidenceProducer: Sendable {
    public static let schemaVersion: UInt32 = 1

    public init() {}

    /// Creates wire evidence from a legacy caller declaration.
    ///
    /// Message text is deliberately ignored in the release path. This prevents
    /// an unevaluated local classifier from activating language-scoped detector
    /// packs. Callers that already supply typed evidence retain ownership of it.
    public func makeEvidence(
        text _: String?,
        declaredLanguage: String?
    ) -> AuraAgentNativeLanguageEvidenceV1? {
        guard let declaredLanguage,
              let canonicalTag = Self.canonicalLanguageTag(declaredLanguage)
        else {
            return nil
        }

        var candidate = AuraAgentNativeLanguageCandidateV1()
        candidate.languageTag = canonicalTag
        candidate.confidence = 1
        candidate.source = .clientDeclared

        var evidence = AuraAgentNativeLanguageEvidenceV1()
        evidence.schemaVersion = Self.schemaVersion
        evidence.candidates = [candidate]
        // Span inference remains disabled until same-script segmentation has
        // independent evidence. Empty spans are valid in schema v1.
        evidence.spans = []
        return evidence
    }

    internal func enriching(
        _ request: AuraAgentNativeLocalDecisionAnalyzeRequest
    ) -> AuraAgentNativeLocalDecisionAnalyzeRequest {
        guard request.hasMessage, !request.message.hasLanguageEvidence else {
            return request
        }

        let originalMessage = request.message
        guard let evidence = makeEvidence(
            text: originalMessage.hasText ? originalMessage.text : nil,
            declaredLanguage: originalMessage.hasLanguage ? originalMessage.language : nil
        ) else {
            return request
        }

        var enrichedMessage = originalMessage
        enrichedMessage.languageEvidence = evidence
        var enrichedRequest = request
        enrichedRequest.message = enrichedMessage
        return enrichedRequest
    }

    /// Mirrors the native boundary's bounded lowercase BCP-47-style grammar.
    internal static func canonicalLanguageTag(_ rawValue: String) -> String? {
        guard !rawValue.isEmpty,
              rawValue.utf8.count <= 35,
              !rawValue.contains("_"),
              rawValue.unicodeScalars.allSatisfy(\.isASCII)
        else {
            return nil
        }

        let normalized = rawValue.lowercased()
        let components = normalized.split(separator: "-", omittingEmptySubsequences: false)
        guard let language = components.first,
              (2 ... 8).contains(language.utf8.count),
              language.unicodeScalars.allSatisfy(Self.isASCIILowercaseLetter)
        else {
            return nil
        }

        for component in components.dropFirst() {
            guard (1 ... 8).contains(component.utf8.count),
                  component.unicodeScalars.allSatisfy({
                      Self.isASCIILowercaseLetter($0) || Self.isASCIIDigit($0)
                  })
            else {
                return nil
            }
        }
        return normalized
    }

    private static func isASCIILowercaseLetter(_ scalar: Unicode.Scalar) -> Bool {
        (0x61 ... 0x7A).contains(scalar.value)
    }

    private static func isASCIIDigit(_ scalar: Unicode.Scalar) -> Bool {
        (0x30 ... 0x39).contains(scalar.value)
    }
}
