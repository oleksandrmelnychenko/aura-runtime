import Foundation
import NaturalLanguage
import XCTest
@testable import AuraAgent

final class AuraLanguageSpanExperimentTests: XCTestCase {
    func testFrozenLanguageSpanExperiment() throws {
        let corpus = try loadCorpus()
        XCTAssertEqual(corpus.schemaVersion, 1)
        XCTAssertEqual(corpus.samples.count, 24)

        let preparedSamples = corpus.samples.map(prepare)
        let variants: [(String, (PreparedSample) -> [String?])] = [
            ("token_tagger", tokenTaggerLabels),
            ("sentence", sentenceLabels),
            ("window_3", { self.windowLabels(for: $0, radius: 1, withinSentences: false) }),
            ("window_5", { self.windowLabels(for: $0, radius: 2, withinSentences: false) }),
            ("sentence_window_5", {
                self.windowLabels(for: $0, radius: 2, withinSentences: true)
            }),
            ("conservative_run_3", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 3,
                    requireSupportedWholeMessage: false,
                    rejectStrongUnsupportedWindow: false,
                    internalRunEdgeTrim: 0
                )
            }),
            ("conservative_run_4", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 4,
                    requireSupportedWholeMessage: false,
                    rejectStrongUnsupportedWindow: false,
                    internalRunEdgeTrim: 0
                )
            }),
            ("whole_gated_conservative_run_3", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 3,
                    requireSupportedWholeMessage: true,
                    rejectStrongUnsupportedWindow: false,
                    internalRunEdgeTrim: 0
                )
            }),
            ("whole_gated_conservative_run_4", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 4,
                    requireSupportedWholeMessage: true,
                    rejectStrongUnsupportedWindow: false,
                    internalRunEdgeTrim: 0
                )
            }),
            ("strict_whole_gated_conservative_run_3", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 3,
                    requireSupportedWholeMessage: true,
                    rejectStrongUnsupportedWindow: true,
                    internalRunEdgeTrim: 0
                )
            }),
            ("strict_core_1_conservative_run_3", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 3,
                    requireSupportedWholeMessage: true,
                    rejectStrongUnsupportedWindow: true,
                    internalRunEdgeTrim: 1
                )
            }),
            ("strict_core_2_conservative_run_3", {
                self.conservativeSentenceWindowLabels(
                    for: $0,
                    minimumRunLength: 3,
                    requireSupportedWholeMessage: true,
                    rejectStrongUnsupportedWindow: true,
                    internalRunEdgeTrim: 2
                )
            }),
        ]

        var results: [String: ExperimentMetrics] = [:]
        for (name, classifier) in variants {
            let predictions = preparedSamples.map { sample in
                (sample, classifier(sample))
            }
            let metrics = evaluate(predictions)
            assertBounded(metrics)
            results[name] = metrics
        }

        let encoded = try JSONEncoder.sorted.encode(results)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        print("LANGUAGE_SPAN_EXPERIMENT_V1 \(json)")
    }

    private func loadCorpus() throws -> ExperimentCorpus {
        let url = try XCTUnwrap(
            Bundle.module.url(
                forResource: "language_span_experiment_v1",
                withExtension: "json"
            )
        )
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(ExperimentCorpus.self, from: Data(contentsOf: url))
    }

    private func prepare(_ fixture: ExperimentSample) -> PreparedSample {
        let text = fixture.segments.map(\.text).joined()
        var segmentRanges: [(range: Range<String.Index>, language: String)] = []
        var segmentStart = text.startIndex
        for segment in fixture.segments {
            let segmentEnd = text.index(segmentStart, offsetBy: segment.text.count)
            segmentRanges.append((segmentStart ..< segmentEnd, segment.language))
            segmentStart = segmentEnd
        }
        XCTAssertEqual(segmentStart, text.endIndex, fixture.id)

        let tokenizer = NLTokenizer(unit: .word)
        tokenizer.string = text
        let wordRanges = tokenizer.tokens(for: text.startIndex ..< text.endIndex)
        let expectedLanguages = wordRanges.map { wordRange in
            segmentRanges.first { segment in
                segment.range.contains(wordRange.lowerBound)
            }?.language
        }
        return PreparedSample(
            identifier: fixture.id,
            category: fixture.category,
            text: text,
            wordRanges: wordRanges,
            expectedLanguages: expectedLanguages
        )
    }

    private func tokenTaggerLabels(for sample: PreparedSample) -> [String?] {
        let tagger = NLTagger(tagSchemes: [.language])
        tagger.string = sample.text
        return sample.wordRanges.map { range in
            let (tag, _) = tagger.tag(at: range.lowerBound, unit: .word, scheme: .language)
            return tag.flatMap { primaryLanguage($0.rawValue) }
        }
    }

    private func sentenceLabels(for sample: PreparedSample) -> [String?] {
        let sentenceRanges = ranges(unit: .sentence, in: sample.text)
        return sample.wordRanges.map { wordRange in
            guard let sentenceRange = sentenceRanges.first(where: {
                $0.contains(wordRange.lowerBound)
            }) else {
                return nil
            }
            return classify(String(sample.text[sentenceRange]))?.language
        }
    }

    private func windowLabels(
        for sample: PreparedSample,
        radius: Int,
        withinSentences: Bool
    ) -> [String?] {
        let groups: [[Int]]
        if withinSentences {
            groups = ranges(unit: .sentence, in: sample.text).map { sentenceRange in
                sample.wordRanges.indices.filter {
                    sentenceRange.contains(sample.wordRanges[$0].lowerBound)
                }
            }
        } else {
            groups = [Array(sample.wordRanges.indices)]
        }

        var labels = Array<String?>(repeating: nil, count: sample.wordRanges.count)
        for group in groups where !group.isEmpty {
            for (offset, wordIndex) in group.enumerated() {
                let lowerOffset = max(group.startIndex, offset - radius)
                let upperOffset = min(group.index(before: group.endIndex), offset + radius)
                let lowerWord = group[lowerOffset]
                let upperWord = group[upperOffset]
                let range = sample.wordRanges[lowerWord].lowerBound
                    ..< sample.wordRanges[upperWord].upperBound
                labels[wordIndex] = classify(String(sample.text[range]))?.language
            }
        }
        return labels
    }

    private func conservativeSentenceWindowLabels(
        for sample: PreparedSample,
        minimumRunLength: Int,
        requireSupportedWholeMessage: Bool,
        rejectStrongUnsupportedWindow: Bool,
        internalRunEdgeTrim: Int
    ) -> [String?] {
        let supportedLanguages: Set<String> = ["en", "uk", "ru"]
        if requireSupportedWholeMessage {
            guard let wholeMessage = classify(sample.text),
                  wholeMessage.confidence >= 0.5,
                  supportedLanguages.contains(wholeMessage.language)
            else {
                return Array(repeating: nil, count: sample.wordRanges.count)
            }
        }
        let sentenceRanges = ranges(unit: .sentence, in: sample.text)
        if rejectStrongUnsupportedWindow,
           hasStrongUnsupportedWindow(
               sample: sample,
               sentenceRanges: sentenceRanges,
               supportedLanguages: supportedLanguages
           )
        {
            return Array(repeating: nil, count: sample.wordRanges.count)
        }
        var labels = Array<String?>(repeating: nil, count: sample.wordRanges.count)

        for sentenceRange in sentenceRanges {
            let group = sample.wordRanges.indices.filter {
                sentenceRange.contains(sample.wordRanges[$0].lowerBound)
            }
            guard !group.isEmpty else {
                continue
            }

            var rawLabels = Array<String?>(repeating: nil, count: group.count)
            for offset in group.indices {
                let lowerOffset = max(group.startIndex, offset - 2)
                let upperOffset = min(group.index(before: group.endIndex), offset + 2)
                let lowerWord = group[lowerOffset]
                let upperWord = group[upperOffset]
                let range = sample.wordRanges[lowerWord].lowerBound
                    ..< sample.wordRanges[upperWord].upperBound
                guard let result = classify(String(sample.text[range])),
                      result.confidence >= 0.5,
                      supportedLanguages.contains(result.language)
                else {
                    continue
                }
                rawLabels[offset] = result.language
            }

            var runStart = rawLabels.startIndex
            while runStart < rawLabels.endIndex {
                let language = rawLabels[runStart]
                var runEnd = rawLabels.index(after: runStart)
                while runEnd < rawLabels.endIndex, rawLabels[runEnd] == language {
                    runEnd = rawLabels.index(after: runEnd)
                }
                if language != nil,
                   rawLabels.distance(from: runStart, to: runEnd) >= minimumRunLength
                {
                    var emittedStart = runStart
                    var emittedEnd = runEnd
                    for _ in 0 ..< internalRunEdgeTrim {
                        if emittedStart > rawLabels.startIndex, emittedStart < emittedEnd {
                            emittedStart = rawLabels.index(after: emittedStart)
                        }
                        if emittedEnd < rawLabels.endIndex, emittedStart < emittedEnd {
                            emittedEnd = rawLabels.index(before: emittedEnd)
                        }
                    }
                    for offset in emittedStart ..< emittedEnd {
                        labels[group[offset]] = language
                    }
                }
                runStart = runEnd
            }
        }
        return labels
    }

    private func hasStrongUnsupportedWindow(
        sample: PreparedSample,
        sentenceRanges: [Range<String.Index>],
        supportedLanguages: Set<String>
    ) -> Bool {
        for sentenceRange in sentenceRanges {
            let group = sample.wordRanges.indices.filter {
                sentenceRange.contains(sample.wordRanges[$0].lowerBound)
            }
            for offset in group.indices {
                let lowerOffset = max(group.startIndex, offset - 2)
                let upperOffset = min(group.index(before: group.endIndex), offset + 2)
                let lowerWord = group[lowerOffset]
                let upperWord = group[upperOffset]
                let range = sample.wordRanges[lowerWord].lowerBound
                    ..< sample.wordRanges[upperWord].upperBound
                if let result = classify(String(sample.text[range])),
                   result.confidence >= 0.5,
                   !supportedLanguages.contains(result.language)
                {
                    return true
                }
            }
        }
        return false
    }

    private func classify(_ text: String) -> Classification? {
        let recognizer = NLLanguageRecognizer()
        recognizer.processString(text)
        guard let hypothesis = recognizer.languageHypotheses(withMaximum: 1).first,
              let language = primaryLanguage(hypothesis.key.rawValue),
              hypothesis.value.isFinite,
              (0 ... 1).contains(hypothesis.value)
        else {
            return nil
        }
        return Classification(language: language, confidence: hypothesis.value)
    }

    private func ranges(unit: NLTokenUnit, in text: String) -> [Range<String.Index>] {
        let tokenizer = NLTokenizer(unit: unit)
        tokenizer.string = text
        return tokenizer.tokens(for: text.startIndex ..< text.endIndex)
    }

    private func primaryLanguage(_ rawValue: String) -> String? {
        AuraLanguageEvidenceProducer.canonicalLanguageTag(rawValue)?
            .split(separator: "-")
            .first
            .map(String.init)
    }

    private func evaluate(
        _ predictions: [(sample: PreparedSample, labels: [String?])]
    ) -> ExperimentMetrics {
        let supportedLanguages: Set<String> = ["en", "uk", "ru"]
        var totalTokens = 0
        var predictedTokens = 0
        var correctTokens = 0
        var supportedMonolingualTokens = 0
        var supportedMonolingualErrors = 0
        var supportedMonolingualWrongEmissions = 0
        var supportedMonolingualAbstentions = 0
        var expectedSwitchBoundaries = 0
        var exactSwitchBoundaries = 0
        var supportedSwitchSamples = 0
        var detectedSupportedSwitchSamples = 0
        var unsupportedTokens = 0
        var unsupportedAsSupportedTokens = 0

        for (sample, labels) in predictions {
            XCTAssertEqual(labels.count, sample.expectedLanguages.count, sample.identifier)
            totalTokens += labels.count
            for (expected, predicted) in zip(sample.expectedLanguages, labels) {
                guard let expected else {
                    continue
                }
                if let predicted {
                    predictedTokens += 1
                    if predicted == expected {
                        correctTokens += 1
                    }
                }
                if sample.category == "monolingual_supported" {
                    supportedMonolingualTokens += 1
                    if predicted != expected {
                        supportedMonolingualErrors += 1
                        if predicted == nil {
                            supportedMonolingualAbstentions += 1
                        } else {
                            supportedMonolingualWrongEmissions += 1
                        }
                    }
                }
                if !supportedLanguages.contains(expected) {
                    unsupportedTokens += 1
                    if let predicted, supportedLanguages.contains(predicted) {
                        unsupportedAsSupportedTokens += 1
                    }
                }
            }

            if sample.category.hasPrefix("switch_supported") {
                supportedSwitchSamples += 1
                let expectedSet = Set(sample.expectedLanguages.compactMap { $0 })
                let predictedSet = Set(labels.compactMap { $0 })
                if expectedSet.isSubset(of: predictedSet) {
                    detectedSupportedSwitchSamples += 1
                }
                for index in 1 ..< sample.expectedLanguages.count {
                    let expectedLeft = sample.expectedLanguages[index - 1]
                    let expectedRight = sample.expectedLanguages[index]
                    guard expectedLeft != nil, expectedRight != nil, expectedLeft != expectedRight else {
                        continue
                    }
                    expectedSwitchBoundaries += 1
                    if labels[index - 1] == expectedLeft, labels[index] == expectedRight {
                        exactSwitchBoundaries += 1
                    }
                }
            }
        }

        return ExperimentMetrics(
            totalTokens: totalTokens,
            coverage: ratio(predictedTokens, totalTokens),
            tokenAccuracy: ratio(correctTokens, totalTokens),
            precisionWhenEmitted: ratio(correctTokens, predictedTokens),
            supportedMonolingualErrorRate: ratio(
                supportedMonolingualErrors,
                supportedMonolingualTokens
            ),
            supportedMonolingualWrongEmissionRate: ratio(
                supportedMonolingualWrongEmissions,
                supportedMonolingualTokens
            ),
            supportedMonolingualAbstentionRate: ratio(
                supportedMonolingualAbstentions,
                supportedMonolingualTokens
            ),
            supportedSwitchSampleRecall: ratio(
                detectedSupportedSwitchSamples,
                supportedSwitchSamples
            ),
            exactSwitchBoundaryRecall: ratio(
                exactSwitchBoundaries,
                expectedSwitchBoundaries
            ),
            unsupportedAsSupportedEmissionRate: ratio(
                unsupportedAsSupportedTokens,
                unsupportedTokens
            )
        )
    }

    private func ratio(_ numerator: Int, _ denominator: Int) -> Double {
        guard denominator > 0 else {
            return 0
        }
        return Double(numerator) / Double(denominator)
    }

    private func assertBounded(_ metrics: ExperimentMetrics) {
        XCTAssertGreaterThan(metrics.totalTokens, 0)
        for value in [
            metrics.coverage,
            metrics.tokenAccuracy,
            metrics.precisionWhenEmitted,
            metrics.supportedMonolingualErrorRate,
            metrics.supportedMonolingualWrongEmissionRate,
            metrics.supportedMonolingualAbstentionRate,
            metrics.supportedSwitchSampleRecall,
            metrics.exactSwitchBoundaryRecall,
            metrics.unsupportedAsSupportedEmissionRate,
        ] {
            XCTAssertTrue(value.isFinite)
            XCTAssertTrue((0 ... 1).contains(value))
        }
    }
}

private struct ExperimentCorpus: Decodable {
    let schemaVersion: Int
    let samples: [ExperimentSample]
}

private struct ExperimentSample: Decodable {
    let id: String
    let category: String
    let segments: [ExperimentSegment]
}

private struct ExperimentSegment: Decodable {
    let language: String
    let text: String
}

private struct PreparedSample {
    let identifier: String
    let category: String
    let text: String
    let wordRanges: [Range<String.Index>]
    let expectedLanguages: [String?]
}

private struct Classification {
    let language: String
    let confidence: Double
}

private struct ExperimentMetrics: Encodable {
    let totalTokens: Int
    let coverage: Double
    let tokenAccuracy: Double
    let precisionWhenEmitted: Double
    let supportedMonolingualErrorRate: Double
    let supportedMonolingualWrongEmissionRate: Double
    let supportedMonolingualAbstentionRate: Double
    let supportedSwitchSampleRecall: Double
    let exactSwitchBoundaryRecall: Double
    let unsupportedAsSupportedEmissionRate: Double
}

private extension JSONEncoder {
    static var sorted: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
