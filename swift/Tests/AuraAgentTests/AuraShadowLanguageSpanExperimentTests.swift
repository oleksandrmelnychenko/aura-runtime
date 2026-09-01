import CoreML
import Foundation
import NaturalLanguage
import XCTest
@testable import AuraAgent

@available(iOS 18.0, macOS 12.0, *)
final class AuraShadowLanguageSpanExperimentTests: XCTestCase {
    func testFrozenShadowLanguageSpanExperiment() async throws {
        let corpus = try loadCorpus()
        let samples = corpus.samples.map(prepare)
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )

        var rawPredictions: [(PreparedSample, [String?])] = []
        for sample in samples {
            rawPredictions.append(
                (sample, await windowLabels(for: sample, identifier: identifier))
            )
        }
        let variants = [
            "shadow_window_5": rawPredictions,
            "shadow_conservative_run_3": rawPredictions.map { sample, labels in
                (sample, retainingRuns(labels, minimumLength: 3))
            },
        ]

        var results: [String: ShadowExperimentMetrics] = [:]
        for (name, predictions) in variants {
            let metrics = evaluate(predictions)
            XCTAssertEqual(
                metrics.unsupportedAsSupportedEmissionRate,
                0,
                "unsupported Cyrillic controls must never activate governed labels"
            )
            results[name] = metrics
        }

        let encoded = try JSONEncoder.sorted.encode(results)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        print("SHADOW_LANGUAGE_SPAN_EXPERIMENT_V1 \(json)")
    }

    private func windowLabels(
        for sample: PreparedSample,
        identifier: AuraShadowLanguageIdentifier
    ) async -> [String?] {
        let sentenceRanges = ranges(unit: .sentence, in: sample.text)
        var result = Array<String?>(repeating: nil, count: sample.wordRanges.count)
        for sentenceRange in sentenceRanges {
            let group = sample.wordRanges.indices.filter {
                sentenceRange.contains(sample.wordRanges[$0].lowerBound)
            }
            for (offset, wordIndex) in group.enumerated() {
                let lowerOffset = max(0, offset - 2)
                let upperOffset = min(group.count - 1, offset + 2)
                let windowRange = sample.wordRanges[group[lowerOffset]].lowerBound
                    ..< sample.wordRanges[group[upperOffset]].upperBound
                let window = String(sample.text[windowRange])
                if case let .language(match) = await identifier.classify(window) {
                    result[wordIndex] = match.languageTag
                }
            }
        }
        return result
    }

    private func retainingRuns(
        _ labels: [String?],
        minimumLength: Int
    ) -> [String?] {
        var result = Array<String?>(repeating: nil, count: labels.count)
        var index = 0
        while index < labels.count {
            guard let label = labels[index] else {
                index += 1
                continue
            }
            var end = index + 1
            while end < labels.count, labels[end] == label {
                end += 1
            }
            if end - index >= minimumLength {
                for retainedIndex in index ..< end {
                    result[retainedIndex] = label
                }
            }
            index = end
        }
        return result
    }

    private func evaluate(
        _ predictions: [(PreparedSample, [String?])]
    ) -> ShadowExperimentMetrics {
        let supported = Set(["en", "ru", "uk"])
        var totalTokens = 0
        var emitted = 0
        var emittedCorrect = 0
        var unsupportedTokens = 0
        var unsupportedAsSupported = 0
        var switchSamples = 0
        var recoveredSwitchSamples = 0
        var switchBoundaries = 0
        var exactSwitchBoundaries = 0

        for (sample, labels) in predictions {
            XCTAssertEqual(labels.count, sample.expectedLanguages.count, sample.identifier)
            totalTokens += labels.count
            for (expected, predicted) in zip(sample.expectedLanguages, labels) {
                if !supported.contains(expected) {
                    unsupportedTokens += 1
                    if let predicted, supported.contains(predicted) {
                        unsupportedAsSupported += 1
                    }
                }
                if let predicted {
                    emitted += 1
                    if predicted == expected {
                        emittedCorrect += 1
                    }
                }
            }

            if sample.category.hasPrefix("switch_supported") {
                switchSamples += 1
                let expectedSet = Set(sample.expectedLanguages.filter(supported.contains))
                let predictedSet = Set(labels.compactMap { $0 }.filter(supported.contains))
                if expectedSet.isSubset(of: predictedSet) {
                    recoveredSwitchSamples += 1
                }
            }

            for boundary in 1 ..< sample.expectedLanguages.count
                where sample.expectedLanguages[boundary - 1] != sample.expectedLanguages[boundary]
            {
                switchBoundaries += 1
                if labels[boundary - 1] == sample.expectedLanguages[boundary - 1],
                   labels[boundary] == sample.expectedLanguages[boundary]
                {
                    exactSwitchBoundaries += 1
                }
            }
        }

        return ShadowExperimentMetrics(
            totalTokens: totalTokens,
            coverage: Double(emitted) / Double(max(1, totalTokens)),
            precisionWhenEmitted: Double(emittedCorrect) / Double(max(1, emitted)),
            supportedSwitchSampleRecall: Double(recoveredSwitchSamples)
                / Double(max(1, switchSamples)),
            exactSwitchBoundaryRecall: Double(exactSwitchBoundaries)
                / Double(max(1, switchBoundaries)),
            unsupportedAsSupportedEmissionRate: Double(unsupportedAsSupported)
                / Double(max(1, unsupportedTokens))
        )
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
        var segmentRanges: [(Range<String.Index>, String)] = []
        var segmentStart = text.startIndex
        for segment in fixture.segments {
            let segmentEnd = text.index(segmentStart, offsetBy: segment.text.count)
            segmentRanges.append((segmentStart ..< segmentEnd, segment.language))
            segmentStart = segmentEnd
        }

        let tokenizer = NLTokenizer(unit: .word)
        tokenizer.string = text
        let wordRanges = tokenizer.tokens(for: text.startIndex ..< text.endIndex)
        let expected = wordRanges.map { wordRange in
            segmentRanges.first(where: { $0.0.contains(wordRange.lowerBound) })?.1 ?? "und"
        }
        return PreparedSample(
            identifier: fixture.id,
            category: fixture.category,
            text: text,
            wordRanges: wordRanges,
            expectedLanguages: expected
        )
    }

    private func ranges(unit: NLTokenUnit, in text: String) -> [Range<String.Index>] {
        let tokenizer = NLTokenizer(unit: unit)
        tokenizer.string = text
        return tokenizer.tokens(for: text.startIndex ..< text.endIndex)
    }
}

private struct ExperimentCorpus: Decodable {
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
    let expectedLanguages: [String]
}

private struct ShadowExperimentMetrics: Codable {
    let totalTokens: Int
    let coverage: Double
    let precisionWhenEmitted: Double
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
