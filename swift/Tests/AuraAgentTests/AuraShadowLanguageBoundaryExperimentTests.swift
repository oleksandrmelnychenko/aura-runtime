import CoreML
import Foundation
import NaturalLanguage
import XCTest
@testable import AuraAgent

/// Developer-only experiment. None of these labels are connected to runtime
/// language evidence or production span emission.
@available(iOS 18.0, macOS 12.0, *)
final class AuraShadowLanguageBoundaryExperimentTests: XCTestCase {
    private let governedLanguages: Set<String> = ["en", "ru", "uk"]

    func testExpandedOpenSetBoundaryExperiment() async throws {
        let originalCorpus = try loadCorpus(named: "language_span_experiment_v1")
        let additiveCorpus = try loadCorpus(named: "language_boundary_experiment_v2")
        XCTAssertEqual(originalCorpus.schemaVersion, 1)
        XCTAssertEqual(originalCorpus.samples.count, 24)
        XCTAssertEqual(additiveCorpus.schemaVersion, 2)
        XCTAssertEqual(additiveCorpus.samples.count, 27)

        let samples = (originalCorpus.samples + additiveCorpus.samples).map(prepare)
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )
        var predictions: [String: [(BoundaryPreparedSample, [String?])]] = [:]

        for sample in samples {
            let width5 = await observations(
                for: sample,
                windowWidth: 5,
                identifier: identifier
            )
            let width7 = await observations(
                for: sample,
                windowWidth: 7,
                identifier: identifier
            )
            append(sample, width5.centered, to: "centered_5", in: &predictions)
            append(sample, width7.centered, to: "centered_7", in: &predictions)

            let strict5 = strictConsensus(width5)
            let strict7 = strictConsensus(width7)
            let centerAnchored5 = centerAnchoredConsensus(width5)
            let centerAnchored7 = centerAnchoredConsensus(width7)
            append(sample, strict5, to: "strict_consensus_5", in: &predictions)
            append(sample, strict7, to: "strict_consensus_7", in: &predictions)
            append(
                sample,
                centerAnchored5,
                to: "center_anchored_consensus_5",
                in: &predictions
            )
            append(
                sample,
                centerAnchored7,
                to: "center_anchored_consensus_7",
                in: &predictions
            )

            let pair5Confirm1 = directionalBoundaryPairs(
                width5,
                confirmationDepth: 1,
                clusterSelection: .last
            )
            let pair5First = directionalBoundaryPairs(
                width5,
                confirmationDepth: 2,
                clusterSelection: .first
            )
            let pair5Middle = directionalBoundaryPairs(
                width5,
                confirmationDepth: 2,
                clusterSelection: .middle
            )
            let pair5Last = directionalBoundaryPairs(
                width5,
                confirmationDepth: 2,
                clusterSelection: .last
            )
            let pair5ScriptAligned = directionalBoundaryPairs(
                width5,
                confirmationDepth: 2,
                clusterSelection: .scriptAlignedThenFirst,
                tokenScripts: tokenScripts(sample)
            )
            let pair7Confirm2 = directionalBoundaryPairs(
                width7,
                confirmationDepth: 2,
                clusterSelection: .last
            )
            append(
                sample,
                pair5Confirm1,
                to: "directional_pairs_5_confirm_1",
                in: &predictions
            )
            append(
                sample,
                pair5First,
                to: "directional_pairs_5_confirm_2_first",
                in: &predictions
            )
            append(
                sample,
                pair5Middle,
                to: "directional_pairs_5_confirm_2_middle",
                in: &predictions
            )
            append(
                sample,
                pair5Last,
                to: "directional_pairs_5_confirm_2_last",
                in: &predictions
            )
            append(
                sample,
                pair5ScriptAligned,
                to: "directional_pairs_5_confirm_2_script_first",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5First, on: strict5),
                to: "strict_5_plus_pairs_confirm_2_first",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5Middle, on: strict5),
                to: "strict_5_plus_pairs_confirm_2_middle",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5Last, on: strict5),
                to: "strict_5_plus_pairs_confirm_2_last",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5ScriptAligned, on: strict5),
                to: "strict_5_plus_pairs_confirm_2_script_first",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5ScriptAligned, on: centerAnchored5),
                to: "center_anchored_5_plus_pairs_confirm_2_script_first",
                in: &predictions
            )
            append(
                sample,
                overlay(pair5ScriptAligned, on: centerAnchored7),
                to: "center_anchored_7_plus_pairs_confirm_2_script_first",
                in: &predictions
            )
            append(
                sample,
                overlay(pair7Confirm2, on: strict7),
                to: "strict_7_plus_pairs_confirm_2",
                in: &predictions
            )
        }

        var results: [String: BoundaryExperimentMetrics] = [:]
        for name in predictions.keys.sorted() {
            let metrics = evaluate(try XCTUnwrap(predictions[name]))
            assertBounded(metrics)
            results[name] = metrics
        }

        let selected = try XCTUnwrap(
            results["strict_5_plus_pairs_confirm_2_script_first"]
        )
        XCTAssertEqual(selected.emittedLabels, 72)
        XCTAssertEqual(selected.precisionWhenEmitted, 1, accuracy: 1e-12)
        XCTAssertEqual(selected.governedBoundaryCount, 24)
        XCTAssertEqual(selected.exactGovernedBoundaryCount, 11)
        XCTAssertEqual(selected.unsupportedTokens, 289)
        XCTAssertEqual(selected.unsupportedEmittedLabels, 0)
        XCTAssertEqual(selected.mixedUnsupportedTokenEmissionRate, 0)
        XCTAssertEqual(selected.unsupportedBoundarySideEmissionRate, 0)
        XCTAssertEqual(selected.unsupportedMonolingualSampleActivationRate, 0)

        let encoded = try JSONEncoder.boundarySorted.encode(results)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        print("SHADOW_LANGUAGE_BOUNDARY_EXPERIMENT_V2 \(json)")
    }

    private func observations(
        for sample: BoundaryPreparedSample,
        windowWidth: Int,
        identifier: AuraShadowLanguageIdentifier
    ) async -> BoundaryWindowObservations {
        precondition(windowWidth > 0 && windowWidth % 2 == 1)
        var centered = Array<String?>(repeating: nil, count: sample.wordRanges.count)
        var leading = centered
        var trailing = centered

        for group in sentenceGroups(sample) where !group.isEmpty {
            for offset in group.indices {
                let centeredOffsets = centeredWindow(
                    center: offset,
                    count: group.count,
                    width: windowWidth
                )
                centered[group[offset]] = await label(
                    for: groupWindow(group, offsets: centeredOffsets, sample: sample),
                    identifier: identifier
                )

                let leadingOffsets = offset ... min(group.count - 1, offset + windowWidth - 1)
                leading[group[offset]] = await label(
                    for: groupWindow(group, offsets: leadingOffsets, sample: sample),
                    identifier: identifier
                )

                let trailingOffsets = max(0, offset - windowWidth + 1) ... offset
                trailing[group[offset]] = await label(
                    for: groupWindow(group, offsets: trailingOffsets, sample: sample),
                    identifier: identifier
                )
            }
        }

        return BoundaryWindowObservations(
            centered: centered,
            leading: leading,
            trailing: trailing
        )
    }

    private func centeredWindow(
        center: Int,
        count: Int,
        width: Int
    ) -> ClosedRange<Int> {
        let actualWidth = min(count, width)
        let maximumStart = count - actualWidth
        let start = min(maximumStart, max(0, center - actualWidth / 2))
        return start ... (start + actualWidth - 1)
    }

    private func groupWindow(
        _ group: [Int],
        offsets: ClosedRange<Int>,
        sample: BoundaryPreparedSample
    ) -> String {
        let lowerWord = group[offsets.lowerBound]
        let upperWord = group[offsets.upperBound]
        return String(
            sample.text[
                sample.wordRanges[lowerWord].lowerBound
                    ..< sample.wordRanges[upperWord].upperBound
            ]
        )
    }

    private func label(
        for text: String,
        identifier: AuraShadowLanguageIdentifier
    ) async -> String? {
        guard case let .language(match) = await identifier.classify(text) else {
            return nil
        }
        return match.languageTag
    }

    private func strictConsensus(
        _ observations: BoundaryWindowObservations
    ) -> [String?] {
        observations.centered.indices.map { index in
            let centered = observations.centered[index]
            guard centered != nil,
                  centered == observations.leading[index],
                  centered == observations.trailing[index]
            else {
                return nil
            }
            return centered
        }
    }

    private func centerAnchoredConsensus(
        _ observations: BoundaryWindowObservations
    ) -> [String?] {
        observations.centered.indices.map { index in
            guard let centered = observations.centered[index],
                  centered == observations.leading[index]
                    || centered == observations.trailing[index]
            else {
                return nil
            }
            return centered
        }
    }

    private func directionalBoundaryPairs(
        _ observations: BoundaryWindowObservations,
        confirmationDepth: Int,
        clusterSelection: BoundaryClusterSelection,
        tokenScripts: [BoundaryTokenScript]? = nil
    ) -> [String?] {
        precondition(confirmationDepth > 0)
        let count = observations.centered.count
        var result = Array<String?>(repeating: nil, count: count)
        var candidates: [DirectionalBoundaryCandidate] = []
        guard count > 1 else {
            return result
        }

        for split in 1 ..< count {
            guard let left = observations.trailing[split - 1],
                  let right = observations.leading[split],
                  left != right,
                  split >= confirmationDepth,
                  split + confirmationDepth - 1 < count
            else {
                continue
            }
            let leftConfirmed = (0 ..< confirmationDepth).allSatisfy { distance in
                observations.trailing[split - 1 - distance] == left
            }
            let rightConfirmed = (0 ..< confirmationDepth).allSatisfy { distance in
                observations.leading[split + distance] == right
            }
            guard leftConfirmed, rightConfirmed else {
                continue
            }
            candidates.append(
                DirectionalBoundaryCandidate(split: split, left: left, right: right)
            )
        }

        var candidateIndex = 0
        while candidateIndex < candidates.count {
            let clusterStart = candidateIndex
            var clusterEnd = candidateIndex + 1
            while clusterEnd < candidates.count,
                  candidates[clusterEnd].split == candidates[clusterEnd - 1].split + 1,
                  candidates[clusterEnd].left == candidates[clusterStart].left,
                  candidates[clusterEnd].right == candidates[clusterStart].right
            {
                clusterEnd += 1
            }
            let selectedIndex: Int
            switch clusterSelection {
            case .first:
                selectedIndex = clusterStart
            case .middle:
                selectedIndex = clusterStart + (clusterEnd - clusterStart - 1) / 2
            case .last:
                selectedIndex = clusterEnd - 1
            case .scriptAlignedThenFirst:
                selectedIndex = (clusterStart ..< clusterEnd).first { index in
                    guard let tokenScripts else {
                        return false
                    }
                    let candidate = candidates[index]
                    return tokenScripts[candidate.split - 1]
                        == BoundaryTokenScript.expected(for: candidate.left)
                        && tokenScripts[candidate.split]
                        == BoundaryTokenScript.expected(for: candidate.right)
                        && tokenScripts[candidate.split - 1] != tokenScripts[candidate.split]
                } ?? clusterStart
            }
            let selected = candidates[selectedIndex]
            result[selected.split - 1] = selected.left
            result[selected.split] = selected.right
            candidateIndex = clusterEnd
        }
        return result
    }

    private func overlay(_ overlay: [String?], on base: [String?]) -> [String?] {
        zip(base, overlay).map { current, replacement in
            replacement ?? current
        }
    }

    private func tokenScripts(_ sample: BoundaryPreparedSample) -> [BoundaryTokenScript] {
        sample.wordRanges.map { range in
            var observed: Set<BoundaryTokenScript> = []
            for scalar in sample.text[range].unicodeScalars where scalar.properties.isAlphabetic {
                if (0x0041 ... 0x024F).contains(scalar.value)
                    || (0x1E00 ... 0x1EFF).contains(scalar.value)
                {
                    observed.insert(.latin)
                } else if (0x0400 ... 0x052F).contains(scalar.value)
                    || (0x2DE0 ... 0x2DFF).contains(scalar.value)
                    || (0xA640 ... 0xA69F).contains(scalar.value)
                {
                    observed.insert(.cyrillic)
                } else {
                    observed.insert(.other)
                }
            }
            guard observed.count == 1, let script = observed.first else {
                return observed.isEmpty ? .other : .mixed
            }
            return script
        }
    }

    private func append(
        _ sample: BoundaryPreparedSample,
        _ labels: [String?],
        to variant: String,
        in predictions: inout [String: [(BoundaryPreparedSample, [String?])]]
    ) {
        predictions[variant, default: []].append((sample, labels))
    }

    private func evaluate(
        _ predictions: [(BoundaryPreparedSample, [String?])]
    ) -> BoundaryExperimentMetrics {
        var totalTokens = 0
        var governedTokens = 0
        var governedEmitted = 0
        var emitted = 0
        var emittedCorrect = 0
        var unsupportedTokens = 0
        var unsupportedEmitted = 0
        var mixedUnsupportedTokens = 0
        var mixedUnsupportedEmitted = 0
        var supportedSwitchSamples = 0
        var recoveredSupportedSwitchSamples = 0
        var governedBoundaries = 0
        var exactGovernedBoundaries = 0
        var unsupportedBoundarySides = 0
        var emittedUnsupportedBoundarySides = 0
        var unsupportedMonolingualSamples = 0
        var activatedUnsupportedMonolingualSamples = 0

        for (sample, labels) in predictions {
            XCTAssertEqual(labels.count, sample.expectedLanguages.count, sample.identifier)
            totalTokens += labels.count
            var unsupportedMonolingualActivated = false

            for (expected, predicted) in zip(sample.expectedLanguages, labels) {
                if governedLanguages.contains(expected) {
                    governedTokens += 1
                    if predicted != nil {
                        governedEmitted += 1
                    }
                } else {
                    unsupportedTokens += 1
                    if predicted != nil {
                        unsupportedEmitted += 1
                        unsupportedMonolingualActivated = true
                    }
                    if sample.category.hasPrefix("switch_unsupported") {
                        mixedUnsupportedTokens += 1
                        if predicted != nil {
                            mixedUnsupportedEmitted += 1
                        }
                    }
                }
                if let predicted {
                    emitted += 1
                    if predicted == expected {
                        emittedCorrect += 1
                    }
                }
            }

            if sample.category.hasPrefix("monolingual_unsupported") {
                unsupportedMonolingualSamples += 1
                if unsupportedMonolingualActivated {
                    activatedUnsupportedMonolingualSamples += 1
                }
            }

            if sample.category.hasPrefix("switch_supported") {
                supportedSwitchSamples += 1
                let expectedSet = Set(
                    sample.expectedLanguages.filter(governedLanguages.contains)
                )
                let predictedSet = Set(labels.compactMap { $0 })
                if expectedSet.isSubset(of: predictedSet) {
                    recoveredSupportedSwitchSamples += 1
                }
            }

            for boundary in 1 ..< sample.expectedLanguages.count
                where sample.expectedLanguages[boundary - 1]
                    != sample.expectedLanguages[boundary]
            {
                let leftExpected = sample.expectedLanguages[boundary - 1]
                let rightExpected = sample.expectedLanguages[boundary]
                let leftGoverned = governedLanguages.contains(leftExpected)
                let rightGoverned = governedLanguages.contains(rightExpected)
                if leftGoverned, rightGoverned {
                    governedBoundaries += 1
                    if labels[boundary - 1] == leftExpected,
                       labels[boundary] == rightExpected
                    {
                        exactGovernedBoundaries += 1
                    }
                } else if leftGoverned != rightGoverned {
                    unsupportedBoundarySides += 1
                    let unsupportedIndex = leftGoverned ? boundary : boundary - 1
                    if labels[unsupportedIndex] != nil {
                        emittedUnsupportedBoundarySides += 1
                    }
                }
            }
        }

        return BoundaryExperimentMetrics(
            totalTokens: totalTokens,
            governedTokens: governedTokens,
            emittedLabels: emitted,
            governedCoverage: ratio(governedEmitted, governedTokens),
            precisionWhenEmitted: ratio(emittedCorrect, emitted),
            supportedSwitchSampleRecall: ratio(
                recoveredSupportedSwitchSamples,
                supportedSwitchSamples
            ),
            exactGovernedBoundaryRecall: ratio(
                exactGovernedBoundaries,
                governedBoundaries
            ),
            governedBoundaryCount: governedBoundaries,
            exactGovernedBoundaryCount: exactGovernedBoundaries,
            unsupportedTokens: unsupportedTokens,
            unsupportedEmittedLabels: unsupportedEmitted,
            unsupportedAsSupportedEmissionRate: ratio(
                unsupportedEmitted,
                unsupportedTokens
            ),
            mixedUnsupportedTokenEmissionRate: ratio(
                mixedUnsupportedEmitted,
                mixedUnsupportedTokens
            ),
            unsupportedBoundarySideEmissionRate: ratio(
                emittedUnsupportedBoundarySides,
                unsupportedBoundarySides
            ),
            unsupportedMonolingualSampleActivationRate: ratio(
                activatedUnsupportedMonolingualSamples,
                unsupportedMonolingualSamples
            )
        )
    }

    private func ratio(_ numerator: Int, _ denominator: Int) -> Double {
        Double(numerator) / Double(max(1, denominator))
    }

    private func assertBounded(_ metrics: BoundaryExperimentMetrics) {
        for value in [
            metrics.governedCoverage,
            metrics.precisionWhenEmitted,
            metrics.supportedSwitchSampleRecall,
            metrics.exactGovernedBoundaryRecall,
            metrics.unsupportedAsSupportedEmissionRate,
            metrics.mixedUnsupportedTokenEmissionRate,
            metrics.unsupportedBoundarySideEmissionRate,
            metrics.unsupportedMonolingualSampleActivationRate,
        ] {
            XCTAssertTrue(value.isFinite)
            XCTAssertTrue((0 ... 1).contains(value))
        }
    }

    private func loadCorpus(named name: String) throws -> BoundaryCorpus {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json")
        )
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(BoundaryCorpus.self, from: Data(contentsOf: url))
    }

    private func prepare(_ fixture: BoundarySample) -> BoundaryPreparedSample {
        let text = fixture.segments.map(\.text).joined()
        var segmentRanges: [(Range<String.Index>, String)] = []
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
        let expected = wordRanges.map { wordRange in
            segmentRanges.first(where: { $0.0.contains(wordRange.lowerBound) })?.1 ?? "und"
        }
        return BoundaryPreparedSample(
            identifier: fixture.id,
            category: fixture.category,
            text: text,
            wordRanges: wordRanges,
            expectedLanguages: expected
        )
    }

    private func sentenceGroups(_ sample: BoundaryPreparedSample) -> [[Int]] {
        let tokenizer = NLTokenizer(unit: .sentence)
        tokenizer.string = sample.text
        return tokenizer.tokens(for: sample.text.startIndex ..< sample.text.endIndex).map {
            sentenceRange in
            sample.wordRanges.indices.filter {
                sentenceRange.contains(sample.wordRanges[$0].lowerBound)
            }
        }
    }
}

private struct BoundaryCorpus: Decodable {
    let schemaVersion: Int
    let samples: [BoundarySample]
}

private struct BoundarySample: Decodable {
    let id: String
    let category: String
    let segments: [BoundarySegment]
}

private struct BoundarySegment: Decodable {
    let language: String
    let text: String
}

private struct BoundaryPreparedSample {
    let identifier: String
    let category: String
    let text: String
    let wordRanges: [Range<String.Index>]
    let expectedLanguages: [String]
}

private struct BoundaryWindowObservations {
    let centered: [String?]
    let leading: [String?]
    let trailing: [String?]
}

private struct DirectionalBoundaryCandidate {
    let split: Int
    let left: String
    let right: String
}

private enum BoundaryClusterSelection {
    case first
    case middle
    case last
    case scriptAlignedThenFirst
}

private enum BoundaryTokenScript: Hashable {
    case latin
    case cyrillic
    case mixed
    case other

    static func expected(for language: String) -> BoundaryTokenScript? {
        switch language {
        case "en":
            .latin
        case "ru", "uk":
            .cyrillic
        default:
            nil
        }
    }
}

private struct BoundaryExperimentMetrics: Codable {
    let totalTokens: Int
    let governedTokens: Int
    let emittedLabels: Int
    let governedCoverage: Double
    let precisionWhenEmitted: Double
    let supportedSwitchSampleRecall: Double
    let exactGovernedBoundaryRecall: Double
    let governedBoundaryCount: Int
    let exactGovernedBoundaryCount: Int
    let unsupportedTokens: Int
    let unsupportedEmittedLabels: Int
    let unsupportedAsSupportedEmissionRate: Double
    let mixedUnsupportedTokenEmissionRate: Double
    let unsupportedBoundarySideEmissionRate: Double
    let unsupportedMonolingualSampleActivationRate: Double
}

private extension JSONEncoder {
    static var boundarySorted: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
