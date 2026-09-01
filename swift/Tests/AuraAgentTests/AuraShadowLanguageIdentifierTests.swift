import CoreML
import XCTest
@testable import AuraAgent

@available(iOS 18.0, macOS 12.0, *)
final class AuraShadowLanguageIdentifierTests: XCTestCase {
    func testBundledArtifactIdentityIsPinnedAndValidated() async throws {
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )

        XCTAssertEqual(
            identifier.artifactIdentity.identifier,
            "aura-language-id-shadow-maxent-ngram-v1"
        )
        XCTAssertEqual(
            identifier.artifactIdentity.manifestSHA256Hex,
            "7bfb27d993fda7591a2414722cefcc8d3c5372638164122bede0bb5450236d5f"
        )
        XCTAssertEqual(identifier.artifactIdentity.artifactSHA256ByPath.count, 4)
    }

    func testWrongManifestPinFailsClosed() throws {
        XCTAssertThrowsError(
            try AuraShadowLanguageIdentifier.validateBundledArtifactsForTesting(
                expectedManifestSHA256Hex: String(repeating: "0", count: 64)
            )
        ) { error in
            XCTAssertEqual(
                error as? AuraShadowLanguageIdentifierError,
                .manifestDigestMismatch
            )
        }
    }

    func testClearGovernedLanguagesRequireThreeWayAgreement() async throws {
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )
        let samples = [
            (
                "en",
                "The weather is calm today, and our family plans to walk through the park after dinner."
            ),
            (
                "uk",
                "Сьогодні надворі спокійна погода, і наша родина планує прогулятися парком після вечері."
            ),
            (
                "ru",
                "Сегодня на улице спокойная погода, и наша семья планирует прогуляться по парку после ужина."
            ),
        ]

        for (expected, text) in samples {
            guard case let .language(match) = await identifier.classify(text) else {
                return XCTFail("expected governed language \(expected)")
            }
            XCTAssertEqual(match.languageTag, expected)
            XCTAssertGreaterThanOrEqual(match.coreMLProbability, 0.50)
            XCTAssertGreaterThanOrEqual(match.coreMLMargin, 0.20)
            XCTAssertGreaterThanOrEqual(match.ngramMargin, 0.20)
        }
    }

    func testUnsupportedCyrillicControlsAbstain() async throws {
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )
        let samples = [
            "Заўтра мы разам паедзем у горад, спакойна сустрэнемся з сябрамі і абмяркуем планы.",
            "Сутра ћемо заједно отићи у град, мирно се срести са пријатељима и разговарати о плановима.",
            "Утре ще отидем заедно в града, спокойно ще се срещнем с приятели и ще обсъдим плановете.",
            "Ертең біз бірге қалаға барып, достарымызбен тыныш кездесіп, жоспарларды талқылаймыз.",
        ]

        for text in samples {
            guard case .abstain = await identifier.classify(text) else {
                return XCTFail("unsupported Cyrillic control must abstain")
            }
        }
    }

    func testSupportedInlineWindowsCanEmitWithoutEnablingSpans() async throws {
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )
        let samples = [
            ("uk", "Я сказала, що повернуся завтра і ми спокійно завершимо розмову."),
            ("ru", "Он ответил, что будет ждать завтра и спокойно закончит разговор."),
        ]

        for (expected, text) in samples {
            guard case let .language(match) = await identifier.classify(text) else {
                return XCTFail("expected conservative window match for \(expected)")
            }
            XCTAssertEqual(match.languageTag, expected)
        }

        let producer = AuraLanguageEvidenceProducer()
        let evidence = try XCTUnwrap(
            producer.makeEvidence(
                text: samples.map(\.1).joined(separator: " "),
                declaredLanguage: "uk"
            )
        )
        XCTAssertTrue(evidence.spans.isEmpty)
    }

    func testShortTextAbstainsDeterministically() async throws {
        let identifier = try await AuraShadowLanguageIdentifier.loadBundled(
            computeUnits: .cpuOnly
        )
        let first = await identifier.classify("все добре")
        let second = await identifier.classify("все добре")
        XCTAssertEqual(first, .abstain(.insufficientText))
        XCTAssertEqual(second, first)
    }
}
