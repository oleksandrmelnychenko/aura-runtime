import XCTest
@testable import AuraAgent

final class AuraLanguageEvidenceProducerTests: XCTestCase {
    func testDeclaredLanguageProducesCanonicalContentFreeEvidence() throws {
        let producer = AuraLanguageEvidenceProducer()

        let evidence = try XCTUnwrap(
            producer.makeEvidence(
                text: "Цей текст не повинен запускати класифікатор у release path.",
                declaredLanguage: "UK"
            )
        )

        XCTAssertEqual(evidence.schemaVersion, 1)
        XCTAssertEqual(evidence.candidates.map(\.languageTag), ["uk"])
        XCTAssertEqual(evidence.candidates.map(\.source), [.clientDeclared])
        XCTAssertEqual(evidence.candidates.map(\.confidence), [1])
        XCTAssertTrue(evidence.spans.isEmpty)
    }

    func testTextAloneNeverCreatesProductionRoutingEvidence() {
        let producer = AuraLanguageEvidenceProducer()

        XCTAssertNil(
            producer.makeEvidence(
                text: "This sentence is deliberately long enough for language classification.",
                declaredLanguage: nil
            )
        )
    }

    func testMalformedDeclarationFailsClosedWithoutTextInference() {
        let producer = AuraLanguageEvidenceProducer()

        XCTAssertNil(
            producer.makeEvidence(
                text: "Це довге повідомлення не має виправляти некоректну декларацію.",
                declaredLanguage: "bad_tag"
            )
        )
    }

    func testDeclaredOnlyEvidenceIsAvailableForShortText() throws {
        let producer = AuraLanguageEvidenceProducer()

        let evidence = try XCTUnwrap(
            producer.makeEvidence(text: "ok", declaredLanguage: "EN-us")
        )

        XCTAssertEqual(evidence.candidates.map(\.languageTag), ["en-us"])
        XCTAssertEqual(evidence.candidates.map(\.source), [.clientDeclared])
        XCTAssertEqual(evidence.candidates.map(\.confidence), [1])
    }

    func testEnrichmentPreservesCallerSuppliedEvidenceExactly() {
        let producer = AuraLanguageEvidenceProducer()
        var supplied = AuraAgentNativeLanguageEvidenceV1()
        supplied.schemaVersion = 91
        var message = AuraAgentNativeMessageInput()
        message.text = "Caller supplied typed evidence must remain authoritative."
        message.languageEvidence = supplied
        var request = AuraAgentNativeLocalDecisionAnalyzeRequest()
        request.message = message

        let enriched = producer.enriching(request)

        XCTAssertEqual(enriched.message.languageEvidence, supplied)
    }

    func testEnrichmentAddsOnlyDeclaredEvidenceWithoutMutatingOriginal() {
        let producer = AuraLanguageEvidenceProducer()
        var message = AuraAgentNativeMessageInput()
        message.text = "Це повідомлення не повинно створити classifier candidate."
        message.language = "uk"
        var request = AuraAgentNativeLocalDecisionAnalyzeRequest()
        request.message = message

        let enriched = producer.enriching(request)

        XCTAssertFalse(request.message.hasLanguageEvidence)
        XCTAssertTrue(enriched.message.hasLanguageEvidence)
        XCTAssertEqual(enriched.message.languageEvidence.candidates.map(\.languageTag), ["uk"])
        XCTAssertEqual(enriched.message.languageEvidence.candidates.map(\.source), [.clientDeclared])
    }

    func testRequestWithoutDeclarationRemainsByteEquivalent() throws {
        let producer = AuraLanguageEvidenceProducer()
        var message = AuraAgentNativeMessageInput()
        message.text = "No language declaration is present in this message."
        var request = AuraAgentNativeLocalDecisionAnalyzeRequest()
        request.message = message

        let originalBytes = try request.serializedData()
        let enrichedBytes = try producer.enriching(request).serializedData()

        XCTAssertEqual(enrichedBytes, originalBytes)
    }

    func testCanonicalTagGrammarMatchesNativeBoundary() {
        XCTAssertEqual(AuraLanguageEvidenceProducer.canonicalLanguageTag("ZH-Hans"), "zh-hans")
        XCTAssertEqual(AuraLanguageEvidenceProducer.canonicalLanguageTag("sr-Latn-RS"), "sr-latn-rs")
        XCTAssertNil(AuraLanguageEvidenceProducer.canonicalLanguageTag("e"))
        XCTAssertNil(AuraLanguageEvidenceProducer.canonicalLanguageTag("en_US"))
        XCTAssertNil(AuraLanguageEvidenceProducer.canonicalLanguageTag("en-"))
        XCTAssertNil(AuraLanguageEvidenceProducer.canonicalLanguageTag("українська"))
    }
}
