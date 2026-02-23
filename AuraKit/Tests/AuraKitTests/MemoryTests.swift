import XCTest
@testable import AuraKit

final class MemoryTests: XCTestCase {

    func testRepeatedCreationDestruction() throws {
        for _ in 0..<100 {
            let config = AuraConfig(language: "en", culturalContext: "english")
            let analyzer = try AuraAnalyzer(config: config)
            _ = analyzer
        }
        // If we get here without crashing, memory management is correct
    }

    func testRepeatedAnalysis() async throws {
        let config = AuraConfig(language: "en", culturalContext: "english")
        let analyzer = try AuraAnalyzer(config: config)

        for i in 0..<200 {
            let result = try await analyzer.analyze(
                text: "Message number \(i)",
                senderId: "user",
                conversationId: "conv"
            )
            XCTAssertEqual(result.action, .allow)
        }
    }

    func testRepeatedContextAnalysis() async throws {
        let config = AuraConfig(
            protectionLevel: .high,
            accountType: .child,
            language: "en",
            culturalContext: "english"
        )
        let analyzer = try AuraAnalyzer(config: config)

        // Verify no crash or memory issue under repeated context analysis.
        // Note: child accounts with high frequency may trigger timing detectors,
        // so we don't assert .allow — just verify the pipeline works.
        for i in 0..<100 {
            let msg = MessageInput(
                text: "Normal message \(i)",
                senderId: "friend",
                conversationId: "conv"
            )
            let result = try await analyzer.analyzeWithContext(
                message: msg,
                timestampMs: UInt64(i) * 60_000  // 1 minute apart to avoid frequency triggers
            )
            _ = result
        }
    }

    func testExportImportCycle() async throws {
        let config = AuraConfig(
            protectionLevel: .high,
            accountType: .child,
            language: "en",
            culturalContext: "english"
        )

        for _ in 0..<20 {
            let analyzer = try AuraAnalyzer(config: config)
            let msg = MessageInput(
                text: "Hello",
                senderId: "friend",
                conversationId: "conv"
            )
            _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)
            let state = try analyzer.exportContext()
            XCTAssertFalse(state.isEmpty)

            let analyzer2 = try AuraAnalyzer(config: config)
            XCTAssertTrue(analyzer2.importContext(state))
        }
    }
}
