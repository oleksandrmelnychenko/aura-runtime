import XCTest
@testable import AuraKit

final class AuraAnalyzerTests: XCTestCase {

    private func makeAnalyzer(
        protectionLevel: ProtectionLevel = .medium,
        accountType: AccountType = .adult,
        language: String = "en",
        culturalContext: String = "english",
        enabled: Bool = true
    ) throws -> AuraAnalyzer {
        let config = AuraConfig(
            protectionLevel: protectionLevel,
            accountType: accountType,
            language: language,
            culturalContext: culturalContext,
            enabled: enabled
        )
        return try AuraAnalyzer(config: config)
    }

    // MARK: - Initialization

    func testInitAndVersion() throws {
        let analyzer = try makeAnalyzer()
        XCTAssertFalse(AuraAnalyzer.version.isEmpty)
        XCTAssertEqual(AuraAnalyzer.version, "0.3.0")
        _ = analyzer
    }

    // MARK: - Basic Analysis

    func testCleanMessageAllowed() async throws {
        let analyzer = try makeAnalyzer()
        let result = try await analyzer.analyze(
            text: "Hey, how are you doing today?",
            senderId: "user_1",
            conversationId: "conv_1"
        )
        XCTAssertEqual(result.action, .allow)
        XCTAssertFalse(result.isThreat)
        XCTAssertEqual(result.threatType, .none)
    }

    func testThreatDetected() async throws {
        let analyzer = try makeAnalyzer()
        let result = try await analyzer.analyze(
            text: "I will kill you",
            senderId: "user_1",
            conversationId: "conv_1"
        )
        XCTAssertTrue(result.isThreat)
        XCTAssertEqual(result.threatType, .threat)
        XCTAssertTrue(result.action >= .warn)
    }

    // MARK: - Structured Input

    func testAnalyzeWithMessageInput() async throws {
        let analyzer = try makeAnalyzer()
        let msg = MessageInput(
            text: "Hey, how are you?",
            senderId: "user_1",
            conversationId: "conv_1",
            language: "en"
        )
        let result = try await analyzer.analyze(message: msg)
        XCTAssertEqual(result.action, .allow)
    }

    // MARK: - Context Analysis

    func testGroomingDetectedWithContext() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg1 = MessageInput(
            text: "You're so beautiful and amazing and perfect!",
            senderId: "stranger",
            conversationId: "conv_1"
        )
        _ = try await analyzer.analyzeWithContext(message: msg1, timestampMs: 1000)

        let msg2 = MessageInput(
            text: "Don't tell your parents about us, ok?",
            senderId: "stranger",
            conversationId: "conv_1"
        )
        let result = try await analyzer.analyzeWithContext(message: msg2, timestampMs: 2000)

        XCTAssertTrue(result.isThreat)
        XCTAssertEqual(result.threatType, .grooming)
    }

    // MARK: - Context Export/Import

    func testContextExportImport() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Don't tell your parents",
            senderId: "stranger",
            conversationId: "conv_1"
        )
        _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)

        let state = try analyzer.exportContext()
        XCTAssertTrue(state.contains("conv_1"))

        let analyzer2 = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )
        XCTAssertTrue(analyzer2.importContext(state))
    }

    // MARK: - Contacts

    func testContactsByRisk() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Don't tell your parents about me",
            senderId: "stranger",
            conversationId: "conv_1"
        )
        _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)

        let contacts = try analyzer.contactsByRisk()
        XCTAssertFalse(contacts.isEmpty)
        XCTAssertTrue(contacts.contains(where: { $0.senderId == "stranger" }))
    }

    func testContactProfileNotFound() throws {
        let analyzer = try makeAnalyzer()
        let profile = try analyzer.contactProfile(senderId: "nonexistent")
        XCTAssertNil(profile)
    }

    func testMarkContactTrusted() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Hello there",
            senderId: "friend",
            conversationId: "conv_1"
        )
        _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)

        XCTAssertTrue(analyzer.markContactTrusted(senderId: "friend"))
    }

    // MARK: - Conversations

    func testConversationSummary() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Hello",
            senderId: "friend",
            conversationId: "conv_A"
        )
        _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)

        let overview = try analyzer.conversationSummary()
        XCTAssertEqual(overview.totalConversations, 1)
        XCTAssertTrue(overview.conversations.contains(where: { $0.conversationId == "conv_A" }))
    }

    // MARK: - Conversation Type

    func testGroupChatConversationType() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Hello everyone!",
            senderId: "friend",
            conversationId: "group_1",
            conversationType: .groupChat,
            memberCount: 25
        )
        let result = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)
        XCTAssertEqual(result.action, .allow)
    }

    // MARK: - Config

    func testDisabledAuraAllowsEverything() async throws {
        let analyzer = try makeAnalyzer(enabled: false)
        let result = try await analyzer.analyze(
            text: "I will kill you",
            senderId: "u",
            conversationId: "c"
        )
        XCTAssertEqual(result.action, .allow)
    }

    func testUpdateConfig() async throws {
        let analyzer = try makeAnalyzer()

        let disabledConfig = AuraConfig(
            protectionLevel: .medium,
            accountType: .adult,
            language: "en",
            culturalContext: "english",
            enabled: false
        )
        XCTAssertTrue(try analyzer.updateConfig(disabledConfig))

        let result = try await analyzer.analyze(
            text: "I will kill you",
            senderId: "u",
            conversationId: "c"
        )
        XCTAssertEqual(result.action, .allow)
    }

    // MARK: - Batch Analysis

    func testBatchAnalysis() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let items = [
            BatchItem(text: "Hello friend!", senderId: "u1", conversationId: "c1", timestampMs: 1000),
            BatchItem(text: "I will kill you", senderId: "u2", conversationId: "c1", timestampMs: 2000),
            BatchItem(text: "Nice weather today", senderId: "u3", conversationId: "c2", timestampMs: 3000),
        ]
        let results = try await analyzer.analyzeBatch(messages: items)
        XCTAssertEqual(results.count, 3)
        XCTAssertEqual(results[0].action, .allow)
        XCTAssertTrue(results[1].action > .allow)
        XCTAssertEqual(results[2].action, .allow)
    }

    // MARK: - Self-Harm

    func testSelfHarmNeverBlocked() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )
        let result = try await analyzer.analyze(
            text: "I feel like there's no reason to live anymore",
            senderId: "child",
            conversationId: "conv"
        )
        if result.threatType == .selfHarm {
            XCTAssertNotEqual(result.action, .block, "Self-harm must never be blocked")
            XCTAssertTrue(result.needsCrisisResources)
        }
    }

    // MARK: - Cleanup

    func testCleanupContext() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Hello",
            senderId: "friend",
            conversationId: "conv_1"
        )
        _ = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)
        XCTAssertTrue(analyzer.cleanupContext(nowMs: UInt64.max))
    }

    // MARK: - Recommended Action

    func testRecommendedActionPresent() async throws {
        let analyzer = try makeAnalyzer(
            protectionLevel: .high,
            accountType: .child
        )

        let msg = MessageInput(
            text: "Don't tell your parents about me ok?",
            senderId: "stranger",
            conversationId: "conv_1"
        )
        let result = try await analyzer.analyzeWithContext(message: msg, timestampMs: 1000)

        if result.isThreat {
            XCTAssertNotNil(result.recommendedAction)
        }
    }
}
