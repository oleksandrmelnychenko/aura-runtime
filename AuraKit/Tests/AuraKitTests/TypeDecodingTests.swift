import XCTest
@testable import AuraKit

final class TypeDecodingTests: XCTestCase {

    func testAnalysisResultDecoding() throws {
        let json = """
        {
            "threat_type": "grooming",
            "confidence": "high",
            "action": "warn",
            "score": 0.85,
            "explanation": "Grooming detected",
            "detected_threats": [["grooming", 0.85]],
            "signals": [],
            "recommended_action": {
                "parent_alert": "high",
                "follow_ups": ["review_contact_profile", "block_suggested"],
                "crisis_resources": false
            },
            "analysis_time_us": 42
        }
        """
        let data = Data(json.utf8)
        let result = try JSONDecoder().decode(AnalysisResult.self, from: data)
        XCTAssertEqual(result.threatType, .grooming)
        XCTAssertEqual(result.confidence, .high)
        XCTAssertEqual(result.action, .warn)
        XCTAssertEqual(result.score, 0.85, accuracy: 0.01)
        XCTAssertTrue(result.isThreat)
        XCTAssertFalse(result.needsCrisisResources)
        XCTAssertEqual(result.detectedThreats.count, 1)
        XCTAssertEqual(result.detectedThreats[0].0, .grooming)

        let rec = result.recommendedAction!
        XCTAssertEqual(rec.parentAlert, .high)
        XCTAssertEqual(rec.followUps.count, 2)
        XCTAssertTrue(rec.followUps.contains(.reviewContactProfile))
        XCTAssertTrue(rec.followUps.contains(.blockSuggested))
        XCTAssertFalse(rec.crisisResources)
    }

    func testContactProfileDecoding() throws {
        let json = """
        {
            "sender_id": "stranger_1",
            "risk_score": 0.45,
            "first_seen_ms": 1000,
            "last_seen_ms": 5000,
            "total_messages": 3,
            "grooming_events": 2,
            "bullying_events": 0,
            "manipulation_events": 0,
            "is_trusted": false,
            "is_new_contact": true,
            "conversation_count": 1,
            "average_severity": 0.6
        }
        """
        let data = Data(json.utf8)
        let profile = try JSONDecoder().decode(ContactProfile.self, from: data)
        XCTAssertEqual(profile.senderId, "stranger_1")
        XCTAssertEqual(profile.id, "stranger_1")
        XCTAssertEqual(profile.riskScore, 0.45, accuracy: 0.01)
        XCTAssertTrue(profile.isNewContact)
        XCTAssertFalse(profile.isTrusted)
        XCTAssertEqual(profile.groomingEvents, 2)
    }

    func testConversationOverviewDecoding() throws {
        let json = """
        {
            "total_conversations": 2,
            "conversations": [
                {
                    "conversation_id": "conv_A",
                    "total_events": 5,
                    "unique_senders": ["alice", "bob"],
                    "threat_event_count": 1,
                    "latest_event_ms": 5000
                },
                {
                    "conversation_id": "conv_B",
                    "total_events": 3,
                    "unique_senders": ["charlie"],
                    "threat_event_count": 0,
                    "latest_event_ms": 3000
                }
            ]
        }
        """
        let data = Data(json.utf8)
        let overview = try JSONDecoder().decode(ConversationOverview.self, from: data)
        XCTAssertEqual(overview.totalConversations, 2)
        XCTAssertEqual(overview.conversations.count, 2)
        XCTAssertEqual(overview.conversations[0].conversationId, "conv_A")
        XCTAssertEqual(overview.conversations[0].uniqueSenders.count, 2)
        XCTAssertEqual(overview.conversations[1].threatEventCount, 0)
    }

    func testDetectionSignalDecoding() throws {
        let json = """
        {
            "threat_type": "bullying",
            "score": 0.75,
            "confidence": "medium",
            "layer": "pattern_matching",
            "explanation": "Insult detected"
        }
        """
        let data = Data(json.utf8)
        let signal = try JSONDecoder().decode(DetectionSignal.self, from: data)
        XCTAssertEqual(signal.threatType, .bullying)
        XCTAssertEqual(signal.score, 0.75, accuracy: 0.01)
        XCTAssertEqual(signal.layer, .patternMatching)
    }

    func testMultipleDetectedThreats() throws {
        let json = """
        {
            "threat_type": "grooming",
            "confidence": "high",
            "action": "warn",
            "score": 0.85,
            "explanation": "test",
            "detected_threats": [["grooming", 0.85], ["manipulation", 0.6], ["threat", 0.3]],
            "signals": [],
            "recommended_action": null,
            "analysis_time_us": 10
        }
        """
        let data = Data(json.utf8)
        let result = try JSONDecoder().decode(AnalysisResult.self, from: data)
        XCTAssertEqual(result.detectedThreats.count, 3)
        XCTAssertEqual(result.detectedThreats[0].0, .grooming)
        XCTAssertEqual(result.detectedThreats[1].0, .manipulation)
        XCTAssertEqual(result.detectedThreats[2].0, .threat)
    }

    func testSelfHarmResult() throws {
        let json = """
        {
            "threat_type": "self_harm",
            "confidence": "high",
            "action": "warn",
            "score": 0.8,
            "explanation": "Self-harm detected",
            "detected_threats": [["self_harm", 0.8]],
            "signals": [],
            "recommended_action": {
                "parent_alert": "urgent",
                "follow_ups": ["monitor_conversation"],
                "crisis_resources": true
            },
            "analysis_time_us": 5
        }
        """
        let data = Data(json.utf8)
        let result = try JSONDecoder().decode(AnalysisResult.self, from: data)
        XCTAssertEqual(result.threatType, .selfHarm)
        XCTAssertTrue(result.needsCrisisResources)
        XCTAssertNotEqual(result.action, .block)
        XCTAssertTrue(result.recommendedAction!.crisisResources)
        XCTAssertEqual(result.recommendedAction!.parentAlert, .urgent)
    }

    // MARK: - Enum Comparable

    func testConfidenceComparable() {
        XCTAssertTrue(Confidence.low < Confidence.medium)
        XCTAssertTrue(Confidence.medium < Confidence.high)
        XCTAssertFalse(Confidence.high < Confidence.low)
    }

    func testActionComparable() {
        XCTAssertTrue(Action.allow < Action.mark)
        XCTAssertTrue(Action.mark < Action.blur)
        XCTAssertTrue(Action.blur < Action.warn)
        XCTAssertTrue(Action.warn < Action.block)
    }

    func testAlertPriorityComparable() {
        XCTAssertTrue(AlertPriority.none < AlertPriority.low)
        XCTAssertTrue(AlertPriority.high < AlertPriority.urgent)
    }
}
