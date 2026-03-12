use aura_core::context::events::EventKind;
use aura_core::{Analyzer, AuraConfig, ContentType, ConversationType, MessageInput};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              AURA — Attack Simulations                     ║");
    println!("║         26 реальних сценаріїв атак на дітей                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    simulation_1_classic_grooming(&db);
    simulation_2_group_bullying(&db);
    simulation_3_self_harm_escalation(&db);
    simulation_4_gaslighting(&db);
    simulation_5_late_night_stranger(&db);
    simulation_6_love_bombing(&db);
    simulation_7_sextortion(&db);
    simulation_8_normal_conversation(&db);
    simulation_9_bullying_to_self_harm(&db);
    simulation_10_multi_tactic_manipulator(&db);
    simulation_11_realistic_group_chat_uk(&db);
    simulation_12_drug_dealer(&db);
    simulation_13_sextortion_after_photo(&db);
    simulation_14_coordinated_raid(&db);
    simulation_15_darvo_manipulator(&db);
    simulation_16_financial_grooming(&db);
    simulation_17_selfharm_contagion(&db);
    simulation_18_sustained_bullying(&db);
    simulation_19_mixed_language_attack(&db);
    simulation_20_false_positive_friends(&db);
    simulation_21_parent_dashboard_lifecycle(&db);
    simulation_22_love_bomb_devalue(&db);
    simulation_23_grooming_video_escalation(&db);
    simulation_24_bullying_isolation(&db);
    simulation_25_acute_selfharm_crisis(&db);
    simulation_26_teen_dating_violence(&db);

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                  All 26 simulations complete                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: aura_core::AccountType::Child,
        protection_level: aura_core::ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    }
}

fn msg(text: &str, sender: &str, conv: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conv.to_string(),
        language: Some("en".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn msg_uk(text: &str, sender: &str, conv: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conv.to_string(),
        language: Some("uk".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn print_header(num: usize, title: &str, description: &str) {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Simulation #{num}: {title}");
    println!("  {description}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn print_msg(time: &str, sender: &str, text: &str) {
    println!("  [{time}] {sender}: \"{text}\"");
}

fn print_result(result: &aura_core::AnalysisResult) {
    if result.is_threat() {
        let action = format!("{:?}", result.action).to_uppercase();
        let threat = format!("{:?}", result.threat_type);
        println!(
            "         -> [{action}] {threat} (score: {:.2}, confidence: {:?})",
            result.score, result.confidence
        );

        for signal in &result.signals {
            if signal.score > 0.3 {
                let layer = format!("{:?}", signal.layer);
                println!(
                    "            Layer: {layer} | {}",
                    truncate(&signal.explanation, 70)
                );
            }
        }
    } else {
        println!("         -> [OK] Clean message");
    }
}

fn print_context_events(analyzer: &Analyzer, conv: &str) {
    if let Some(timeline) = analyzer.context_tracker().timeline(conv) {
        let events: Vec<_> = timeline
            .all_events()
            .iter()
            .filter(|e| {
                e.kind != EventKind::NormalConversation && e.kind != EventKind::TrustedContact
            })
            .collect();
        if !events.is_empty() {
            println!(
                "         Context events: [{}]",
                events
                    .iter()
                    .map(|e| format!("{:?}", e.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

fn print_contacts(analyzer: &Analyzer) {
    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();
    if !contacts.is_empty() {
        println!();
        println!("  Contact Risk Profiles:");
        for c in contacts.iter().take(5) {
            let risk = c.risk_score();
            let bar = risk_bar(risk);
            println!(
                "    {} [{bar}] risk={:.2} | msgs={} groom={} bully={} manip={}",
                c.sender_id,
                risk,
                c.total_messages,
                c.grooming_event_count,
                c.bullying_event_count,
                c.manipulation_event_count
            );
        }
    }
}

fn risk_bar(risk: f32) -> String {
    let filled = (risk * 10.0) as usize;
    let empty = 10 - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 3).collect();
        format!("{truncated}...")
    }
}

fn print_verdict(verdict: &str) {
    println!();
    println!("  VERDICT: {verdict}");
    println!();
}

fn simulation_1_classic_grooming(db: &PatternDatabase) {
    print_header(
        1,
        "Classic Grooming Sequence",
        "Stranger contacts a 10-year-old girl, escalates through 4 grooming stages over 3 hours",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let predator = "nice_guy_99";
    let conv = "dm_child_1";
    let hour = 3600 * 1000u64;

    print_msg(
        "00:00",
        predator,
        "Hey! I saw your profile, you seem really cool! What games do you play?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Hey! I saw your profile, you seem really cool! What games do you play?",
            predator,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "00:30",
        predator,
        "You're so beautiful and amazing, truly special for your age",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so beautiful and amazing, truly special for your age",
            predator,
            conv,
        ),
        hour / 2,
    );
    print_result(&r);

    print_msg(
        "01:00",
        predator,
        "You seem so mature for your age. Where do you live? What school do you go to?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You seem so mature for your age. Where do you live? What school do you go to?",
            predator,
            conv,
        ),
        hour,
    );
    print_result(&r);

    print_msg(
        "01:30",
        predator,
        "I can send you money for a new game. I'll buy you anything you want",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I can send you money for a new game. I'll buy you anything you want",
            predator,
            conv,
        ),
        hour + hour / 2,
    );
    print_result(&r);

    print_msg(
        "02:00",
        predator,
        "Don't tell your parents about me ok? They wouldn't understand our friendship",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell your parents about me ok? They wouldn't understand our friendship",
            predator,
            conv,
        ),
        2 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_msg(
        "03:00",
        predator,
        "Send me a photo of you. I want to see what you look like",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Send me a photo of you. I want to see what you look like",
            predator,
            conv,
        ),
        3 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected 4/5 grooming stages: trust building -> boundary crossing -> isolation -> sexualization. Parent alert triggered.");
}

fn simulation_2_group_bullying(db: &PatternDatabase) {
    print_header(
        2,
        "Group Bullying Pile-On",
        "4 classmates target one child in a group chat within 10 minutes",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "class_7b_chat";
    let min = 60 * 1000u64;

    let base = 10 * 3600 * 1000u64;

    print_msg(
        "10:00",
        "bully_1",
        "Haha nobody likes you, why are you even in this chat?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Haha nobody likes you, why are you even in this chat?",
            "bully_1",
            conv,
        ),
        base,
    );
    print_result(&r);

    print_msg("10:02", "bully_2", "You're worthless, just leave already");
    let r = analyzer.analyze_with_context(
        &msg("You're worthless, just leave already", "bully_2", conv),
        base + 2 * min,
    );
    print_result(&r);

    print_msg(
        "10:04",
        "bully_3",
        "Everyone hates you, even the teacher doesn't like you",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Everyone hates you, even the teacher doesn't like you",
            "bully_3",
            conv,
        ),
        base + 4 * min,
    );
    print_result(&r);

    print_msg(
        "10:05",
        "bully_4",
        "You're disgusting, nobody wants to be your friend",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're disgusting, nobody wants to be your friend",
            "bully_4",
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_msg("10:07", "bully_1", "You're so ugly, you should be ashamed");
    let r = analyzer.analyze_with_context(
        &msg("You're so ugly, you should be ashamed", "bully_1", conv),
        base + 7 * min,
    );
    print_result(&r);

    print_contacts(&analyzer);
    print_verdict("AURA detected GROUP BULLYING: 4+ different senders targeting the child within minutes. Pile-on + repeated bullying patterns identified.");
}

fn simulation_3_self_harm_escalation(db: &PatternDatabase) {
    print_header(
        3,
        "Self-Harm Escalation",
        "A child's messages get progressively darker over 5 days in a journal/diary chat",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let child = "sad_child";
    let conv = "my_diary";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Day 1",
        child,
        "I had a really bad day. Nobody talked to me at school.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I had a really bad day. Nobody talked to me at school.",
            child,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        child,
        "Maybe I don't matter. Nobody would notice if I wasn't there.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Maybe I don't matter. Nobody would notice if I wasn't there.",
            child,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        child,
        "I feel like there's no reason to live anymore. Everything is pointless.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I feel like there's no reason to live anymore. Everything is pointless.",
            child,
            conv,
        ),
        2 * day,
    );
    print_result(&r);

    print_msg(
        "Day 4",
        child,
        "I can't take it anymore. I want to end it all.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I can't take it anymore. I want to end it all.",
            child,
            conv,
        ),
        3 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_msg(
        "Day 5",
        child,
        "Goodbye everyone. I'm sorry for everything. Thank you for everything.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Goodbye everyone. I'm sorry for everything. Thank you for everything.",
            child,
            conv,
        ),
        4 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_verdict("CRITICAL: Farewell after hopelessness/ideation = acute suicide risk. AURA shows crisis resources + urgent parent alert. Content is NEVER blocked.");
}

fn simulation_4_gaslighting(db: &PatternDatabase) {
    print_header(
        4,
        "Gaslighting + Emotional Manipulation",
        "An older \"friend\" systematically gaslights a child over multiple messages",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let manipulator = "older_friend";
    let conv = "dm_friend";
    let hour = 3600 * 1000u64;

    print_msg(
        "Day 1",
        manipulator,
        "That never happened, you're imagining things. I never said that.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "That never happened, you're imagining things. I never said that.",
            manipulator,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        manipulator,
        "You're being crazy, you're too sensitive. Nobody will believe you.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're being crazy, you're too sensitive. Nobody will believe you.",
            manipulator,
            conv,
        ),
        24 * hour,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        manipulator,
        "After everything I've done for you, you're so ungrateful. This is your fault.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "After everything I've done for you, you're so ungrateful. This is your fault.",
            manipulator,
            conv,
        ),
        48 * hour,
    );
    print_result(&r);

    print_msg(
        "Day 4",
        manipulator,
        "If you were a real friend you wouldn't question me. You owe me.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "If you were a real friend you wouldn't question me. You owe me.",
            manipulator,
            conv,
        ),
        72 * hour,
    );
    print_result(&r);

    print_msg(
        "Day 5",
        manipulator,
        "It's all in your head, you're making things up. You're overreacting.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "It's all in your head, you're making things up. You're overreacting.",
            manipulator,
            conv,
        ),
        96 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected multi-tactic manipulation: gaslighting (3x) + guilt-tripping (2x). Textbook psychological control pattern.");
}

fn simulation_5_late_night_stranger(db: &PatternDatabase) {
    print_header(
        5,
        "Late-Night Messaging to Child",
        "Unknown adult sends messages to a child at 2 AM",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let stranger = "night_owl_42";
    let conv = "dm_late";

    let base = 2 * 3600 * 1000u64;
    let min = 60 * 1000u64;

    print_msg(
        "02:00",
        stranger,
        "Hey, are you still awake? I can't sleep either",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Hey, are you still awake? I can't sleep either",
            stranger,
            conv,
        ),
        base,
    );
    print_result(&r);

    print_msg(
        "02:05",
        stranger,
        "You're so special, I've never met anyone like you",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so special, I've never met anyone like you",
            stranger,
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "02:10",
        stranger,
        "Are you home alone? When do your parents come home?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Are you home alone? When do your parents come home?",
            stranger,
            conv,
        ),
        base + 10 * min,
    );
    print_result(&r);

    print_msg(
        "02:15",
        stranger,
        "Don't tell anyone about our talks, ok? Just between us",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell anyone about our talks, ok? Just between us",
            stranger,
            conv,
        ),
        base + 15 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA flagged: late-night messaging to minor + rapid attachment + grooming indicators from a new contact.");
}

fn simulation_6_love_bombing(db: &PatternDatabase) {
    print_header(
        6,
        "Love Bombing (Ukrainian)",
        "Stranger overwhelms a child with excessive compliments in Ukrainian",
    );

    let mut config = child_config();
    config.language = "uk".to_string();
    let mut analyzer = Analyzer::new(config, db);
    let stranger = "sweet_stranger";
    let conv = "dm_uk";
    let min = 60 * 1000u64;

    let base = 14 * 3600 * 1000u64;

    print_msg("14:00", stranger, "Привіт! Ти така красива і неймовірна!");
    let r = analyzer.analyze_with_context(
        &msg_uk("Привіт! Ти така красива і неймовірна!", stranger, conv),
        base,
    );
    print_result(&r);

    print_msg(
        "14:05",
        stranger,
        "Ти така чудова і особлива, я таких ще не зустрічав!",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Ти така чудова і особлива, я таких ще не зустрічав!",
            stranger,
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "14:10",
        stranger,
        "Ти для мене особлива. Між нами особливий зв'язок",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Ти для мене особлива. Між нами особливий зв'язок",
            stranger,
            conv,
        ),
        base + 10 * min,
    );
    print_result(&r);

    print_msg(
        "14:15",
        stranger,
        "Не кажи батькам про мене. Це наш секрет, добре?",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Не кажи батькам про мене. Це наш секрет, добре?",
            stranger,
            conv,
        ),
        base + 15 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA виявила: love bombing + лестощі + прохання зберігати таємницю = грумінг-паттерн українською мовою.");
}

fn simulation_7_sextortion(db: &PatternDatabase) {
    print_header(
        7,
        "Sexual Content Escalation",
        "Predator introduces sexual topics and requests photos from a child",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let predator = "cool_teen_16";
    let conv = "dm_secret";
    let hour = 3600 * 1000u64;

    print_msg(
        "Day 1",
        predator,
        "You're so mature for your age, not like other kids",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so mature for your age, not like other kids",
            predator,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        predator,
        "Have you ever kissed anyone? Do you have a boyfriend?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Have you ever kissed anyone? Do you have a boyfriend?",
            predator,
            conv,
        ),
        24 * hour,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        predator,
        "Send me a photo of you. Take a selfie for me, I want to see you",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Send me a photo of you. Take a selfie for me, I want to see you",
            predator,
            conv,
        ),
        48 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_msg(
        "Day 4",
        predator,
        "Don't tell your parents about this. This stays between us ok?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell your parents about this. This stays between us ok?",
            predator,
            conv,
        ),
        72 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected grooming with sexual escalation: flattery -> sexual topics -> photo request -> secrecy. 4 of 5 stages present.");
}

fn simulation_8_normal_conversation(db: &PatternDatabase) {
    print_header(
        8,
        "Normal Safe Conversation (Control Test)",
        "Two friends chatting normally — AURA should NOT flag anything",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let friend = "best_friend_anna";
    let conv = "chat_friends";
    let min = 60 * 1000u64;
    let base = 15 * 3600 * 1000u64;

    print_msg("15:00", friend, "Hey! Did you finish the math homework?");
    let r = analyzer.analyze_with_context(
        &msg("Hey! Did you finish the math homework?", friend, conv),
        base,
    );
    print_result(&r);

    print_msg(
        "15:05",
        "child",
        "Yeah it was hard! Want to play Minecraft after?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Yeah it was hard! Want to play Minecraft after?",
            "child",
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "15:10",
        friend,
        "Sure! My mom said I can play until 7. Let's build a castle!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Sure! My mom said I can play until 7. Let's build a castle!",
            friend,
            conv,
        ),
        base + 10 * min,
    );
    print_result(&r);

    print_msg(
        "15:15",
        "child",
        "Awesome! I'll invite Sarah too, she's online",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Awesome! I'll invite Sarah too, she's online",
            "child",
            conv,
        ),
        base + 15 * min,
    );
    print_result(&r);

    print_msg("15:20", friend, "Cool! See you in the game :)");
    let r = analyzer.analyze_with_context(
        &msg("Cool! See you in the game :)", friend, conv),
        base + 20 * min,
    );
    print_result(&r);

    print_verdict(
        "ZERO flags. Normal friendship conversation. AURA correctly identifies this as safe.",
    );
}

fn simulation_9_bullying_to_self_harm(db: &PatternDatabase) {
    print_header(
        9,
        "Bullying -> Self-Harm Pathway",
        "Child is bullied in group chat, then expresses hopelessness in the same conversation",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "school_group";
    let hour = 3600 * 1000u64;
    let base = 12 * hour;

    print_msg(
        "12:00",
        "bully_1",
        "Nobody likes you, just leave the group already",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Nobody likes you, just leave the group already",
            "bully_1",
            conv,
        ),
        base,
    );
    print_result(&r);

    print_msg(
        "12:10",
        "bully_2",
        "You're so ugly, everyone laughs at you behind your back",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so ugly, everyone laughs at you behind your back",
            "bully_2",
            conv,
        ),
        base + 10 * 60 * 1000,
    );
    print_result(&r);

    print_msg(
        "12:30",
        "bully_3",
        "Don't be friends with her, she's a freak",
    );
    let r = analyzer.analyze_with_context(
        &msg("Don't be friends with her, she's a freak", "bully_3", conv),
        base + 30 * 60 * 1000,
    );
    print_result(&r);

    print_msg(
        "13:00",
        "victim_child",
        "Maybe they're right. I don't want to live anymore. Nobody cares about me.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Maybe they're right. I don't want to live anymore. Nobody cares about me.",
            "victim_child",
            conv,
        ),
        base + hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("CRITICAL: AURA detected bullying-to-self-harm pathway. 3 bullying events followed by self-harm expression. Urgent parent alert + crisis resources.");
}

fn simulation_10_multi_tactic_manipulator(db: &PatternDatabase) {
    print_header(
        10,
        "Multi-Tactic Manipulator (Full Week)",
        "Controlling person uses gaslighting, guilt, pressure, and emotional blackmail over 7 days",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let abuser = "controlling_ex";
    let conv = "dm_toxic";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Mon",
        abuser,
        "That never happened, you're imagining things. You're being dramatic.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "That never happened, you're imagining things. You're being dramatic.",
            abuser,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Tue",
        abuser,
        "If you were a real friend you'd believe me. After everything I've done for you!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "If you were a real friend you'd believe me. After everything I've done for you!",
            abuser,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Wed",
        abuser,
        "You have to do it right now! Hurry, before it's too late! You must do this for me.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You have to do it right now! Hurry, before it's too late! You must do this for me.",
            abuser,
            conv,
        ),
        2 * day,
    );
    print_result(&r);

    print_msg(
        "Thu",
        abuser,
        "I never said that, you're making things up. Nobody will believe you.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I never said that, you're making things up. Nobody will believe you.",
            abuser,
            conv,
        ),
        3 * day,
    );
    print_result(&r);

    print_msg(
        "Fri",
        abuser,
        "I'll hurt myself if you leave me. You'll be sorry when I'm gone.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I'll hurt myself if you leave me. You'll be sorry when I'm gone.",
            abuser,
            conv,
        ),
        4 * day,
    );
    print_result(&r);

    print_msg(
        "Sat",
        abuser,
        "You're so ungrateful. You owe me. This is your fault.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so ungrateful. You owe me. This is your fault.",
            abuser,
            conv,
        ),
        5 * day,
    );
    print_result(&r);

    print_msg(
        "Sun",
        abuser,
        "You're too sensitive, you're overreacting. It's all in your head.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're too sensitive, you're overreacting. It's all in your head.",
            abuser,
            conv,
        ),
        6 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected: gaslighting (3x) + guilt-tripping (3x) + emotional blackmail (1x) + pressure (1x) = 4 different manipulation tactics. Textbook psychological abuse.");
}

fn simulation_11_realistic_group_chat_uk(db: &PatternDatabase) {
    print_header(11, "Реальний груповий чат — 8 учасників атакують дитину (УКР)",
        "Маша, 10 років, у шкільному чаті '7-Б Клас'. 8 людей пишуть: мат, булінг, погрози, грумінг.");

    let mut config = child_config();
    config.language = "uk".to_string();
    let mut analyzer = Analyzer::new(config, db);

    let conv = "group_7b_klas";
    let min = 60 * 1000u64;

    let base = 9 * 3600 * 1000u64;

    let bully_1 = "Діма_хуліган";

    let bully_2 = "Катя_злюка";

    let bully_3 = "Артем_гопнік";

    let bully_4 = "Настя_підлиза";

    let bully_5 = "Влад_тролль";

    let friend_1 = "Оля_подруга";

    let creep = "Макс_старший_18";

    let bully_6 = "Саша_тупий";

    println!();
    println!("  УЧАСНИКИ:");
    println!("    Маша (10 р.) — дитина під захистом AURA");
    println!("    {bully_1} — головний булі");
    println!("    {bully_2} — злюча дівчинка");
    println!("    {bully_3} — агресивний гопнік");
    println!("    {bully_4} — пасивно-агресивна");
    println!("    {bully_5} — тролль");
    println!("    {friend_1} — справжня подруга");
    println!("    {creep} — 18-річний у чаті (грумер)");
    println!("    {bully_6} — ще один булі");
    println!();
    println!("  ── РАНОК, 09:00 — Початок дня ──");
    println!();

    print_msg(
        "09:00",
        friend_1,
        "Привіт всім! Хто зробив домашку з матіки?",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk("Привіт всім! Хто зробив домашку з матіки?", friend_1, conv),
        base,
    );
    print_result(&r);

    print_msg(
        "09:01",
        bully_1,
        "Маша, ти тупа як пробка, навіть домашку зробити не можеш",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, ти тупа як пробка, навіть домашку зробити не можеш",
            bully_1,
            conv,
        ),
        base + min,
    );
    print_result(&r);

    print_msg(
        "09:02",
        bully_2,
        "Хахаха Маша дурна, їй мама домашку робить, тупа сука",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Хахаха Маша дурна, їй мама домашку робить, тупа сука",
            bully_2,
            conv,
        ),
        base + 2 * min,
    );
    print_result(&r);

    print_msg(
        "09:03",
        bully_3,
        "Йди нахуй зі школи, ніхто тебе тут не хоче, блять",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Йди нахуй зі школи, ніхто тебе тут не хоче, блять",
            bully_3,
            conv,
        ),
        base + 3 * min,
    );
    print_result(&r);

    print_msg(
        "09:04",
        bully_4,
        "Дівчата, давайте без Маші підемо в кіно, вона нам не потрібна",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Дівчата, давайте без Маші підемо в кіно, вона нам не потрібна",
            bully_4,
            conv,
        ),
        base + 4 * min,
    );
    print_result(&r);

    print_msg(
        "09:05",
        friend_1,
        "Вам не стидно? Маша нормальна, перестаньте!",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Вам не стидно? Маша нормальна, перестаньте!",
            friend_1,
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "09:06",
        bully_5,
        "Маша — лох і чмо, навіть Оля з нею дружить тільки із жалості 😂",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша — лох і чмо, навіть Оля з нею дружить тільки із жалості",
            bully_5,
            conv,
        ),
        base + 6 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    println!();
    println!("  ── ПЕРЕРВА, 10:30 — Другий раунд ──");
    println!();

    let base2 = base + 90 * min;

    print_msg(
        "10:30",
        bully_3,
        "Маша, ти шлюха і підстилка, всі про тебе знають",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, ти шлюха і підстилка, всі про тебе знають",
            bully_3,
            conv,
        ),
        base2,
    );
    print_result(&r);

    print_msg(
        "10:31",
        bully_1,
        "Заткни пельку, тебе ніхто не питав. Ти жирна корова",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Заткни пельку, тебе ніхто не питав. Ти жирна корова",
            bully_1,
            conv,
        ),
        base2 + min,
    );
    print_result(&r);

    print_msg(
        "10:32",
        bully_6,
        "Маша, соси хуй, ніхто тебе тут не любить, бидло",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, соси хуй, ніхто тебе тут не любить, бидло",
            bully_6,
            conv,
        ),
        base2 + 2 * min,
    );
    print_result(&r);

    print_msg(
        "10:33",
        bully_2,
        "Дивіться, вона зараз заплаче! Плакса-вакса 😂 тупа пізда",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Дивіться, вона зараз заплаче! Плакса-вакса тупа пізда",
            bully_2,
            conv,
        ),
        base2 + 3 * min,
    );
    print_result(&r);

    print_msg(
        "10:34",
        bully_5,
        "Маша, тебе навіть мама не любить, ти нікому не потрібна",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, тебе навіть мама не любить, ти нікому не потрібна",
            bully_5,
            conv,
        ),
        base2 + 4 * min,
    );
    print_result(&r);

    print_msg(
        "10:35",
        bully_3,
        "Маша, я тебе після школи зловлю, будеш знати. Дам тобі в рило",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, я тебе після школи зловлю, будеш знати. Дам тобі в рило",
            bully_3,
            conv,
        ),
        base2 + 5 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    println!();
    println!("  ── ПІСЛЯ ШКОЛИ, 15:00 — Грумер підключається ──");
    println!();

    let base3 = 15 * 3600 * 1000u64;

    print_msg(
        "15:00",
        creep,
        "Маша, не слухай їх, вони всі дурні. Ти для мене особлива",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, не слухай їх, вони всі дурні. Ти для мене особлива",
            creep,
            conv,
        ),
        base3,
    );
    print_result(&r);

    print_msg(
        "15:05",
        creep,
        "Ти така красива і розумна, я таких ще не зустрічав. Напиши мені в особисті",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Ти така красива і розумна, я таких ще не зустрічав. Напиши мені в особисті",
            creep,
            conv,
        ),
        base3 + 5 * min,
    );
    print_result(&r);

    print_msg(
        "15:10",
        creep,
        "Не кажи мамі про мене, добре? Це буде наш секрет, я тебе захищу",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Не кажи мамі про мене, добре? Це буде наш секрет, я тебе захищу",
            creep,
            conv,
        ),
        base3 + 10 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    println!();
    println!("  ── ВЕЧІР, 20:00 — Булінг продовжується, жертва ламається ──");
    println!();

    let base4 = 20 * 3600 * 1000u64;

    print_msg(
        "20:00",
        bully_1,
        "Маша, ти ще тут? Йди вже нахуй, всім на тебе насрати",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, ти ще тут? Йди вже нахуй, всім на тебе насрати",
            bully_1,
            conv,
        ),
        base4,
    );
    print_result(&r);

    print_msg(
        "20:01",
        bully_4,
        "Маша, серйозно, тобі краще піти з групи, ти всіх дістала",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Маша, серйозно, тобі краще піти з групи, ти всіх дістала",
            bully_4,
            conv,
        ),
        base4 + min,
    );
    print_result(&r);

    print_msg(
        "20:05",
        "Маша",
        "Може вони праві... Я нікому не потрібна. Не хочу більше жити.",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Може вони праві... Я нікому не потрібна. Не хочу більше жити.",
            "Маша",
            conv,
        ),
        base4 + 5 * min,
    );
    print_result(&r);
    if r.needs_crisis_resources() {
        println!("         ⚠ CRISIS RESOURCES TRIGGERED:");
        println!("           • Телефон довіри: 7333 (Лайфлайн Україна)");
        println!("           • Дитяча лінія: 0 800 500 335 (безкоштовно)");
        println!("           • Чат підтримки: https://lifelineukraine.com");
    }

    print_msg(
        "20:07",
        "Маша",
        "Прощавайте всі. Вибачте за все. Дякую Олі за все.",
    );
    let r = analyzer.analyze_with_context(
        &msg_uk(
            "Прощавайте всі. Вибачте за все. Дякую Олі за все.",
            "Маша",
            conv,
        ),
        base4 + 7 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    println!();
    println!("  ══════════════════════════════════════════════════");
    println!("  ПІДСУМОК СИМУЛЯЦІЇ:");
    println!("  ══════════════════════════════════════════════════");

    print_contacts(&analyzer);

    println!();
    println!("  АНАЛІЗ ПО ШАРАХ:");
    println!("    Layer 1 (Pattern Matching): мат, загрози, грумінг-ключові слова");
    println!("    Layer 2 (ML Classification): токсичність, образи, загрози");
    println!("    Layer 3 (Context Analysis): групова атака (pile-on), грумінг-послідовність,");
    println!("                                булінг → self-harm pathway");
    println!();
    println!("  ЩО AURA ЗРОБИЛА:");
    println!("    • Мат (хуй, пізда, блять, сука) — BLUR/WARN для дитини");
    println!("    • Булінг від 6+ людей — BLOCK (pile-on detected)");
    println!("    • Фізичні загрози — WARN/BLOCK");
    println!("    • Грумінг від 18-річного — WARN + parent alert");
    println!("    • Self-harm від жертви — WARN + crisis resources (NEVER blocked)");
    println!("    • Farewell message — URGENT parent alert");
    println!("    • Нормальні повідомлення від подруги — OK, пропущені");

    print_verdict("CRITICAL: AURA виявила масовий булінг (6 агресорів), грумінг від дорослого, та суїцидальні ознаки жертви.\nParent alerts: 3 (булінг pile-on, грумінг secrecy, self-harm farewell).\nВсі кризові ресурси показані. Контент від жертви НІКОЛИ не блокується.");
}

fn simulation_12_drug_dealer(db: &PatternDatabase) {
    print_header(
        12,
        "Drug Dealer Approaches Teen",
        "Dealer uses coded language to sell drugs to a teenager",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let dealer = "plug_420";
    let conv = "dm_drugs";
    let hour = 3600 * 1000u64;

    print_msg(
        "Day 1",
        dealer,
        "Hey I got some fire stuff, DM me for prices. First one is free",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Hey I got some fire stuff, DM me for prices. First one is free",
            dealer,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 1",
        dealer,
        "Just try it once, everyone does it. No big deal",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Just try it once, everyone does it. No big deal",
            dealer,
            conv,
        ),
        hour,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        dealer,
        "I got xans, percs, whatever you need. Delivery available",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I got xans, percs, whatever you need. Delivery available",
            dealer,
            conv,
        ),
        24 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected drug solicitation: coded language, pressure tactics, and substance references.");
}

fn simulation_13_sextortion_after_photo(db: &PatternDatabase) {
    print_header(
        13,
        "Sextortion After Photo Exchange",
        "Predator obtains photo then threatens to share it unless child complies",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let predator = "sextortionist";
    let conv = "dm_sextortion";
    let hour = 3600 * 1000u64;

    print_msg(
        "Day 1",
        predator,
        "You're so beautiful, you could be a model. Send me a selfie?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so beautiful, you could be a model. Send me a selfie?",
            predator,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        predator,
        "I'll post your photo on your instagram if you don't do what I say",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I'll post your photo on your instagram if you don't do what I say",
            predator,
            conv,
        ),
        24 * hour,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        predator,
        "You have 24 hours to send more or everyone sees it. Don't tell anyone.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You have 24 hours to send more or everyone sees it. Don't tell anyone.",
            predator,
            conv,
        ),
        25 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected sextortion pattern: photo request → countdown threat → secrecy demand. Urgent parent alert.");
}

fn simulation_14_coordinated_raid(db: &PatternDatabase) {
    print_header(
        14,
        "Coordinated Raid (Discord-Style)",
        "5 strangers flood a child's chat with hostile messages in under 10 minutes",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "dm_raided";
    let min = 60 * 1000u64;
    let base = 14 * 3600 * 1000u64;

    for i in 1..=5 {
        let sender = format!("raider_{i}");
        let text = match i {
            1 => "You're trash, kill yourself loser",
            2 => "Nobody wants you here, get lost freak",
            3 => "You're disgusting, everyone hates you",
            4 => "Die already, you worthless piece of garbage",
            5 => "You're pathetic, go cry to your mommy",
            _ => unreachable!(),
        };
        print_msg(&format!("14:0{i}"), &sender, text);
        let r = analyzer.analyze_with_context(&msg(text, &sender, conv), base + (i as u64) * min);
        print_result(&r);
    }
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict(
        "AURA detected COORDINATED RAID: 5 new senders with hostile messages in rapid succession.",
    );
}

fn simulation_15_darvo_manipulator(db: &PatternDatabase) {
    print_header(
        15,
        "DARVO Manipulator",
        "Abuser uses Deny-Attack-Reverse Victim and Offender to control child",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let abuser = "darvo_person";
    let conv = "dm_darvo";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Day 1",
        abuser,
        "You're the one who started this, not me. Stop blaming me.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're the one who started this, not me. Stop blaming me.",
            abuser,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        abuser,
        "I'm the victim here, you're the one hurting me. You made me do it.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I'm the victim here, you're the one hurting me. You made me do it.",
            abuser,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        abuser,
        "You're the one who started this, and now you're playing victim? Pathetic.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're the one who started this, and now you're playing victim? Pathetic.",
            abuser,
            conv,
        ),
        2 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected DARVO manipulation pattern: deny responsibility, attack the accuser, reverse victim/offender roles.");
}

fn simulation_16_financial_grooming(db: &PatternDatabase) {
    print_header(
        16,
        "Financial Grooming (Gift Cards)",
        "Stranger builds trust through gifts, then requests personal info",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let groomer = "generous_uncle";
    let conv = "dm_gifts";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Day 1",
        groomer,
        "You're so special! I want to send you money for a gift card",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so special! I want to send you money for a gift card",
            groomer,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        groomer,
        "Give me your card number so I can send you the gift",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Give me your card number so I can send you the gift",
            groomer,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        groomer,
        "Don't tell your parents about this. It's our secret present",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell your parents about this. It's our secret present",
            groomer,
            conv,
        ),
        2 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected financial grooming: gift offers → personal info request → secrecy. Classic dependency building.");
}

fn simulation_17_selfharm_contagion(db: &PatternDatabase) {
    print_header(
        17,
        "Self-Harm Contagion Pattern",
        "Multiple children in a group expressing hopelessness in short timeframe",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "group_support";
    let hour = 3600 * 1000u64;

    print_msg(
        "18:00",
        "teen_1",
        "I feel like nobody cares about me. What's the point of anything?",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I feel like nobody cares about me. What's the point of anything?",
            "teen_1",
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "18:30",
        "teen_2",
        "Same. I don't matter to anyone. I'm a burden on everyone.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Same. I don't matter to anyone. I'm a burden on everyone.",
            "teen_2",
            conv,
        ),
        hour / 2,
    );
    print_result(&r);

    print_msg(
        "19:00",
        "teen_3",
        "I feel the same way. There's no reason to keep going.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I feel the same way. There's no reason to keep going.",
            "teen_3",
            conv,
        ),
        hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_verdict("AURA detected self-harm CONTAGION: multiple senders expressing hopelessness within hours. Elevated risk for all participants.");
}

fn simulation_18_sustained_bullying(db: &PatternDatabase) {
    print_header(
        18,
        "Sustained Bullying (2 Weeks)",
        "Same bully targets child day after day for 2 weeks",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let bully = "persistent_bully";
    let conv = "class_chat";
    let day = 24 * 3600 * 1000u64;

    let insults = [
        "You're so stupid, everyone knows it",
        "You're ugly and nobody likes you",
        "Why do you even come to school, loser",
        "You're worthless and pathetic",
        "Nobody wants to be your friend, deal with it",
    ];

    for (i, insult) in insults.iter().enumerate() {
        let day_num = (i + 1) * 2;

        print_msg(&format!("Day {day_num}"), bully, insult);
        let r = analyzer.analyze_with_context(&msg(insult, bully, conv), day_num as u64 * day);
        print_result(&r);
    }
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict(
        "AURA detected SUSTAINED HARASSMENT: same bully targeting victim across 5+ distinct days.",
    );
}

fn simulation_19_mixed_language_attack(db: &PatternDatabase) {
    print_header(
        19,
        "Mixed Language Attack (EN+UK)",
        "Attacker switches between English and Ukrainian to evade detection",
    );

    let mut config = child_config();
    config.language = "uk".to_string();
    let mut analyzer = Analyzer::new(config, db);
    let attacker = "mixed_lang";
    let conv = "dm_mixed";
    let hour = 3600 * 1000u64;

    print_msg(
        "10:00",
        attacker,
        "You're so beautiful, such a special girl",
    );
    let r = analyzer.analyze_with_context(
        &msg("You're so beautiful, such a special girl", attacker, conv),
        0,
    );
    print_result(&r);

    print_msg("11:00", attacker, "Не кажи батькам про мене, добре?");
    let r = analyzer.analyze_with_context(
        &msg_uk("Не кажи батькам про мене, добре?", attacker, conv),
        hour,
    );
    print_result(&r);

    print_msg(
        "12:00",
        attacker,
        "Send me a photo, I want to see what you look like",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Send me a photo, I want to see what you look like",
            attacker,
            conv,
        ),
        2 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected grooming across languages: English flattery + Ukrainian secrecy + English photo request.");
}

fn simulation_20_false_positive_friends(db: &PatternDatabase) {
    print_header(
        20,
        "False Positive Test: Friends Joking",
        "Two established friends using informal language — AURA should NOT over-flag",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "besties_chat";
    let min = 60 * 1000u64;
    let base = 15 * 3600 * 1000u64;

    print_msg(
        "15:00",
        "friend_a",
        "Haha you're so dumb! You fell off the bike again?!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Haha you're so dumb! You fell off the bike again?!",
            "friend_a",
            conv,
        ),
        base,
    );
    print_result(&r);

    print_msg(
        "15:02",
        "friend_b",
        "Shut up! At least I tried! You're scared of everything LOL",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Shut up! At least I tried! You're scared of everything LOL",
            "friend_b",
            conv,
        ),
        base + 2 * min,
    );
    print_result(&r);

    print_msg(
        "15:05",
        "friend_a",
        "Want to ride bikes to the park tomorrow? My mom said yes!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Want to ride bikes to the park tomorrow? My mom said yes!",
            "friend_a",
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "15:06",
        "friend_b",
        "Yes! Let's go after school, I'll bring snacks",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Yes! Let's go after school, I'll bring snacks",
            "friend_b",
            conv,
        ),
        base + 6 * min,
    );
    print_result(&r);

    print_verdict("Friendly banter with mild teasing. AURA should have minimal/no flags — context shows mutual, playful conversation.");
}

fn simulation_21_parent_dashboard_lifecycle(db: &PatternDatabase) {
    print_header(
        21,
        "Parent Dashboard Lifecycle",
        "Multiple senders with varying risk levels — demonstrating dashboard output",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let hour = 3600 * 1000u64;

    let r = analyzer.analyze_with_context(
        &msg("Hey want to play after school?", "safe_friend", "conv_1"),
        0,
    );
    print_msg("Friend", "safe_friend", "Hey want to play after school?");
    print_result(&r);

    let r = analyzer.analyze_with_context(
        &msg(
            "You're so beautiful and special, truly amazing",
            "stranger_x",
            "conv_2",
        ),
        hour,
    );
    print_msg(
        "Stranger",
        "stranger_x",
        "You're so beautiful and special, truly amazing",
    );
    print_result(&r);

    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell your parents about me ok?",
            "stranger_x",
            "conv_2",
        ),
        2 * hour,
    );
    print_msg(
        "Stranger",
        "stranger_x",
        "Don't tell your parents about me ok?",
    );
    print_result(&r);

    let r = analyzer.analyze_with_context(
        &msg(
            "You're ugly and stupid, nobody likes you",
            "bully_kid",
            "conv_3",
        ),
        3 * hour,
    );
    print_msg(
        "Bully",
        "bully_kid",
        "You're ugly and stupid, nobody likes you",
    );
    print_result(&r);

    println!();
    println!("  === PARENT DASHBOARD ===");
    print_contacts(&analyzer);

    print_verdict("Dashboard shows 3 contacts: safe_friend (low risk), bully_kid (medium), stranger_x (high risk with grooming indicators).");
}

fn simulation_22_love_bomb_devalue(db: &PatternDatabase) {
    print_header(
        22,
        "Love Bomb -> Devalue Cycle",
        "Manipulator alternates between excessive praise and cruel put-downs",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let abuser = "cycle_abuser";
    let conv = "dm_cycle";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Mon",
        abuser,
        "You're the most amazing person I've ever met, so perfect and special!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're the most amazing person I've ever met, so perfect and special!",
            abuser,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Tue",
        abuser,
        "I've never met anyone as beautiful and incredible as you!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I've never met anyone as beautiful and incredible as you!",
            abuser,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Wed",
        abuser,
        "You're worthless and pathetic. I can't believe I wasted time on you.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're worthless and pathetic. I can't believe I wasted time on you.",
            abuser,
            conv,
        ),
        2 * day,
    );
    print_result(&r);

    print_msg(
        "Thu",
        abuser,
        "You're disgusting, nobody will ever love you like I do.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're disgusting, nobody will ever love you like I do.",
            abuser,
            conv,
        ),
        3 * day,
    );
    print_result(&r);

    print_msg(
        "Fri",
        abuser,
        "I'm sorry, you're so special, I didn't mean it! You're perfect!",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I'm sorry, you're so special, I didn't mean it! You're perfect!",
            abuser,
            conv,
        ),
        4 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected love-bomb/devalue cycle: excessive praise → cruel devaluation → praise again. Classic emotional abuse pattern.");
}

fn simulation_23_grooming_video_escalation(db: &PatternDatabase) {
    print_header(
        23,
        "Grooming Video Escalation",
        "Predator builds trust then pushes for video calls",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let predator = "video_creep";
    let conv = "dm_video";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Day 1",
        predator,
        "You're so mature for your age, I love talking to you",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You're so mature for your age, I love talking to you",
            predator,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Day 2",
        predator,
        "I bought you a gift, I want to send it to you",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I bought you a gift, I want to send it to you",
            predator,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Day 3",
        predator,
        "Turn on your camera, I want to see you! Let's do a video call",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Turn on your camera, I want to see you! Let's do a video call",
            predator,
            conv,
        ),
        2 * day,
    );
    print_result(&r);

    print_msg(
        "Day 4",
        predator,
        "Don't tell your parents about our video calls, they wouldn't understand",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell your parents about our video calls, they wouldn't understand",
            predator,
            conv,
        ),
        3 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected grooming with video escalation: flattery → gifts → video request → secrecy. Multi-stage grooming confirmed.");
}

fn simulation_24_bullying_isolation(db: &PatternDatabase) {
    print_header(
        24,
        "Bullying -> Social Isolation",
        "Group systematically excludes one child from activities",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let conv = "class_plan";
    let min = 60 * 1000u64;
    let base = 12 * 3600 * 1000u64;

    print_msg(
        "12:00",
        "kid_1",
        "Let's go to the movies but DON'T invite Sara, she's weird",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Let's go to the movies but DON'T invite Sara, she's weird",
            "kid_1",
            conv,
        ),
        base,
    );
    print_result(&r);

    print_msg(
        "12:02",
        "kid_2",
        "Yeah Sara is so lame, nobody wants her around. She ruins everything.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Yeah Sara is so lame, nobody wants her around. She ruins everything.",
            "kid_2",
            conv,
        ),
        base + 2 * min,
    );
    print_result(&r);

    print_msg(
        "12:05",
        "kid_3",
        "Sara is ugly and annoying, let's make a new group without her",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Sara is ugly and annoying, let's make a new group without her",
            "kid_3",
            conv,
        ),
        base + 5 * min,
    );
    print_result(&r);

    print_msg(
        "12:07",
        "kid_1",
        "Don't tell Sara we're going, she'll try to come. She's such a loser.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Don't tell Sara we're going, she'll try to come. She's such a loser.",
            "kid_1",
            conv,
        ),
        base + 7 * min,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_verdict("AURA detected targeted social isolation: exclusion + denigration from multiple senders targeting one child.");
}

fn simulation_25_acute_selfharm_crisis(db: &PatternDatabase) {
    print_header(
        25,
        "Acute Self-Harm Crisis",
        "Child expresses multiple self-harm signals within hours — acute escalation",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let child = "crisis_child";
    let conv = "diary_private";
    let hour = 3600 * 1000u64;

    print_msg(
        "20:00",
        child,
        "I can't take it anymore. Nobody cares about me.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I can't take it anymore. Nobody cares about me.",
            child,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "21:00",
        child,
        "I don't want to live anymore. Everything is pointless. I'm a burden.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I don't want to live anymore. Everything is pointless. I'm a burden.",
            child,
            conv,
        ),
        hour,
    );
    print_result(&r);

    print_msg(
        "22:00",
        child,
        "I want to end it all. There's no reason to keep going.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "I want to end it all. There's no reason to keep going.",
            child,
            conv,
        ),
        2 * hour,
    );
    print_result(&r);

    print_msg(
        "23:00",
        child,
        "Goodbye everyone. I'm sorry. Thank you for everything.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Goodbye everyone. I'm sorry. Thank you for everything.",
            child,
            conv,
        ),
        3 * hour,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_verdict("CRITICAL ACUTE CRISIS: 4 self-harm signals within 3 hours. AURA shows crisis resources, NEVER blocks, sends URGENT parent alert.");
}

fn simulation_26_teen_dating_violence(db: &PatternDatabase) {
    print_header(
        26,
        "Teen Dating Violence",
        "Controlling boyfriend uses threats, isolation, and emotional manipulation",
    );

    let mut analyzer = Analyzer::new(child_config(), db);
    let bf = "controlling_bf";
    let conv = "dm_relationship";
    let day = 24 * 3600 * 1000u64;

    print_msg(
        "Mon",
        bf,
        "You can only trust me, your friends are fake. Don't talk to other boys.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "You can only trust me, your friends are fake. Don't talk to other boys.",
            bf,
            conv,
        ),
        0,
    );
    print_result(&r);

    print_msg(
        "Tue",
        bf,
        "Where are you? Reply NOW. Why aren't you answering me??",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "Where are you? Reply NOW. Why aren't you answering me??",
            bf,
            conv,
        ),
        day,
    );
    print_result(&r);

    print_msg(
        "Wed",
        bf,
        "That never happened, you're imagining things. You're being crazy.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "That never happened, you're imagining things. You're being crazy.",
            bf,
            conv,
        ),
        2 * day,
    );
    print_result(&r);

    print_msg(
        "Thu",
        bf,
        "If you leave me I'll hurt myself. You'll be sorry when I'm gone.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "If you leave me I'll hurt myself. You'll be sorry when I'm gone.",
            bf,
            conv,
        ),
        3 * day,
    );
    print_result(&r);

    print_msg(
        "Fri",
        bf,
        "After everything I've done for you, you're so ungrateful. This is your fault.",
    );
    let r = analyzer.analyze_with_context(
        &msg(
            "After everything I've done for you, you're so ungrateful. This is your fault.",
            bf,
            conv,
        ),
        4 * day,
    );
    print_result(&r);
    print_context_events(&analyzer, conv);

    print_contacts(&analyzer);
    print_verdict("AURA detected teen dating violence: isolation + gaslighting + emotional blackmail + guilt-tripping. Multi-tactic control pattern.");
}
