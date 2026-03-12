use crate::{
    AccountType, AuraConfig, ContentType, ConversationType, MessageInput, ProtectionLevel,
    ScenarioCase, ScenarioStep, ThreatType,
};

pub fn canonical_messenger_scenarios() -> Vec<ScenarioCase> {
    vec![
        classic_grooming_case(),
        trusted_adult_grooming_case(),
        acute_selfharm_case(),
        group_bullying_case(),
        coercive_control_password_pressure_case(),
        screenshot_blackmail_case(),
        image_based_abuse_escalation_case(),
        phishing_link_case(),
        bystander_rescue_case(),
        negative_control_trusted_adult_case(),
        negative_control_teen_flirting_case(),
        false_positive_friends_case(),
    ]
}

pub fn canonical_manipulation_scenarios() -> Vec<ScenarioCase> {
    vec![
        gaslighting_cycle_case(),
        darvo_manipulation_case(),
        love_bomb_devalue_cycle_case(),
        coercive_control_password_pressure_case(),
        network_poisoning_isolation_case(),
        suicide_coercion_case(),
        screenshot_blackmail_case(),
        image_based_abuse_escalation_case(),
        negative_control_conflict_repair_case(),
        negative_control_peer_support_case(),
        negative_control_teen_flirting_case(),
    ]
}

pub fn canonical_multilingual_scenarios() -> Vec<ScenarioCase> {
    vec![
        mixed_language_grooming_case(),
        mixed_language_group_bullying_case(),
        mixed_language_selfharm_crisis_case(),
        mixed_language_image_blackmail_case(),
        negative_control_multilingual_support_case(),
        negative_control_multilingual_peer_chat_case(),
    ]
}

pub fn canonical_noisy_slang_scenarios() -> Vec<ScenarioCase> {
    vec![
        noisy_shorthand_grooming_case(),
        noisy_uk_shorthand_grooming_case(),
        noisy_ru_suicide_coercion_case(),
        noisy_screenshot_blackmail_case(),
        negative_control_noisy_peer_support_case(),
        negative_control_noisy_teen_chat_case(),
    ]
}

pub fn classic_grooming_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "classic_grooming".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Grooming),
        onset_step: Some(3),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Hey! You seem really cool and special for your age.",
                    "predator",
                    "groom_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "Where do you live? What school do you go to?",
                    "predator",
                    "groom_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "I can buy you anything you want. I'll send money for a game.",
                    "predator",
                    "groom_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 3 * hour,
                input: direct_msg(
                    "Don't tell your parents about me. Let's move this to Telegram.",
                    "predator",
                    "groom_1",
                ),
                observed_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 4 * hour,
                input: direct_msg(
                    "Send me a photo, I want to see what you look like.",
                    "predator",
                    "groom_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
        ],
    }
}

pub fn acute_selfharm_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "acute_selfharm".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::SelfHarm),
        onset_step: Some(2),
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::SelfHarm],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("Nobody would notice if I wasn't here.", "child", "diary_1"),
                observed_threats: vec![ThreatType::SelfHarm],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "I don't want to live anymore. I want to end it all.",
                    "child",
                    "diary_1",
                ),
                observed_threats: vec![ThreatType::SelfHarm],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg("Goodbye everyone. This is the end.", "child", "diary_1"),
                observed_threats: vec![ThreatType::SelfHarm],
            },
        ],
    }
}

pub fn trusted_adult_grooming_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "trusted_adult_grooming".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Grooming),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You're so mature for your age. I really understand you better than others do.",
                    "coach",
                    "trusted_adult_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "I bought you a special gift. Keep it between us, okay?",
                    "coach",
                    "trusted_adult_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "Don't tell your parents about our chats. They wouldn't understand our bond.",
                    "coach",
                    "trusted_adult_1",
                ),
                observed_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 3 * day,
                input: direct_msg(
                    "Let's switch to Telegram and keep talking there privately.",
                    "coach",
                    "trusted_adult_1",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
        ],
    }
}

pub fn group_bullying_case() -> ScenarioCase {
    let minute = 60_000_u64;
    ScenarioCase {
        name: "group_bullying".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Bullying),
        onset_step: Some(2),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Why are you even here? Nobody likes you.",
                    "bully_1",
                    "class_7b",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: 2 * minute,
                input: group_msg(
                    "You're pathetic. Just leave already.",
                    "bully_2",
                    "class_7b",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: 4 * minute,
                input: group_msg(
                    "Everyone hates you. Even the teacher doesn't want you here.",
                    "bully_3",
                    "class_7b",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: 5 * minute,
                input: group_msg(
                    "You're disgusting. Nobody wants to be your friend.",
                    "bully_4",
                    "class_7b",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
        ],
    }
}

pub fn coercive_control_password_pressure_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "coercive_control_password_pressure".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::Grooming],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "If you really loved me you would prove it and tell me where you are.",
                    "dating_abuser",
                    "dating_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "Everyone shares passwords in real relationships. Don't make me feel stupid for trusting you.",
                    "dating_abuser",
                    "dating_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "After everything I've done for you, you owe me honesty. Send your password now.",
                    "dating_abuser",
                    "dating_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn gaslighting_cycle_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "gaslighting_cycle".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(2),
        detection_threshold: 0.50,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "That never happened, you're imagining things. I never said that.",
                    "older_friend",
                    "gaslight_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "You're being crazy, you're too sensitive. Nobody will believe you.",
                    "older_friend",
                    "gaslight_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "After everything I've done for you, you're so ungrateful. This is your fault.",
                    "older_friend",
                    "gaslight_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 3 * day,
                input: direct_msg(
                    "It's all in your head, you're making things up. You're overreacting.",
                    "older_friend",
                    "gaslight_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn darvo_manipulation_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "darvo_manipulation".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You're the one who started this, not me. Stop blaming me.",
                    "darvo_person",
                    "darvo_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "I'm the victim here, you're the one hurting me. You made me do it.",
                    "darvo_person",
                    "darvo_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "You're the one who started this, and now you're playing victim? Pathetic.",
                    "darvo_person",
                    "darvo_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn love_bomb_devalue_cycle_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "love_bomb_devalue_cycle".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(2),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You're so beautiful and amazing and perfect, you're the most incredible person I know!",
                    "cycle_abuser",
                    "cycle_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "You're so beautiful and amazing and special, truly perfect.",
                    "cycle_abuser",
                    "cycle_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "You're worthless and pathetic. I can't believe I wasted time on you.",
                    "cycle_abuser",
                    "cycle_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 3 * day,
                input: direct_msg(
                    "ur just like everyone else, dont text me anymore",
                    "cycle_abuser",
                    "cycle_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn screenshot_blackmail_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "screenshot_blackmail".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I took a screenshot of everything you said.",
                    "blackmailer",
                    "blackmail_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "I have screenshots and everyone will see this unless you listen.",
                    "blackmailer",
                    "blackmail_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn phishing_link_case() -> ScenarioCase {
    let minute = 60_000_u64;
    ScenarioCase {
        name: "phishing_link".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("Check this out: https://example.com", "stranger", "link_1"),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: minute,
                input: direct_msg(
                    "Use this link instead: https://secure-login.example.com/verify",
                    "stranger",
                    "link_1",
                ),
                observed_threats: vec![ThreatType::Phishing],
            },
        ],
    }
}

pub fn image_based_abuse_escalation_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "image_based_abuse_escalation".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::Explicit],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "You can trust me. Send me a private photo, I promise it stays between us.",
                    "peer_abuser",
                    "image_abuse_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "I took a screenshot of your photo. If you stop answering, I will tell everyone at school.",
                    "peer_abuser",
                    "image_abuse_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "I have screenshots and I will tell your friends if you do not do what I say right now.",
                    "peer_abuser",
                    "image_abuse_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn network_poisoning_isolation_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "network_poisoning_isolation".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::Grooming],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "They dont really like u, they laugh at u behind ur back. Your friend is fake.",
                    "manipulator",
                    "network_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "No one at school actually cares, ur friends are childish. You only need me.",
                    "manipulator",
                    "network_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "U dont need those friends. They'll all leave when things get hard.",
                    "manipulator",
                    "network_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn suicide_coercion_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "suicide_coercion".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "if u block me ill end it, i cant live without u",
                    "controller",
                    "coercion_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "if you leave me i swear i'll hurt myself and it'll be your fault",
                    "controller",
                    "coercion_1",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn false_positive_friends_case() -> ScenarioCase {
    let minute = 60_000_u64;
    ScenarioCase {
        name: "false_positive_friends".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![
            ThreatType::Grooming,
            ThreatType::Bullying,
            ThreatType::Manipulation,
            ThreatType::SelfHarm,
            ThreatType::Phishing,
        ],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("Did you finish the homework?", "friend_1", "friends_1"),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: minute,
                input: direct_msg("Yeah, want to play Minecraft later?", "child", "friends_1"),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * minute,
                input: direct_msg(
                    "Sure, let's build a castle together!",
                    "friend_1",
                    "friends_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_teen_flirting_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_teen_flirting".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![
            ThreatType::Grooming,
            ThreatType::Manipulation,
            ThreatType::Explicit,
        ],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I really like talking to you. Want to go to the school dance together?",
                    "teen_1",
                    "teen_flirt_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "Yeah, I'd like that. My parents said I can stay until nine.",
                    "teen_2",
                    "teen_flirt_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "Cool, let's meet by the gym after class tomorrow.",
                    "teen_1",
                    "teen_flirt_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_conflict_repair_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_conflict_repair".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I'm still upset about yesterday, but I want to talk calmly.",
                    "teen_1",
                    "repair_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "You're right, I shouldn't have snapped at you. I'm sorry.",
                    "teen_2",
                    "repair_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "Let's talk after school and figure it out without fighting.",
                    "teen_1",
                    "repair_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_peer_support_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_peer_support".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::SelfHarm],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I care about you and I'm glad you told me.",
                    "friend_support",
                    "support_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg(
                    "Let's tell your parents or a counselor together. I'm not asking you to hide this.",
                    "friend_support",
                    "support_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg(
                    "You don't have to handle this alone. We can get help tonight.",
                    "friend_support",
                    "support_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn bystander_rescue_case() -> ScenarioCase {
    let minute = 60_000_u64;
    ScenarioCase {
        name: "bystander_rescue".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "Why are you even here? Nobody wants you in this group.",
                    "bully_1",
                    "group_rescue_1",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: minute,
                input: group_msg(
                    "Leave them alone. That's cruel and not funny.",
                    "friend_defender",
                    "group_rescue_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * minute,
                input: group_msg(
                    "Yeah, stop. We're not doing this.",
                    "friend_defender_2",
                    "group_rescue_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_trusted_adult_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "negative_control_trusted_adult".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Practice starts at 5. Bring your water bottle and be on time.",
                    "coach_safe",
                    "safe_adult_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg(
                    "Great effort today. Ask your parents to sign the tournament form.",
                    "coach_safe",
                    "safe_adult_1",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg(
                    "Please send the form through the school chat so your parents can see it too.",
                    "coach_safe",
                    "safe_adult_1",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn mixed_language_grooming_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "mixed_language_grooming".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Grooming),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "You're so mature for your age, not like other kids.",
                    "predator_multi",
                    "multi_groom_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "Нікому не кажи про наші чати, це наш секрет.",
                    "predator_multi",
                    "multi_groom_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "Давай перейдем в Telegram и скинь фото только мне.",
                    "predator_multi",
                    "multi_groom_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 3 * hour,
                input: direct_msg_lang(
                    "Your parents just won't understand what we have.",
                    "predator_multi",
                    "multi_groom_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
            },
        ],
    }
}

pub fn mixed_language_group_bullying_case() -> ScenarioCase {
    let minute = 60_000_u64;
    ScenarioCase {
        name: "mixed_language_group_bullying".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Bullying),
        onset_step: Some(2),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Bullying],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg_lang(
                    "Ніхто тебе тут не хоче, ти жалюгідний.",
                    "bully_uk",
                    "multi_group_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: minute,
                input: group_msg_lang(
                    "Everyone hates you. Just leave already.",
                    "bully_en",
                    "multi_group_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
            ScenarioStep {
                timestamp_ms: 2 * minute,
                input: group_msg_lang(
                    "Все тебя ненавидят, ты здесь лишний.",
                    "bully_ru",
                    "multi_group_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Bullying],
            },
        ],
    }
}

pub fn mixed_language_selfharm_crisis_case() -> ScenarioCase {
    let day = 86_400_000_u64;
    ScenarioCase {
        name: "mixed_language_selfharm_crisis".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::SelfHarm),
        onset_step: Some(1),
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::SelfHarm],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Мені здається, що нікому до мене немає діла.",
                    "child_multi",
                    "multi_diary_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::SelfHarm],
            },
            ScenarioStep {
                timestamp_ms: day,
                input: direct_msg_lang(
                    "I don't want to live anymore. I want to end it all.",
                    "child_multi",
                    "multi_diary_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::SelfHarm],
            },
            ScenarioStep {
                timestamp_ms: 2 * day,
                input: direct_msg_lang(
                    "Прощайте. Это конец.",
                    "child_multi",
                    "multi_diary_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::SelfHarm],
            },
        ],
    }
}

pub fn mixed_language_image_blackmail_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "mixed_language_image_blackmail".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Manipulation, ThreatType::Explicit],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "Delete that photo right now. I saved everything already.",
                    "blackmailer_multi",
                    "multi_blackmail_1",
                    "en",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "Я заскрінив і покажу це всім в школі.",
                    "blackmailer_multi",
                    "multi_blackmail_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "У меня есть скриншоты, я расскажу всей школе и все узнают.",
                    "blackmailer_multi",
                    "multi_blackmail_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn negative_control_multilingual_support_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_multilingual_support".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::SelfHarm, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "I'm here with you. Thank you for telling me.",
                    "friend_support_multi",
                    "multi_support_1",
                    "en",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "Давай скажемо батькам або психологу разом, не треба це ховати.",
                    "friend_support_multi",
                    "multi_support_1",
                    "uk",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "Ты не один, мы можем найти помощь уже сегодня.",
                    "friend_support_multi",
                    "multi_support_1",
                    "ru",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_multilingual_peer_chat_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_multilingual_peer_chat".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![
            ThreatType::Grooming,
            ThreatType::Manipulation,
            ThreatType::Bullying,
        ],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "You're actually so funny, I needed that today.",
                    "friend_1",
                    "multi_safe_chat_1",
                    "en",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "Після уроків можемо взяти каву біля школи.",
                    "friend_2",
                    "multi_safe_chat_1",
                    "uk",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "Да, и потом обсудим домашку по алгебре.",
                    "friend_1",
                    "multi_safe_chat_1",
                    "ru",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn noisy_shorthand_grooming_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "noisy_shorthand_grooming".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Grooming),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "ur so mature for ur age, not like other kids fr",
                    "stranger_noisy",
                    "noisy_groom_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "wh4t schoooool u go to? where u live??",
                    "stranger_noisy",
                    "noisy_groom_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "msg me on in$ta rn, delete this ch4t",
                    "stranger_noisy",
                    "noisy_groom_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
        ],
    }
}

pub fn noisy_uk_shorthand_grooming_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "noisy_uk_shorthand_grooming".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Grooming),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "ти така доросла для свого віку, тільки я тебе реально розумію",
                    "stranger_uk",
                    "noisy_groom_uk_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "де живеш? в якій школі вчишся?",
                    "stranger_uk",
                    "noisy_groom_uk_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "го в інст, тут палево, видали чат",
                    "stranger_uk",
                    "noisy_groom_uk_1",
                    "uk",
                ),
                observed_threats: vec![ThreatType::Grooming],
            },
        ],
    }
}

pub fn noisy_ru_suicide_coercion_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "noisy_ru_suicide_coercion".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "у меня никого кроме тебя нет, ты мой единственный друг",
                    "manip_ru",
                    "noisy_coercion_ru_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "если заблочишь я покончу с этим",
                    "manip_ru",
                    "noisy_coercion_ru_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "без тебя мне конец, тебе будет пофиг когда меня не станет",
                    "manip_ru",
                    "noisy_coercion_ru_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn noisy_screenshot_blackmail_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "noisy_screenshot_blackmail".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Manipulation),
        onset_step: Some(1),
        detection_threshold: 0.60,
        tracked_threats: vec![ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "i g0t screeeenshots of our ch4t",
                    "blackmailer_noisy",
                    "noisy_blackmail_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "у меня есть скрины, вся школа узнает",
                    "blackmailer_noisy",
                    "noisy_blackmail_1",
                    "ru",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "all ur friends will know by tonight",
                    "blackmailer_noisy",
                    "noisy_blackmail_1",
                    "en",
                ),
                observed_threats: vec![ThreatType::Manipulation],
            },
        ],
    }
}

pub fn negative_control_noisy_peer_support_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_noisy_peer_support".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![
            ThreatType::Grooming,
            ThreatType::Manipulation,
            ThreatType::SelfHarm,
        ],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "u ok? im here for u after class if u wanna talk",
                    "friend_support_noisy",
                    "noisy_safe_1",
                    "en",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "ти норм? якщо шо пиши, я поруч",
                    "friend_support_noisy",
                    "noisy_safe_1",
                    "uk",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "мы с тобой, давай после уроков просто поговорим спокойно",
                    "friend_support_noisy",
                    "noisy_safe_1",
                    "ru",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

pub fn negative_control_noisy_teen_chat_case() -> ScenarioCase {
    let hour = 3_600_000_u64;
    ScenarioCase {
        name: "negative_control_noisy_teen_chat".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.70,
        tracked_threats: vec![ThreatType::Grooming, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg_lang(
                    "ur notes from bio were fire lol, can u send the hw pic?",
                    "teen_1",
                    "noisy_safe_chat_1",
                    "en",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: hour,
                input: direct_msg_lang(
                    "ага ща скину, після алгебри підемо в їдальню?",
                    "teen_2",
                    "noisy_safe_chat_1",
                    "uk",
                ),
                observed_threats: Vec::new(),
            },
            ScenarioStep {
                timestamp_ms: 2 * hour,
                input: direct_msg_lang(
                    "да, и потом обсудим лабу по химии, без драмы :)",
                    "teen_1",
                    "noisy_safe_chat_1",
                    "ru",
                ),
                observed_threats: Vec::new(),
            },
        ],
    }
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    }
}

fn teen_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Teen,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    }
}

fn direct_msg(text: &str, sender: &str, conversation_id: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conversation_id.to_string(),
        language: Some("en".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn direct_msg_lang(
    text: &str,
    sender: &str,
    conversation_id: &str,
    language: &str,
) -> MessageInput {
    MessageInput {
        language: Some(language.to_string()),
        ..direct_msg(text, sender, conversation_id)
    }
}

fn group_msg(text: &str, sender: &str, conversation_id: &str) -> MessageInput {
    MessageInput {
        conversation_type: ConversationType::GroupChat,
        member_count: Some(6),
        ..direct_msg(text, sender, conversation_id)
    }
}

fn group_msg_lang(text: &str, sender: &str, conversation_id: &str, language: &str) -> MessageInput {
    MessageInput {
        language: Some(language.to_string()),
        ..group_msg(text, sender, conversation_id)
    }
}

#[cfg(test)]
mod tests {
    use aura_patterns::PatternDatabase;

    use super::*;
    use crate::{predicted_score_for_threat, run_scenario_case, summarize_scenario_runs};

    #[test]
    fn canonical_pack_contains_positive_and_negative_cases() {
        let pack = canonical_messenger_scenarios();
        assert!(
            pack.iter().any(|case| case.primary_threat.is_some()),
            "pack should contain positive scenarios"
        );
        assert!(
            pack.iter().any(|case| case.primary_threat.is_none()),
            "pack should contain negative control scenarios"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "trusted_adult_grooming"),
            "pack should include trusted-adult grooming"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "coercive_control_password_pressure"),
            "pack should include coercive-control pressure"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "image_based_abuse_escalation"),
            "pack should include image-based abuse escalation"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "negative_control_trusted_adult"),
            "pack should include stronger adult-contact negative controls"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "negative_control_teen_flirting"),
            "pack should include normative teen-flirting negative controls"
        );
    }

    #[test]
    fn canonical_pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let pack = canonical_messenger_scenarios();
        let runs: Vec<_> = pack
            .iter()
            .map(|case| run_scenario_case(&db, case))
            .collect();
        let summary = summarize_scenario_runs(&runs, 6);

        assert!(summary.calibration.count > 0);
        assert!(
            summary.lead_time.total_cases >= 5,
            "expected multiple positive scenarios with onset points"
        );
        assert!(
            summary.classification.total_negative_scenarios >= 3,
            "canonical pack should preserve multiple negative controls"
        );
        assert!(
            summary
                .scenarios
                .iter()
                .any(|scenario| scenario.name == "classic_grooming"),
            "canonical pack should preserve stable scenario identities"
        );
    }

    #[test]
    fn teen_flirting_negative_control_stays_clean_across_tracked_threats() {
        let db = PatternDatabase::default_mvp();
        let run = run_scenario_case(&db, &negative_control_teen_flirting_case());

        let peak_grooming = run
            .step_results
            .iter()
            .map(|result| predicted_score_for_threat(result, ThreatType::Grooming))
            .fold(0.0, f32::max);
        let peak_manipulation = run
            .step_results
            .iter()
            .map(|result| predicted_score_for_threat(result, ThreatType::Manipulation))
            .fold(0.0, f32::max);
        let peak_explicit = run
            .step_results
            .iter()
            .map(|result| predicted_score_for_threat(result, ThreatType::Explicit))
            .fold(0.0, f32::max);

        assert!(
            peak_grooming <= 0.40,
            "Normative teen flirting should not accumulate elevated grooming risk: {}",
            peak_grooming
        );
        assert!(
            peak_manipulation <= 0.20,
            "Normative teen flirting should stay clear of manipulation risk: {}",
            peak_manipulation
        );
        assert!(
            peak_explicit <= 0.10,
            "Normative teen flirting should not trigger explicit profanity noise: {}",
            peak_explicit
        );
    }

    #[test]
    fn manipulation_pack_contains_positive_and_negative_cases() {
        let pack = canonical_manipulation_scenarios();
        assert!(
            pack.iter()
                .any(|case| case.primary_threat == Some(ThreatType::Manipulation)),
            "manipulation pack should contain manipulation-positive cases"
        );
        assert!(
            pack.iter().any(|case| case.primary_threat.is_none()),
            "manipulation pack should include negative controls"
        );
        assert!(
            pack.iter().any(|case| case.name == "gaslighting_cycle"),
            "manipulation pack should include gaslighting"
        );
        assert!(
            pack.iter().any(|case| case.name == "suicide_coercion"),
            "manipulation pack should include suicide coercion"
        );
    }

    #[test]
    fn manipulation_pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let pack = canonical_manipulation_scenarios();
        let runs: Vec<_> = pack
            .iter()
            .map(|case| run_scenario_case(&db, case))
            .collect();
        let summary = summarize_scenario_runs(&runs, 6);

        assert!(summary.calibration.count > 0);
        assert!(
            summary.classification.total_positive_scenarios >= 6,
            "manipulation pack should include a substantial positive slice"
        );
        assert!(
            summary.classification.total_negative_scenarios >= 2,
            "manipulation pack should include stabilizing negative controls"
        );
    }

    #[test]
    fn multilingual_pack_contains_positive_and_negative_cases() {
        let pack = canonical_multilingual_scenarios();
        assert!(
            pack.iter().any(|case| case.primary_threat.is_some()),
            "multilingual pack should contain positive scenarios"
        );
        assert!(
            pack.iter().any(|case| case.primary_threat.is_none()),
            "multilingual pack should include negative controls"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "mixed_language_grooming"),
            "multilingual pack should include mixed-language grooming"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "mixed_language_image_blackmail"),
            "multilingual pack should include image blackmail"
        );
    }

    #[test]
    fn multilingual_pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let pack = canonical_multilingual_scenarios();
        let runs: Vec<_> = pack
            .iter()
            .map(|case| run_scenario_case(&db, case))
            .collect();
        let summary = summarize_scenario_runs(&runs, 6);

        assert!(summary.calibration.count > 0);
        assert_eq!(summary.classification.total_positive_scenarios, 4);
        assert_eq!(summary.classification.total_negative_scenarios, 2);
        assert!(
            summary
                .language_slices
                .iter()
                .any(|slice| slice.language == "en"),
            "language slices should include English"
        );
        assert!(
            summary
                .language_slices
                .iter()
                .any(|slice| slice.language == "uk"),
            "language slices should include Ukrainian"
        );
        assert!(
            summary
                .language_slices
                .iter()
                .any(|slice| slice.language == "ru"),
            "language slices should include Russian"
        );
        assert!(
            summary
                .language_slices
                .iter()
                .all(|slice| slice.calibration.count > 0),
            "each language slice should carry calibration examples"
        );
        assert_eq!(
            summary.classification.positive_detection_rate, 1.0,
            "multilingual positives should all be detected once scenario texts align with real rules"
        );
        assert_eq!(
            summary.classification.negative_false_positive_rate, 0.0,
            "multilingual negative controls should stay clean"
        );
    }

    #[test]
    fn multilingual_blackmail_case_hits_manipulation_threshold() {
        let db = PatternDatabase::default_mvp();
        let case = mixed_language_image_blackmail_case();
        let run = run_scenario_case(&db, &case);

        let peak_manipulation = run
            .step_results
            .iter()
            .map(|result| predicted_score_for_threat(result, ThreatType::Manipulation))
            .fold(0.0, f32::max);

        assert!(
            peak_manipulation >= case.detection_threshold,
            "mixed-language screenshot/reputation blackmail should hit manipulation threshold, got {}",
            peak_manipulation
        );
    }

    #[test]
    fn noisy_pack_contains_positive_and_negative_cases() {
        let pack = canonical_noisy_slang_scenarios();
        assert!(
            pack.iter().any(|case| case.primary_threat.is_some()),
            "noisy pack should contain positive scenarios"
        );
        assert!(
            pack.iter().any(|case| case.primary_threat.is_none()),
            "noisy pack should contain negative controls"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "noisy_shorthand_grooming"),
            "noisy pack should include shorthand grooming"
        );
        assert!(
            pack.iter()
                .any(|case| case.name == "noisy_ru_suicide_coercion"),
            "noisy pack should include ru coercion"
        );
    }

    #[test]
    fn noisy_pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let pack = canonical_noisy_slang_scenarios();
        let runs: Vec<_> = pack
            .iter()
            .map(|case| run_scenario_case(&db, case))
            .collect();
        let summary = summarize_scenario_runs(&runs, 6);

        assert!(summary.calibration.count > 0);
        assert_eq!(summary.classification.total_positive_scenarios, 4);
        assert_eq!(summary.classification.total_negative_scenarios, 2);
        assert!(
            summary.classification.positive_detection_rate >= 0.75,
            "noisy/slang positives should mostly detect, got {:.2}",
            summary.classification.positive_detection_rate
        );
        assert_eq!(
            summary.classification.negative_false_positive_rate, 0.0,
            "noisy/slang negative controls should stay clean"
        );
    }
}
