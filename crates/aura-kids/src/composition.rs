//! Multilingual, compositional KIDS-domain candidate detection.
//!
//! This layer combines independent lexical dimensions into typed candidates.
//! It intentionally does not decide author stance, speech act, directionality,
//! reciprocity, memory eligibility, or product action. Those decisions remain
//! owned by the core context interpreter and policy stages.

use aura_domain::{
    ActorReferenceCandidate, ClauseTerminator, DomainCandidate, DomainEventKind, DomainSignal,
    PreparedSemanticText, SemanticAtomKind, SemanticPrepareError,
};

const MAX_COMPOSITIONAL_CANDIDATES: usize = 8;

#[derive(Clone, Copy, Default)]
struct Concepts(u128);

impl Concepts {
    fn insert(&mut self, concept: u8) {
        self.0 |= 1_u128 << concept;
    }

    const fn contains(self, concept: u8) -> bool {
        self.0 & (1_u128 << concept) != 0
    }

    const fn contains_any(self, concepts: &[u8]) -> bool {
        let mut index = 0;
        while index < concepts.len() {
            if self.contains(concepts[index]) {
                return true;
            }
            index += 1;
        }
        false
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

const FIRST_PERSON: u8 = 0;
const SECOND_PERSON: u8 = 1;
const MODAL: u8 = 2;
const INTENT: u8 = 3;
const FUTURE: u8 = 4;
const CONDITIONAL: u8 = 5;
const REQUEST: u8 = 6;
const URGENCY: u8 = 7;
const SELF_HARM: u8 = 8;
const DEATH: u8 = 9;
const HOPELESSNESS: u8 = 10;
const FAREWELL: u8 = 11;
const UNSAFE_ALONE: u8 = 12;
const VIOLENCE: u8 = 13;
const RETALIATION: u8 = 14;
const PROPERTY_HARM: u8 = 15;
const SECRECY: u8 = 16;
const ISOLATION: u8 = 17;
const PLATFORM: u8 = 18;
const MEETING: u8 = 19;
const MEDIA: u8 = 20;
const LOCATION: u8 = 21;
const GIFT: u8 = 22;
const CONCEALMENT: u8 = 23;
const TRUST: u8 = 24;
const FAMILY: u8 = 25;
const MINOR_AGE: u8 = 26;
const GUILT: u8 = 27;
const DEBT: u8 = 28;
const FALSE_CONSENSUS: u8 = 29;
const DEPENDENCY: u8 = 30;
const BLACKMAIL: u8 = 31;
const COMPEL: u8 = 32;
const BLAME: u8 = 33;
const ULTIMATUM: u8 = 34;
const DEVALUATION: u8 = 35;
const MOCKERY: u8 = 36;
const EXCLUSION: u8 = 37;
const HUMILIATION: u8 = 38;
const SEXUAL: u8 = 39;
const NUDE: u8 = 40;
const DISTRIBUTION: u8 = 41;
const CONSUMPTION: u8 = 42;
const CHANNEL: u8 = 43;
const ADULT_CONTENT: u8 = 44;
const CREDENTIAL: u8 = 45;
const AUTH_CODE: u8 = 46;
const PAYMENT: u8 = 47;
const LINK: u8 = 48;
const SERVICE_PRETEXT: u8 = 49;
const ACCOUNT_PROBLEM: u8 = 50;
const PRIZE: u8 = 51;
const ALONE: u8 = 52;
const LOVE: u8 = 53;
const APOLOGY: u8 = 54;
const IGNORE: u8 = 55;
const SOCIAL_GROUP: u8 = 56;
const SAFE_STATE: u8 = 57;
const NEGATION: u8 = 58;
const SELF_REFLEXIVE: u8 = 59;
const EXCLUSIVITY: u8 = 60;
const OBLIGATION: u8 = 61;
const CAUSAL: u8 = 62;
const ANGER: u8 = 63;
const FRIENDS: u8 = 64;
const ABSENCE: u8 = 65;
const BETTER_WITHOUT: u8 = 66;
const FINALITY: u8 = 67;
const ANAPHORIC_ACTION: u8 = 68;

/// Detects bounded compositional candidates without assigning final context.
///
/// # Errors
///
/// Returns a typed preparation error when attacker-controlled structure exceeds
/// a fixed semantic bound. Callers must keep the existing detector fallback and
/// must not treat this error as evidence that the message is safe.
pub(crate) fn detect(text: &str) -> Result<Vec<DomainCandidate>, SemanticPrepareError> {
    let (semantic, clauses) = prepare_concepts(text)?;

    let mut candidates = Vec::with_capacity(MAX_COMPOSITIONAL_CANDIDATES);
    let mut emitted = Concepts::default();
    for index in 0..clauses.len() {
        let window = clause_window(&semantic, &clauses, index);
        emit_matches(window, &mut emitted, &mut candidates);
        if candidates.len() == MAX_COMPOSITIONAL_CANDIDATES {
            break;
        }
    }
    Ok(candidates)
}

/// Returns whether an otherwise ambiguous message is an acute continuation of
/// already-confirmed self-harm context.
///
/// This deliberately cannot create a standalone self-harm candidate. The
/// conversation-memory boundary must first establish same-sender self-harm,
/// which keeps ordinary uses of words such as "done" and "end" from becoming
/// crisis alerts on their own.
pub(crate) fn is_ambiguous_self_harm_followup(text: &str) -> Result<bool, SemanticPrepareError> {
    let (semantic, clauses) = prepare_concepts(text)?;
    let combined = clauses
        .into_iter()
        .fold(Concepts::default(), Concepts::union);

    let finality_declaration = contains_token_sequence(&semantic, &["this", "is", "the", "end"])
        || contains_token_sequence(&semantic, &["це", "кінець"])
        || contains_token_sequence(&semantic, &["це", "все"])
        || contains_token_sequence(&semantic, &["это", "конец"])
        || contains_token_sequence(&semantic, &["это", "всё"])
        || contains_token_sequence(&semantic, &["это", "все"]);
    let farewell_finality = combined.contains(FAREWELL) && finality_declaration;
    let self_directed_finality = combined.contains(FIRST_PERSON)
        && (finality_declaration
            || combined.contains(FINALITY)
                && combined.contains(COMPEL)
                && combined.contains(ANAPHORIC_ACTION)
                && combined.contains_any(&[FUTURE, URGENCY]));

    Ok(farewell_finality || self_directed_finality)
}

fn contains_token_sequence(semantic: &PreparedSemanticText<'_>, expected: &[&str]) -> bool {
    if expected.is_empty() {
        return false;
    }
    semantic.tokens().windows(expected.len()).any(|tokens| {
        let Some(first) = tokens.first() else {
            return false;
        };
        tokens
            .iter()
            .all(|token| token.clause_index() == first.clause_index())
            && tokens.iter().zip(expected).all(|(token, expected)| {
                semantic
                    .slice(token.span())
                    .is_ok_and(|lexeme| eq_folded(lexeme, expected))
            })
    })
}

fn prepare_concepts(
    text: &str,
) -> Result<(PreparedSemanticText<'_>, Vec<Concepts>), SemanticPrepareError> {
    let semantic = PreparedSemanticText::new(text)?;
    let mut clauses = vec![Concepts::default(); semantic.clauses().len()];

    for atom in semantic.atoms() {
        let concept = match atom.kind() {
            SemanticAtomKind::ActorReference(ActorReferenceCandidate::FirstPerson) => {
                Some(FIRST_PERSON)
            }
            SemanticAtomKind::ActorReference(ActorReferenceCandidate::SecondPerson) => {
                Some(SECOND_PERSON)
            }
            SemanticAtomKind::ActorReference(ActorReferenceCandidate::ThirdPerson) => None,
            SemanticAtomKind::NegationCue => Some(NEGATION),
            SemanticAtomKind::ModalCue => Some(MODAL),
        };
        if let (Some(concept), Some(clause)) = (concept, clauses.get_mut(atom.clause_index())) {
            clause.insert(concept);
        }
    }

    for token in semantic.tokens() {
        let Some(clause) = clauses.get_mut(token.clause_index()) else {
            continue;
        };
        let Ok(lexeme) = semantic.slice(token.span()) else {
            continue;
        };
        classify_lexeme(lexeme, clause);
    }

    Ok((semantic, clauses))
}

fn clause_window(
    semantic: &PreparedSemanticText<'_>,
    clauses: &[Concepts],
    index: usize,
) -> Concepts {
    let mut window = clauses[index];
    if index > 0
        && matches!(
            semantic.clauses()[index - 1].terminator(),
            ClauseTerminator::Semicolon | ClauseTerminator::Colon | ClauseTerminator::LineBreak
        )
    {
        window = window.union(clauses[index - 1]);
    }
    if matches!(
        semantic.clauses()[index].terminator(),
        ClauseTerminator::Semicolon | ClauseTerminator::Colon | ClauseTerminator::LineBreak
    ) && index + 1 < clauses.len()
    {
        window = window.union(clauses[index + 1]);
    }
    window
}

fn emit_matches(concepts: Concepts, emitted: &mut Concepts, candidates: &mut Vec<DomainCandidate>) {
    if !emitted.contains(SELF_HARM) && matches_self_harm(concepts) {
        push_candidate(
            candidates,
            emitted,
            SELF_HARM,
            "semantic_self_harm_composition_v1",
            "kids.composition.selfharm.v1",
            "self_harm",
            0.96,
            "critical",
            98,
            DomainEventKind::SuicidalIdeation,
        );
    }
    if !emitted.contains(VIOLENCE) && matches_threat(concepts) {
        push_candidate(
            candidates,
            emitted,
            VIOLENCE,
            "semantic_direct_threat_composition_v1",
            "kids.composition.threat.v1",
            "threat",
            0.91,
            "high",
            95,
            DomainEventKind::PhysicalThreat,
        );
    }
    if !emitted.contains(SECRECY) && matches_grooming(concepts) {
        let event_kind = if concepts.contains(MEETING) {
            DomainEventKind::MeetingRequest
        } else if concepts.contains(MEDIA) {
            DomainEventKind::PhotoRequest
        } else if concepts.contains(LOCATION) {
            DomainEventKind::LocationRequest
        } else if concepts.contains(GIFT) {
            DomainEventKind::GiftOffer
        } else if concepts.contains(PLATFORM) {
            DomainEventKind::PlatformSwitch
        } else {
            DomainEventKind::SecrecyRequest
        };
        push_candidate(
            candidates,
            emitted,
            SECRECY,
            "semantic_grooming_composition_v1",
            "kids.composition.grooming.v1",
            "grooming",
            0.89,
            "high",
            94,
            event_kind,
        );
    }
    if !emitted.contains(COMPEL) && matches_manipulation(concepts) {
        let event_kind = if concepts.contains(DEBT) {
            DomainEventKind::DebtCreation
        } else if concepts.contains(FALSE_CONSENSUS) {
            DomainEventKind::FalseConsensus
        } else if concepts.contains(ISOLATION) || concepts.contains(DEPENDENCY) {
            DomainEventKind::NetworkPoisoning
        } else if concepts.contains(BLACKMAIL) || concepts.contains(ULTIMATUM) {
            DomainEventKind::EmotionalBlackmail
        } else {
            DomainEventKind::GuiltTripping
        };
        push_candidate(
            candidates,
            emitted,
            COMPEL,
            "semantic_manipulation_composition_v1",
            "kids.composition.manipulation.v1",
            "manipulation",
            0.87,
            "high",
            93,
            event_kind,
        );
    }
    if !emitted.contains(DEVALUATION) && matches_bullying(concepts) {
        let event_kind = if concepts.contains(EXCLUSION) {
            DomainEventKind::Exclusion
        } else if concepts.contains(MOCKERY) {
            DomainEventKind::Mockery
        } else {
            DomainEventKind::Denigration
        };
        push_candidate(
            candidates,
            emitted,
            DEVALUATION,
            "semantic_bullying_composition_v1",
            "kids.composition.bullying.v1",
            "bullying",
            0.88,
            "high",
            92,
            event_kind,
        );
    }
    if !emitted.contains(NUDE) && matches_explicit(concepts) {
        push_candidate(
            candidates,
            emitted,
            NUDE,
            "semantic_explicit_request_composition_v1",
            "kids.composition.explicit.v1",
            "explicit",
            0.94,
            "critical",
            97,
            DomainEventKind::SexualContent,
        );
    }
    if !emitted.contains(ADULT_CONTENT) && matches_nsfw(concepts) {
        push_candidate(
            candidates,
            emitted,
            ADULT_CONTENT,
            "semantic_nsfw_distribution_composition_v1",
            "kids.composition.nsfw.v1",
            "nsfw",
            0.96,
            "high",
            92,
            DomainEventKind::SexualContent,
        );
    }
    if !emitted.contains(CREDENTIAL) && matches_phishing(concepts) {
        push_candidate(
            candidates,
            emitted,
            CREDENTIAL,
            "semantic_phishing_request_composition_v1",
            "kids.composition.phishing.v1",
            "phishing",
            0.91,
            "high",
            95,
            DomainEventKind::PersonalInfoRequest,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "stable candidate metadata remains explicit at the domain boundary"
)]
fn push_candidate(
    candidates: &mut Vec<DomainCandidate>,
    emitted: &mut Concepts,
    family_marker: u8,
    threat_key: &str,
    reason_code: &str,
    threat_type: &str,
    score: f32,
    severity: &str,
    priority: u8,
    event_kind: DomainEventKind,
) {
    if candidates.len() >= MAX_COMPOSITIONAL_CANDIDATES {
        return;
    }
    emitted.insert(family_marker);
    candidates.push(DomainCandidate::new(
        DomainSignal {
            threat_key: threat_key.to_string(),
            score,
            reason_code: reason_code.to_string(),
            threat_type: Some(threat_type.to_string()),
            severity: Some(severity.to_string()),
            priority: Some(priority),
            action: None,
        },
        event_kind,
    ));
}

fn matches_self_harm(c: Concepts) -> bool {
    c.contains(FIRST_PERSON)
        && ((c.contains(SELF_HARM) && c.contains(SELF_REFLEXIVE) || c.contains(DEATH))
            && c.contains_any(&[INTENT, MODAL, FUTURE, URGENCY, FAREWELL])
            || c.contains(HOPELESSNESS)
            || c.contains(BETTER_WITHOUT) && c.contains(NEGATION)
            || c.contains(FAREWELL)
            || (c.contains(ALONE)
                && (c.contains(UNSAFE_ALONE) || c.contains(SAFE_STATE) && c.contains(NEGATION))))
}

fn matches_threat(c: Concepts) -> bool {
    c.contains(SECOND_PERSON)
        && c.contains_any(&[VIOLENCE, RETALIATION, PROPERTY_HARM])
        && c.contains_any(&[FIRST_PERSON, MODAL, FUTURE, CONDITIONAL, REQUEST, INTENT])
}

fn matches_grooming(c: Concepts) -> bool {
    (c.contains(SECRECY) && c.contains_any(&[CONCEALMENT, TRUST, MEETING, ISOLATION]))
        || (c.contains(SECRECY)
            && c.contains(FAMILY)
            && c.contains_any(&[SECOND_PERSON, CONCEALMENT]))
        || (c.contains(SECRECY) && c.contains(MEDIA) && c.contains(REQUEST))
        || (c.contains(FAMILY)
            && c.contains(TRUST)
            && c.contains_any(&[SECOND_PERSON, CONCEALMENT]))
        || (c.contains(ISOLATION) && c.contains_any(&[TRUST, MEETING, MEDIA]))
        || (c.contains(PLATFORM)
            && (c.contains(CONCEALMENT)
                || c.contains(SECRECY) && c.contains(FAMILY) && c.contains(SECOND_PERSON)))
        || (c.contains(GIFT) && c.contains_any(&[MEETING, ALONE, REQUEST]))
        || (c.contains(MEDIA)
            && (c.contains(ALONE) && c.contains(ISOLATION)
                || c.contains(CONCEALMENT) && c.contains_any(&[SECRECY, REQUEST])))
        || (c.contains(LOCATION)
            && c.contains(MEETING)
            && c.contains_any(&[ALONE, SECRECY, CONCEALMENT]))
        || (c.contains(MINOR_AGE) && c.contains_any(&[PLATFORM, SECRECY, TRUST]))
}

fn matches_manipulation(c: Concepts) -> bool {
    (c.contains(GUILT) && c.contains_any(&[COMPEL, REQUEST, LOVE]))
        || (c.contains(DEBT)
            && c.contains_any(&[COMPEL, REQUEST, GUILT, FIRST_PERSON, SECOND_PERSON]))
        || (c.contains(FALSE_CONSENSUS) && c.contains(DEVALUATION))
        || (c.contains(ISOLATION) && c.contains(TRUST))
        || (c.contains(EXCLUSIVITY)
            && c.contains_any(&[TRUST, DEPENDENCY])
            && c.contains(FIRST_PERSON)
            && c.contains(SECOND_PERSON))
        || (c.contains(ISOLATION)
            && c.contains(COMPEL)
            && c.contains(SECOND_PERSON)
            && c.contains(EXCLUSION))
        || (c.contains(OBLIGATION) && c.contains(COMPEL) && c.contains(SECOND_PERSON))
        || (c.contains(CAUSAL)
            && c.contains(ANGER)
            && c.contains(FIRST_PERSON)
            && c.contains(SECOND_PERSON))
        || (c.contains(BLAME) && c.contains_any(&[DEVALUATION, COMPEL]))
        || (c.contains(BLAME) && c.contains(FIRST_PERSON) && c.contains(SECOND_PERSON))
        || (c.contains(BLACKMAIL) && c.contains_any(&[COMPEL, REQUEST, CONDITIONAL]))
        || (c.contains(ULTIMATUM) && c.contains_any(&[COMPEL, FAMILY, LOVE]))
        || (c.contains(IGNORE) && c.contains_any(&[APOLOGY, CONDITIONAL, COMPEL]))
}

fn matches_bullying(c: Concepts) -> bool {
    c.contains(SECOND_PERSON)
        && (c.contains_any(&[DEVALUATION, MOCKERY, EXCLUSION, HUMILIATION])
            || c.contains(FRIENDS) && c.contains(ABSENCE))
}

fn matches_explicit(c: Concepts) -> bool {
    c.contains_any(&[SEXUAL, NUDE])
        && c.contains_any(&[MEDIA, SECOND_PERSON])
        && c.contains_any(&[REQUEST, INTENT, SECOND_PERSON, DISTRIBUTION, COMPEL])
        && (c.contains(NUDE)
            || !c.contains(ADULT_CONTENT) && !c.contains(CONSUMPTION) && !c.contains(CHANNEL))
}

fn matches_nsfw(c: Concepts) -> bool {
    c.contains_any(&[SEXUAL, NUDE]) && c.contains_any(&[CONSUMPTION, CHANNEL, ADULT_CONTENT])
}

fn matches_phishing(c: Concepts) -> bool {
    (c.contains_any(&[CREDENTIAL, AUTH_CODE, PAYMENT, PRIZE])
        && c.contains_any(&[REQUEST, URGENCY, LINK, SERVICE_PRETEXT, ACCOUNT_PROBLEM]))
        || (c.contains(ACCOUNT_PROBLEM) && c.contains(LINK) && c.contains(REQUEST))
        || (c.contains(SERVICE_PRETEXT) && c.contains(LINK) && c.contains(REQUEST))
}

fn classify_lexeme(lexeme: &str, concepts: &mut Concepts) {
    mark_exact(
        lexeme,
        concepts,
        INTENT,
        &[
            "want",
            "wish",
            "plan",
            "planning",
            "thinking",
            "looking",
            "intend",
            "going",
            "хочу",
            "бажаю",
            "планую",
            "думаю",
            "шукаю",
            "збираюся",
            "хотів",
            "хочу",
            "желаю",
            "планирую",
            "думаю",
            "ищу",
            "собираюсь",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        FUTURE,
        &[
            "will",
            "tomorrow",
            "tonight",
            "after",
            "later",
            "буду",
            "завтра",
            "сьогодні",
            "після",
            "потім",
            "сегодня",
            "после",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        CONDITIONAL,
        &[
            "if",
            "unless",
            "until",
            "otherwise",
            "or",
            "якщо",
            "доки",
            "інакше",
            "або",
            "если",
            "пока",
            "иначе",
            "или",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        REQUEST,
        &[
            "send",
            "show",
            "open",
            "watch",
            "share",
            "tell",
            "enter",
            "confirm",
            "reply",
            "install",
            "update",
            "turn",
            "record",
            "take",
            "undress",
            "pose",
            "sign",
            "login",
            "move",
            "join",
            "claim",
            "надішл",
            "покаж",
            "відкри",
            "диви",
            "поділи",
            "скажи",
            "введ",
            "підтверд",
            "встанов",
            "онов",
            "увімк",
            "запиш",
            "роздяг",
            "позув",
            "увій",
            "перейд",
            "приєдн",
            "забер",
            "пришл",
            "покаж",
            "откро",
            "смотр",
            "подел",
            "скажи",
            "введ",
            "подтверд",
            "установ",
            "обнов",
            "включ",
            "запиш",
            "разден",
            "раздев",
            "позир",
            "войд",
            "перейд",
            "присоедин",
            "забер",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        URGENCY,
        &[
            "now",
            "immediately",
            "urgent",
            "today",
            "tonight",
            "зараз",
            "негайно",
            "терміново",
            "сьогодні",
            "сейчас",
            "немедленно",
            "срочно",
            "сегодня",
        ],
    );

    mark_prefix(
        lexeme,
        concepts,
        SELF_HARM,
        &[
            "selfharm",
            "suicid",
            "hurt",
            "harm",
            "самогуб",
            "суїцид",
            "нашкод",
            "шкод",
            "навред",
            "самопошкод",
            "суицид",
            "вред",
            "самоповрежд",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        DEATH,
        &[
            "die",
            "dying",
            "death",
            "kill",
            "dead",
            "end",
            "wake",
            "помер",
            "смерт",
            "вбит",
            "прокин",
            "покінч",
            "умер",
            "смерт",
            "убит",
            "просну",
            "поконч",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        HOPELESSNESS,
        &[
            "hopeless",
            "worthless",
            "disappear",
            "безнаді",
            "зник",
            "безнадеж",
            "исчез",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        BETTER_WITHOUT,
        &["better", "краще", "лучше"],
    );
    mark_prefix(
        lexeme,
        concepts,
        FAREWELL,
        &["goodbye", "farewell", "прощ", "прощ"],
    );
    mark_prefix(
        lexeme,
        concepts,
        FINALITY,
        &[
            "finally",
            "done",
            "end",
            "finish",
            "нарешті",
            "закінч",
            "кінец",
            "заверш",
            "наконец",
            "конец",
            "оконч",
            "заверш",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        ANAPHORIC_ACTION,
        &["it", "all", "everything", "це", "это", "все"],
    );
    mark_prefix(
        lexeme,
        concepts,
        UNSAFE_ALONE,
        &["unsafe", "небезп", "небезопас"],
    );
    mark_exact(
        lexeme,
        concepts,
        SAFE_STATE,
        &["safe", "безпечно", "безопасно"],
    );
    mark_exact(
        lexeme,
        concepts,
        FIRST_PERSON,
        &[
            "myself",
            "себе",
            "собі",
            "собою",
            "собі",
            "собой",
            "мене",
            "меня",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        SELF_REFLEXIVE,
        &["myself", "ourselves", "себе", "собі", "собою", "собой"],
    );
    mark_exact(
        lexeme,
        concepts,
        SECOND_PERSON,
        &[
            "your",
            "yourself",
            "твоя",
            "твоє",
            "твою",
            "твої",
            "тобою",
            "твой",
            "твоя",
            "твоё",
            "твое",
            "твою",
            "твои",
            "тобой",
        ],
    );
    mark_prefix(lexeme, concepts, SECOND_PERSON, &["тво", "ваш"]);

    mark_prefix(
        lexeme,
        concepts,
        VIOLENCE,
        &[
            "hurt",
            "harm",
            "attack",
            "beat",
            "injur",
            "напад",
            "напаст",
            "поб",
            "завдам",
            "нашкод",
            "постраж",
            "изоб",
            "напаст",
            "причин",
            "навред",
            "пострада",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        RETALIATION,
        &[
            "regret",
            "come",
            "find",
            "пошкод",
            "пошкоду",
            "заплат",
            "знайд",
            "добер",
            "пожале",
            "найд",
        ],
    );
    mark_exact(lexeme, concepts, RETALIATION, &["pay"]);
    mark_prefix(
        lexeme,
        concepts,
        PROPERTY_HARM,
        &["destroy", "break", "знищ", "злама", "уничтож", "слома"],
    );

    mark_prefix(
        lexeme,
        concepts,
        SECRECY,
        &[
            "secret",
            "private",
            "between",
            "quiet",
            "таєм",
            "секрет",
            "приват",
            "мовч",
            "секрет",
            "личн",
            "молч",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        ISOLATION,
        &[
            "alone",
            "isolate",
            "separate",
            "наодин",
            "розлуч",
            "наедин",
            "разлуч",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        EXCLUSIVITY,
        &["only", "лише", "тільки", "только"],
    );
    mark_prefix(
        lexeme,
        concepts,
        PLATFORM,
        &[
            "chat",
            "message",
            "app",
            "platform",
            "чат",
            "повідом",
            "додат",
            "платформ",
            "сообщ",
            "прилож",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        MEETING,
        &["meet", "meeting", "зустр", "побач", "встрет"],
    );
    mark_prefix(
        lexeme,
        concepts,
        MEDIA,
        &[
            "photo",
            "picture",
            "video",
            "camera",
            "record",
            "image",
            "clip",
            "file",
            "attachment",
            "фото",
            "зображ",
            "відео",
            "камер",
            "ролик",
            "файл",
            "вкладен",
            "картин",
            "изображ",
            "видео",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        LOCATION,
        &[
            "where",
            "location",
            "address",
            "schedule",
            "school",
            "де",
            "адрес",
            "розклад",
            "школ",
            "где",
            "расписан",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        GIFT,
        &["gift", "buy", "подар", "куп", "подар", "куп"],
    );
    mark_prefix(
        lexeme,
        concepts,
        CONCEALMENT,
        &[
            "delete",
            "hide",
            "nobody",
            "cannot",
            "can't",
            "видал",
            "схов",
            "ніхто",
            "удал",
            "скры",
            "никто",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        TRUST,
        &[
            "trust",
            "understand",
            "special",
            "довір",
            "розумі",
            "особлив",
            "довер",
            "понима",
            "особенн",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        FAMILY,
        &[
            "parent",
            "adult",
            "family",
            "mother",
            "father",
            "бать",
            "доросл",
            "родин",
            "мам",
            "тат",
            "родител",
            "взросл",
            "семь",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        MINOR_AGE,
        &[
            "age",
            "mature",
            "years",
            "віку",
            "доросл",
            "років",
            "возраст",
            "взросл",
            "лет",
        ],
    );
    mark_exact(
        lexeme,
        concepts,
        ALONE,
        &["alone", "наодинці", "один", "наедине"],
    );

    mark_prefix(
        lexeme,
        concepts,
        GUILT,
        &[
            "care",
            "prove",
            "responsib",
            "дбав",
            "довед",
            "відповідал",
            "забот",
            "докаж",
            "ответствен",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        DEBT,
        &["owe", "debt", "винен", "борг", "долж", "долг"],
    );
    mark_prefix(
        lexeme,
        concepts,
        FALSE_CONSENSUS,
        &["everyone", "everybody", "all", "усі", "кожен", "всі", "все"],
    );
    mark_prefix(
        lexeme,
        concepts,
        DEPENDENCY,
        &["listen", "understand", "слух", "розумі", "слуш", "понима"],
    );
    mark_prefix(
        lexeme,
        concepts,
        BLACKMAIL,
        &[
            "blackmail",
            "expose",
            "шантаж",
            "оприлюд",
            "шантаж",
            "опубли",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        COMPEL,
        &[
            "agree",
            "listen",
            "apolog",
            "зроб",
            "погод",
            "слух",
            "вибач",
            "сдел",
            "соглас",
            "слуш",
            "извин",
        ],
    );
    mark_exact(lexeme, concepts, COMPEL, &["do"]);
    mark_exact(lexeme, concepts, OBLIGATION, &["must", "should"]);
    mark_prefix(lexeme, concepts, OBLIGATION, &["мус", "повин", "долж"]);
    mark_prefix(
        lexeme,
        concepts,
        BLAME,
        &["fault", "problem", "вин", "проблем"],
    );
    mark_exact(lexeme, concepts, CAUSAL, &["because", "бо", "из"]);
    mark_prefix(lexeme, concepts, CAUSAL, &["через", "потому"]);
    mark_prefix(
        lexeme,
        concepts,
        ANGER,
        &["angry", "розлю", "злил", "разозл"],
    );
    mark_prefix(
        lexeme,
        concepts,
        ULTIMATUM,
        &[
            "choose",
            "lose",
            "refuse",
            "обира",
            "втрат",
            "відмов",
            "выбира",
            "потер",
            "отказ",
        ],
    );
    mark_prefix(lexeme, concepts, LOVE, &["love", "кохан", "люб"]);
    mark_prefix(lexeme, concepts, APOLOGY, &["apolog", "вибач", "извин"]);
    mark_prefix(lexeme, concepts, IGNORE, &["ignore", "ігнор", "игнор"]);

    mark_prefix(
        lexeme,
        concepts,
        DEVALUATION,
        &[
            "stupid",
            "pathetic",
            "worthless",
            "loser",
            "disgust",
            "дурн",
            "жалюг",
            "невдах",
            "огид",
            "проблем",
            "глуп",
            "жалк",
            "неудач",
            "отврат",
        ],
    );
    mark_exact(lexeme, concepts, DEVALUATION, &["problem", "wrong"]);
    mark_prefix(
        lexeme,
        concepts,
        MOCKERY,
        &["laugh", "mock", "ridicul", "смі", "насміх", "издев", "сме"],
    );
    mark_prefix(lexeme, concepts, EXCLUSION, &["nobody", "ніхто", "никто"]);
    mark_prefix(lexeme, concepts, FRIENDS, &["friends", "друз"]);
    mark_exact(lexeme, concepts, ABSENCE, &["no", "нет"]);
    mark_prefix(lexeme, concepts, ABSENCE, &["нема"]);
    mark_prefix(
        lexeme,
        concepts,
        HUMILIATION,
        &["ruin", "псу", "замовк", "зіпс", "порт", "замолч"],
    );
    mark_prefix(
        lexeme,
        concepts,
        SOCIAL_GROUP,
        &["group", "school", "everyone", "груп", "школ", "усі", "все"],
    );

    mark_prefix(
        lexeme,
        concepts,
        SEXUAL,
        &[
            "sex",
            "sexual",
            "intimate",
            "porn",
            "explicit",
            "інтим",
            "сексуал",
            "порн",
            "відверт",
            "интим",
            "сексуал",
            "откров",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        NUDE,
        &[
            "nude",
            "naked",
            "undress",
            "unclothed",
            "clothes",
            "оголен",
            "роздяг",
            "одяг",
            "обнаж",
            "раздев",
            "разден",
            "одежд",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        DISTRIBUTION,
        &[
            "send",
            "share",
            "post",
            "publish",
            "forward",
            "надсил",
            "поділи",
            "опублік",
            "обмін",
            "отправ",
            "пришл",
            "подел",
            "опубли",
            "обмен",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        CONSUMPTION,
        &[
            "open",
            "watch",
            "see",
            "view",
            "відкри",
            "див",
            "побач",
            "откро",
            "смотр",
            "увид",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        CHANNEL,
        &["group", "channel", "chat", "груп", "канал", "чат"],
    );
    mark_prefix(
        lexeme,
        concepts,
        ADULT_CONTENT,
        &[
            "adult",
            "graphic",
            "uncensor",
            "explicit",
            "доросл",
            "відверт",
            "цензур",
            "взросл",
            "откров",
        ],
    );

    mark_prefix(
        lexeme,
        concepts,
        CREDENTIAL,
        &[
            "password",
            "login",
            "credential",
            "identity",
            "detail",
            "card",
            "парол",
            "логін",
            "увій",
            "особ",
            "дан",
            "карт",
            "логин",
            "войд",
            "личност",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        AUTH_CODE,
        &["code", "otp", "код", "однораз"],
    );
    mark_prefix(
        lexeme,
        concepts,
        PAYMENT,
        &[
            "payment",
            "bank",
            "card",
            "платіж",
            "банк",
            "карт",
            "платеж",
        ],
    );
    mark_exact(lexeme, concepts, LINK, &["link", "url"]);
    mark_prefix(
        lexeme,
        concepts,
        SERVICE_PRETEXT,
        &[
            "support",
            "security",
            "verify",
            "update",
            "fix",
            "підтрим",
            "безпек",
            "підтверд",
            "онов",
            "виправ",
            "поддерж",
            "безопас",
            "подтверд",
            "обнов",
            "исправ",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        ACCOUNT_PROBLEM,
        &[
            "account",
            "locked",
            "suspend",
            "failed",
            "обліков",
            "заблок",
            "блокув",
            "помил",
            "учёт",
            "учет",
            "заблок",
            "приостанов",
        ],
    );
    mark_prefix(
        lexeme,
        concepts,
        PRIZE,
        &[
            "prize",
            "won",
            "reward",
            "приз",
            "виграв",
            "нагород",
            "выиграл",
        ],
    );
}

fn mark_exact(lexeme: &str, concepts: &mut Concepts, concept: u8, terms: &[&str]) {
    if terms.iter().any(|term| eq_folded(lexeme, term)) {
        concepts.insert(concept);
    }
}

fn mark_prefix(lexeme: &str, concepts: &mut Concepts, concept: u8, stems: &[&str]) {
    if stems.iter().any(|stem| starts_with_folded(lexeme, stem)) {
        concepts.insert(concept);
    }
}

fn eq_folded(value: &str, expected_lower: &str) -> bool {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .eq(expected_lower.chars())
}

fn starts_with_folded(value: &str, prefix_lower: &str) -> bool {
    let mut folded = value.chars().flat_map(char::to_lowercase);
    for expected in prefix_lower.chars() {
        if folded.next() != Some(expected) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{detect, is_ambiguous_self_harm_followup};
    use aura_domain::{DomainEventKind, QuoteContext};

    fn families(text: &str) -> Vec<String> {
        detect(text)
            .expect("bounded semantic preparation")
            .into_iter()
            .filter_map(|candidate| candidate.signal.threat_type)
            .collect()
    }

    #[test]
    fn detects_self_harm_and_threat_compositions_across_languages() {
        let cases = [
            ("I plan to harm myself after everyone sleeps.", "self_harm"),
            ("Я хочу зникнути й більше не прокинутися.", "self_harm"),
            ("Я могу навредить себе сегодня.", "self_harm"),
            ("I will attack you after school.", "threat"),
            ("Завтра я тебе поб'ю.", "threat"),
            ("Если ты скажешь, я причиню тебе вред.", "threat"),
        ];

        for (text, family) in cases {
            assert!(families(text).iter().any(|item| item == family), "{text}");
        }
    }

    #[test]
    fn identifies_only_structured_ambiguous_self_harm_followups() {
        for text in [
            "Goodbye everyone. This is the end.",
            "tonight feels like the night i finally do it",
            "I'll finally do it tonight",
            "im done trying, this is the end",
            "Сьогодні я нарешті це зроблю.",
            "Сегодня я наконец это сделаю.",
            "Прощавайте. Це кінець.",
        ] {
            assert!(
                is_ambiguous_self_harm_followup(text).expect("bounded semantic preparation"),
                "{text}"
            );
            assert!(
                !families(text).iter().any(|family| family == "self_harm"),
                "ambiguous followup must not become standalone evidence: {text}"
            );
        }

        for text in [
            "Goodbye everyone, the school meeting is done.",
            "I'm done trying to solve this homework tonight.",
            "This is the end of the movie.",
            "Я нарешті закінчу звіт сьогодні.",
            "Я наконец закончу отчёт сегодня.",
        ] {
            assert!(
                !is_ambiguous_self_harm_followup(text).expect("bounded semantic preparation"),
                "{text}"
            );
        }
    }

    #[test]
    fn detects_grooming_manipulation_and_bullying_compositions() {
        let cases = [
            ("Keep our private chat secret from your family.", "grooming"),
            (
                "Куплю подарунок, якщо зустрінешся зі мною наодинці.",
                "grooming",
            ),
            (
                "After all I did, you owe me and must agree.",
                "manipulation",
            ),
            ("Не довіряй друзям, лише я тебе розумію.", "manipulation"),
            ("You are pathetic and nobody wants you here.", "bullying"),
            ("Ти жалюгідний, усі з тебе сміються.", "bullying"),
        ];

        for (text, family) in cases {
            assert!(families(text).iter().any(|item| item == family), "{text}");
        }
    }

    #[test]
    fn separates_explicit_exchange_nsfw_distribution_and_phishing() {
        let cases = [
            ("Send me an intimate nude photo.", "explicit"),
            ("Надішли мені оголене інтимне фото.", "explicit"),
            (
                "Share uncensored adult sexual content in the group.",
                "nsfw",
            ),
            ("Watch this explicit adult clip now.", "nsfw"),
            ("Открой порнографическое видео в канале.", "nsfw"),
            ("Enter your password at [LINK] now.", "phishing"),
            ("Надішли одноразовий код підтвердження.", "phishing"),
        ];

        for (text, family) in cases {
            assert!(families(text).iter().any(|item| item == family), "{text}");
        }
    }

    #[test]
    fn emits_multiple_independent_families_and_typed_routes() {
        let candidates = detect(
            "Prove your love: send me a nude photo and keep the private chat secret from family.",
        )
        .expect("bounded semantic preparation");

        assert!(candidates
            .iter()
            .any(
                |candidate| candidate.signal.threat_type.as_deref() == Some("explicit")
                    && candidate.event_kind == DomainEventKind::SexualContent
            ));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.signal.threat_type.as_deref() == Some("grooming")));
    }

    #[test]
    fn nearby_taxonomies_do_not_collapse_into_each_other() {
        let threat = families("I will hurt you tomorrow.");
        assert!(threat.iter().any(|family| family == "threat"));
        assert!(!threat.iter().any(|family| family == "self_harm"));

        let phishing = families("Your payment failed; update your card at [LINK].");
        assert!(phishing.iter().any(|family| family == "phishing"));
        assert!(!phishing.iter().any(|family| family == "threat"));

        let explicit = families("Send me a nude photo of yourself.");
        assert!(explicit.iter().any(|family| family == "explicit"));
        assert!(!explicit.iter().any(|family| family == "nsfw"));

        let nsfw = families("Open this uncensored adult porn clip.");
        assert!(nsfw.iter().any(|family| family == "nsfw"));
        assert!(!nsfw.iter().any(|family| family == "explicit"));
    }

    #[test]
    fn quoted_content_remains_raw_evidence_for_interpreter_confirmation() {
        let text = "She reported: “send me a nude photo”.";
        let candidates = detect(text).expect("bounded semantic preparation");

        assert!(candidates
            .iter()
            .any(|candidate| candidate.signal.threat_type.as_deref() == Some("explicit")));
        let semantic = aura_domain::PreparedSemanticText::new(text).expect("semantic input");
        assert!(semantic
            .tokens()
            .iter()
            .any(|token| matches!(token.quote_context(), QuoteContext::Closed { .. })));
    }

    #[test]
    fn benign_single_dimension_messages_do_not_compose() {
        for text in [
            "The family photo is in our private album.",
            "I forgot my password yesterday.",
            "We will meet the teacher at school.",
            "This adult bought a normal gift.",
            "The documentary discusses online safety.",
            "Can you explain what you want to discuss?",
            "Що ти хочеш обговорити?",
            "Скажи ясно, чего ты хочешь.",
        ] {
            assert!(
                detect(text)
                    .expect("bounded semantic preparation")
                    .is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn benign_multidimensional_context_does_not_self_compose_from_shared_tokens() {
        for text in [
            "Only use the parent chat; do not send documents privately.",
            "I will not handle this alone because your safety matters and an adult should be with us.",
            "Тільки не показуй нікому цей мем, він кринжовий.",
            "I support your friends and I understand you.",
            "The documentary explains why you should ask an adult for help.",
            "The library makerspace is open to students this Saturday with parents present.",
            "Скинь підтвердження поїздки в батьківський чат до восьмої вечора.",
            "I can tell you get me better than other kids do.",
            "Move to Telegram later; game chat logs everything.",
        ] {
            assert!(
                detect(text)
                    .expect("bounded semantic preparation")
                    .is_empty(),
                "{text}: {:?}",
                families(text)
            );
        }
    }

    #[test]
    fn exclusive_dependency_is_manipulation_not_grooming() {
        for text in [
            "Only I understand you, so listen only to me.",
            "Лише я тебе розумію, тому слухай тільки мене.",
            "Только я тебя понимаю, поэтому слушай только меня.",
        ] {
            let detected = families(text);
            assert!(
                detected.iter().any(|family| family == "manipulation"),
                "{text}"
            );
            assert!(
                !detected.iter().any(|family| family == "grooming"),
                "{text}"
            );
        }
    }

    #[test]
    fn absence_of_friends_and_causal_anger_require_independent_anchors() {
        for text in [
            "You have no friends because something is wrong with you.",
            "У тебе немає друзів, бо з тобою щось не так.",
            "У тебя нет друзей, потому что с тобой что-то не так.",
        ] {
            assert!(
                families(text).iter().any(|family| family == "bullying"),
                "{text}"
            );
        }

        for text in [
            "I feel like everyone would be better without me.",
            "Мені здається, що всім було б краще без мене.",
            "Мне кажется, что всем было бы лучше без меня.",
        ] {
            assert!(
                families(text).iter().any(|family| family == "self_harm"),
                "{text}"
            );
        }

        assert!(families("Это случилось из-за того, что ты меня разозлил.")
            .iter()
            .any(|family| family == "manipulation"));

        for text in [
            "Your friends are waiting outside.",
            "Твої друзі чекають біля входу.",
            "You made me angry, but I am taking time to calm down instead of blaming you.",
        ] {
            assert!(
                detect(text)
                    .expect("bounded semantic preparation")
                    .is_empty(),
                "{text}: {:?}",
                families(text)
            );
        }
    }
}
