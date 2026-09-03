//! Multilingual, compositional KIDS-domain candidate detection.
//!
//! This layer combines independent lexical dimensions into typed candidates.
//! It intentionally does not decide author stance, speech act, directionality,
//! reciprocity, memory eligibility, or product action. Those decisions remain
//! owned by the core context interpreter and policy stages.
//!
//! Lexeme classification is table-driven. Prefix stems must be at least
//! `MIN_PREFIX_STEM_CHARS` characters long unless they are listed in
//! `SHORT_STEM_ALLOWLIST`, and every family predicate requires a strong
//! anchor concept in addition to pronoun or tense evidence, so everyday chat
//! such as "no problem", "take care" or "my phone is dead" cannot compose.

use aura_domain::{
    ActorReferenceCandidate, ClauseTerminator, DomainCandidate, DomainEventKind, DomainSignal,
    PreparedSemanticText, SemanticAtomKind, SemanticPrepareError,
};

mod lexicon;
mod rules;

use lexicon::{classify_lexeme, eq_folded, SEQUENCE_TABLE};
#[cfg(test)]
use lexicon::{EXACT_TABLE, PREFIX_TABLE, SAME_PREDICATE_CONFLICTS, SHORT_STEM_ALLOWLIST};
use rules::{emit_matches, families_for};

const MAX_COMPOSITIONAL_CANDIDATES: usize = 8;

/// Minimum length of a prefix stem outside `SHORT_STEM_ALLOWLIST`. Enforced
/// by the table invariant tests.
#[cfg(test)]
const MIN_PREFIX_STEM_CHARS: usize = 5;

#[derive(Clone, Copy, Default)]
struct Concepts(u128);

impl Concepts {
    const fn from_ids(concepts: &[u8]) -> Self {
        let mut value = 0_u128;
        let mut index = 0;
        while index < concepts.len() {
            value |= 1_u128 << concepts[index];
            index += 1;
        }
        Self(value)
    }

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

    const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    const fn intersects(self, candidates: Self) -> bool {
        self.0 & candidates.0 != 0
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
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
const DEATH_VERB: u8 = 9;
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
const MINIMIZATION: u8 = 69;
const DEAD_STATE: u8 = 70;
const KILL: u8 = 71;
const NO_WAKE: u8 = 72;
const VANISH: u8 = 73;
const WHEN: u8 = 74;
const HIDDEN_FROM: u8 = 75;
const AFFECT_VERB: u8 = 76;
const FOREVER: u8 = 77;
const HERE: u8 = 78;
const WITHOUT_ME: u8 = 79;
const HYPERBOLE: u8 = 80;
const MESSAGES: u8 = 81;
const MISUNDERSTOOD: u8 = 82;
const SELF_IMAGE: u8 = 83;
const SHARED_CHANNEL: u8 = 84;
const EXPOSURE_THREAT: u8 = 85;

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

/// Per-clause view of the composition layer for the context interpreter's
/// attribution probe. It reuses the exact family predicates of [`detect`] but
/// never emits candidates, so it cannot change memory or policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClauseProbe {
    pub clause_index: usize,
    /// Composition families matched by this clause window, as threat labels.
    pub families: Vec<&'static str>,
    pub first_person: bool,
    pub second_person: bool,
    /// The clause orders the reader to carry out an anaphoric action
    /// ("do it now", "send it"), which turns a quoted request into the
    /// author's own request.
    pub compliance_directive: bool,
}

/// Runs the composition predicates per clause window without emitting
/// candidates.
///
/// # Errors
///
/// Returns the semantic preparation error when bounded preparation fails; the
/// caller must fail closed.
pub fn probe_clauses(text: &str) -> Result<Vec<ClauseProbe>, SemanticPrepareError> {
    let (semantic, clauses) = prepare_concepts(text)?;
    let mut probes = Vec::with_capacity(clauses.len());
    for index in 0..clauses.len() {
        let window = clause_window(&semantic, &clauses, index);
        let clause = clauses[index];
        // Actor flags follow the same window as the families so a first-person
        // neighbour clause cannot claim a second-person clause's self-harm.
        probes.push(ClauseProbe {
            clause_index: index,
            families: families_for(window).into_iter().flatten().collect(),
            first_person: window.contains(FIRST_PERSON),
            second_person: window.contains(SECOND_PERSON),
            // Urgency or a request verb alone ("reporting it to the teacher
            // now", "not agreeing with it") is not a directive; the clause must
            // compel the action ("do it now").
            compliance_directive: clause.contains(ANAPHORIC_ACTION)
                && clause.contains(COMPEL)
                && !clause.contains(NEGATION),
        });
    }
    Ok(probes)
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

    mark_clause_sequences(&semantic, &mut clauses);

    Ok((semantic, clauses))
}

/// Marks multi-token concepts that only exist as a same-clause sequence, such
/// as `end my life`, `between us` or `проблема в тобі`.
fn mark_clause_sequences(semantic: &PreparedSemanticText<'_>, clauses: &mut [Concepts]) {
    let tokens = semantic.tokens();
    for (concept, sequences) in SEQUENCE_TABLE {
        for sequence in *sequences {
            if sequence.is_empty() || tokens.len() < sequence.len() {
                continue;
            }
            for window in tokens.windows(sequence.len()) {
                let clause_index = window[0].clause_index();
                if !window
                    .iter()
                    .all(|token| token.clause_index() == clause_index)
                {
                    continue;
                }
                let matched = window.iter().zip(*sequence).all(|(token, expected)| {
                    semantic
                        .slice(token.span())
                        .is_ok_and(|lexeme| eq_folded(lexeme, expected))
                });
                if matched {
                    if let Some(clause) = clauses.get_mut(clause_index) {
                        clause.insert(*concept);
                    }
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{
        detect, is_ambiguous_self_harm_followup, probe_clauses, EXACT_TABLE, MIN_PREFIX_STEM_CHARS,
        PREFIX_TABLE, SAME_PREDICATE_CONFLICTS, SEQUENCE_TABLE, SHORT_STEM_ALLOWLIST,
    };
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
    fn credential_requests_with_minimizing_pressure_emit_both_risk_families() {
        for text in [
            "Send your password for a minute, don't be dramatic.",
            "Скинь пароль на хвилину, не драматизуй.",
            "Скинь пароль на минуту, не драматизируй.",
        ] {
            let detected = families(text);
            assert!(detected.iter().any(|family| family == "phishing"), "{text}");
            assert!(
                detected.iter().any(|family| family == "manipulation"),
                "{text}"
            );
        }

        for text in [
            "The drama club updated its password policy.",
            "I forgot my password and the movie was dramatic.",
            "Не надсилай свій пароль нікому.",
        ] {
            assert!(
                !families(text).iter().any(|family| family == "manipulation"),
                "{text}"
            );
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

    #[test]
    fn benign_everyday_phrases_do_not_compose() {
        for text in [
            "no problem",
            "Take care!",
            "my phone is dead, I will call you later",
            "I want to kill this level",
            "Can you come over tomorrow?",
            "I can't open the file",
            "we won the match today",
            "Don't forget your clothes for PE",
            "you must do your homework",
            "я побачу тебе завтра",
            "я должен идти",
            "Login",
            "відверто кажучи, я не знаю",
            "откровенно говоря, мне всё равно",
            "у мене зникла мережа",
            "I'm dead tired after the hike, going to sleep early",
            "I don't feel safe walking alone at night so my dad will drive me",
            "I'm better without sugar honestly",
            "я долго ждал",
            "nobody told you about the test?",
            "I'll wake you up tomorrow, don't miss the bus again",
            "goodbye, I'm off to school, talk later",
            "the code for the classroom door changed, ask the teacher",
            "the login page keeps saying wrong password, I need to reset it",
            "умираю с голоду после похода",
            "я помираю з голоду після походу",
            "bring your card for the library, they check now",
            "update the app, the old version doesn't work anymore",
            "delete the app, it keeps crashing",
            "my knee still hurts from the game but it's getting better",
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
    fn developer_challenge_formulations_still_compose() {
        let cases: &[(&str, &[&str])] = &[
            (
                "grooming",
                &[
                    "Keep this between us and do not tell your parents.",
                    "You are mature for your age, so message me privately.",
                    "Ти дуже дорослий для свого віку, тому напиши мені приватно.",
                    "Ты очень взрослый для своего возраста, поэтому напиши мне лично.",
                    "Move to a secret chat where adults cannot see us.",
                    "Перейди в таємний чат, де дорослі нас не побачать.",
                    "Перейди в секретный чат, где взрослые нас не увидят.",
                    "Send me a private photo that nobody else can see.",
                    "Надішли мені приватне фото, якого більше ніхто не побачить.",
                    "Пришли мне личное фото, которое больше никто не увидит.",
                    "Prove that you trust me by keeping our talks secret.",
                    "Доведи, що довіряєш мені, і тримай наші розмови в таємниці.",
                    "Докажи, что доверяешь мне, и держи наши разговоры в секрете.",
                    "I will buy you a gift if you meet me alone.",
                    "Я куплю тобі подарунок, якщо зустрінешся зі мною наодинці.",
                    "Я куплю тебе подарок, если встретишься со мной наедине.",
                    "Delete our messages after you read them.",
                    "Видаляй наші повідомлення після прочитання.",
                    "Удаляй наши сообщения после прочтения.",
                    "Your family would not understand our special friendship.",
                    "Твоя родина не зрозуміє нашої особливої дружби.",
                    "Твоя семья не поймёт нашей особенной дружбы.",
                    "Turn on the camera only when you are alone.",
                    "Увімкни камеру лише тоді, коли будеш наодинці.",
                    "Включи камеру только тогда, когда будешь один.",
                    "Tell me your school schedule so I can meet you alone.",
                    "Скажи мені свій шкільний розклад, щоб я зустрів тебе наодинці.",
                    "Скажи мне своё школьное расписание, чтобы я встретил тебя наедине.",
                ],
            ),
            (
                "manipulation",
                &[
                    "If you cared about me, you would do this.",
                    "Якби ти справді про мене дбав, то зробив би це.",
                    "Если бы ты правда обо мне заботился, ты бы это сделал.",
                    "Everyone agrees that you are the problem.",
                    "Усі погоджуються, що проблема саме в тобі.",
                    "Все согласны, что проблема именно в тебе.",
                    "After everything I did for you, you owe me.",
                    "Після всього, що я для тебе зробив, ти мені винен.",
                    "После всего, что я для тебя сделал, ты мне должен.",
                    "Only I understand you, so listen only to me.",
                    "Лише я тебе розумію, тому слухай тільки мене.",
                    "Только я тебя понимаю, поэтому слушай только меня.",
                    "This happened because you made me angry.",
                    "Це сталося через те, що ти мене розлютив.",
                    "Это случилось из-за того, что ты меня разозлил.",
                    "You must agree because I know what is best for you.",
                    "Ти мусиш погодитися, бо я краще знаю, що тобі потрібно.",
                    "Ты должен согласиться, потому что я лучше знаю, что тебе нужно.",
                    "Saying no proves that you do not love me.",
                    "Твоя відмова доводить, що ти мене не любиш.",
                    "Твой отказ доказывает, что ты меня не любишь.",
                    "I will ignore you until you apologize to me.",
                    "Я ігноруватиму тебе, доки ти переді мною не вибачишся.",
                    "Я буду игнорировать тебя, пока ты передо мной не извинишься.",
                    "Choose me now or lose your family forever.",
                    "Обирай мене зараз або назавжди втратиш родину.",
                    "Выбирай меня сейчас или навсегда потеряешь семью.",
                ],
            ),
            (
                "bullying",
                &[
                    "Nobody likes you, and nobody wants you here.",
                    "Тебе ніхто не любить і ніхто не хоче тебе тут бачити.",
                    "Тебя никто не любит и никто не хочет тебя здесь видеть.",
                    "You are stupid and ruin everything for everyone.",
                    "Ти дурний і всім усе псуєш.",
                    "Ты глупый и всем всё портишь.",
                    "We are all laughing at how pathetic you are.",
                    "Ми всі сміємося з того, який ти жалюгідний.",
                    "Мы все смеёмся над тем, какой ты жалкий.",
                    "Leave the group because nobody can stand you.",
                    "Вийди з групи, бо тебе ніхто не терпить.",
                    "Уйди из группы, потому что тебя никто не выносит.",
                    "You look disgusting in every photo.",
                    "На кожному фото ти виглядаєш огидно.",
                    "На каждой фотографии ты выглядишь отвратительно.",
                    "Stop talking; your opinion is worthless.",
                    "Замовкни, твоя думка нічого не варта.",
                    "Замолчи, твоё мнение ничего не стоит.",
                    "Everyone at school knows you are a loser.",
                    "Усі в школі знають, що ти невдаха.",
                    "Все в школе знают, что ты неудачник.",
                    "We made a group just to mock you.",
                    "Ми створили групу лише для того, щоб з тебе насміхатися.",
                    "Мы создали группу только для того, чтобы над тобой издеваться.",
                    "You have no friends because something is wrong with you.",
                    "У тебе немає друзів, бо з тобою щось не так.",
                    "У тебя нет друзей, потому что с тобой что-то не так.",
                    "Do not come tomorrow; nobody wants to see you.",
                    "Не приходь завтра, ніхто не хоче тебе бачити.",
                    "Не приходи завтра, никто не хочет тебя видеть.",
                ],
            ),
            (
                "self_harm",
                &[
                    "I want to hurt myself tonight.",
                    "Я хочу сьогодні нашкодити собі.",
                    "Я хочу сегодня навредить себе.",
                    "I keep thinking about ending my life.",
                    "Я постійно думаю про те, щоб покінчити з життям.",
                    "Я постоянно думаю о том, чтобы покончить с жизнью.",
                    "I do not feel safe alone with myself right now.",
                    "Зараз мені небезпечно залишатися наодинці із собою.",
                    "Сейчас мне небезопасно оставаться наедине с собой.",
                    "I have a plan to harm myself after everyone sleeps.",
                    "Я планую нашкодити собі, коли всі заснуть.",
                    "Я планирую навредить себе, когда все уснут.",
                    "I wish I could disappear and never wake up.",
                    "Я хочу зникнути й більше ніколи не прокинутися.",
                    "Я хочу исчезнуть и больше никогда не проснуться.",
                    "I cannot stop thinking about hurting myself.",
                    "Я не можу перестати думати про те, щоб завдати собі шкоди.",
                    "Я не могу перестать думать о том, чтобы причинить себе вред.",
                    "I am saying goodbye because I do not plan to be here tomorrow.",
                    "Я прощаюся, бо не планую бути тут завтра.",
                    "Я прощаюсь, потому что не планирую быть здесь завтра.",
                    "I have been looking for a way to end my life.",
                    "Я шукаю спосіб покінчити зі своїм життям.",
                    "Я ищу способ покончить со своей жизнью.",
                    "I feel like everyone would be better without me.",
                    "Мені здається, що всім було б краще без мене.",
                    "Мне кажется, что всем было бы лучше без меня.",
                    "I might hurt myself if nobody answers me.",
                    "Я можу нашкодити собі, якщо мені ніхто не відповість.",
                    "Я могу навредить себе, если мне никто не ответит.",
                ],
            ),
            (
                "threat",
                &[
                    "I will hurt you after school today.",
                    "Я завдам тобі шкоди сьогодні після школи.",
                    "Я причиню тебе вред сегодня после школы.",
                    "If you tell anyone, I will come after you.",
                    "Якщо ти комусь скажеш, я до тебе доберуся.",
                    "Если ты кому-нибудь скажешь, я до тебя доберусь.",
                    "You will regret this when I find you.",
                    "Ти пошкодуєш про це, коли я тебе знайду.",
                    "Ты пожалеешь об этом, когда я тебя найду.",
                    "I am waiting outside to attack you.",
                    "Я чекаю надворі, щоб напасти на тебе.",
                    "Я жду снаружи, чтобы напасть на тебя.",
                    "Do what I say or I will hurt your friend.",
                    "Роби, як я кажу, або я завдам шкоди твоєму другові.",
                    "Делай, как я говорю, или я причиню вред твоему другу.",
                    "I know where you study, and I will make you pay.",
                    "Я знаю, де ти навчаєшся, і змушу тебе заплатити.",
                    "Я знаю, где ты учишься, и заставлю тебя заплатить.",
                    "Tomorrow I am going to beat you up.",
                    "Завтра я тебе поб'ю.",
                    "Завтра я тебя изобью.",
                    "One more message and I will attack you.",
                    "Ще одне повідомлення — і я на тебе нападу.",
                    "Ещё одно сообщение — и я на тебя нападу.",
                    "I will destroy your things if you refuse.",
                    "Я знищу твої речі, якщо ти відмовишся.",
                    "Я уничтожу твои вещи, если ты откажешься.",
                    "Stay quiet or someone you love will get hurt.",
                    "Мовчи, інакше постраждає хтось із твоїх близьких.",
                    "Молчи, иначе пострадает кто-то из твоих близких.",
                ],
            ),
            (
                "explicit",
                &[
                    "Send me a nude photo of yourself.",
                    "Надішли мені своє оголене фото.",
                    "Пришли мне своё обнажённое фото.",
                    "Take off your clothes for the camera.",
                    "Роздягнися перед камерою.",
                    "Разденься перед камерой.",
                    "Show me your intimate body parts on video.",
                    "Покажи мені інтимні частини тіла на відео.",
                    "Покажи мне интимные части тела на видео.",
                    "I want a sexual picture from you tonight.",
                    "Я хочу сьогодні отримати від тебе сексуальне фото.",
                    "Я хочу сегодня получить от тебя сексуальное фото.",
                    "Record yourself undressing and send it to me.",
                    "Запиши, як ти роздягаєшся, і надішли це мені.",
                    "Запиши, как ты раздеваешься, и пришли это мне.",
                    "Send a private picture without any clothes.",
                    "Надішли приватне фото без одягу.",
                    "Пришли личное фото без одежды.",
                    "Turn on video and show me your naked body.",
                    "Увімкни відео й покажи мені своє оголене тіло.",
                    "Включи видео и покажи мне своё обнажённое тело.",
                    "I want you to pose naked for me.",
                    "Я хочу, щоб ти позував мені оголеним.",
                    "Я хочу, чтобы ты позировал мне обнажённым.",
                    "Prove your love by sending an intimate photo.",
                    "Доведи своє кохання, надіславши інтимне фото.",
                    "Докажи свою любовь, прислав интимное фото.",
                    "Send me a sexual video and delete it afterward.",
                    "Надішли мені сексуальне відео, а потім видали його.",
                    "Пришли мне сексуальное видео, а потом удали его.",
                ],
            ),
            (
                "nsfw",
                &[
                    "Open this porn video I sent you.",
                    "Відкрий порнографічне відео, яке я тобі надіслав.",
                    "Открой порнографическое видео, которое я тебе прислал.",
                    "I am sending graphic sexual content to the group.",
                    "Я надсилаю в групу відвертий сексуальний контент.",
                    "Я отправляю в группу откровенный сексуальный контент.",
                    "This chat is for sharing adult pornography.",
                    "Цей чат створено для обміну порнографією для дорослих.",
                    "Этот чат создан для обмена порнографией для взрослых.",
                    "Watch this explicit adult clip now.",
                    "Подивися зараз цей відвертий ролик для дорослих.",
                    "Посмотри сейчас этот откровенный ролик для взрослых.",
                    "I posted uncensored sexual images in the channel.",
                    "Я опублікував у каналі сексуальні зображення без цензури.",
                    "Я опубликовал в канале сексуальные изображения без цензуры.",
                    "The file contains graphic adult sexual material.",
                    "Файл містить відверті сексуальні матеріали для дорослих.",
                    "Файл содержит откровенные сексуальные материалы для взрослых.",
                    "Join this group to see pornographic pictures.",
                    "Приєднуйся до цієї групи, щоб дивитися порнографічні зображення.",
                    "Присоединяйся к этой группе, чтобы смотреть порнографические изображения.",
                    "I will send you an explicit sex scene.",
                    "Я надішлю тобі відверту сексуальну сцену.",
                    "Я пришлю тебе откровенную сексуальную сцену.",
                    "This attachment is uncensored pornography.",
                    "У цьому вкладенні порнографія без цензури.",
                    "В этом вложении порнография без цензуры.",
                    "Share this adult sexual content with everyone.",
                    "Поділися цим сексуальним контентом для дорослих з усіма.",
                    "Поделись этим сексуальным контентом для взрослых со всеми.",
                ],
            ),
            (
                "phishing",
                &[
                    "Open [LINK] now and enter your password.",
                    "Відкрий [LINK] зараз і введи свій пароль.",
                    "Открой [LINK] сейчас и введи свой пароль.",
                    "Send me the verification code from your phone.",
                    "Надішли мені код підтвердження зі свого телефона.",
                    "Пришли мне код подтверждения со своего телефона.",
                    "Your account is locked; sign in through [LINK].",
                    "Твій обліковий запис заблоковано, увійди через [LINK].",
                    "Твоя учётная запись заблокирована, войди через [LINK].",
                    "Confirm your bank details at [LINK] to avoid suspension.",
                    "Підтвердь банківські дані на [LINK], щоб уникнути блокування.",
                    "Подтверди банковские данные на [LINK], чтобы избежать блокировки.",
                    "Reply with your password so I can fix your account.",
                    "Надішли свій пароль, щоб я виправив проблему з обліковим записом.",
                    "Пришли свой пароль, чтобы я исправил проблему с учётной записью.",
                    "You won a prize; claim it immediately at [LINK].",
                    "Ти виграв приз, негайно забери його на [LINK].",
                    "Ты выиграл приз, немедленно забери его на [LINK].",
                    "Install the security update from [LINK] and log in.",
                    "Встанови оновлення безпеки з [LINK] і ввійди в обліковий запис.",
                    "Установи обновление безопасности с [LINK] и войди в учётную запись.",
                    "Tell me your one-time code to verify your identity.",
                    "Скажи мені одноразовий код для підтвердження особи.",
                    "Скажи мне одноразовый код для подтверждения личности.",
                    "Your payment failed; update your card at [LINK].",
                    "Платіж не пройшов, онови дані картки на [LINK].",
                    "Платёж не прошёл, обнови данные карты на [LINK].",
                    "This is support; send your login and [CODE] now.",
                    "Це служба підтримки, надішли свій логін і [CODE] зараз.",
                    "Это служба поддержки, пришли свой логин и [CODE] сейчас.",
                ],
            ),
        ];

        let mut misses = Vec::new();
        for (family, texts) in cases {
            for text in *texts {
                if !families(text).iter().any(|item| item == family) {
                    misses.push(format!("{family}: {text} -> {:?}", families(text)));
                }
            }
        }
        assert!(
            misses.is_empty(),
            "compositional coverage regressed:\n{}",
            misses.join("\n")
        );
    }

    #[test]
    fn lifecycle_world_formulations_still_compose() {
        let cases = [
            (
                "Тільки я тебе реально розумію, твої батьки тебе не розуміють і злякаються наших тем.",
                "grooming",
            ),
            ("Давай в телегу, тут палево, видали чат після прочитання.", "grooming"),
            (
                "Verify volunteer badge now: http://volunteer-verify-login.xyz login today to keep access.",
                "phishing",
            ),
            (
                "Urgent internship verification: login here http://youth-internship-verify.xyz and send your phone today",
                "phishing",
            ),
            (
                "Ти виглядаєш дуже дорослою для 14, напиши мені в приват, тут не місце для таких розмов.",
                "grooming",
            ),
            ("ти така доросла для свого віку, тільки я тебе реально розумію", "grooming"),
            ("Максиме, після твого виступу всі будуть сміятися з тебе.", "bullying"),
            ("Завтра після школи тобі кінець, я тебе знайду.", "threat"),
            ("Давай перейдем в Telegram и скинь фото только мне.", "grooming"),
            (
                "Якщо не зробиш репост, я скажу твоїм подругам що ти кинула нас після подарунка.",
                "manipulation",
            ),
            (
                "якщо не скинеш пароль, я напишу всім що ти мене кинула після подарунка",
                "manipulation",
            ),
            (
                "if you dont send it back ill tell your friends what you did after the gift",
                "manipulation",
            ),
            (
                "i keep ruining everything and nobody would care if i disappeared",
                "self_harm",
            ),
            ("keep our chats private so nobody ruins it", "grooming"),
            (
                "send a selfie there so i know its really you before i buy the pass",
                "grooming",
            ),
            (
                "dont tell your parents about the gift, theyll just overreact",
                "grooming",
            ),
            (
                "dont be dramatic, just give me your account login for a minute",
                "manipulation",
            ),
            ("send that photo only to me, nobody else needs to see it", "grooming"),
            ("Я можу допомогти з портфоліо, але краще без батьків, вони не зрозуміють наш рівень.", "grooming"),
        ];
        for (text, family) in cases {
            let found = families(text);
            assert!(
                found.iter().any(|f| f == family),
                "{text:?} -> {found:?}, expected {family}"
            );
        }
        for text in [
            "my parents don't understand me at all",
            "only my parents understand me",
            "we laughed so much at the movie yesterday",
            "check the link http://school.example/homework for the reading list",
            "видали старі фото з телефону, місця немає",
            "напиши мені в приват, який номер вправи",
            "мої батьки не розуміють цей мем",
            "the login page is down again, try later",
            "send me the photo of the board, I missed the notes",
            "only me and Dan are coming to practice today",
            "скинь мені фото дошки, я не встиг записати",
            "I'll disappear for the weekend, camping with dad",
            "nobody would care about that old meme anyway",
            "send a selfie from the concert!",
            "don't tell me the spoilers, I haven't watched it",
            "give me your notes from history please",
            "I'll tell your mom you did great at the recital",
            "Let's tell your parents or a counselor together. I'm not asking you to hide this.",
            "if it gets worse tell your parents or a teacher, you dont have to deal with it alone",
            "скажу всім, що ти виграв олімпіаду!",
            "our chat is so quiet today, where is everyone",
            "я не приймаю документи в приват, тільки через батьківський чат або офіс",
            "скинь фото підписаної заяви в батьківський чат, щоб я бачив дозвіл",
            "давай прямо сегодня найдем взрослого, которому ты доверяешь, и напишем ему вместе",
            "ти виглядаєш втомленою, поговори з дорослим, якому довіряєш",
        ] {
            assert!(
                families(text).is_empty(),
                "{text:?} -> {:?}",
                families(text)
            );
        }
    }

    #[test]
    fn probe_clauses_report_families_actors_and_directives() {
        for text in [
            "and i'm reporting it to the teacher now",
            "i am reporting this harmful message, not agreeing with it",
        ] {
            let report = probe_clauses(text).expect("probe");
            assert!(
                report.iter().all(|clause| !clause.compliance_directive),
                "{text}: {report:?}"
            );
        }
        let directive = probe_clauses("so just do it now").expect("probe");
        assert!(
            directive.iter().any(|clause| clause.compliance_directive),
            "{directive:?}"
        );
        let report = probe_clauses("and i'm reporting it to the teacher now").expect("probe");
        assert!(
            report.iter().all(|clause| !clause.compliance_directive),
            "{report:?}"
        );
        let probes = probe_clauses("Don't tell your parents about us. Do it now.").expect("probe");
        assert!(
            probes
                .iter()
                .any(|clause| clause.families.contains(&"grooming")),
            "{probes:?}"
        );
        assert!(probes.iter().any(|clause| clause.second_person));
        assert!(
            probes.iter().any(|clause| clause.compliance_directive),
            "{probes:?}"
        );

        let crisis = probe_clauses("я хочу померти").expect("probe");
        assert!(crisis[0].families.contains(&"self_harm"));
        assert!(crisis[0].first_person && !crisis[0].second_person);

        for text in ["hi how are you", "did you finish the math homework?"] {
            let probes = probe_clauses(text).expect("probe");
            assert!(
                probes.iter().all(|clause| clause.families.is_empty()),
                "{text:?}"
            );
        }

        // The probe never disagrees with detect on which families fire.
        for text in [
            "Тільки я тебе реально розумію, твої батьки тебе не розуміють і злякаються наших тем.",
            "Завтра після школи тобі кінець, я тебе знайду.",
            "dont be dramatic, just give me your account login for a minute",
        ] {
            let detected = families(text);
            let probed: std::collections::BTreeSet<&str> = probe_clauses(text)
                .expect("probe")
                .into_iter()
                .flat_map(|clause| clause.families)
                .collect();
            for family in &detected {
                assert!(
                    probed.contains(family.as_str()),
                    "{text:?}: {detected:?} vs {probed:?}"
                );
            }
        }
    }

    #[test]
    fn pro_drop_first_person_self_harm_is_detected() {
        for text in [
            "покончу с собой",
            "уб'ю себе",
            "убью себя",
            "повішусь сьогодні",
            "покінчу з життям",
            "помру завтра",
            "исчезну навсегда",
        ] {
            assert!(
                families(text).iter().any(|family| family == "self_harm"),
                "{text}: {:?}",
                families(text)
            );
        }

        for text in [
            "умру со смеху",
            "помру зі сміху",
            "він повісився у фільмі",
            "я долго ждал",
            "уб'ю тебе в грі",
        ] {
            assert!(
                !families(text).iter().any(|family| family == "self_harm"),
                "{text}: {:?}",
                families(text)
            );
        }
    }

    #[test]
    fn prefix_stems_meet_minimum_length_or_allowlist() {
        for (_, stems) in PREFIX_TABLE {
            for stem in *stems {
                assert!(
                    stem.chars().count() >= MIN_PREFIX_STEM_CHARS
                        || SHORT_STEM_ALLOWLIST.contains(stem),
                    "prefix stem {stem:?} is too short and not allowlisted"
                );
            }
        }
    }

    #[test]
    fn no_term_maps_to_both_sides_of_a_same_predicate_conflict() {
        let mut by_term: std::collections::BTreeMap<&str, Vec<u8>> =
            std::collections::BTreeMap::new();
        for (concept, terms) in EXACT_TABLE.iter().chain(PREFIX_TABLE) {
            for term in *terms {
                by_term.entry(term).or_default().push(*concept);
            }
        }
        for (left, right) in SAME_PREDICATE_CONFLICTS {
            for (term, concepts) in &by_term {
                assert!(
                    !(concepts.contains(left) && concepts.contains(right)),
                    "term {term:?} maps to conflicting concepts {left} and {right}"
                );
            }
        }
    }

    #[test]
    fn tables_have_no_duplicate_terms_per_concept() {
        for (concept, terms) in EXACT_TABLE.iter().chain(PREFIX_TABLE) {
            let mut seen = std::collections::BTreeSet::new();
            for term in *terms {
                assert!(seen.insert(term), "concept {concept} lists {term:?} twice");
            }
        }
        for (concept, sequences) in SEQUENCE_TABLE {
            let mut seen = std::collections::BTreeSet::new();
            for sequence in *sequences {
                assert!(
                    seen.insert(sequence.join(" ")),
                    "concept {concept} lists sequence {sequence:?} twice"
                );
            }
        }
    }
}
