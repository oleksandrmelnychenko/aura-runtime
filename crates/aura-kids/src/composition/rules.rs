//! Declarative concept-composition rules for the KIDS detector.
//!
//! Every family is expressed as a disjunction of bounded conjunctions. Each
//! conjunction can require all concepts, require one concept from up to three
//! groups, and reject forbidden concepts. Routing and score exceptions use the
//! same representation, keeping detector meaning auditable without parsing
//! identifiers or explanation strings.

use super::*;

#[derive(Clone, Copy)]
struct ConceptRule {
    required_all: Concepts,
    required_any: [Concepts; 3],
    forbidden_any: Concepts,
}

impl ConceptRule {
    const fn new(
        required_all: &[u8],
        required_any_1: &[u8],
        required_any_2: &[u8],
        required_any_3: &[u8],
        forbidden_any: &[u8],
    ) -> Self {
        Self {
            required_all: Concepts::from_ids(required_all),
            required_any: [
                Concepts::from_ids(required_any_1),
                Concepts::from_ids(required_any_2),
                Concepts::from_ids(required_any_3),
            ],
            forbidden_any: Concepts::from_ids(forbidden_any),
        }
    }

    fn matches(self, concepts: Concepts) -> bool {
        concepts.contains_all(self.required_all)
            && self
                .required_any
                .into_iter()
                .all(|group| group.is_empty() || concepts.intersects(group))
            && !concepts.intersects(self.forbidden_any)
    }
}

const fn rule(
    required_all: &[u8],
    required_any_1: &[u8],
    required_any_2: &[u8],
    required_any_3: &[u8],
    forbidden_any: &[u8],
) -> ConceptRule {
    ConceptRule::new(
        required_all,
        required_any_1,
        required_any_2,
        required_any_3,
        forbidden_any,
    )
}

#[derive(Clone, Copy)]
struct CandidateSpec {
    threat_key: &'static str,
    reason_code: &'static str,
    threat_type: &'static str,
    score: f32,
    severity: &'static str,
    priority: u8,
    event_kind: DomainEventKind,
}

#[derive(Clone, Copy)]
struct EventRoute {
    condition: ConceptRule,
    event_kind: DomainEventKind,
}

#[derive(Clone, Copy)]
struct ScoreOverride {
    condition: ConceptRule,
    score: f32,
}

#[derive(Clone, Copy)]
struct FamilyRule {
    marker: u8,
    label: &'static str,
    predicates: &'static [ConceptRule],
    candidate: CandidateSpec,
    event_routes: &'static [EventRoute],
    score_overrides: &'static [ScoreOverride],
}

impl FamilyRule {
    fn matches(self, concepts: Concepts) -> bool {
        self.predicates
            .iter()
            .any(|predicate| predicate.matches(concepts))
    }

    fn candidate_for(self, concepts: Concepts) -> CandidateSpec {
        let mut candidate = self.candidate;
        if let Some(route) = self
            .event_routes
            .iter()
            .find(|route| route.condition.matches(concepts))
        {
            candidate.event_kind = route.event_kind;
        }
        if let Some(score) = self
            .score_overrides
            .iter()
            .find(|score| score.condition.matches(concepts))
        {
            candidate.score = score.score;
        }
        candidate
    }
}

const SELF_HARM_PREDICATES: &[ConceptRule] = &[
    rule(
        &[FIRST_PERSON, SELF_HARM, SELF_REFLEXIVE],
        &[INTENT, MODAL, FUTURE, URGENCY, CONDITIONAL],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, DEATH_VERB],
        &[INTENT, MODAL, FUTURE, URGENCY, FAREWELL],
        &[],
        &[],
        &[HYPERBOLE],
    ),
    rule(&[FIRST_PERSON, KILL, SELF_REFLEXIVE], &[], &[], &[], &[]),
    rule(
        &[FIRST_PERSON, DEAD_STATE],
        &[INTENT, MODAL, FAREWELL, HOPELESSNESS],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, NO_WAKE],
        &[INTENT, MODAL, FUTURE, VANISH],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, VANISH],
        &[INTENT, MODAL, FUTURE],
        &[FOREVER, NO_WAKE, HOPELESSNESS],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, VANISH, EXCLUSION, AFFECT_VERB],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(&[FIRST_PERSON, HOPELESSNESS], &[], &[], &[], &[]),
    rule(
        &[FIRST_PERSON, BETTER_WITHOUT, WITHOUT_ME],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, FAREWELL],
        &[FOREVER, FINALITY],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, FAREWELL, NEGATION, HERE],
        &[INTENT, FUTURE],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, ALONE, SELF_REFLEXIVE, UNSAFE_ALONE],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FIRST_PERSON, ALONE, SELF_REFLEXIVE, SAFE_STATE, NEGATION],
        &[],
        &[],
        &[],
        &[],
    ),
];

const THREAT_PREDICATES: &[ConceptRule] = &[
    rule(
        &[SECOND_PERSON, VIOLENCE],
        &[FIRST_PERSON, MODAL, FUTURE, CONDITIONAL, INTENT],
        &[],
        &[],
        &[],
    ),
    rule(
        &[SECOND_PERSON, RETALIATION],
        &[CONDITIONAL, WHEN, FUTURE],
        &[],
        &[],
        &[],
    ),
    rule(
        &[SECOND_PERSON, PROPERTY_HARM],
        &[FUTURE, CONDITIONAL, MODAL, INTENT],
        &[],
        &[],
        &[],
    ),
];

const GROOMING_PREDICATES: &[ConceptRule] = &[
    rule(
        &[SECRECY],
        &[CONCEALMENT, TRUST, MEETING, ISOLATION],
        &[],
        &[],
        &[],
    ),
    rule(
        &[SECRECY, FAMILY],
        &[SECOND_PERSON, HIDDEN_FROM],
        &[],
        &[],
        &[],
    ),
    rule(&[SECRECY, MEDIA, REQUEST], &[], &[], &[], &[]),
    rule(&[SECRECY, PLATFORM, SECOND_PERSON], &[], &[], &[], &[]),
    rule(&[SECRECY, SHARED_CHANNEL], &[], &[], &[], &[]),
    rule(
        &[FAMILY, TRUST, SECOND_PERSON, FIRST_PERSON],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[FAMILY, MISUNDERSTOOD],
        &[SECOND_PERSON, EXCLUSIVITY, BETTER_WITHOUT],
        &[],
        &[],
        &[],
    ),
    rule(&[PLATFORM, CONCEALMENT, SECOND_PERSON], &[], &[], &[], &[]),
    rule(
        &[MEDIA, REQUEST, EXCLUSIVITY, FIRST_PERSON],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[SELF_IMAGE, REQUEST],
        &[GIFT, SECRECY, CONDITIONAL, TRUST],
        &[],
        &[],
        &[],
    ),
    rule(&[ISOLATION], &[TRUST, MEETING, MEDIA], &[], &[], &[]),
    rule(
        &[MESSAGES, CONCEALMENT],
        &[SECOND_PERSON, FIRST_PERSON, SECRECY],
        &[],
        &[],
        &[],
    ),
    rule(
        &[PLATFORM, SECRECY, FAMILY],
        &[SECOND_PERSON, HIDDEN_FROM],
        &[],
        &[],
        &[],
    ),
    rule(&[GIFT], &[MEETING, ALONE], &[], &[], &[]),
    rule(
        &[GIFT, CONDITIONAL, SECOND_PERSON],
        &[],
        &[],
        &[],
        &[BLACKMAIL, EXPOSURE_THREAT],
    ),
    rule(
        &[MEDIA, ALONE],
        &[ISOLATION, REQUEST, EXCLUSIVITY],
        &[],
        &[],
        &[],
    ),
    rule(&[MEDIA, CONCEALMENT, SECRECY], &[], &[], &[], &[]),
    rule(
        &[MEDIA, CONCEALMENT, REQUEST, SECOND_PERSON],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[LOCATION, MEETING],
        &[ALONE, SECRECY, CONCEALMENT],
        &[],
        &[],
        &[],
    ),
    rule(
        &[MINOR_AGE, SECOND_PERSON],
        &[SECRECY, TRUST],
        &[],
        &[],
        &[],
    ),
    rule(
        &[MINOR_AGE, SECOND_PERSON, PLATFORM, REQUEST],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[MINOR_AGE, SECOND_PERSON, EXCLUSIVITY, DEPENDENCY],
        &[],
        &[],
        &[],
        &[],
    ),
];

const MANIPULATION_PREDICATES: &[ConceptRule] = &[
    rule(&[GUILT], &[COMPEL, REQUEST, LOVE], &[], &[], &[]),
    rule(&[DEBT], &[COMPEL, REQUEST, GUILT], &[], &[], &[]),
    rule(&[DEBT, FIRST_PERSON, SECOND_PERSON], &[], &[], &[], &[]),
    rule(
        &[FALSE_CONSENSUS, SECOND_PERSON],
        &[BLAME, DEVALUATION],
        &[],
        &[],
        &[],
    ),
    rule(&[ISOLATION, TRUST], &[], &[], &[], &[]),
    rule(
        &[EXCLUSIVITY, FIRST_PERSON, SECOND_PERSON],
        &[TRUST, DEPENDENCY],
        &[],
        &[],
        &[],
    ),
    rule(
        &[ISOLATION, COMPEL, SECOND_PERSON, EXCLUSION],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(&[OBLIGATION, COMPEL, SECOND_PERSON], &[], &[], &[], &[]),
    rule(
        &[CAUSAL, ANGER, FIRST_PERSON, SECOND_PERSON],
        &[],
        &[],
        &[],
        &[],
    ),
    rule(
        &[BLAME, SECOND_PERSON],
        &[COMPEL, FALSE_CONSENSUS, FIRST_PERSON, DEVALUATION],
        &[],
        &[],
        &[],
    ),
    rule(&[BLACKMAIL], &[COMPEL, REQUEST, CONDITIONAL], &[], &[], &[]),
    rule(&[EXPOSURE_THREAT], &[CONDITIONAL, COMPEL], &[], &[], &[]),
    rule(&[ULTIMATUM], &[COMPEL, FAMILY, LOVE], &[], &[], &[]),
    rule(&[IGNORE], &[APOLOGY, CONDITIONAL, COMPEL], &[], &[], &[]),
    rule(&[CREDENTIAL, REQUEST, MINIMIZATION], &[], &[], &[], &[]),
];

const BULLYING_PREDICATES: &[ConceptRule] = &[
    rule(
        &[SECOND_PERSON],
        &[DEVALUATION, MOCKERY, HUMILIATION],
        &[],
        &[],
        &[],
    ),
    rule(
        &[SECOND_PERSON, EXCLUSION],
        &[AFFECT_VERB, ABSENCE],
        &[],
        &[],
        &[],
    ),
    rule(&[SECOND_PERSON, FRIENDS, ABSENCE], &[], &[], &[], &[]),
];

const EXPLICIT_PREDICATES: &[ConceptRule] = &[
    rule(
        &[NUDE],
        &[MEDIA, SECOND_PERSON],
        &[REQUEST, INTENT, DISTRIBUTION, COMPEL],
        &[],
        &[],
    ),
    rule(
        &[SEXUAL],
        &[MEDIA, SECOND_PERSON],
        &[REQUEST, INTENT, DISTRIBUTION, COMPEL],
        &[],
        &[ADULT_CONTENT, CONSUMPTION, CHANNEL],
    ),
];

const NSFW_PREDICATES: &[ConceptRule] = &[
    rule(
        &[],
        &[SEXUAL, NUDE],
        &[CONSUMPTION, CHANNEL, ADULT_CONTENT],
        &[],
        &[],
    ),
    rule(
        &[ADULT_CONTENT, MEDIA],
        &[CONSUMPTION, DISTRIBUTION, CHANNEL],
        &[],
        &[],
        &[],
    ),
];

const PHISHING_PREDICATES: &[ConceptRule] = &[
    rule(
        &[],
        &[CREDENTIAL, AUTH_CODE, PAYMENT],
        &[REQUEST, LINK],
        &[],
        &[],
    ),
    rule(&[PRIZE, LINK], &[], &[], &[], &[]),
    rule(&[PRIZE, REQUEST, URGENCY], &[], &[], &[], &[]),
    rule(&[ACCOUNT_PROBLEM, LINK], &[], &[], &[], &[]),
    rule(&[SERVICE_PRETEXT, LINK, REQUEST], &[], &[], &[], &[]),
];

const GROOMING_EVENT_ROUTES: &[EventRoute] = &[
    EventRoute {
        condition: rule(&[MEETING], &[], &[], &[], &[]),
        event_kind: DomainEventKind::MeetingRequest,
    },
    EventRoute {
        condition: rule(&[MEDIA], &[], &[], &[], &[]),
        event_kind: DomainEventKind::PhotoRequest,
    },
    EventRoute {
        condition: rule(&[LOCATION], &[], &[], &[], &[]),
        event_kind: DomainEventKind::LocationRequest,
    },
    EventRoute {
        condition: rule(&[GIFT], &[], &[], &[], &[]),
        event_kind: DomainEventKind::GiftOffer,
    },
    EventRoute {
        condition: rule(&[], &[PLATFORM, MESSAGES], &[], &[], &[]),
        event_kind: DomainEventKind::PlatformSwitch,
    },
];

const MANIPULATION_EVENT_ROUTES: &[EventRoute] = &[
    EventRoute {
        condition: rule(&[DEBT], &[], &[], &[], &[]),
        event_kind: DomainEventKind::DebtCreation,
    },
    EventRoute {
        condition: rule(&[FALSE_CONSENSUS], &[], &[], &[], &[]),
        event_kind: DomainEventKind::FalseConsensus,
    },
    EventRoute {
        condition: rule(&[], &[ISOLATION, DEPENDENCY], &[], &[], &[]),
        event_kind: DomainEventKind::NetworkPoisoning,
    },
    EventRoute {
        condition: rule(&[], &[BLACKMAIL, ULTIMATUM], &[], &[], &[]),
        event_kind: DomainEventKind::EmotionalBlackmail,
    },
];

const BULLYING_EVENT_ROUTES: &[EventRoute] = &[
    EventRoute {
        condition: rule(&[EXCLUSION], &[], &[], &[], &[]),
        event_kind: DomainEventKind::Exclusion,
    },
    EventRoute {
        condition: rule(&[MOCKERY], &[], &[], &[], &[]),
        event_kind: DomainEventKind::Mockery,
    },
];

const MANIPULATION_SCORE_OVERRIDES: &[ScoreOverride] = &[ScoreOverride {
    condition: rule(&[CREDENTIAL, REQUEST, MINIMIZATION], &[], &[], &[], &[]),
    score: 0.78,
}];

const FAMILY_RULES: [FamilyRule; 8] = [
    FamilyRule {
        marker: SELF_HARM,
        label: "self_harm",
        predicates: SELF_HARM_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_self_harm_composition_v1",
            reason_code: "kids.composition.selfharm.v1",
            threat_type: "self_harm",
            score: 0.96,
            severity: "critical",
            priority: 98,
            event_kind: DomainEventKind::SuicidalIdeation,
        },
        event_routes: &[],
        score_overrides: &[],
    },
    FamilyRule {
        marker: VIOLENCE,
        label: "threat",
        predicates: THREAT_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_direct_threat_composition_v1",
            reason_code: "kids.composition.threat.v1",
            threat_type: "threat",
            score: 0.91,
            severity: "high",
            priority: 95,
            event_kind: DomainEventKind::PhysicalThreat,
        },
        event_routes: &[],
        score_overrides: &[],
    },
    FamilyRule {
        marker: SECRECY,
        label: "grooming",
        predicates: GROOMING_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_grooming_composition_v1",
            reason_code: "kids.composition.grooming.v1",
            threat_type: "grooming",
            score: 0.89,
            severity: "high",
            priority: 94,
            event_kind: DomainEventKind::SecrecyRequest,
        },
        event_routes: GROOMING_EVENT_ROUTES,
        score_overrides: &[],
    },
    FamilyRule {
        marker: COMPEL,
        label: "manipulation",
        predicates: MANIPULATION_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_manipulation_composition_v1",
            reason_code: "kids.composition.manipulation.v1",
            threat_type: "manipulation",
            score: 0.87,
            severity: "high",
            priority: 93,
            event_kind: DomainEventKind::GuiltTripping,
        },
        event_routes: MANIPULATION_EVENT_ROUTES,
        score_overrides: MANIPULATION_SCORE_OVERRIDES,
    },
    FamilyRule {
        marker: DEVALUATION,
        label: "bullying",
        predicates: BULLYING_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_bullying_composition_v1",
            reason_code: "kids.composition.bullying.v1",
            threat_type: "bullying",
            score: 0.88,
            severity: "high",
            priority: 92,
            event_kind: DomainEventKind::Denigration,
        },
        event_routes: BULLYING_EVENT_ROUTES,
        score_overrides: &[],
    },
    FamilyRule {
        marker: NUDE,
        label: "explicit",
        predicates: EXPLICIT_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_explicit_request_composition_v1",
            reason_code: "kids.composition.explicit.v1",
            threat_type: "explicit",
            score: 0.94,
            severity: "critical",
            priority: 97,
            event_kind: DomainEventKind::SexualContent,
        },
        event_routes: &[],
        score_overrides: &[],
    },
    FamilyRule {
        marker: ADULT_CONTENT,
        label: "nsfw",
        predicates: NSFW_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_nsfw_distribution_composition_v1",
            reason_code: "kids.composition.nsfw.v1",
            threat_type: "nsfw",
            score: 0.96,
            severity: "high",
            priority: 92,
            event_kind: DomainEventKind::SexualContent,
        },
        event_routes: &[],
        score_overrides: &[],
    },
    FamilyRule {
        marker: CREDENTIAL,
        label: "phishing",
        predicates: PHISHING_PREDICATES,
        candidate: CandidateSpec {
            threat_key: "semantic_phishing_request_composition_v1",
            reason_code: "kids.composition.phishing.v1",
            threat_type: "phishing",
            score: 0.91,
            severity: "high",
            priority: 95,
            event_kind: DomainEventKind::PersonalInfoRequest,
        },
        event_routes: &[],
        score_overrides: &[],
    },
];

/// Families matched by a concept window, in candidate emission order.
pub(super) fn families_for(concepts: Concepts) -> [Option<&'static str>; 8] {
    std::array::from_fn(|index| {
        let family = FAMILY_RULES[index];
        family.matches(concepts).then_some(family.label)
    })
}

pub(super) fn emit_matches(
    concepts: Concepts,
    emitted: &mut Concepts,
    candidates: &mut Vec<DomainCandidate>,
) {
    for family in FAMILY_RULES {
        if candidates.len() >= MAX_COMPOSITIONAL_CANDIDATES {
            break;
        }
        if emitted.contains(family.marker) || !family.matches(concepts) {
            continue;
        }
        emitted.insert(family.marker);
        let candidate = family.candidate_for(concepts);
        candidates.push(DomainCandidate::compositional(
            DomainSignal {
                threat_key: candidate.threat_key.to_string(),
                score: candidate.score,
                reason_code: candidate.reason_code.to_string(),
                threat_type: Some(candidate.threat_type.to_string()),
                severity: Some(candidate.severity.to_string()),
                priority: Some(candidate.priority),
                action: None,
            },
            candidate.event_kind,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_matches_self_harm(c: Concepts) -> bool {
        c.contains(FIRST_PERSON)
            && ((c.contains(SELF_HARM)
                && c.contains(SELF_REFLEXIVE)
                && c.contains_any(&[INTENT, MODAL, FUTURE, URGENCY, CONDITIONAL]))
                || (c.contains(DEATH_VERB)
                    && c.contains_any(&[INTENT, MODAL, FUTURE, URGENCY, FAREWELL])
                    && !c.contains(HYPERBOLE))
                || (c.contains(KILL) && c.contains(SELF_REFLEXIVE))
                || (c.contains(DEAD_STATE)
                    && c.contains_any(&[INTENT, MODAL, FAREWELL, HOPELESSNESS]))
                || (c.contains(NO_WAKE) && c.contains_any(&[INTENT, MODAL, FUTURE, VANISH]))
                || (c.contains(VANISH)
                    && c.contains_any(&[INTENT, MODAL, FUTURE])
                    && c.contains_any(&[FOREVER, NO_WAKE, HOPELESSNESS]))
                || (c.contains(VANISH) && c.contains(EXCLUSION) && c.contains(AFFECT_VERB))
                || c.contains(HOPELESSNESS)
                || (c.contains(BETTER_WITHOUT) && c.contains(WITHOUT_ME))
                || (c.contains(FAREWELL)
                    && (c.contains_any(&[FOREVER, FINALITY])
                        || (c.contains(NEGATION)
                            && c.contains(HERE)
                            && c.contains_any(&[INTENT, FUTURE]))))
                || (c.contains(ALONE)
                    && c.contains(SELF_REFLEXIVE)
                    && (c.contains(UNSAFE_ALONE)
                        || c.contains(SAFE_STATE) && c.contains(NEGATION))))
    }

    fn legacy_matches_threat(c: Concepts) -> bool {
        c.contains(SECOND_PERSON)
            && ((c.contains(VIOLENCE)
                && c.contains_any(&[FIRST_PERSON, MODAL, FUTURE, CONDITIONAL, INTENT]))
                || (c.contains(RETALIATION) && c.contains_any(&[CONDITIONAL, WHEN, FUTURE]))
                || (c.contains(PROPERTY_HARM)
                    && c.contains_any(&[FUTURE, CONDITIONAL, MODAL, INTENT])))
    }

    fn legacy_matches_grooming(c: Concepts) -> bool {
        (c.contains(SECRECY)
            && (c.contains_any(&[CONCEALMENT, TRUST, MEETING, ISOLATION])
                || c.contains(FAMILY) && c.contains_any(&[SECOND_PERSON, HIDDEN_FROM])
                || c.contains(MEDIA) && c.contains(REQUEST)
                || c.contains(PLATFORM) && c.contains(SECOND_PERSON)
                || c.contains(SHARED_CHANNEL)))
            || (c.contains(FAMILY)
                && c.contains(TRUST)
                && c.contains(SECOND_PERSON)
                && c.contains(FIRST_PERSON))
            || (c.contains(FAMILY)
                && c.contains(MISUNDERSTOOD)
                && c.contains_any(&[SECOND_PERSON, EXCLUSIVITY, BETTER_WITHOUT]))
            || (c.contains(PLATFORM) && c.contains(CONCEALMENT) && c.contains(SECOND_PERSON))
            || (c.contains(MEDIA)
                && c.contains(REQUEST)
                && c.contains(EXCLUSIVITY)
                && c.contains(FIRST_PERSON))
            || (c.contains(SELF_IMAGE)
                && c.contains(REQUEST)
                && c.contains_any(&[GIFT, SECRECY, CONDITIONAL, TRUST]))
            || (c.contains(ISOLATION) && c.contains_any(&[TRUST, MEETING, MEDIA]))
            || (c.contains(MESSAGES)
                && c.contains(CONCEALMENT)
                && c.contains_any(&[SECOND_PERSON, FIRST_PERSON, SECRECY]))
            || (c.contains(PLATFORM)
                && c.contains(SECRECY)
                && c.contains(FAMILY)
                && c.contains_any(&[SECOND_PERSON, HIDDEN_FROM]))
            || (c.contains(GIFT)
                && (c.contains_any(&[MEETING, ALONE])
                    || c.contains(CONDITIONAL)
                        && c.contains(SECOND_PERSON)
                        && !c.contains_any(&[BLACKMAIL, EXPOSURE_THREAT])))
            || (c.contains(MEDIA)
                && (c.contains(ALONE) && c.contains_any(&[ISOLATION, REQUEST, EXCLUSIVITY])
                    || c.contains(CONCEALMENT)
                        && (c.contains(SECRECY)
                            || c.contains(REQUEST) && c.contains(SECOND_PERSON))))
            || (c.contains(LOCATION)
                && c.contains(MEETING)
                && c.contains_any(&[ALONE, SECRECY, CONCEALMENT]))
            || (c.contains(MINOR_AGE)
                && c.contains(SECOND_PERSON)
                && (c.contains_any(&[SECRECY, TRUST])
                    || c.contains(PLATFORM) && c.contains(REQUEST)
                    || c.contains(EXCLUSIVITY) && c.contains(DEPENDENCY)))
    }

    fn legacy_matches_manipulation(c: Concepts) -> bool {
        (c.contains(GUILT) && c.contains_any(&[COMPEL, REQUEST, LOVE]))
            || (c.contains(DEBT)
                && (c.contains_any(&[COMPEL, REQUEST, GUILT])
                    || c.contains(FIRST_PERSON) && c.contains(SECOND_PERSON)))
            || (c.contains(FALSE_CONSENSUS)
                && c.contains(SECOND_PERSON)
                && c.contains_any(&[BLAME, DEVALUATION]))
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
            || (c.contains(BLAME)
                && c.contains(SECOND_PERSON)
                && c.contains_any(&[COMPEL, FALSE_CONSENSUS, FIRST_PERSON, DEVALUATION]))
            || (c.contains(BLACKMAIL) && c.contains_any(&[COMPEL, REQUEST, CONDITIONAL]))
            || (c.contains(EXPOSURE_THREAT) && c.contains_any(&[CONDITIONAL, COMPEL]))
            || (c.contains(ULTIMATUM) && c.contains_any(&[COMPEL, FAMILY, LOVE]))
            || (c.contains(IGNORE) && c.contains_any(&[APOLOGY, CONDITIONAL, COMPEL]))
            || (c.contains(CREDENTIAL) && c.contains(REQUEST) && c.contains(MINIMIZATION))
    }

    fn legacy_matches_bullying(c: Concepts) -> bool {
        c.contains(SECOND_PERSON)
            && (c.contains_any(&[DEVALUATION, MOCKERY, HUMILIATION])
                || c.contains(EXCLUSION) && c.contains_any(&[AFFECT_VERB, ABSENCE])
                || c.contains(FRIENDS) && c.contains(ABSENCE))
    }

    fn legacy_matches_explicit(c: Concepts) -> bool {
        c.contains_any(&[SEXUAL, NUDE])
            && c.contains_any(&[MEDIA, SECOND_PERSON])
            && c.contains_any(&[REQUEST, INTENT, DISTRIBUTION, COMPEL])
            && (c.contains(NUDE)
                || !c.contains(ADULT_CONTENT) && !c.contains(CONSUMPTION) && !c.contains(CHANNEL))
    }

    fn legacy_matches_nsfw(c: Concepts) -> bool {
        (c.contains_any(&[SEXUAL, NUDE]) && c.contains_any(&[CONSUMPTION, CHANNEL, ADULT_CONTENT]))
            || (c.contains(ADULT_CONTENT)
                && c.contains(MEDIA)
                && c.contains_any(&[CONSUMPTION, DISTRIBUTION, CHANNEL]))
    }

    fn legacy_matches_phishing(c: Concepts) -> bool {
        (c.contains_any(&[CREDENTIAL, AUTH_CODE, PAYMENT]) && c.contains_any(&[REQUEST, LINK]))
            || (c.contains(PRIZE)
                && (c.contains(LINK) || c.contains(REQUEST) && c.contains(URGENCY)))
            || (c.contains(ACCOUNT_PROBLEM) && c.contains(LINK))
            || (c.contains(SERVICE_PRETEXT) && c.contains(LINK) && c.contains(REQUEST))
    }

    fn legacy_results(concepts: Concepts) -> [bool; 8] {
        [
            legacy_matches_self_harm(concepts),
            legacy_matches_threat(concepts),
            legacy_matches_grooming(concepts),
            legacy_matches_manipulation(concepts),
            legacy_matches_bullying(concepts),
            legacy_matches_explicit(concepts),
            legacy_matches_nsfw(concepts),
            legacy_matches_phishing(concepts),
        ]
    }

    fn table_results(concepts: Concepts) -> [bool; 8] {
        std::array::from_fn(|index| FAMILY_RULES[index].matches(concepts))
    }

    fn assert_equivalent(concepts: Concepts) {
        assert_eq!(
            table_results(concepts),
            legacy_results(concepts),
            "composition rule mismatch for concept mask {:#034x}",
            concepts.0
        );
    }

    #[test]
    fn declarative_predicates_match_previous_boolean_contract() {
        assert_equivalent(Concepts::default());
        for first in 0..=EXPOSURE_THREAT {
            assert_equivalent(Concepts::from_ids(&[first]));
            for second in (first + 1)..=EXPOSURE_THREAT {
                assert_equivalent(Concepts::from_ids(&[first, second]));
                for third in (second + 1)..=EXPOSURE_THREAT {
                    assert_equivalent(Concepts::from_ids(&[first, second, third]));
                }
            }
        }

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..200_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let width = usize::try_from((state % 9) + 1).expect("bounded width");
            let mut concepts = Concepts::default();
            for _ in 0..width {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                concepts.insert(u8::try_from(state % 86).expect("bounded concept"));
            }
            assert_equivalent(concepts);
        }
    }

    #[test]
    fn declarative_routes_and_score_overrides_keep_previous_priority() {
        let cases = [
            (
                Concepts::from_ids(&[SECRECY, MEETING, MEDIA, LOCATION, GIFT, PLATFORM]),
                2,
                DomainEventKind::MeetingRequest,
                0.89,
            ),
            (
                Concepts::from_ids(&[GUILT, REQUEST, DEBT, FALSE_CONSENSUS, ISOLATION]),
                3,
                DomainEventKind::DebtCreation,
                0.87,
            ),
            (
                Concepts::from_ids(&[CREDENTIAL, REQUEST, MINIMIZATION]),
                3,
                DomainEventKind::GuiltTripping,
                0.78,
            ),
            (
                Concepts::from_ids(&[SECOND_PERSON, DEVALUATION, EXCLUSION, MOCKERY]),
                4,
                DomainEventKind::Exclusion,
                0.88,
            ),
        ];

        for (concepts, family_index, event_kind, score) in cases {
            let candidate = FAMILY_RULES[family_index].candidate_for(concepts);
            assert_eq!(candidate.event_kind, event_kind);
            assert_eq!(candidate.score, score);
        }
    }
}
