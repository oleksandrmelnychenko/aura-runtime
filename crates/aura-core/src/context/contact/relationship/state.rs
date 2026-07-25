use super::*;

/// Manages a bounded collection of contact profiles and provides anomaly detection.
pub struct ContactProfiler {
    pub(super) profiles: HashMap<SenderId, ContactProfile>,
    max_profiles: usize,
}

/// Represents the serializable wire state of the contact profiler.
#[derive(Debug, Clone)]
pub struct ContactProfilerWireState {
    pub profiles: Vec<ContactProfileState>,
}

impl Default for ContactProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactProfiler {
    /// Creates a new profiler with the default maximum profile limit.
    pub fn new() -> Self {
        Self::with_max_profiles(DEFAULT_MAX_CONTACT_PROFILES)
    }

    /// Creates a new profiler with an explicit maximum profile count.
    pub fn with_max_profiles(max_profiles: usize) -> Self {
        Self {
            profiles: HashMap::new(),
            max_profiles: max_profiles.max(1),
        }
    }

    /// Records a context event, updating or creating the corresponding contact profile.
    pub fn record_event(&mut self, event: &ContextEvent) {
        self.ensure_capacity_for_sender(&event.sender_id);
        let profile = self
            .profiles
            .entry(event.sender_id.clone())
            .or_insert_with(|| ContactProfile::new(event.sender_id.clone(), event.timestamp_ms));

        profile.total_messages += 1;
        profile.last_seen_ms = profile.last_seen_ms.max(event.timestamp_ms);

        if !profile.conversations.contains(&event.conversation_id) {
            profile.conversations.push(event.conversation_id.clone());
            profile.conversation_count = profile.conversations.len();
        }

        if event.kind.is_core_grooming_indicator() && event.supports_grooming_inference() {
            profile.grooming_event_count += 1;
        }
        if event.supports_grooming_inference() {
            profile
                .child_safety
                .record_grooming_event(&event.kind, event.timestamp_ms);
        }
        if event.kind.is_bullying_indicator() {
            profile.bullying_event_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            profile.manipulation_event_count += 1;
        }

        let is_propaganda_event = event.supports_propaganda_inference();
        if is_propaganda_event {
            profile.propaganda_event_count += 1;
            if profile.first_propaganda_ms == 0 {
                profile.first_propaganda_ms = event.timestamp_ms;
            }
            profile.last_propaganda_ms = event.timestamp_ms;

            if let Some(ref st) = event.subtype {
                profile.record_narrative_hit(st, event.timestamp_ms);
            }
            profile.record_weekly_propaganda_count(event.timestamp_ms);
            if let Some(content_hash) = event.content_hash {
                profile.record_message_fingerprint(event.timestamp_ms, content_hash);
            }

            let hour = ((event.timestamp_ms / 3_600_000) % 24) as usize;
            profile.hourly_activity[hour] = profile.hourly_activity[hour].saturating_add(1);

            if !profile
                .propaganda_conversations
                .contains(&event.conversation_id)
                && profile.propaganda_conversations.len() < 50
            {
                profile
                    .propaganda_conversations
                    .push(event.conversation_id.clone());
            }

            if event.kind == EventKind::SuspiciousSource {
                profile.propaganda_source_count += 1;
            }
        }
        if profile.propaganda_event_count > 0 {
            profile.update_propaganda_score();
        }

        let severity = event.effective_severity();
        if severity > 0.0 {
            profile.severity_sum += severity;
            profile.severity_count += 1;
        }

        profile.update_rating(event);
    }

    /// Updates the maximum profile limit and evicts excess profiles if needed.
    pub fn update_max_profiles(&mut self, max_profiles: usize) {
        self.max_profiles = max_profiles.max(1);
        self.enforce_profile_limit();
    }

    /// Returns true if the sender is unknown or was first seen within the last 48 hours.
    pub fn is_new_contact(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => true,
            Some(p) => !p.is_trusted && p.relationship_age_ms() < 48 * 60 * 60 * 1000,
        }
    }

    /// Returns true if the sender appears in many conversations with grooming indicators.
    pub fn contacts_many_minors(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => false,
            Some(p) => p.conversation_count >= 5 && p.grooming_event_count >= 3,
        }
    }

    /// Returns the profile for the given sender, if one exists.
    pub fn profile(&self, sender_id: &str) -> Option<&ContactProfile> {
        self.profiles.get(sender_id)
    }

    /// Removes a contact profile, if it exists.
    pub fn remove_profile(&mut self, sender_id: &str) {
        self.profiles.remove(sender_id);
    }

    /// Returns a lightweight snapshot for the given sender, if a profile exists.
    pub fn snapshot(&self, sender_id: &str) -> Option<ContactSnapshot> {
        self.profile(sender_id)
            .map(|profile| profile.snapshot(self.is_new_contact(sender_id)))
    }

    /// Returns all contact profiles sorted by risk score in descending order.
    pub fn contacts_by_risk(&self) -> Vec<&ContactProfile> {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(p);
        }
        profiles.sort_by(|a, b| {
            b.risk_score()
                .partial_cmp(&a.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        profiles
    }

    /// Marks the given sender as fully trusted.
    pub fn mark_trusted(&mut self, sender_id: &str) {
        self.ensure_capacity_for_sender(sender_id);
        let profile = self
            .profiles
            .entry(SenderId::from(sender_id))
            .or_insert_with(|| ContactProfile::new(SenderId::from(sender_id), 0));
        profile.trust_level = 1.0;
        profile.is_trusted = true;
    }

    /// Sets the inferred age for a sender if not already set and the value is valid (5-99).
    ///
    /// A higher-confidence source always overwrites a lower-confidence one
    /// (e.g. `ParentVerified` replaces `MlInferred`), but a same-or-lower
    /// source is ignored once the age is already set.
    pub fn set_inferred_age(&mut self, sender_id: &str, age: u16) {
        self.set_inferred_age_with_source(sender_id, age, AgeSource::UserReported);
    }

    /// Sets the inferred age with an explicit source confidence tag.
    pub fn set_inferred_age_with_source(&mut self, sender_id: &str, age: u16, source: AgeSource) {
        if let Some(profile) = self.profiles.get_mut(sender_id) {
            // Require at least minimal history before accepting claimed age.
            if profile.total_messages < 2 {
                return;
            }
            if !(5..=99).contains(&age) {
                return;
            }
            let dominated = match (profile.inferred_age, source, profile.age_source) {
                (None, _, _) => false,
                (Some(_), AgeSource::ParentVerified, AgeSource::ParentVerified) => true,
                (Some(_), AgeSource::ParentVerified, _) => false,
                (Some(_), _, _) => true,
            };
            if !dominated {
                profile.inferred_age = Some(age);
                profile.age_source = source;
            }
        }
    }

    /// Generates detection signals if a significant age gap exists between sender and account holder.
    pub fn check_age_gap(
        &self,
        sender_id: &str,
        account_holder_age: Option<u16>,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.is_trusted {
            return signals;
        }

        let sender_age = match profile.inferred_age {
            Some(age) => age,
            None => return signals,
        };

        let holder_age = match account_holder_age {
            Some(age) => age,
            None => return signals,
        };

        if holder_age < 18 && sender_age >= 18 {
            let gap = sender_age - holder_age;
            if gap >= 5 {
                let raw_score = if profile.grooming_event_count > 0 {
                    (0.6 + gap as f32 * 0.02).min(0.95)
                } else {
                    (0.3 + gap as f32 * 0.01).min(0.6)
                };
                // Scale the score by how confident we are in the age
                // data. ParentVerified → full score, MlInferred → 70%.
                let score = (raw_score * profile.age_source.confidence_factor()).min(0.95);

                signals.push(DetectionSignal::context(
                    ThreatType::Grooming,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    if profile.grooming_event_count > 0 {
                        "conversation.contact.age_gap_with_grooming"
                    } else {
                        "conversation.contact.age_gap"
                    },
                    format!(
                        "Age gap detected: sender claims age {sender_age}, account holder is {holder_age} (gap: {gap} years){}",
                        if profile.grooming_event_count > 0 {
                            format!(" with {} grooming indicators", profile.grooming_event_count)
                        } else {
                            String::new()
                        }
                    ),
                ));
            }
        }

        signals
    }

    /// Checks a contact for anomalous patterns such as new risky contacts or multi-conversation predators.
    pub fn check_anomalies(&self, sender_id: &str, is_minor_account: bool) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.is_trusted {
            return signals;
        }

        let risk = profile.risk_score();

        if is_minor_account && self.is_new_contact(sender_id) && risk >= 0.3 {
            let dominant_threat = profile.dominant_contact_risk_threat();
            signals.push(DetectionSignal::context(
                dominant_threat,
                risk,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.contact.new_risky_contact",
                format!(
                    "New contact with suspicious behavior pattern (risk: {risk:.2}). {} grooming indicators, {} manipulation indicators, {} bullying indicators.",
                    profile.grooming_event_count,
                    profile.manipulation_event_count,
                    profile.bullying_event_count,
                ),
            ));
        }

        if is_minor_account && profile.conversation_count >= 5 && profile.grooming_event_count >= 3
        {
            signals.push(DetectionSignal::context(
                ThreatType::Grooming,
                0.8,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.contact.multi_conversation_predator_pattern",
                format!(
                    "Contact appears in {} conversations with {} grooming indicators — possible predator pattern",
                    profile.conversation_count,
                    profile.grooming_event_count,
                ),
            ));
        }

        signals
    }

    /// Checks persistent child-safety trajectory memory for grooming escalation.
    pub fn check_child_safety_trajectory(
        &self,
        sender_id: &str,
        is_minor_account: bool,
        account_holder_age: Option<u16>,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        let risk = profile.child_safety_trajectory_risk(is_minor_account, account_holder_age);
        if risk < 0.55 {
            return signals;
        }

        let stage_count = profile.child_safety.stage_count();
        let high_risk_stage_count = profile.child_safety.high_risk_stage_count();
        let confidence = if risk >= 0.75 || high_risk_stage_count >= 3 {
            Confidence::High
        } else {
            Confidence::Medium
        };

        signals.push(DetectionSignal::context(
            ThreatType::Grooming,
            risk,
            confidence,
            SignalFamily::Conversation,
            "conversation.contact.grooming_trajectory_risk",
            format!(
                "Contact-level grooming trajectory risk: {stage_count} stages, {high_risk_stage_count} high-risk stages, {} grooming events{}",
                profile.child_safety.grooming_event_count,
                if profile.child_safety.has_rapid_escalation() {
                    " with rapid escalation"
                } else {
                    ""
                }
            ),
        ));

        signals
    }

    /// Generates signals for behavioral trend changes such as rapid worsening or role reversal.
    pub fn check_behavioral_shift(&self, sender_id: &str) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();
        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.weekly_snapshots.len() < 3 {
            return signals;
        }

        match profile.trend {
            BehavioralTrend::RapidWorsening => {
                let mut score = 0.5;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Manipulation,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_rapid_worsening",
                    format!(
                        "Contact {} showing rapid behavioral worsening (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::RoleReversal => {
                let mut score = 0.6;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                if profile.trust_level < 0.4 {
                    if let Some(first) = profile.weekly_snapshots.front() {
                        if first.supportive_ratio() > 0.3 {
                            score += 0.1;
                        }
                    }
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Bullying,
                    score,
                    Confidence::High,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_role_reversal",
                    format!(
                        "Contact {} role reversal: was supportive, now hostile (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::GradualWorsening => {
                let mut score = 0.35;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Manipulation,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_gradual_worsening",
                    format!(
                        "Contact {} showing gradual behavioral worsening over weeks (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::Stable | BehavioralTrend::Improving => {}
        }

        if profile.rating < 20.0 && profile.circle_tier == CircleTier::Inner {
            signals.push(DetectionSignal::context(
                ThreatType::Bullying,
                0.55,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.contact.inner_circle_low_rating",
                format!(
                    "Inner circle contact {} has critically low rating ({:.0}/100)",
                    sender_id, profile.rating
                ),
            ));
        }

        signals
    }

    /// Exports all profiles as a cloneable state snapshot.
    pub fn export(&self) -> ContactProfilerState {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(p.clone());
        }
        ContactProfilerState { profiles }
    }

    /// Exports all profiles as a wire-format state for serialization.
    pub fn export_wire_state(&self) -> ContactProfilerWireState {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(ContactProfileState::from(p));
        }
        ContactProfilerWireState { profiles }
    }

    /// Imports profiles from a state snapshot, replacing existing profiles with the same sender ID.
    pub fn import(&mut self, state: ContactProfilerState) {
        for profile in state.profiles {
            self.profiles.insert(profile.sender_id.clone(), profile);
        }
        self.enforce_profile_limit();
    }

    /// Merge-based import: preserves local profiles, takes the most cautious values.
    pub fn merge_import(&mut self, state: ContactProfilerState) {
        for incoming in state.profiles {
            match self.profiles.get_mut(&incoming.sender_id) {
                Some(local) => {
                    let incoming_average = incoming.average_severity();
                    let incoming_severity_count = incoming.severity_count;
                    local.first_seen_ms = local.first_seen_ms.min(incoming.first_seen_ms);
                    local.last_seen_ms = local.last_seen_ms.max(incoming.last_seen_ms);
                    local.total_messages = local.total_messages.max(incoming.total_messages);
                    local.grooming_event_count = local
                        .grooming_event_count
                        .max(incoming.grooming_event_count);
                    local.bullying_event_count = local
                        .bullying_event_count
                        .max(incoming.bullying_event_count);
                    local.manipulation_event_count = local
                        .manipulation_event_count
                        .max(incoming.manipulation_event_count);
                    local.propaganda_event_count = local
                        .propaganda_event_count
                        .max(incoming.propaganda_event_count);
                    local.propaganda_source_count = local
                        .propaganda_source_count
                        .max(incoming.propaganda_source_count);
                    local.first_propaganda_ms = if local.first_propaganda_ms == 0 {
                        incoming.first_propaganda_ms
                    } else if incoming.first_propaganda_ms == 0 {
                        local.first_propaganda_ms
                    } else {
                        local.first_propaganda_ms.min(incoming.first_propaganda_ms)
                    };
                    local.last_propaganda_ms =
                        local.last_propaganda_ms.max(incoming.last_propaganda_ms);
                    local.propaganda_score = local.propaganda_score.max(incoming.propaganda_score);
                    local.narrative_diversity =
                        local.narrative_diversity.max(incoming.narrative_diversity);
                    for (nid, count) in &incoming.narrative_hits {
                        let mut found = false;
                        for entry in &mut local.narrative_hits {
                            if entry.0 == *nid {
                                entry.1 = entry.1.max(*count);
                                found = true;
                                break;
                            }
                        }
                        if !found && local.narrative_hits.len() < 15 {
                            local.narrative_hits.push((*nid, *count));
                        }
                    }
                    local.narrative_diversity = local.narrative_hits.len() as u8;
                    let mut known_propaganda_conversations: HashSet<ConversationId> =
                        HashSet::with_capacity(local.propaganda_conversations.len());
                    for conv in &local.propaganda_conversations {
                        known_propaganda_conversations.insert(conv.clone());
                    }
                    for conv in &incoming.propaganda_conversations {
                        if local.propaganda_conversations.len() >= 50 {
                            break;
                        }
                        if known_propaganda_conversations.insert(conv.clone()) {
                            local.propaganda_conversations.push(conv.clone());
                        }
                    }
                    for (idx, count) in incoming.hourly_activity.iter().enumerate() {
                        local.hourly_activity[idx] = local.hourly_activity[idx].max(*count);
                    }

                    let mut local_fingerprint_counts: HashMap<u64, usize> = HashMap::new();
                    for fingerprint in &local.message_fingerprints {
                        let entry = local_fingerprint_counts.entry(*fingerprint).or_insert(0);
                        *entry += 1;
                    }
                    let mut incoming_fingerprint_counts: HashMap<u64, usize> = HashMap::new();
                    for fingerprint in incoming.message_fingerprints {
                        let entry = incoming_fingerprint_counts.entry(fingerprint).or_insert(0);
                        *entry += 1;
                    }
                    let mut fingerprint_counts = local_fingerprint_counts;
                    for (fingerprint, incoming_count) in incoming_fingerprint_counts {
                        let entry = fingerprint_counts.entry(fingerprint).or_insert(0);
                        *entry = (*entry).max(incoming_count);
                    }
                    let mut ranked_fingerprints: Vec<(u64, usize)> =
                        Vec::with_capacity(fingerprint_counts.len());
                    for (fingerprint, count) in fingerprint_counts {
                        ranked_fingerprints.push((fingerprint, count));
                    }
                    ranked_fingerprints
                        .sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    local.message_fingerprints.clear();
                    'outer: for (fingerprint, count) in ranked_fingerprints {
                        for _ in 0..count {
                            if local.message_fingerprints.len() >= MAX_MESSAGE_FINGERPRINTS {
                                break 'outer;
                            }
                            local.message_fingerprints.push_back(fingerprint);
                        }
                    }
                    local.last_fingerprint_marker = None;

                    let mut merged_timeline = Vec::with_capacity(
                        local.narrative_timeline.len() + incoming.narrative_timeline.len(),
                    );
                    for point in &local.narrative_timeline {
                        merged_timeline.push(*point);
                    }
                    for point in incoming.narrative_timeline {
                        merged_timeline.push(point);
                    }
                    merged_timeline
                        .sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                    merged_timeline.dedup();
                    if merged_timeline.len() > MAX_NARRATIVE_TIMELINE {
                        let overflow = merged_timeline.len() - MAX_NARRATIVE_TIMELINE;
                        merged_timeline.drain(0..overflow);
                    }
                    local.narrative_timeline.clear();
                    for point in merged_timeline {
                        local.narrative_timeline.push_back(point);
                    }

                    for (week_start_ms, count) in incoming.weekly_propaganda_counts {
                        let mut found = false;
                        for entry in &mut local.weekly_propaganda_counts {
                            if entry.0 == week_start_ms {
                                entry.1 = entry.1.max(count);
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            local
                                .weekly_propaganda_counts
                                .push_back((week_start_ms, count));
                        }
                    }
                    let mut merged_weekly =
                        Vec::with_capacity(local.weekly_propaganda_counts.len());
                    for entry in &local.weekly_propaganda_counts {
                        merged_weekly.push(*entry);
                    }
                    merged_weekly.sort_unstable_by_key(|entry| entry.0);
                    if merged_weekly.len() > MAX_WEEKLY_PROPAGANDA_BUCKETS {
                        let overflow = merged_weekly.len() - MAX_WEEKLY_PROPAGANDA_BUCKETS;
                        merged_weekly.drain(0..overflow);
                    }
                    local.weekly_propaganda_counts.clear();
                    for entry in merged_weekly {
                        local.weekly_propaganda_counts.push_back(entry);
                    }

                    let mut known_conversations: HashSet<ConversationId> =
                        HashSet::with_capacity(local.conversations.len());
                    for conv in &local.conversations {
                        known_conversations.insert(conv.clone());
                    }
                    for conv in incoming.conversations {
                        if known_conversations.insert(conv.clone()) {
                            local.conversations.push(conv);
                        }
                    }
                    local.conversation_count = local.conversations.len();

                    local.trust_level = local.trust_level.min(incoming.trust_level);
                    local.rating = local.rating.min(incoming.rating);
                    local.is_trusted = local.is_trusted && incoming.is_trusted;

                    if trend_severity(&incoming.trend) > trend_severity(&local.trend) {
                        local.trend = incoming.trend;
                    }

                    if local.inferred_age.is_none() {
                        local.inferred_age = incoming.inferred_age;
                    }
                    local.child_safety =
                        merge_child_safety_trajectory(local.child_safety, incoming.child_safety);
                    for snapshot in incoming.weekly_snapshots {
                        merge_weekly_snapshot(&mut local.weekly_snapshots, snapshot);
                    }
                    if let Some(incoming_snapshot) = incoming.current_snapshot {
                        match local.current_snapshot.as_mut() {
                            Some(current)
                                if current.period_start_ms == incoming_snapshot.period_start_ms =>
                            {
                                current.merge_from(incoming_snapshot);
                            }
                            Some(current)
                                if current.period_start_ms > incoming_snapshot.period_start_ms =>
                            {
                                merge_weekly_snapshot(
                                    &mut local.weekly_snapshots,
                                    incoming_snapshot,
                                );
                            }
                            Some(_) => {
                                let previous = local
                                    .current_snapshot
                                    .replace(incoming_snapshot)
                                    .expect("current snapshot is present");
                                merge_weekly_snapshot(&mut local.weekly_snapshots, previous);
                            }
                            None => {
                                local.current_snapshot = Some(incoming_snapshot);
                            }
                        }
                    }
                    local.active_days.extend(incoming.active_days);

                    let local_average = local.average_severity();
                    let merged_average = local_average.max(incoming_average);
                    local.severity_count = local.severity_count.max(incoming_severity_count);
                    if local.severity_count == 0 {
                        local.severity_sum = 0.0;
                    } else {
                        local.severity_sum = merged_average * local.severity_count as f32;
                    }
                    if local.propaganda_event_count > 0 {
                        local.update_propaganda_score();
                    }
                }
                None => {
                    self.profiles.insert(incoming.sender_id.clone(), incoming);
                }
            }
        }
        self.enforce_profile_limit();
    }

    /// Imports profiles from wire-format state, replacing existing profiles with the same sender ID.
    pub fn import_wire_state(&mut self, state: ContactProfilerWireState) {
        let mut profiles = Vec::with_capacity(state.profiles.len());
        for p in state.profiles {
            profiles.push(ContactProfile::from(p));
        }
        self.import(ContactProfilerState { profiles });
    }

    /// Merges profiles from wire-format state, taking the most cautious values for conflicts.
    pub fn merge_import_wire_state(&mut self, state: ContactProfilerWireState) {
        let mut profiles = Vec::with_capacity(state.profiles.len());
        for p in state.profiles {
            profiles.push(ContactProfile::from(p));
        }
        self.merge_import(ContactProfilerState { profiles });
    }

    /// Removes profiles not seen since the cutoff and prunes stale active-day entries.
    pub fn cleanup(&mut self, cutoff_ms: u64) {
        let cutoff_day = (cutoff_ms / DAY_MS) as u32;
        self.profiles.retain(|_, p| {
            if p.last_seen_ms < cutoff_ms {
                return false;
            }
            p.active_days
                .retain(|&d| d >= cutoff_day.saturating_sub(90));
            true
        });
    }

    fn ensure_capacity_for_sender(&mut self, sender_id: &str) {
        if self.profiles.contains_key(sender_id) {
            return;
        }

        self.enforce_profile_limit_for_incoming(sender_id);
    }

    fn enforce_profile_limit(&mut self) {
        while self.profiles.len() > self.max_profiles {
            if self.evict_oldest_profile(None).is_none() {
                break;
            }
        }
    }

    fn enforce_profile_limit_for_incoming(&mut self, incoming_sender_id: &str) {
        while self.profiles.len() >= self.max_profiles {
            if self
                .evict_oldest_profile(Some(incoming_sender_id))
                .is_none()
            {
                break;
            }
        }
    }

    fn evict_oldest_profile(
        &mut self,
        protected_sender_id: Option<&str>,
    ) -> Option<ContactProfile> {
        let mut oldest_sender: Option<SenderId> = None;
        let mut best_risk_band = u8::MAX;
        let mut best_last_seen = u64::MAX;
        let mut best_first_seen = u64::MAX;
        let mut best_id: Option<&str> = None;
        for (sender_id, profile) in &self.profiles {
            if Some(&**sender_id) == protected_sender_id {
                continue;
            }
            let risk_band = if profile.risk_score() >= 0.75 {
                2u8
            } else if profile.risk_score() >= 0.45 {
                1u8
            } else {
                0u8
            };
            let cmp = risk_band
                .cmp(&best_risk_band)
                .then_with(|| profile.last_seen_ms.cmp(&best_last_seen))
                .then_with(|| profile.first_seen_ms.cmp(&best_first_seen))
                .then_with(|| (**sender_id).cmp(best_id.unwrap_or("")));
            if cmp == std::cmp::Ordering::Less || oldest_sender.is_none() {
                best_risk_band = risk_band;
                best_last_seen = profile.last_seen_ms;
                best_first_seen = profile.first_seen_ms;
                best_id = Some(&**sender_id);
                oldest_sender = Some(sender_id.clone());
            }
        }

        let key = oldest_sender?;
        self.profiles.remove(&key)
    }
}

/// Holds a snapshot of all contact profiles for export or import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactProfilerState {
    pub profiles: Vec<ContactProfile>,
}
