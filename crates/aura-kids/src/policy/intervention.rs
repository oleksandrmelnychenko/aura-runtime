use aura_domain::{decide_action_with_thresholds, DomainAction, DomainPolicyThresholds, DomainSignal};

pub fn decide(signals: &[DomainSignal]) -> Option<DomainAction> {
    decide_with_thresholds(signals, DomainPolicyThresholds::default())
}

pub fn decide_with_thresholds(
    signals: &[DomainSignal],
    thresholds: DomainPolicyThresholds,
) -> Option<DomainAction> {
    decide_action_with_thresholds(signals, thresholds)
}
