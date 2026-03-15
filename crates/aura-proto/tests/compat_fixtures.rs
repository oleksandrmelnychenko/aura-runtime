use aura_proto::compat_fixtures::{
    analysis_result_fixture, batch_analyze_response_fixture, tracker_state_fixture,
};
use aura_proto::messenger::v1 as proto;
use prost::Message;

const ANALYSIS_RESULT_FIXTURE: &[u8] = include_bytes!("fixtures/analysis_result.pb");
const TRACKER_STATE_FIXTURE: &[u8] = include_bytes!("fixtures/tracker_state.pb");
const BATCH_ANALYZE_RESPONSE_FIXTURE: &[u8] = include_bytes!("fixtures/batch_analyze_response.pb");

#[test]
fn analysis_result_fixture_matches_wire_contract() {
    let decoded = proto::AnalysisResult::decode(ANALYSIS_RESULT_FIXTURE).expect("decode fixture");
    assert_eq!(decoded, analysis_result_fixture());
    assert_eq!(decoded.encode_to_vec(), ANALYSIS_RESULT_FIXTURE);
}

#[test]
fn tracker_state_fixture_matches_wire_contract() {
    let decoded = proto::TrackerState::decode(TRACKER_STATE_FIXTURE).expect("decode fixture");
    assert_eq!(decoded, tracker_state_fixture());
    assert_eq!(decoded.encode_to_vec(), TRACKER_STATE_FIXTURE);
}

#[test]
fn batch_analyze_response_fixture_matches_wire_contract() {
    let decoded = proto::BatchAnalyzeResponse::decode(BATCH_ANALYZE_RESPONSE_FIXTURE)
        .expect("decode fixture");
    assert_eq!(decoded, batch_analyze_response_fixture());
    assert_eq!(decoded.encode_to_vec(), BATCH_ANALYZE_RESPONSE_FIXTURE);
}
