use std::fs;
use std::path::PathBuf;

use aura_proto::compat_fixtures::{
    analysis_result_fixture, batch_analyze_response_fixture, tracker_state_fixture,
};
use prost::Message;

fn main() {
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    fs::create_dir_all(&output_dir).expect("create compatibility fixtures directory");

    write_fixture(
        &output_dir,
        "analysis_result.pb",
        analysis_result_fixture().encode_to_vec(),
    );
    write_fixture(
        &output_dir,
        "tracker_state.pb",
        tracker_state_fixture().encode_to_vec(),
    );
    write_fixture(
        &output_dir,
        "batch_analyze_response.pb",
        batch_analyze_response_fixture().encode_to_vec(),
    );
}

fn write_fixture(output_dir: &PathBuf, file_name: &str, bytes: Vec<u8>) {
    let path = output_dir.join(file_name);
    fs::write(&path, bytes)
        .unwrap_or_else(|error| panic!("write compatibility fixture {}: {error}", path.display()));
    println!("wrote {}", path.display());
}
