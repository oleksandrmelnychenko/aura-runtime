fn main() {
    let messenger_proto = "../../proto/aura/messenger/v1/messenger.proto";
    let pilot_proto = "../../proto/aura/messenger/v1/pilot.proto";
    println!("cargo:rerun-if-changed={messenger_proto}");
    println!("cargo:rerun-if-changed={pilot_proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(&[messenger_proto, pilot_proto], &["../../proto"])
        .expect("compile protos");
}
