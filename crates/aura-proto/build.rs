fn main() {
    let proto = "../../proto/aura/messenger/v1/messenger.proto";
    println!("cargo:rerun-if-changed={proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(&[proto], &["../../proto"])
        .expect("compile protos");
}
