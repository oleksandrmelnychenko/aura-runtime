use std::{env, fs, path::PathBuf};

const TRUST_KEYRING_PATH_ENV: &str = "AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH";
const TRUST_KEYRING_DIGEST_ENV: &str = "AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256";

fn main() {
    println!("cargo:rerun-if-env-changed={TRUST_KEYRING_PATH_ENV}");
    println!("cargo:rerun-if-env-changed={TRUST_KEYRING_DIGEST_ENV}");

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo always supplies OUT_DIR"))
        .join("execution-policy-trust-keyring.json");
    let path = env::var_os(TRUST_KEYRING_PATH_ENV);
    let digest = env::var(TRUST_KEYRING_DIGEST_ENV).ok();
    let embedded = match (path, digest) {
        (None, None) => Vec::new(),
        (Some(path), Some(digest)) => {
            assert!(
                is_nonzero_lower_hex_digest(&digest),
                "execution-policy trust keyring digest must be 64 lowercase nonzero hex characters"
            );
            println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
            println!("cargo:rustc-env={TRUST_KEYRING_DIGEST_ENV}={digest}");
            fs::read(path).expect("failed to read execution-policy trust keyring")
        }
        _ => panic!(
            "{TRUST_KEYRING_PATH_ENV} and {TRUST_KEYRING_DIGEST_ENV} must be supplied together"
        ),
    };
    fs::write(output, embedded).expect("failed to stage execution-policy trust keyring");
}

fn is_nonzero_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}
