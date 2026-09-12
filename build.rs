mod build_support;
use std::{env, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let inputs = build_support::inputs(&root).expect("detector source inventory");
    println!("cargo:rerun-if-changed=src");
    for path in &inputs {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let compiler = Command::new(env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .expect("compiler identity");
    assert!(compiler.status.success());
    let mut context: Vec<_> = env::vars()
        .filter(|(key, _)| key.starts_with("CARGO_FEATURE_"))
        .collect();
    for key in [
        "TARGET",
        "PROFILE",
        "OPT_LEVEL",
        "CARGO_CFG_TARGET_FEATURE",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
        context.push((key.into(), env::var(key).unwrap_or_default()));
    }
    context.sort();
    let context = format!(
        "{:?}\n{}",
        context,
        String::from_utf8(compiler.stdout).unwrap()
    );
    let digest = build_support::fingerprint(&root, &inputs, &context)
        .expect("detector compatibility digest");
    println!("cargo:rustc-env=NOISEFENCE_DETECTOR_BUILD_SHA256={digest}");
}
