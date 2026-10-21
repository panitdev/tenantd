//! `src/generated/tenantd.v1.rs` is committed so the published crate needs no
//! build script or protoc. This fails when it drifts from proto/tenantd.proto;
//! rerun with `TENANTD_REGEN=1` to rewrite it.

use std::path::Path;

#[test]
fn generated_code_matches_proto() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = root.join("../../proto");
    let committed = root.join("src/generated/tenantd.v1.rs");

    let out = tempfile::tempdir().unwrap();
    tonic_prost_build::configure()
        .out_dir(out.path())
        .compile_protos(&[proto_dir.join("tenantd.proto")], &[proto_dir])
        .expect("compiling tenantd.proto");
    let fresh = std::fs::read_to_string(out.path().join("tenantd.v1.rs")).unwrap();

    if std::env::var_os("TENANTD_REGEN").is_some() {
        std::fs::write(&committed, &fresh).unwrap();
        return;
    }
    let current = std::fs::read_to_string(&committed).unwrap_or_default();
    assert!(
        current == fresh,
        "src/generated/tenantd.v1.rs is stale; run `TENANTD_REGEN=1 cargo test -p tenantd-client --test generated`"
    );
}
