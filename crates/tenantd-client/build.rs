fn main() {
    println!("cargo:rerun-if-changed=../../proto/tenantd.proto");
    tonic_prost_build::configure()
        .compile_protos(&["../../proto/tenantd.proto"], &["../../proto"])
        .expect("compiling tenantd.proto");
}
