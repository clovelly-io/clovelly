//! Writes the gRPC and protobuf bindings for `proto/` into `crates/common/src/proto/`.
//! Needs `protoc` on PATH or in `PROTOC`. Run from anywhere in the repository.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let proto = root.join("proto");
    let out = root.join("crates/common/src/proto");
    tonic_prost_build::configure()
        .out_dir(&out)
        .emit_rerun_if_changed(false)
        .compile_protos(
            &[
                proto.join("clovelly/verifier/v1/verifier.proto"),
                proto.join("clovelly/cell/v1/cell.proto"),
                proto.join("clovelly/control/v1/control.proto"),
                proto.join("grpc/health/v1/health.proto"),
                proto.join("vendor/gce-tcb-verifier/endorsement.proto"),
            ],
            &[proto],
        )?;
    println!("wrote {}", out.display());
    Ok(())
}
