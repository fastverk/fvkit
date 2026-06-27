// Generates Rust bindings (tonic server + client + prost messages)
// for the fastverk app contract. Mirrors services/org/build.rs so the
// codegen runs identically under cargo and under Bazel's
// cargo_build_script (which supplies PROTOC). Proto sources are
// reached relative to CARGO_MANIFEST_DIR = `app/core`, i.e.
// `../../proto/...`, exactly as the service build scripts do.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("fastverk_descriptor.bin"))
        .compile_protos(
            &[
                "../../proto/fastverk/v1/fvd.proto",
                "../../proto/fastverk/v1/connection.proto",
                "../../proto/fastverk/v1/maintenance.proto",
                "../../proto/fastverk/v1/repos.proto",
                "../../proto/fastverk/plugin/v1/manifest.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
