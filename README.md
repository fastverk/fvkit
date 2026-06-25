# fvkit

The fastverk core/runtime module: the platform-abstracted machinery the
fastverk app is built on.

- **`fvkit`** (`app/core`, lib) — managed filesystem volumes (repos + bazel
  caches), ownership of the user's `~/.bazelrc`, bazelisk/bazel provisioning,
  authenticated "connections" (host → keychain-backed token) with OAuth,
  periodic maintenance, and self-update. Per-OS work lives behind a `platform`
  boundary; macOS is implemented first, other targets are stubs.
- **`fvd`** (`app/daemon`, bin) — an unprivileged, user-level gRPC server over
  a Unix-domain socket that wraps `fvkit` and is the single owner of mutable
  state. The menu-bar GUI, the `fv` CLI, and the Bazel credential helper are
  clients.

The gRPC + DTO contract is `fastverk.v1`, defined under
[`proto/fastverk/v1`](proto/fastverk/v1) and compiled by `app/core/build.rs`
(tonic-build). The build script reaches the `.proto` sources relative to its
manifest dir (`../../proto`), so the same bindings come out of `cargo build`
and `bazel build`.

## Build

Dual-built with Cargo and Bazel.

```sh
# Cargo
cargo build --workspace

# Bazel (resolves module deps from the fastverk bazel-registry + BCR; the
# crate hub is repinned from Cargo.lock).
CARGO_BAZEL_REPIN=1 bazel build //...
bazel test //...
```

The proto is compiled by `build.rs` under a `cargo_build_script`, so the only
Bazel codegen dependency is `protobuf` (for `protoc`).
