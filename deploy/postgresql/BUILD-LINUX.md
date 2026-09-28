# Cross-compiling the Linux recovery binary

On an ARM development host, an ARM-native compiler can produce the Linux x86-64
binary without executing x86-64 compiler processes through emulation. The helper
image installs the GNU x86-64 cross toolchain and the Rust target. It does not need
privileged mode, host binary-format registrations, production SSH access or mail data.

From the repository root:

```sh
docker build -f deploy/postgresql/Dockerfile.cross -t noisefence-cross-builder .
docker run --name noisefence-cross-build --cpus 2 --memory 4g --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  --mount type=volume,source=noisefence-cross-target,target=/build \
  --mount type=volume,source=noisefence-cross-registry,target=/usr/local/cargo/registry \
  --workdir /workspace --env CARGO_TARGET_DIR=/build --env CARGO_INCREMENTAL=0 \
  noisefence-cross-builder cargo build --release --locked --features semantic \
  --bin noisefence --target x86_64-unknown-linux-gnu -j2
```

Keep the checkout unchanged during compilation, or build from a separate snapshot
with a recorded file inventory. Include the `examples` directory: Cargo validates
explicit example paths even when only the application binary is requested.

Only after the build exits successfully, copy its result:

```sh
mkdir -p release/cross-build
docker cp noisefence-cross-build:/build/x86_64-unknown-linux-gnu/release/noisefence \
  release/cross-build/noisefence
```

Do not copy a cached binary after a failed build. Record the source inventory, builder
image digest and output SHA-256 alongside the artifact. The base Rust image is pinned;
Debian cross-toolchain packages are resolved when building the helper image, so retain
that resulting image digest for the release record.

Compilation does not establish production compatibility. Verify the ELF architecture,
required shared libraries, native execution on the target distribution and the full
migration/recovery rehearsal before selecting the release. The detector build binding
must be carried through the normal policy publication process; never bypass it to
reuse an older policy artifact with a newly compiled binary.
