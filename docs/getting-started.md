# Getting started with the Phase 1 preview

MorphGate is a defensive bot-management and traffic-security platform for owner-controlled web properties. This source preview lets you build the Edge, the operations CLI and the browser SDK, then validate their integration on your own machine.

The recommended deployment is `Cloudflare → cloudflared → mg-edge → origin`, with `cloudflared` and the loopback Edge listener on the same host. Phase 1 is ready for evaluation; the owner-operated Cloudflare monitor period and production acceptance checks are still pending. See the [preview release notes](releases/v0.1.0-preview.1.md) for the scope and limitations.

## Prerequisites

The repository has been tested locally on macOS arm64 and in CI on Ubuntu 24.04 x86_64. Windows builds and other operating-system/architecture combinations are not verified for this preview.

| Tool | Requirement |
|---|---|
| Rust and Cargo | Rust 1.88 or newer; CI uses 1.91.1 for the main test/build job and separately checks the 1.88 minimum |
| Go | Go 1.25; also needed by BoringSSL's build-time generators |
| Native build tools | CMake, a C/C++ compiler, Clang and the libclang shared library for bindgen; on macOS, install the Apple command-line developer tools as well |
| Node.js | Node 26 matches CI; the SDK declares Node 22 or newer |
| pnpm | 10.23.0, as pinned in `sdk/web/package.json` |
| Local test tools | GNU Make, Bash, Python 3 and curl |
| State service for the Lab | `valkey-server` on `PATH`, or a dedicated local Valkey instance supplied through `MG_TEST_VALKEY_URL` |

On Ubuntu, the native compiler and utility prerequisites can be installed with:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake clang libclang-dev pkg-config python3 curl git
```

Install the language toolchains, pnpm and Valkey separately. On macOS, CMake and libclang must be available to the native build; if bindgen cannot locate libclang, set `LIBCLANG_PATH` to the directory containing your installed libclang library. BoringSSL is compiled from source during the Cargo build.

Docker is optional for the loopback checks below. It is required for the Compose environment and the separate Lab network-isolation check. Building the committed Go protobuf sources does not require `protoc`; regenerating them does.

## Build from the source release

Download and extract the source archive from [v0.1.0-preview.1](https://github.com/SkyBlue997/MorphGate/releases/tag/v0.1.0-preview.1), or check out that tag in a Git clone. Run the following from the extracted repository root. Keep Cargo builds in the shared `target/` directory and run them sequentially.

```sh
cargo build --release --locked -p mg-edge
mkdir -p target/install
install -m 0755 target/release/mg-edge target/install/mg-edge
go build -trimpath -o target/install/mgctl ./control-plane/cmd/mgctl
go build -trimpath -o target/install/mglab ./lab/cmd/mglab
pnpm -C sdk/web install --frozen-lockfile
pnpm -C sdk/web run check
```

The commands install local executables into the Git-ignored `target/install/` directory. The SDK check runs type checking, unit tests, the production build and the compressed-size check. Build tools fetch dependencies from their configured registries; the validation traffic in the next section stays on loopback.

Check the installed programs:

```sh
target/install/mg-edge --version
target/install/mgctl help
target/install/mglab help
```

The Edge's deployable SDK directory is **`sdk/web/dist/sdk/`**, containing a content-hashed JavaScript file, `manifest.json` and `challenge.html`. Keep all three together. `edge/tests/fixtures/sdk/` is a test fixture and must not be substituted for the built SDK in a deployment.

This preview uses the existing component versions: `mg-edge --version` reports `0.1.0`, while the SDK reports `0.1.0-phase1`. The repository release is identified by the `v0.1.0-preview.1` tag.

## Install the browser assets from npm

The matching SDK assets are distributed as `@ermiaodada/morphgate-web-sdk@0.1.0-phase1`, under the `preview` distribution tag. To obtain the built assets without a local TypeScript build, install the exact version in your deployment project:

```sh
npm install --save-exact @ermiaodada/morphgate-web-sdk@0.1.0-phase1
```

Use the complete `node_modules/@ermiaodada/morphgate-web-sdk/dist/sdk/` directory as the SDK directory, and retain the package's `LICENSE` and `NOTICE` when copying it to the Edge host. The [package guide](../sdk/web/README.md) covers installation and `sdk.dir`. This package supplies browser assets for the Phase 1 Edge; it has no Node.js import entry point and does not include the Edge server or deployment credentials.

For the Lab command below, set `MG_LAB_SDK_DIR` to this installed directory instead of `sdk/web/dist/sdk` when validating the npm distribution.

## Validate on loopback

First run the daemon/proxy smoke check using the binary you just built:

```sh
MG_EDGE_BIN="$PWD/target/install/mg-edge" make edge-smoke
```

This starts a temporary origin and Edge, validates configuration loading, signed-bundle activation, proxying, reserved endpoints, metrics and event output, then stops its processes. It uses intentionally public test credentials and an SDK fixture. The default ports are `18080`, `18081` and `19901`; the script reports a conflict if they are already occupied.

Then run the Phase 1 Lab scenarios with the **built SDK** and mandatory dependency checks:

```sh
MG_EDGE_BIN="$PWD/target/install/mg-edge" \
MG_LAB_SDK_DIR="$PWD/sdk/web/dist/sdk" \
MG_LAB_E2E_REQUIRE=1 \
make lab-e2e
```

The Lab builds its own temporary `mgctl` and `mglab`, generates throwaway test keys, signs and publishes a test configuration, and starts a temporary origin and Edge. By default it starts a local `valkey-server` on a private Unix socket. Its scenarios check crawler impersonation decisions and refusal to issue clearance to the supplied non-JavaScript clients. The Lab's target allowlist remains enforced.

To use an existing dedicated local Valkey test instance, add `MG_TEST_VALKEY_URL=redis://127.0.0.1:6379/` to that command. This instance receives test state; use a disposable instance. `MG_LAB_E2E_REQUIRE=1` makes a missing dependency fail instead of returning a successful skip, and `MG_LAB_SDK_DIR` prevents fallback to the SDK fixture.

The scripts remove their temporary files and stop processes they started on exit. Setting `MG_SMOKE_KEEP=1` or `MG_LAB_E2E_KEEP=1` retains test files and logs for debugging; these directories also contain test keys. A successful Lab run does not validate a live Cloudflare zone, browser compatibility or production latency.

## Configure an owner-operated deployment

Use the [control-plane command reference](../control-plane/README.md), [Cloudflare setup checklist](../adapters/cloudflare/README.md) and section 17 of the [Phase 1 implementation specification](impl/phase1-spec.md) for the full deployment and rotation procedures.

1. Generate fresh owner signing, pseudonymisation, upstream-header and per-site token/seal keys with `mgctl`. Keep the normal age work factor; `--insecure-test-key` and `MGCTL_AGE_WORK_FACTOR=10` are for tests only. Protect the passphrase and keep encrypted key material outside the repository.
2. Write the site's YAML and policy, including its real owner-controlled hostnames and generated key IDs. Obtain the required intelligence data through the documented tools and the data providers' own terms. Build, sign, verify and publish the site bundle with `mgctl`.
3. Adapt [`deploy/systemd/edge.toml.example`](../deploy/systemd/edge.toml.example) for the actual hosts, origin, state service, SDK and bundle locations. It is a template; its domains, addresses and paths need review. The template has `bootstrap = "open"`, which forwards traffic before the first bundle is active. Choose the intended bootstrap policy explicitly.
4. Install `mg-edge`, the complete built SDK directory and the owner public key. Use the [example systemd service](../deploy/systemd/mg-edge.service) and its `LoadCredentialEncrypted` entries to deliver the freshly generated Edge credentials. The unit's installation comments describe the user, directory and executable paths.
5. Run `mg-edge --check-config --config /etc/morphgate/edge.toml` in an environment with the configured credentials available. A shell outside systemd does not automatically receive its `CREDENTIALS_DIRECTORY`. Start the service only after the configuration, credentials, SDK and bundle setup have been checked.
6. Begin with `monitor_only: true` for at least seven days, review decisions and metrics, perform the real-browser regression checks, and complete `mgctl cf audit` for the owner's zone before deciding which routes to enforce.

The source archive deliberately includes test keys, TLS private keys, synthetic IP data and signed test bundles under the test directories. **Never use them as deployment secrets or deploy the development configuration as a production configuration.** The development Compose file also contains documented local-only password defaults.

## Scope and release maintenance

Phase 1 includes the Edge decision pipeline, rate limiting, signed configuration bundles, proof-of-work challenges, short-lived clearance tokens and operational event/metric output. The `mg-control` service has a health endpoint and a placeholder bundle endpoint; a management API/UI, interactive challenges and the later SDK/AI-agent features are future work.

Keep the previous executable, SDK and configuration available when upgrading. Review the key-rotation sequence before changing keys: reverting an old binary does not restore a deleted key or make a rejected bundle version acceptable. The systemd unit provides a checked graceful reload path for Edge upgrades. Review [known limitations and acceptance status](impl/phase1-status.md) for each release.

The project's own code is licensed under [Apache-2.0](../LICENSE). Dependencies and third-party data retain their own licenses. This release distributes source; it does not include native binaries, bundled dependencies or production intelligence databases.
