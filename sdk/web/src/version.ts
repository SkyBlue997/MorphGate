/**
 * The SDK's semantic version (`SDK_VERSION`), shared by the page and the
 * Worker: the Worker reports it in its acknowledgement so the page can tell
 * a Worker started from a cached `/__mg/s/mg.js` alias of another build
 * (docs/impl/phase2-spec.md D-39, §12.6), and the interactive telemetry
 * sends it as `t.ix.sv` (§7.6).
 */
export const SDK_VERSION = "0.3.0";

/**
 * The SDK directory manifest version this bundle was built for
 * (`DEFAULT_MANIFEST_VERSION` in `scripts/build-dist.mjs`, spec §2.1),
 * injected by the build as `MG_MANIFEST_VERSION`. Solving JSON challenges in
 * place (§12.5) needs an Edge that serves manifest v2, so it is enabled
 * only in a v2 build. Unit tests run the source without the define (1).
 */
declare const MG_MANIFEST_VERSION: number | undefined;
export const BUILD_MANIFEST_VERSION: number = typeof MG_MANIFEST_VERSION === "number" ? MG_MANIFEST_VERSION : 1;
