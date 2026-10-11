/**
 * The SDK in a Worker (docs/impl/phase2-spec.md §12.6, phase1-spec §11.3):
 * one message handler for both PoW protocols, dispatched on `t`. The
 * Phase 1 protocol (`mg-pow`) serves the non-interactive challenge and the
 * in-place solving of JSON challenges; v2 (`mg-pow2`) the interactive one.
 */

import { handlePowMessage, type PowReply } from "./pow";
import { handlePow2Message, type Pow2Reply } from "./powv2";
import { SDK_VERSION } from "./version";

export interface SdkWorkerScope {
  addEventListener(type: "message" | "messageerror", listener: (event: { data?: unknown }) => void): void;
  postMessage(message: PowReply | Pow2Reply): void;
}

/** Install the PoW handlers (the only thing the SDK does in a Worker). */
export function installWorker(scope: SdkWorkerScope, sv: string = SDK_VERSION): void {
  const post = (reply: PowReply | Pow2Reply): void => scope.postMessage(reply);
  scope.addEventListener("message", (event) => {
    const data = event.data;
    const t = typeof data === "object" && data !== null ? (data as { t?: unknown }).t : undefined;
    if (t === "mg-pow2") handlePow2Message(data, post, sv);
    else handlePowMessage(data, post);
  });
  scope.addEventListener("messageerror", () => post({ t: "mg-pow-err" }));
}
