/**
 * `ui_seed` derivation (docs/impl/phase2-spec.md §6.3):
 *
 *   u                = SHA-256("mg-ui-v1" || 0x00 || u64be(ui_seed))
 *   required_hold_ms = 1200 + (u16be(u[0..2]) mod 1301)        // 1200..2500
 *   offset_x_px      = (u[2] mod 33) - 16                      // -16..16
 *   offset_y_px      = (u[3] mod 17) - 8                       // -8..8
 *
 * The SDK never sees `ui_seed` (it is sealed in C): the Edge sends the
 * derived values in `ix` (§7.2). This function exists so the SDK's tests
 * check the same known answers as the Edge and keep `ix.hold_ms` and
 * `ix.offset` within the ranges above. It is not part of the bundle.
 */

import { sha256 } from "./sha256";

export interface UiParams {
  requiredHoldMs: number;
  offsetXPx: number;
  offsetYPx: number;
}

export const MIN_HOLD_MS = 1200;
export const MAX_HOLD_MS = 2500;

export function uiParams(uiSeed: bigint): UiParams {
  const label = new TextEncoder().encode("mg-ui-v1");
  const message = new Uint8Array(label.length + 9);
  message.set(label, 0);
  let seed = BigInt.asUintN(64, uiSeed);
  for (let b = 7; b >= 0; b--) {
    message[label.length + 1 + b] = Number(seed & 0xffn);
    seed >>= 8n;
  }
  const u = sha256(message);
  return {
    requiredHoldMs: MIN_HOLD_MS + (((u[0]! << 8) | u[1]!) % 1301),
    offsetXPx: (u[2]! % 33) - 16,
    offsetYPx: (u[3]! % 17) - 8,
  };
}
