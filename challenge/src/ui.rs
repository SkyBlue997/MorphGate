//! Interactive control parameters derived from the sealed `ui_seed`
//! (docs/impl/phase2-spec.md §6.3): the required hold time (1200..=2500 ms)
//! and the button offset, recomputed by the server on submission.
//!
//! ```text
//! u                = SHA-256("mg-ui-v1" ‖ 0x00 ‖ u64be(ui_seed))
//! required_hold_ms = 1200 + (u16be(u[0..2]) mod 1301)        // 1200..2500
//! offset_x_px      = (u[2] mod 33) − 16                      // −16..16
//! offset_y_px      = (u[3] mod 17) − 8                       // −8..8
//! ```
//!
//! The ranges are constants, not bundle settings: the bundle may change
//! after a `C` was issued, and the server must recompute what the client was
//! shown (the `ix.hold_ms` and `ix.offset` of §7.2).

use sha2::{Digest, Sha256};

/// Shortest required hold.
pub const MIN_HOLD_MS: u32 = 1200;
/// Longest required hold.
pub const MAX_HOLD_MS: u32 = 2500;
/// Largest horizontal button offset, either direction.
pub const MAX_OFFSET_X_PX: i8 = 16;
/// Largest vertical button offset, either direction.
pub const MAX_OFFSET_Y_PX: i8 = 8;

const UI_DOMAIN: &[u8] = b"mg-ui-v1";

/// The parameters of the interactive control for one `ui_seed`. They are
/// shown to the client in `ix`, so they are not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiParams {
    /// How long the button must be held, 1200..=2500 ms.
    pub required_hold_ms: u32,
    /// Horizontal offset of the button, −16..=16 px.
    pub offset_x_px: i8,
    /// Vertical offset of the button, −8..=8 px.
    pub offset_y_px: i8,
}

/// The control parameters of `ui_seed` (spec §6.3).
pub fn ui_params(ui_seed: u64) -> UiParams {
    let mut h = Sha256::new();
    h.update(UI_DOMAIN);
    h.update([0]);
    h.update(ui_seed.to_be_bytes());
    let u: [u8; 32] = h.finalize().into();
    let span = MAX_HOLD_MS - MIN_HOLD_MS + 1; // 1301
    let x_span = 2 * MAX_OFFSET_X_PX.unsigned_abs() + 1; // 33
    let y_span = 2 * MAX_OFFSET_Y_PX.unsigned_abs() + 1; // 17
    UiParams {
        required_hold_ms: MIN_HOLD_MS + u32::from(u16::from_be_bytes([u[0], u[1]])) % span,
        // `u[2] mod 33` is 0..=32, so the cast is lossless and the result
        // lies in −16..=16 (likewise for y).
        offset_x_px: (u[2] % x_span) as i8 - MAX_OFFSET_X_PX,
        offset_y_px: (u[3] % y_span) as i8 - MAX_OFFSET_Y_PX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_hold_for_many_seeds() {
        let mut seen_min = (u32::MAX, i8::MAX, i8::MAX);
        let mut seen_max = (0, i8::MIN, i8::MIN);
        for seed in (0..20_000u64).chain([u64::MAX, u64::MAX - 1, 1 << 63]) {
            let p = ui_params(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            assert!((MIN_HOLD_MS..=MAX_HOLD_MS).contains(&p.required_hold_ms));
            assert!((-16..=16).contains(&p.offset_x_px));
            assert!((-8..=8).contains(&p.offset_y_px));
            seen_min = (
                seen_min.0.min(p.required_hold_ms),
                seen_min.1.min(p.offset_x_px),
                seen_min.2.min(p.offset_y_px),
            );
            seen_max = (
                seen_max.0.max(p.required_hold_ms),
                seen_max.1.max(p.offset_x_px),
                seen_max.2.max(p.offset_y_px),
            );
        }
        // The offsets reach both ends; the hold time comes close to them.
        assert_eq!((seen_min.1, seen_min.2), (-16, -8));
        assert_eq!((seen_max.1, seen_max.2), (16, 8));
        assert!(
            seen_min.0 < 1210 && seen_max.0 > 2490,
            "{seen_min:?} {seen_max:?}"
        );
    }

    #[test]
    fn deterministic() {
        assert_eq!(ui_params(42), ui_params(42));
        assert_ne!(ui_params(1), ui_params(2));
    }
}
