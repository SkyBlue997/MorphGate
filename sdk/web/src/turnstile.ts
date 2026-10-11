/**
 * Turnstile in the interactive control (docs/impl/phase2-spec.md §8.3, D-70).
 *
 * Loaded only when Turnstile is the current provider: the SDK adds the
 * page-nonce'd `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit">`
 * (never proxied, cached or put under `/__mg/`) and renders explicitly into
 * `#mg-turnstile` (no `cf-turnstile` class) with `sitekey`, `action`, `cData`
 * and `language` from `ix.turnstile`, `appearance: "interaction-only"`,
 * `execution: "render"`, `"response-field": false`, `theme: "auto"`,
 * `retry: "auto"`, `"refresh-expired": "auto"`, and `size: "compact"` in a
 * container narrower than 300 px.
 *
 * Falling back (to the next provider of C; nothing is consumed or counted):
 * - api.js not ready within 5 s, or failing to load: `ts_load_timeout`;
 * - `unsupported-callback`: `ts_unsupported`;
 * - `error-callback` with 110xxx (but 110600 / 110620), 400xxx or 200100:
 *   configuration, no retry: `ts_config`;
 * - any other error code (110600, 110620, 200500, 300xxx, 600xxx, ...): the
 *   widget gets one reset, a second error falls back: `ts_error`.
 * `expired-callback` waits for the widget's own refresh. Tests use a fake
 * `turnstile` object; nothing in the test suites reaches Cloudflare (D-52).
 */

export const TURNSTILE_API_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
export const TS_LOAD_TIMEOUT_MS = 5_000;
export const COMPACT_BELOW_PX = 300;

export type TsFallback = "ts_unsupported" | "ts_load_timeout" | "ts_error" | "ts_config";

export interface TurnstileRenderParams {
  sitekey: string;
  action: string;
  cData: string;
  language: string;
  appearance: "interaction-only";
  execution: "render";
  "response-field": false;
  theme: "auto";
  retry: "auto";
  "refresh-expired": "auto";
  size?: "compact";
  callback: (token: string) => void;
  "error-callback": (code: string | number) => boolean;
  "unsupported-callback": () => void;
  "expired-callback": () => void;
}

export interface TurnstileApi {
  render(container: unknown, params: TurnstileRenderParams): string | undefined | null;
  remove(widgetId: string): void;
  reset(widgetId: string): void;
}

export interface TurnstileHost {
  /** `window.turnstile` once api.js has run. */
  api(): TurnstileApi | null;
  /** Append the nonce'd api.js script; the callbacks fire on load / error. */
  loadScript(src: string, nonce: string | null, onLoad: () => void, onError: () => void): void;
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface TurnstileParams {
  sitekey: string;
  action: string;
  cdata: string;
  lang: string;
}

/** How an `error-callback` code is handled (§8.3). */
export function tsErrorClass(code: string | number): "config" | "retry" {
  const c = String(code).trim();
  if (c === "110600" || c === "110620") return "retry";
  if (/^110\d{3}$/.test(c) || /^400\d{3}$/.test(c) || c === "200100") return "config";
  return "retry";
}

export interface TurnstileCallbacks {
  token(token: string): void;
  fallback(reason: TsFallback): void;
}

/** One widget for one C. Every callback fires at most once per outcome; never throws. */
export class TurnstileWidget {
  private widgetId: string | null = null;
  private done = false;
  private errors = 0;
  private static loading: Promise<TurnstileApi | null> | null = null;

  constructor(
    private readonly host: TurnstileHost,
    private readonly nonce: string | null,
  ) {}

  /** api.js, loaded once per page (5 s budget). */
  private load(): Promise<TurnstileApi | null> {
    const ready = this.host.api();
    if (ready !== null) return Promise.resolve(ready);
    if (TurnstileWidget.loading === null) {
      TurnstileWidget.loading = new Promise<TurnstileApi | null>((resolve) => {
        let settled = false;
        const settle = (api: TurnstileApi | null): void => {
          if (settled) return;
          settled = true;
          this.host.clearTimeout(timer);
          resolve(api);
        };
        const timer = this.host.setTimeout(() => settle(null), TS_LOAD_TIMEOUT_MS);
        try {
          this.host.loadScript(TURNSTILE_API_URL, this.nonce, () => settle(this.host.api()), () => settle(null));
        } catch {
          settle(null);
        }
      }).then((api) => {
        if (api === null) TurnstileWidget.loading = null;
        return api;
      });
    }
    return TurnstileWidget.loading;
  }

  /** Render into `container`; `width` is its current width in CSS px. */
  async start(container: unknown, width: number, params: TurnstileParams, callbacks: TurnstileCallbacks): Promise<void> {
    const fallback = (reason: TsFallback): void => {
      if (this.done) return;
      this.done = true;
      this.remove();
      try {
        callbacks.fallback(reason);
      } catch {
        // The control handles its own errors.
      }
    };
    const api = await this.load();
    if (this.done) return;
    if (api === null) {
      fallback("ts_load_timeout");
      return;
    }
    const renderParams: TurnstileRenderParams = {
      sitekey: params.sitekey,
      action: params.action,
      cData: params.cdata,
      language: params.lang,
      appearance: "interaction-only",
      execution: "render",
      "response-field": false,
      theme: "auto",
      retry: "auto",
      "refresh-expired": "auto",
      callback: (token) => {
        if (this.done || typeof token !== "string" || token.length === 0) return;
        callbacks.token(token);
      },
      "error-callback": (code) => {
        if (tsErrorClass(code) === "config") {
          fallback("ts_config");
        } else if (++this.errors > 1) {
          fallback("ts_error");
        } else if (this.widgetId !== null) {
          try {
            api.reset(this.widgetId);
          } catch {
            fallback("ts_error");
          }
        }
        return true;
      },
      "unsupported-callback": () => fallback("ts_unsupported"),
      "expired-callback": () => undefined,
    };
    if (width > 0 && width < COMPACT_BELOW_PX) renderParams.size = "compact";
    try {
      const id = api.render(container, renderParams);
      this.widgetId = typeof id === "string" ? id : null;
    } catch {
      fallback("ts_error");
    }
  }

  /** Remove the widget (a new C needs a new `cData`). */
  remove(): void {
    this.done = true;
    const id = this.widgetId;
    this.widgetId = null;
    const api = this.host.api();
    if (id !== null && api !== null) {
      try {
        api.remove(id);
      } catch {
        // Already gone.
      }
    }
  }

  /** Test hook: forget the page-wide api.js load. */
  static resetForTests(): void {
    TurnstileWidget.loading = null;
  }
}
