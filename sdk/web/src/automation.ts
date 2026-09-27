/**
 * Automation summary (docs/04 §7, module `automation`).
 *
 * Phase 0 reads exactly one standard signal: `navigator.webdriver`, which the
 * WebDriver spec requires user agents to set to true while under remote
 * control. It is a cooperative flag: `true` is a strong hint, `false` proves
 * nothing, and the server scores it accordingly.
 *
 * Phase 2 extends this module (headless-environment traits, injected-script
 * traces, integrity of key native functions) behind the same summary type.
 */

export const AUTOMATION_SCHEMA_VERSION = 1;

export interface AutomationSummary {
  v: typeof AUTOMATION_SCHEMA_VERSION;
  /**
   * `true` / `false` as reported; `null` when the property is missing, not a
   * boolean, or its getter throws. The server treats `null` as "signal missing".
   */
  webdriver: boolean | null;
}

export interface AutomationSource {
  navigator?: { webdriver?: unknown } | undefined;
}

function defaultSource(): AutomationSource {
  return { get navigator() { return (globalThis as { navigator?: { webdriver?: unknown } }).navigator; } };
}

/** Collect the automation summary. Never throws. */
export function collectAutomation(source: AutomationSource = defaultSource()): AutomationSummary {
  let webdriver: boolean | null = null;
  try {
    const value = source.navigator?.webdriver;
    webdriver = typeof value === "boolean" ? value : null;
  } catch {
    webdriver = null;
  }
  return { v: AUTOMATION_SCHEMA_VERSION, webdriver };
}
