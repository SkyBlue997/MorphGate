/**
 * Interface copy of the interactive control (docs/impl/phase2-spec.md §12.7).
 * The SDK writes only these strings; the purpose text, the two alternative
 * entries, the links and the fallback notices live in the template
 * (`templates/challenge.v2.html`), in both languages.
 *
 * Rules (docs/09 §2.3): short and neutral, every state label distinct, no
 * "robot" / "suspicious" / "blocked" wording, no countdown, no failure
 * reason; help sits behind the separate "Troubleshoot" link.
 */

export type Lang = "zh" | "en";

export const COPY = {
  zh: {
    holdLabel: "按住以验证",
    keepHolding: "继续按住…",
    letGo: "可以松开了",
    holdLonger: "请按住稍久一些",
    cantHold: "无法按住？可以直接点击",
    tooLong: "按住时间过长，请改为点击",
    finishing: "正在完成…",
    verifying: "正在验证…",
    verified: "验证完成",
    singleLabel: "按一下以验证",
    singleWait: "正在验证，请稍候…",
    a11yWait: "正在验证，通常需要几秒钟",
    a11ySlow: "仍在验证，较慢的设备可能需要一分钟",
    backToHold: "改用按住验证",
    external: "正在进行安全检查…",
    failed: "验证未完成，请重试。",
    later: "请稍后再试。",
    retryNow: "现在可以重试",
    network: "网络连接不稳定，正在重新加载…",
    cookies: "请允许本站使用 Cookie 后重试",
    unsupported: "当前浏览器无法完成验证，请更新或换用其他浏览器",
    requestId: "请求 ID：",
  },
  en: {
    holdLabel: "Press and hold to verify",
    keepHolding: "Keep holding…",
    letGo: "You can let go now",
    holdLonger: "Hold a little longer",
    cantHold: "Can't hold? You can click instead",
    tooLong: "That took too long. Please click instead.",
    finishing: "Finishing…",
    verifying: "Verifying…",
    verified: "Verified",
    singleLabel: "Press to verify",
    singleWait: "Verifying, please wait…",
    a11yWait: "Verifying. This usually takes a few seconds.",
    a11ySlow: "Still verifying. Slower devices can take up to a minute.",
    backToHold: "Use press and hold instead",
    external: "Running a security check…",
    failed: "Verification didn't complete. Please try again.",
    later: "Please try again later.",
    retryNow: "You can try again now",
    network: "Connection problem. Reloading…",
    cookies: "Please allow cookies for this site, then try again",
    unsupported: "This browser can't complete the check. Please update it or use another browser.",
    requestId: "Request ID: ",
  },
} as const;

export type CopyKey = keyof (typeof COPY)["zh"];

/** The page language the Edge chose (`<html lang>`): zh-* or en (§7.3). */
export function langOf(htmlLang: string | null | undefined): Lang {
  return typeof htmlLang === "string" && htmlLang.trim().toLowerCase().startsWith("zh") ? "zh" : "en";
}
