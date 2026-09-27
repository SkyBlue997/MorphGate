// Type declarations for build-dist.mjs (plain ESM run by Node; imported by the vitest suite).

export interface SdkManifest {
  v: 1;
  /** First 16 hex characters of the bundle's SHA-256. */
  build: string;
  /** `mg.<build>.js` */
  sdk: string;
  /** Files the Edge serves under /__mg/s/: name -> SHA-256 hex. */
  files: Record<string, string>;
  /** Templates the Edge reads (never served): name -> SHA-256 hex. */
  templates: Record<string, string>;
}

export interface DistInput {
  bundle: Uint8Array | string;
  template: Uint8Array | string;
}

export const MANIFEST_VERSION: 1;
export const TEMPLATE_NAME: "challenge.html";
export const MANIFEST_NAME: "manifest.json";
export const MAX_TEMPLATE_BYTES: number;
export const SDK_FILE_PATTERN: RegExp;
export const TEMPLATE_PLACEHOLDERS: readonly string[];

export function sha256Hex(bytes: Uint8Array): string;
export function validateTemplate(template: Uint8Array | string): string[];
export function buildDist(input: DistInput, outDir: string): SdkManifest;
