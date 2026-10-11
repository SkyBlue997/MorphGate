// Type declarations for build-dist.mjs (plain ESM run by Node; imported by the vitest suite).

export type ManifestVersion = 1 | 2;

export interface SdkManifest {
  v: ManifestVersion;
  /** First 16 hex characters of the bundle's SHA-256. */
  build: string;
  /** `mg.<build>.js` (never the alias `mg.js`, D-39). */
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

export interface EsbuildOptions {
  entryPoints: string[];
  bundle: true;
  format: "iife";
  minify: true;
  target: "es2020";
  legalComments: "none";
  define: { MG_MANIFEST_VERSION: string };
  outfile: string;
}

export interface V2Element {
  id: string;
  tag: string;
  attrs: Record<string, string | null>;
  in: string;
}

export const DEFAULT_MANIFEST_VERSION: ManifestVersion;
export const MANIFEST_VERSION: ManifestVersion;
export const TEMPLATE_NAME: "challenge.html";
export const TEMPLATE_SOURCES: Readonly<Partial<Record<ManifestVersion, string>>>;
export const MANIFEST_NAME: "manifest.json";
export const MAX_TEMPLATE_BYTES: number;
export const SDK_FILE_PATTERN: RegExp;
export const TEMPLATE_PLACEHOLDERS: readonly string[];
export const TEMPLATE_PLACEHOLDERS_V2: readonly string[];
export const V2_ELEMENTS: readonly V2Element[];

export function esbuildOptions(version?: ManifestVersion): EsbuildOptions;
export function templatePlaceholders(version?: ManifestVersion): readonly string[];
export function sha256Hex(bytes: Uint8Array): string;
export function validateTemplate(template: Uint8Array | string, version?: number): string[];
export function buildDist(input: DistInput, outDir: string, version?: ManifestVersion): SdkManifest;
