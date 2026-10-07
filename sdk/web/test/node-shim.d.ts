// Minimal declarations for the Node.js built-ins the tests use.
//
// The package deliberately has no @types/node: src/ is browser code and must
// not typecheck against Node globals. Only test files import these modules,
// and only the members declared here.

declare module "node:fs" {
  export function readFileSync(path: string | URL): Uint8Array;
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string | Uint8Array): void;
  export function mkdtempSync(prefix: string): string;
  export function readdirSync(path: string): string[];
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function existsSync(path: string): boolean;
}

declare module "node:os" {
  export function tmpdir(): string;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
}

declare module "node:crypto" {
  interface Hash {
    update(data: string | Uint8Array): Hash;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: "sha256"): Hash;
}
