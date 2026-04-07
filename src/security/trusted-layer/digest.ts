import crypto from "node:crypto";

export function digestTrustedValue(input: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
