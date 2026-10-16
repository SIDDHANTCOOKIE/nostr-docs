/**
 * src/features/driveImport/blossom/auth.ts
 * Blossom Kind 24242 Nostr HTTP Authorization Header generation.
 *
 * Implements BUD-01, BUD-11, and NIP-98 authentication:
 * Creates an ephemeral Nostr event of kind 24242 with tags:
 *   - ["t", "get"] (verb)
 *   - ["x", "<sha256>"] (hash scoping, supporting multiple hashes)
 *   - ["expiration", "<unix_seconds>"]
 * Encodes as: Authorization: Nostr <base64-json-event>
 */

import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools";
import { bytesToHex, hexToBytes } from "nostr-tools/utils";
import { DriveImportError, type NostrSignerLike } from "../types";

/**
 * Creates a signed Nostr Kind 24242 authorization header string.
 */
export async function createKind24242AuthHeader(
  signer: NostrSignerLike,
  hashOrHashes: string | string[],
  verb: "get" | "upload" | "delete" = "get",
  expirationSeconds = 60,
): Promise<string> {
  try {
    const pubkey = await signer.getPublicKey();
    const now = Math.floor(Date.now() / 1000);

    const tags: string[][] = [
      ["t", verb],
      ["expiration", String(now + Math.max(10, expirationSeconds))],
    ];

    if (Array.isArray(hashOrHashes)) {
      if (hashOrHashes.length === 0) {
        throw new DriveImportError(
          "BLOSSOM_AUTH_FAILED",
          "Cannot create Blossom auth event without target blob hash",
          "Signer requires target hash",
          "Authorization Failed",
          "hashes",
        );
      }
      for (const h of hashOrHashes) {
        tags.push(["x", h.toLowerCase().trim()]);
      }
    } else {
      tags.push(["x", hashOrHashes.toLowerCase().trim()]);
    }

    const primaryHash = Array.isArray(hashOrHashes) ? hashOrHashes[0] : hashOrHashes;
    const content = `${verb.charAt(0).toUpperCase() + verb.slice(1)} ${primaryHash}`;

    const unsignedEvent = {
      kind: 24242,
      pubkey,
      created_at: now,
      tags,
      content,
    };

    const signedEvent = await signer.signEvent(unsignedEvent);
    const json = JSON.stringify(signedEvent);
    const b64 = btoa(unescape(encodeURIComponent(json)));
    return `Nostr ${b64}`;
  } catch (error) {
    if (error instanceof DriveImportError) throw error;
    throw new DriveImportError(
      "BLOSSOM_AUTH_FAILED",
      `Failed to sign Blossom Kind 24242 auth event: ${error instanceof Error ? error.message : String(error)}`,
      "Nostr signature was cancelled or failed",
      "Authorization Failed",
      "auth",
    );
  }
}

/**
 * Parses and validates a Kind 24242 Nostr authorization header.
 * Utility for verification, debugging, and mock server testing.
 */
export function parseKind24242AuthHeader(authHeader: string): {
  kind: number;
  pubkey: string;
  created_at: number;
  tags: string[][];
  content: string;
  sig?: string;
  id?: string;
} {
  const trimmed = authHeader.trim();
  if (!trimmed.startsWith("Nostr ")) {
    throw new DriveImportError(
      "BLOSSOM_AUTH_FAILED",
      `Invalid Authorization header scheme: must start with "Nostr ", got "${trimmed.substring(0, 10)}"`,
      "Malformed authorization header",
      "Authorization Failed",
      "header",
    );
  }

  const b64 = trimmed.substring(6).trim();
  try {
    const json = decodeURIComponent(escape(atob(b64)));
    const event = JSON.parse(json);

    if (event.kind !== 24242) {
      throw new DriveImportError(
        "BLOSSOM_AUTH_FAILED",
        `Expected kind 24242 auth event, got kind ${event.kind}`,
        "Incorrect event kind",
        "Authorization Failed",
        "kind",
      );
    }

    return event;
  } catch (error) {
    if (error instanceof DriveImportError) throw error;
    throw new DriveImportError(
      "BLOSSOM_AUTH_FAILED",
      `Failed to decode Nostr auth header: ${error instanceof Error ? error.message : String(error)}`,
      "Corrupted authorization header",
      "Authorization Failed",
      "header",
    );
  }
}

/**
 * Creates an in-memory ephemeral Nostr signer.
 * Convenient for testing or signing without a browser extension.
 */
export function createEphemeralSigner(
  secretKeyHex?: string,
): NostrSignerLike & { secretKeyHex: string } {
  const secretKey = secretKeyHex
    ? hexToBytes(secretKeyHex.trim())
    : generateSecretKey();
  const hex = bytesToHex(secretKey);
  const pubkey = getPublicKey(secretKey);

  return {
    secretKeyHex: hex,
    async getPublicKey(): Promise<string> {
      return pubkey;
    },
    async signEvent(event: {
      kind: number;
      tags: string[][];
      content: string;
      created_at: number;
      pubkey?: string;
    }) {
      const template = {
        kind: event.kind,
        tags: event.tags,
        content: event.content,
        created_at: event.created_at,
      };
      const signed = finalizeEvent(template, secretKey);
      return signed;
    },
  };
}
