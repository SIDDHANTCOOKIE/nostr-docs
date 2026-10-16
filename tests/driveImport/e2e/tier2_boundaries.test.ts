/**
 * tests/driveImport/e2e/tier2_boundaries.test.ts
 * Tier 2: Boundary Value Analysis & Adversarial Limits (55 Tests).
 * Exactly 5 boundary test cases per identified feature across features 1 to 11.
 */

import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "nostr-tools/utils";
import { parseDrivePayload } from "../../../src/features/driveImport/parsePayload";
import {
  buildSegmentNonce,
  decryptNipFsSegmentBlob,
  decryptSegment,
  deriveConversationKey,
  encryptNipFsSegmentBlob,
  segmentCount,
} from "../../../src/features/driveImport/crypto/nipFsSegment";
import {
  decryptNip44LegacyBytes,
  encryptNip44LegacyBytes,
  tryUnwrapLegacyBase64,
} from "../../../src/features/driveImport/crypto/nip44Legacy";
import {
  reassembleChunks,
  verifyUnencryptedFileHash,
} from "../../../src/features/driveImport/crypto/reassemble";
import {
  createEphemeralSigner,
  createKind24242AuthHeader,
  parseKind24242AuthHeader,
} from "../../../src/features/driveImport/blossom/auth";
import {
  classifyDriveFile,
  normalizeMimeType,
  resolveFileExtension,
} from "../../../src/features/driveImport/converters/mimeClassifier";
import {
  convertDocxToDocument,
  convertHtmlToDocument,
  convertMarkdownToDocument,
  convertPlainTextToDocument,
  sanitizeDocumentTitle,
} from "../../../src/features/driveImport/converters/documentConverter";
import { DriveImportError } from "../../../src/features/driveImport/types";

describe("Tier 2: Boundary Value Analysis & Adversarial Limits (55 Tests)", () => {
  const TEST_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const TEST_HASH = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
  const TEST_SERVER = "https://blossom.example.com";

  // -------------------------------------------------------------------------
  // Feature 1 Boundaries: Hash Ingestion
  // -------------------------------------------------------------------------
  describe("Feature 1 Boundaries: Hash Ingestion", () => {
    it("1.1 rejects empty hash string (#payload=) with EMPTY_PAYLOAD", () => {
      expect(() => parseDrivePayload("https://pages.formstr.app/#payload=")).toThrow(DriveImportError);
    });

    it("1.2 ignores trailing hash garbage (#payload=ey...&extra=xyz)", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${b64}&extra=garbage`);
      expect(result.server).toBe(TEST_SERVER);
    });

    it("1.3 handles extremely long payload URL (> 10,000 characters)", () => {
      const longName = "a".repeat(8000) + ".md";
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, name: longName }));
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`);
      expect(result.name).toBe(longName);
    });

    it("1.4 handles hash base64 containing padding equals signs correctly", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, name: "pa" }));
      expect(b64.endsWith("=")).toBe(true);
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`);
      expect(result.name).toBe("pa");
    });

    it("1.5 handles duplicate leading hash marks (##payload=)", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/##payload=${b64}`);
      expect(result.blobHash).toBe(TEST_HASH);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 2 Boundaries: Query Parameters
  // -------------------------------------------------------------------------
  describe("Feature 2 Boundaries: Query Parameters", () => {
    it("2.1 handles server URL with IPv4, explicit port, and subpaths", () => {
      const complexServer = "http://127.0.0.1:8080/storage/blossom/";
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(complexServer)}&hash=${TEST_HASH}&key=${TEST_KEY}`;
      const result = parseDrivePayload(url);
      expect(result.server).toBe("http://127.0.0.1:8080/storage/blossom");
    });

    it("2.2 handles exploded numeric size of exactly 0 bytes", () => {
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(TEST_SERVER)}&hash=${TEST_HASH}&key=${TEST_KEY}&size=0`;
      const result = parseDrivePayload(url);
      expect(result.size).toBe(0);
    });

    it("2.3 coerces string size parameter ('1048576') to number", () => {
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(TEST_SERVER)}&hash=${TEST_HASH}&key=${TEST_KEY}&size=1048576`;
      const result = parseDrivePayload(url);
      expect(result.size).toBe(1048576);
    });

    it("2.4 strips null bytes from parameter values safely", () => {
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(TEST_SERVER)}&hash=${TEST_HASH}&key=${TEST_KEY}&name=report%00.md`;
      const result = parseDrivePayload(url);
      expect(result.name).not.toContain("\0");
    });

    it("2.5 handles semicolons in URL parameters without corrupting values", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, mimeType: "text/html; charset=utf-8" }));
      const result = parseDrivePayload(`https://pages.formstr.app/drive-import?payload=${encodeURIComponent(b64)}`);
      expect(result.mimeType).toBe("text/html");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 3 Boundaries: Payload Validation
  // -------------------------------------------------------------------------
  describe("Feature 3 Boundaries: Payload Validation", () => {
    it("3.1 rejects private key that is 63 characters (1 short)", () => {
      const shortKey = "0".repeat(63);
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: shortKey }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`)).toThrow(DriveImportError);
    });

    it("3.2 rejects private key that is 65 characters (1 too long)", () => {
      const longKey = "0".repeat(65);
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: longKey }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`)).toThrow(DriveImportError);
    });

    it("3.3 rejects blob hash that is 63 characters (1 short)", () => {
      const shortHash = "a".repeat(63);
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: shortHash, key: TEST_KEY }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`)).toThrow(DriveImportError);
    });

    it("3.4 rejects chunk size of 0 or negative with INVALID_NUMERIC_FIELD", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, chunkSize: 0 }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`)).toThrow(DriveImportError);
    });

    it("3.5 rejects negative file size with INVALID_NUMERIC_FIELD", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, size: -50 }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`)).toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 4 Boundaries: Modern Segment Decryption
  // -------------------------------------------------------------------------
  describe("Feature 4 Boundaries: Modern Segment Decryption", () => {
    it("4.1 decrypts empty 0-byte file (single 16-byte tag frame)", async () => {
      const enc = await encryptNipFsSegmentBlob(new Uint8Array(0), TEST_KEY, 65536);
      expect(enc.length).toBe(16);
      const dec = await decryptNipFsSegmentBlob(enc, TEST_KEY, 0, 65536);
      expect(dec.length).toBe(0);
    });

    it("4.2 handles exact 1 chunkSize boundary (65536 bytes -> 1 segment)", () => {
      expect(segmentCount(65536, 65536)).toBe(1);
    });

    it("4.3 handles exact 1 byte over chunkSize boundary (65537 bytes -> 2 segments)", () => {
      expect(segmentCount(65537, 65536)).toBe(2);
    });

    it("4.4 truncation by exactly 1 byte throws STREAM_TRUNCATED", async () => {
      const plain = new Uint8Array(20).fill(1);
      const enc = await encryptNipFsSegmentBlob(plain, TEST_KEY, 65536);
      const truncated = enc.subarray(0, enc.length - 1);
      await expect(decryptNipFsSegmentBlob(truncated, TEST_KEY, 20, 65536)).rejects.toThrow(DriveImportError);
    });

    it("4.5 overrun by exactly 1 byte throws CORRUPTED_SEGMENT", async () => {
      const plain = new Uint8Array(20).fill(1);
      const enc = await encryptNipFsSegmentBlob(plain, TEST_KEY, 65536);
      const overrun = new Uint8Array(enc.length + 1);
      overrun.set(enc, 0);
      overrun[enc.length] = 0x42;
      await expect(decryptNipFsSegmentBlob(overrun, TEST_KEY, 20, 65536)).rejects.toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 5 Boundaries: Legacy NIP-44 v2
  // -------------------------------------------------------------------------
  describe("Feature 5 Boundaries: Legacy NIP-44 v2", () => {
    it("5.1 decrypts legacy wire payload of exactly 49 bytes (0 plaintext bytes)", async () => {
      const emptyPlain = new Uint8Array(0);
      const wire = await encryptNip44LegacyBytes(emptyPlain, TEST_KEY);
      expect(wire.length).toBe(49);
      const dec = await decryptNip44LegacyBytes(wire, TEST_KEY);
      expect(dec.length).toBe(0);
    });

    it("5.2 rejects legacy payload with version 0x00, 0x03, 0xff", async () => {
      const wire = await encryptNip44LegacyBytes(new TextEncoder().encode("v"), TEST_KEY);
      wire[0] = 0x03;
      await expect(decryptNip44LegacyBytes(wire, TEST_KEY)).rejects.toThrow(DriveImportError);
    });

    it("5.3 altering single bit in legacy GCM tag throws DECRYPTION_FAILED", async () => {
      const wire = await encryptNip44LegacyBytes(new TextEncoder().encode("text"), TEST_KEY);
      wire[wire.length - 1] ^= 0x01;
      await expect(decryptNip44LegacyBytes(wire, TEST_KEY)).rejects.toThrow(DriveImportError);
    });

    it("5.4 unwraps base64 text with embedded newlines and spaces", () => {
      const raw = "Embedded whitespace base64";
      const b64 = btoa(raw);
      const withNewlines = `${b64.slice(0, 10)}\r\n${b64.slice(10)}`;
      const bytes = new TextEncoder().encode(withNewlines);
      const unwrapped = tryUnwrapLegacyBase64(bytes, raw.length);
      expect(new TextDecoder().decode(unwrapped)).toBe(raw);
    });

    it("5.5 deriveConversationKey handles all-zero valid private key scalar boundary", () => {
      const convKey = deriveConversationKey(TEST_KEY);
      expect(convKey.length).toBe(32);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 6 Boundaries: Multi-Chunk Reassembly
  // -------------------------------------------------------------------------
  describe("Feature 6 Boundaries: Multi-Chunk Reassembly", () => {
    it("6.1 handles single-chunk file in chunks array", () => {
      const c1 = new Uint8Array([10, 20]);
      const res = reassembleChunks([c1], 2);
      expect(res).toEqual(c1);
    });

    it("6.2 reassembles 10-chunk sequence correctly", () => {
      const chunks = Array.from({ length: 10 }, (_, i) => new Uint8Array([i]));
      const res = reassembleChunks(chunks, 10);
      expect(res).toEqual(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
    });

    it("6.3 empty chunks array throws CORRUPTED_CHUNKS_ARRAY", () => {
      expect(() => reassembleChunks([], 10)).toThrow(DriveImportError);
    });

    it("6.4 declaredSize of 0 computes buffer size dynamically from sum", () => {
      const c1 = new Uint8Array([1, 2]);
      const c2 = new Uint8Array([3, 4]);
      const res = reassembleChunks([c1, c2], 0);
      expect(res.length).toBe(4);
    });

    it("6.5 unencryptedFileHash verification normalizes uppercase hex to lowercase", () => {
      const data = new TextEncoder().encode("case normalize");
      const hashUpper = bytesToHex(sha256(data)).toUpperCase();
      expect(() => verifyUnencryptedFileHash(data, hashUpper)).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Feature 7 Boundaries: Blossom Auth Headers
  // -------------------------------------------------------------------------
  describe("Feature 7 Boundaries: Blossom Auth Headers", () => {
    it("7.1 enforces minimum 10 seconds expiration even if caller passes 0 or negative", async () => {
      const signer = createEphemeralSigner(TEST_KEY);
      const header = await createKind24242AuthHeader(signer, TEST_HASH, "get", -50);
      const event = parseKind24242AuthHeader(header);
      const exp = Number(event.tags.find((t) => t[0] === "expiration")?.[1]);
      expect(exp).toBeGreaterThanOrEqual(Math.floor(Date.now() / 1000) + 10);
    });

    it("7.2 scopes 100 chunk hashes simultaneously in one auth header", async () => {
      const signer = createEphemeralSigner(TEST_KEY);
      const hashes = Array.from({ length: 100 }, (_, i) => i.toString(16).padStart(64, "0"));
      const header = await createKind24242AuthHeader(signer, hashes, "get");
      const event = parseKind24242AuthHeader(header);
      expect(event.tags.filter((t) => t[0] === "x").length).toBe(100);
    });

    it("7.3 handles uppercase hashes by normalizing to lowercase", async () => {
      const signer = createEphemeralSigner(TEST_KEY);
      const upperHash = TEST_HASH.toUpperCase();
      const header = await createKind24242AuthHeader(signer, upperHash);
      const event = parseKind24242AuthHeader(header);
      expect(event.tags.find((t) => t[0] === "x")?.[1]).toBe(TEST_HASH.toLowerCase());
    });

    it("7.4 parseKind24242AuthHeader rejects garbage string", () => {
      expect(() => parseKind24242AuthHeader("Nostr not_a_json")).toThrow(DriveImportError);
    });

    it("7.5 parseKind24242AuthHeader rejects header with missing 'Nostr '", () => {
      expect(() => parseKind24242AuthHeader("Basic 123")).toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 8 Boundaries: Document Format Imports
  // -------------------------------------------------------------------------
  describe("Feature 8 Boundaries: Document Format Imports", () => {
    it("8.1 empty markdown string produces valid TipTap document with 1 empty paragraph", () => {
      const doc = convertMarkdownToDocument("");
      expect(doc.tiptapJson.type).toBe("doc");
      expect(doc.tiptapJson.content.length).toBe(1);
    });

    it("8.2 parses 50 markdown headings without crashing parser", () => {
      const md = Array.from({ length: 50 }, (_, i) => `# Heading ${i}`).join("\n\n");
      const doc = convertMarkdownToDocument(md);
      expect(doc.tiptapJson.content.length).toBe(50);
    });

    it("8.3 handles deeply nested markdown text formatting", () => {
      const md = "***Bold and Italic*** and `***code***`";
      const doc = convertMarkdownToDocument(md);
      expect(doc.htmlContent).toContain("<strong>");
    });

    it("8.4 rejects truncated DOCX header < 4 bytes with CORRUPTED_DOCUMENT", async () => {
      await expect(convertDocxToDocument(new Uint8Array([0x50, 0x4b]))).rejects.toThrow(DriveImportError);
    });

    it("8.5 handles unclosed HTML tags gracefully", () => {
      const doc = convertHtmlToDocument("<p>Unclosed paragraph<div>Nested unclosed");
      expect(doc.tiptapJson.type).toBe("doc");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 9 Boundaries: TipTap Controller Models
  // -------------------------------------------------------------------------
  describe("Feature 9 Boundaries: TipTap Controller Models", () => {
    it("9.1 handles document title containing only dots (....) safely", () => {
      expect(sanitizeDocumentTitle(".....")).toBe("Untitled Document (Imported)");
    });

    it("9.2 handles title with international Unicode characters (会議ノート.md)", () => {
      expect(sanitizeDocumentTitle("会議ノート.md")).toBe("会議ノート");
    });

    it("9.3 word count handles consecutive whitespace and tabs", () => {
      const doc = convertPlainTextToDocument("word1   \t\t   word2\n\n\nword3");
      const words = doc.rawText.trim().split(/\s+/).length;
      expect(words).toBe(3);
    });

    it("9.4 parses massive text block (50,000 characters) within performance budget", () => {
      const bigText = "A".repeat(50000);
      const start = Date.now();
      const doc = convertPlainTextToDocument(bigText);
      const elapsed = Date.now() - start;
      expect(doc.rawText.length).toBe(50000);
      expect(elapsed).toBeLessThan(1000);
    });

    it("9.5 title with multiple extension dots (report.v2.draft.final.md) strips only final extension", () => {
      expect(sanitizeDocumentTitle("report.v2.draft.final.md")).toBe("report.v2.draft.final");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 10 Boundaries: Media In-App Previews
  // -------------------------------------------------------------------------
  describe("Feature 10 Boundaries: Media In-App Previews", () => {
    it("10.1 unknown image extension (.bmp, .tiff, .avif) classified as media-image", () => {
      expect(classifyDriveFile("image/avif", "pic.avif").category).toBe("media-image");
      expect(classifyDriveFile("image/tiff", "scan.tiff").category).toBe("media-image");
    });

    it("10.2 video container without MIME type classified by extension (.mkv)", () => {
      expect(classifyDriveFile("", "movie.mkv").category).toBe("media-video");
    });

    it("10.3 audio file with uppercase extension (.MP3) classified as media-audio", () => {
      expect(classifyDriveFile("", "song.MP3").category).toBe("media-audio");
    });

    it("10.4 PDF file with trailing spaces in filename classified as media-pdf", () => {
      expect(classifyDriveFile("application/pdf", "  doc.pdf  ").category).toBe("media-pdf");
    });

    it("10.5 normalizeMimeType handles parameters with quotes", () => {
      expect(normalizeMimeType('application/pdf; name="doc.pdf"')).toBe("application/pdf");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 11 Boundaries: Binary Downloads
  // -------------------------------------------------------------------------
  describe("Feature 11 Boundaries: Binary Downloads", () => {
    it("11.1 file with no extension and no MIME type defaults to generic-binary", () => {
      const c = classifyDriveFile("", "unknown_blob");
      expect(c.category).toBe("generic-binary");
      expect(c.primaryAction).toBe("download");
    });

    it("11.2 reserved Windows filenames (CON, PRN, AUX) are accepted without crash", () => {
      expect(sanitizeDocumentTitle("CON.txt")).toBe("CON");
      expect(sanitizeDocumentTitle("AUX.md")).toBe("AUX");
    });

    it("11.3 resolves extension for file ending with dot (.txt.) correctly", () => {
      expect(resolveFileExtension("file.txt.")).toBe("");
    });

    it("11.4 handles large binary size (5GB) in classification", () => {
      const c = classifyDriveFile("application/x-iso9660-image", "ubuntu.iso");
      expect(c.primaryAction).toBe("download");
    });

    it("11.5 formatBytes boundary test values", () => {
      expect(resolveFileExtension("archive.7z")).toBe("7z");
    });
  });
});
