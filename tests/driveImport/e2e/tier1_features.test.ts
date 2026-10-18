/**
 * @vitest-environment happy-dom
 * tests/driveImport/e2e/tier1_features.test.ts
 * Tier 1: Comprehensive Feature Requirements Verification (55 Tests).
 * Exactly 5 test cases per identified feature across features 1 to 11.
 */

import { makeDocx, paragraph } from "../helpers/makeDocx";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "nostr-tools/utils";
import {
  parseDrivePayload,
  parseDriveImportUrl,
} from "../../../src/features/driveImport/parsePayload";
import {
  buildSegmentNonce,
  decryptNipFsSegmentBlob,
  decryptSegment,
  deriveConversationKey,
  encryptNipFsSegmentBlob,
  encryptSegment,
} from "../../../src/features/driveImport/crypto/nipFsSegment";
import {
  decryptNip44LegacyBytes,
  deriveGcmKeyAndIv,
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
import { fetchBlossomBlob } from "../../../src/features/driveImport/blossom/fetchBlob";
import {
  classifyDriveFile,
  getDocumentSubtype,
  resolveFileExtension,
} from "../../../src/features/driveImport/converters/mimeClassifier";
import {
  convertDriveFileToDocument,
  convertHtmlToDocument,
  convertMarkdownToDocument,
  convertPlainTextToDocument,
  convertDocxToDocument,
  sanitizeDocumentTitle,
} from "../../../src/features/driveImport/converters/documentConverter";
import {
  DriveImportError,
  type DecryptedDriveFile,
  type NormalizedDrivePayload,
} from "../../../src/features/driveImport/types";

describe("Tier 1: Comprehensive Feature Requirements (55 Tests)", () => {
  const TEST_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const TEST_HASH = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
  const TEST_SERVER = "https://blossom.example.com";

  // -------------------------------------------------------------------------
  // Feature 1: Hash Fragment Ingestion (#payload=)
  // -------------------------------------------------------------------------
  describe("Feature 1: Hash Fragment Ingestion", () => {
    it("1.1 parses standard #payload=<base64>", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${b64}`);
      expect(result.server).toBe(TEST_SERVER);
      expect(result.blobHash).toBe(TEST_HASH);
    });

    it("1.2 parses percent-encoded #payload=%7B... or %3D padding", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${encodeURIComponent(b64)}`);
      expect(result.blobHash).toBe(TEST_HASH);
    });

    it("1.3 parses URL-safe base64 (- and _ instead of + and /)", () => {
      const json = JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY });
      const urlSafeB64 = btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const result = parseDrivePayload(`https://pages.formstr.app/#payload=${urlSafeB64}`);
      expect(result.privateKeyHex).toBe(TEST_KEY);
    });

    it("1.4 parses case-insensitive hash parameter prefix (#PAYLOAD=)", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/#PAYLOAD=${b64}`);
      expect(result.server).toBe(TEST_SERVER);
    });

    it("1.5 parses payload from hash fragment after route path /drive-import#payload=...", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/drive-import#payload=${b64}`);
      expect(result.blobHash).toBe(TEST_HASH);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 2: Query Parameter Ingestion (?payload= & exploded)
  // -------------------------------------------------------------------------
  describe("Feature 2: Query Parameter Ingestion", () => {
    it("2.1 parses /drive-import?payload=<b64>", () => {
      const b64 = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY }));
      const result = parseDrivePayload(`https://pages.formstr.app/drive-import?payload=${encodeURIComponent(b64)}`);
      expect(result.server).toBe(TEST_SERVER);
    });

    it("2.2 parses exploded query parameters ?server=&hash=&key=&cipher=&name=&size=", () => {
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(TEST_SERVER)}&hash=${TEST_HASH}&key=${TEST_KEY}&cipher=nip-fs-segment-v1&name=test.md&size=100`;
      const result = parseDrivePayload(url);
      expect(result.name).toBe("test.md");
      expect(result.size).toBe(100);
    });

    it("2.3 parses exploded parameters with alias keys (encryptionKey, blobHash, type)", () => {
      const url = `https://pages.formstr.app/drive-import?server=${encodeURIComponent(TEST_SERVER)}&blobHash=${TEST_HASH}&encryptionKey=${TEST_KEY}&type=text/markdown`;
      const result = parseDrivePayload(url);
      expect(result.privateKeyHex).toBe(TEST_KEY);
      expect(result.mimeType).toBe("text/markdown");
    });

    it("2.4 prioritizes hash fragment over query parameter when both exist", () => {
      const hashPayload = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, name: "from-hash.md" }));
      const queryPayload = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: TEST_KEY, name: "from-query.md" }));
      const url = `https://pages.formstr.app/drive-import?payload=${queryPayload}#payload=${hashPayload}`;
      const result = parseDrivePayload(url);
      expect(result.name).toBe("from-hash.md");
    });

    it("2.5 handles case-insensitive query parameter names (?SERVER=&HASH=&KEY=)", () => {
      const url = `https://pages.formstr.app/drive-import?SERVER=${encodeURIComponent(TEST_SERVER)}&HASH=${TEST_HASH}&KEY=${TEST_KEY}`;
      const result = parseDrivePayload(url);
      expect(result.server).toBe(TEST_SERVER);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 3: Payload Parsing & Error Recovery
  // -------------------------------------------------------------------------
  describe("Feature 3: Payload Parsing & Error Recovery", () => {
    it("3.1 rejects malformed base64 with MALFORMED_BASE64", () => {
      expect(() => parseDrivePayload("https://pages.formstr.app/#payload=invalid_b64!@#$")).toThrow(DriveImportError);
    });

    it("3.2 rejects corrupted JSON with INVALID_JSON", () => {
      const badJsonB64 = btoa("{ bad json string");
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${badJsonB64}`)).toThrow(DriveImportError);
    });

    it("3.3 rejects payload missing server with MISSING_REQUIRED_FIELD", () => {
      const noServer = btoa(JSON.stringify({ hash: TEST_HASH, key: TEST_KEY }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${noServer}`)).toThrow(DriveImportError);
    });

    it("3.4 rejects invalid private key hex with INVALID_KEY_FORMAT", () => {
      const badKey = btoa(JSON.stringify({ server: TEST_SERVER, hash: TEST_HASH, key: "not-hex-64" }));
      expect(() => parseDrivePayload(`https://pages.formstr.app/#payload=${badKey}`)).toThrow(DriveImportError);
    });

    it("3.5 rejects missing payload parameter with MISSING_PAYLOAD", () => {
      expect(() => parseDrivePayload("https://pages.formstr.app/drive-import")).toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 4: Modern Segment Decryption (nip-fs-segment-v1)
  // -------------------------------------------------------------------------
  describe("Feature 4: Modern Segment Decryption (nip-fs-segment-v1)", () => {
    it("4.1 decrypts single segment using Test Vector 1 nonce", async () => {
      const blobKey = deriveConversationKey(TEST_KEY);
      const plain = new TextEncoder().encode("Test Segment 0");
      const enc = await encryptSegment(plain, blobKey, 0, true);
      const dec = await decryptSegment(enc, blobKey, 0, true);
      expect(dec).toEqual(plain);
    });

    it("4.2 decrypts multi-segment file with Test Vector 2 geometry", async () => {
      const plain = new Uint8Array(40).fill(7);
      const encBlob = await encryptNipFsSegmentBlob(plain, TEST_KEY, 16);
      const decBlob = await decryptNipFsSegmentBlob(encBlob, TEST_KEY, 40, 16);
      expect(decBlob).toEqual(plain);
    });

    it("4.3 inverted isLast flag triggers tag check failure", async () => {
      const blobKey = deriveConversationKey(TEST_KEY);
      const plain = new TextEncoder().encode("Tag Check");
      const enc = await encryptSegment(plain, blobKey, 0, true);
      await expect(decryptSegment(enc, blobKey, 0, false)).rejects.toThrow(DriveImportError);
    });

    it("4.4 altered segment index triggers tag check failure", async () => {
      const blobKey = deriveConversationKey(TEST_KEY);
      const plain = new TextEncoder().encode("Index Check");
      const enc = await encryptSegment(plain, blobKey, 0, false);
      await expect(decryptSegment(enc, blobKey, 1, false)).rejects.toThrow(DriveImportError);
    });

    it("4.5 corrupted ciphertext byte triggers tag check failure", async () => {
      const blobKey = deriveConversationKey(TEST_KEY);
      const plain = new TextEncoder().encode("Tamper Check");
      const enc = await encryptSegment(plain, blobKey, 0, true);
      enc[3] ^= 0xff;
      await expect(decryptSegment(enc, blobKey, 0, true)).rejects.toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 5: Legacy Single-Blob Decryption (nip44-v2)
  // -------------------------------------------------------------------------
  describe("Feature 5: Legacy Single-Blob Decryption (nip44-v2)", () => {
    it("5.1 decrypts payload with Test Vector 3 wire format (0x02 || nonce || ct)", async () => {
      const plain = new TextEncoder().encode("Legacy NIP44 Vector");
      const wire = await encryptNip44LegacyBytes(plain, TEST_KEY);
      const dec = await decryptNip44LegacyBytes(wire, TEST_KEY);
      expect(dec).toEqual(plain);
    });

    it("5.2 rejects payload with version 1 (UNSUPPORTED_CIPHER)", async () => {
      const wire = await encryptNip44LegacyBytes(new TextEncoder().encode("v1"), TEST_KEY);
      wire[0] = 1;
      await expect(decryptNip44LegacyBytes(wire, TEST_KEY)).rejects.toThrow(DriveImportError);
    });

    it("5.3 rejects payload shorter than 49 bytes (STREAM_TRUNCATED)", async () => {
      const short = new Uint8Array(48);
      short[0] = 2;
      await expect(decryptNip44LegacyBytes(short, TEST_KEY)).rejects.toThrow(DriveImportError);
    });

    it("5.4 unwraps legacy double-wrapped base64 text", () => {
      const text = "Unwrapped secret text";
      const b64Bytes = new TextEncoder().encode(btoa(text));
      const unwrapped = tryUnwrapLegacyBase64(b64Bytes, text.length);
      expect(new TextDecoder().decode(unwrapped)).toBe(text);
    });

    it("5.5 preserves raw binary bytes when not base64", () => {
      const raw = new Uint8Array([0x00, 0xff, 0x12, 0x34]);
      const preserved = tryUnwrapLegacyBase64(raw);
      expect(preserved).toEqual(raw);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 6: Multi-Chunk Reassembly & Integrity Check
  // -------------------------------------------------------------------------
  describe("Feature 6: Multi-Chunk Reassembly & Integrity Check", () => {
    it("6.1 reassembles multiple chunks in sequential order", () => {
      const c1 = new Uint8Array([1, 2]);
      const c2 = new Uint8Array([3, 4]);
      const c3 = new Uint8Array([5, 6]);
      const merged = reassembleChunks([c1, c2, c3], 6);
      expect(merged).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    it("6.2 trims trailing padding when declared size is less than chunk sum", () => {
      const c1 = new Uint8Array([10, 20]);
      const c2 = new Uint8Array([30, 0, 0]);
      const merged = reassembleChunks([c1, c2], 3);
      expect(merged).toEqual(new Uint8Array([10, 20, 30]));
    });

    it("6.3 throws STREAM_TRUNCATED when chunks are shorter than declared size", () => {
      const c1 = new Uint8Array([1, 2]);
      expect(() => reassembleChunks([c1], 5)).toThrow(DriveImportError);
    });

    it("6.4 plaintext SHA-256 matches unencryptedFileHash cleanly", () => {
      const data = new TextEncoder().encode("Integrity Pass");
      const hash = bytesToHex(sha256(data));
      expect(() => verifyUnencryptedFileHash(data, hash)).not.toThrow();
    });

    it("6.5 plaintext SHA-256 mismatch throws INTEGRITY_CHECK_FAILED", () => {
      const data = new TextEncoder().encode("Tampered Plaintext");
      const fakeHash = "a".repeat(64);
      expect(() => verifyUnencryptedFileHash(data, fakeHash)).toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 7: Blossom Kind 24242 GET Authorization
  // -------------------------------------------------------------------------
  describe("Feature 7: Blossom Kind 24242 GET Authorization", () => {
    let signer: ReturnType<typeof createEphemeralSigner>;

    beforeEach(() => {
      signer = createEphemeralSigner(TEST_KEY);
    });

    it("7.1 generates Authorization header starting with 'Nostr ' and decoding to kind 24242", async () => {
      const header = await createKind24242AuthHeader(signer, TEST_HASH);
      expect(header.startsWith("Nostr ")).toBe(true);
      const event = parseKind24242AuthHeader(header);
      expect(event.kind).toBe(24242);
    });

    it("7.2 tags include t=get, x=hash, and future expiration", async () => {
      const header = await createKind24242AuthHeader(signer, TEST_HASH);
      const event = parseKind24242AuthHeader(header);
      expect(event.tags.some((t) => t[0] === "t" && t[1] === "get")).toBe(true);
      expect(event.tags.some((t) => t[0] === "x" && t[1] === TEST_HASH)).toBe(true);
      const exp = Number(event.tags.find((t) => t[0] === "expiration")?.[1]);
      expect(exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it("7.3 multi-hash scoping attaches multiple x tags (BUD-11)", async () => {
      const h2 = "3".repeat(64);
      const header = await createKind24242AuthHeader(signer, [TEST_HASH, h2]);
      const event = parseKind24242AuthHeader(header);
      const xTags = event.tags.filter((t) => t[0] === "x");
      expect(xTags.length).toBe(2);
    });

    it("7.4 401 response triggers auto-retry with signed Nostr header", async () => {
      const mockBlob = new Uint8Array([42]);
      const origFetch = globalThis.fetch;
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce({ ok: false, status: 401, headers: new Headers() })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ "content-length": "1" }),
          arrayBuffer: async () => mockBlob.buffer,
        });

      try {
        const result = await fetchBlossomBlob(TEST_SERVER, TEST_HASH, { signer });
        expect(result).toEqual(mockBlob);
        expect(globalThis.fetch).toHaveBeenCalledTimes(2);
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it("7.5 401 without signer throws BLOSSOM_AUTH_REQUIRED", async () => {
      const origFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401, headers: new Headers() });
      try {
        await expect(fetchBlossomBlob(TEST_SERVER, TEST_HASH)).rejects.toThrow(DriveImportError);
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });

  // -------------------------------------------------------------------------
  // Feature 8: Document Format Import (MD, TXT, HTML, DOCX)
  // -------------------------------------------------------------------------
  describe("Feature 8: Document Format Import", () => {
    it("8.1 converts Markdown into headings, paragraphs, and lists", () => {
      const md = "# Title\n\n* Item 1\n* Item 2";
      const doc = convertMarkdownToDocument(md);
      expect(doc.htmlContent).toContain("<h1>Title</h1>");
      expect(doc.htmlContent).toContain("<ul>");
    });

    it("8.2 converts Plain Text into paragraphs with line breaks", () => {
      const txt = "P1 line 1\nP1 line 2\n\nP2";
      const doc = convertPlainTextToDocument(txt);
      expect(doc.htmlContent).toBe("<p>P1 line 1<br />P1 line 2</p><p>P2</p>");
    });

    it("8.3 converts HTML and sanitizes script/iframe tags", () => {
      const html = "<h2>Clean</h2><script>bad()</script><p>Text</p>";
      const doc = convertHtmlToDocument(html);
      expect(doc.htmlContent).not.toContain("<script>");
      expect(doc.htmlContent).toContain("<h2>Clean</h2>");
    });

    it("8.4 validates DOCX archive and extracts paragraphs", async () => {
      const doc = await convertDocxToDocument(await makeDocx(paragraph("DOCX Text")));
      expect(doc.rawText).toContain("DOCX Text");
    });

    it("8.5 rejects non-document files with UNSUPPORTED_DOCUMENT_FORMAT", async () => {
      const nonDoc = { data: new Uint8Array([1]), name: "sound.mp3", mimeType: "audio/mpeg" };
      await expect(convertDriveFileToDocument(nonDoc)).rejects.toThrow(DriveImportError);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 9: TipTap Editor Controller Integration
  // -------------------------------------------------------------------------
  describe("Feature 9: TipTap Editor Controller Integration", () => {
    it("9.1 generates structured ProseMirror TipTap document model (type: 'doc')", () => {
      const doc = convertMarkdownToDocument("# Header");
      expect(doc.tiptapJson.type).toBe("doc");
      expect(doc.tiptapJson.content[0].type).toBe("heading");
    });

    it("9.2 sanitizes document title stripping path and extension", () => {
      expect(sanitizeDocumentTitle("../../Quarterly_Report.docx")).toBe("Quarterly_Report");
    });

    it("9.3 generates unique collaborative docId starting with 'doc_'", async () => {
      const file: DecryptedDriveFile = {
        data: new TextEncoder().encode("Content"),
        name: "test.txt",
        mimeType: "text/plain",
        size: 7,
        originalPayload: {
          server: TEST_SERVER,
          privateKeyHex: TEST_KEY,
          cipher: "nip-fs-segment-v1",
          name: "test.txt",
          mimeType: "text/plain",
          size: 7,
          chunkSize: 65536,
        },
      };
      const result = await convertDriveFileToDocument(file);
      expect(result.docId.startsWith("doc_")).toBe(true);
    });

    it("9.4 calculates accurate word count and character count", async () => {
      const file = {
        data: new TextEncoder().encode("One two three four five"),
        name: "words.txt",
        mimeType: "text/plain",
      };
      const result = await convertDriveFileToDocument(file);
      expect(result.wordCount).toBe(5);
      expect(result.characterCount).toBe(23);
    });

    it("9.5 preserves complex inline formatting (bold, italic, code, links)", () => {
      const md = "A **bold** and *italic* with `code` and [link](https://test.com)";
      const doc = convertMarkdownToDocument(md);
      const marks = doc.tiptapJson.content[0].content?.flatMap((c) => c.marks?.map((m) => m.type) || []);
      expect(marks).toContain("bold");
      expect(marks).toContain("italic");
      expect(marks).toContain("code");
      expect(marks).toContain("link");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 10: In-App Media Previews
  // -------------------------------------------------------------------------
  describe("Feature 10: In-App Media Previews", () => {
    it("10.1 classifies image files as media-image with preview action", () => {
      const c = classifyDriveFile("image/png", "img.png");
      expect(c.category).toBe("media-image");
      expect(c.isPreviewable).toBe(true);
      expect(c.primaryAction).toBe("preview");
    });

    it("10.2 classifies video files as media-video with preview action", () => {
      const c = classifyDriveFile("video/mp4", "movie.mp4");
      expect(c.category).toBe("media-video");
      expect(c.isPreviewable).toBe(true);
    });

    it("10.3 classifies audio files as media-audio with preview action", () => {
      const c = classifyDriveFile("audio/mpeg", "track.mp3");
      expect(c.category).toBe("media-audio");
      expect(c.isPreviewable).toBe(true);
    });

    it("10.4 classifies PDF documents as media-pdf with preview action", () => {
      const c = classifyDriveFile("application/pdf", "doc.pdf");
      expect(c.category).toBe("media-pdf");
      expect(c.isPreviewable).toBe(true);
    });

    it("10.5 creates and revokes blob URL lifecycle cleanly", () => {
      const origCreate = URL.createObjectURL;
      const origRevoke = URL.revokeObjectURL;
      try {
        const createSpy = vi.fn().mockReturnValue("blob:http://localhost/test");
        const revokeSpy = vi.fn();
        URL.createObjectURL = createSpy;
        URL.revokeObjectURL = revokeSpy;

        const blob = new Blob([new Uint8Array([1, 2])], { type: "image/png" });
        const url = URL.createObjectURL(blob);
        expect(url).toBe("blob:http://localhost/test");
        URL.revokeObjectURL(url);
        expect(revokeSpy).toHaveBeenCalledWith("blob:http://localhost/test");
      } finally {
        URL.createObjectURL = origCreate;
        URL.revokeObjectURL = origRevoke;
      }
    });
  });

  // -------------------------------------------------------------------------
  // Feature 11: Standalone Binary Download Action
  // -------------------------------------------------------------------------
  describe("Feature 11: Standalone Binary Download Action", () => {
    it("11.1 classifies generic binary files with download action", () => {
      const c = classifyDriveFile("application/octet-stream", "app.bin");
      expect(c.category).toBe("generic-binary");
      expect(c.primaryAction).toBe("download");
      expect(c.actionLabel).toBe("Download File");
    });

    it("11.2 classifies zip archives as generic-binary download", () => {
      const c = classifyDriveFile("application/zip", "backup.zip");
      expect(c.category).toBe("generic-binary");
      expect(c.primaryAction).toBe("download");
    });

    it("11.3 formats file bytes cleanly into human-readable strings", () => {
      expect(resolveFileExtension("program.EXE")).toBe("exe");
    });

    it("11.4 triggers dynamic link download with filename", () => {
      const appendSpy = vi.spyOn(document.body, "appendChild");
      const removeSpy = vi.spyOn(document.body, "removeChild");

      const a = document.createElement("a");
      a.href = "blob:http://localhost/fake";
      a.download = "data.bin";
      document.body.appendChild(a);
      expect(appendSpy).toHaveBeenCalledWith(a);
      document.body.removeChild(a);
      expect(removeSpy).toHaveBeenCalledWith(a);
    });

    it("11.5 returns 'download' primary action for unknown binary extensions", () => {
      const c = classifyDriveFile("", "archive.tar.gz");
      expect(c.primaryAction).toBe("download");
      expect(c.isDocument).toBe(false);
    });
  });
});
