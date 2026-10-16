/**
 * src/features/driveImport/converters/documentConverter.ts
 * Universal Document Converter for TipTap ProseMirror Collaborative Editor.
 *
 * Converts Markdown, HTML, Plain Text, and DOCX binary payloads into:
 * 1. Clean sanitized HTML content string.
 * 2. Structured TipTap ProseMirror document JSON (`TipTapDocNode`).
 * 3. Title sanitization, word counts, and unique collaborative document descriptors.
 */

import {
  DriveImportError,
  type DecryptedDriveFile,
  type DocumentImportResult,
  type TipTapDocNode,
  type TipTapNode,
} from "../types";
import { classifyDriveFile } from "./mimeClassifier";

/**
 * Strips path components and document file extensions to derive a clean display title.
 * Falls back to "Untitled Document (Imported)" if result is empty.
 */
export function sanitizeDocumentTitle(fileName?: string): string {
  if (!fileName || typeof fileName !== "string") {
    return "Untitled Document (Imported)";
  }

  // Strip path traversal prefixes (both UNIX / and Windows \)
  const baseName = fileName.replace(/^.*[/\\]/, "").trim();
  if (!baseName) {
    return "Untitled Document (Imported)";
  }

  // Strip known document extensions
  const stripped = baseName.replace(
    /\.(md|markdown|mdown|mkdn|txt|text|html|htm|xhtml|docx|doc|odt|log|json|xml|csv)$/i,
    "",
  ).trim();

  return stripped.length > 0 ? stripped : "Untitled Document (Imported)";
}

/**
 * Escapes unsafe HTML characters to prevent XSS injection.
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Parses inline markdown marks (bold, italic, strikethrough, inline code, links)
 * into HTML and TipTap inline nodes.
 */
function parseInlineMarkdown(text: string): { html: string; nodes: TipTapNode[] } {
  const nodes: TipTapNode[] = [];
  let html = "";

  // Regular expression matching bold (** or __), italic (* or _), strikethrough (~~), code (`), or links [text](url)
  const tokenRegex = /(\*\*(.+?)\*\*|__(.+?)__|~~(.+?)~~|\*(.+?)\*|_(.+?)_|`(.+?)`|\[(.+?)\]\((.+?)\))/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(text)) !== null) {
    // Push preceding text if any
    if (match.index > lastIndex) {
      const plainSegment = text.slice(lastIndex, match.index);
      html += escapeHtml(plainSegment);
      nodes.push({ type: "text", text: plainSegment });
    }

    if (match[2] || match[3]) {
      // Bold: **text** or __text__
      const boldText = match[2] || match[3];
      html += `<strong>${escapeHtml(boldText)}</strong>`;
      nodes.push({
        type: "text",
        text: boldText,
        marks: [{ type: "bold" }],
      });
    } else if (match[4]) {
      // Strikethrough: ~~text~~
      const strikeText = match[4];
      html += `<s>${escapeHtml(strikeText)}</s>`;
      nodes.push({
        type: "text",
        text: strikeText,
        marks: [{ type: "strike" }],
      });
    } else if (match[5] || match[6]) {
      // Italic: *text* or _text_
      const italicText = match[5] || match[6];
      html += `<em>${escapeHtml(italicText)}</em>`;
      nodes.push({
        type: "text",
        text: italicText,
        marks: [{ type: "italic" }],
      });
    } else if (match[7]) {
      // Inline code: `code`
      const codeText = match[7];
      html += `<code>${escapeHtml(codeText)}</code>`;
      nodes.push({
        type: "text",
        text: codeText,
        marks: [{ type: "code" }],
      });
    } else if (match[8] && match[9]) {
      // Link: [text](href)
      const linkText = match[8];
      const linkHref = match[9];
      html += `<a href="${escapeHtml(linkHref)}">${escapeHtml(linkText)}</a>`;
      nodes.push({
        type: "text",
        text: linkText,
        marks: [{ type: "link", attrs: { href: linkHref } }],
      });
    }

    lastIndex = tokenRegex.lastIndex;
  }

  // Push remaining trailing text
  if (lastIndex < text.length) {
    const trailingSegment = text.slice(lastIndex);
    html += escapeHtml(trailingSegment);
    nodes.push({ type: "text", text: trailingSegment });
  }

  return { html, nodes };
}

/**
 * Converts Markdown string into clean HTML and TipTap ProseMirror document JSON.
 */
export function convertMarkdownToDocument(markdownText: string, _title?: string): {
  htmlContent: string;
  tiptapJson: TipTapDocNode;
  rawText: string;
} {
  const normText = (markdownText || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normText.split("\n");

  const docContent: TipTapNode[] = [];
  const htmlParts: string[] = [];

  let inCodeBlock = false;
  let codeBlockLang = "";
  let codeBlockLines: string[] = [];

  let inList: "bullet" | "ordered" | null = null;
  let listItems: TipTapNode[] = [];
  let listHtmlParts: string[] = [];

  function flushList() {
    if (!inList) return;
    if (inList === "bullet") {
      docContent.push({ type: "bulletList", content: listItems });
      htmlParts.push(`<ul>${listHtmlParts.join("")}</ul>`);
    } else {
      docContent.push({ type: "orderedList", content: listItems });
      htmlParts.push(`<ol>${listHtmlParts.join("")}</ol>`);
    }
    inList = null;
    listItems = [];
    listHtmlParts = [];
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // 1. Code Blocks (```)
    if (trimmed.startsWith("```")) {
      if (inCodeBlock) {
        // End code block
        const codeContent = codeBlockLines.join("\n");
        docContent.push({
          type: "codeBlock",
          attrs: { language: codeBlockLang || null },
          content: codeContent ? [{ type: "text", text: codeContent }] : [],
        });
        htmlParts.push(
          `<pre><code class="language-${escapeHtml(codeBlockLang)}">${escapeHtml(codeContent)}</code></pre>`,
        );
        inCodeBlock = false;
        codeBlockLines = [];
        codeBlockLang = "";
      } else {
        // Start code block
        flushList();
        inCodeBlock = true;
        codeBlockLang = trimmed.slice(3).trim();
        codeBlockLines = [];
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockLines.push(line);
      continue;
    }

    // 2. Empty Lines
    if (trimmed === "") {
      flushList();
      continue;
    }

    // 3. Headings (# H1 to ###### H6)
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      flushList();
      const level = headingMatch[1].length;
      const headingText = headingMatch[2].trim();
      const inline = parseInlineMarkdown(headingText);

      docContent.push({
        type: "heading",
        attrs: { level },
        content: inline.nodes.length > 0 ? inline.nodes : [{ type: "text", text: headingText }],
      });
      htmlParts.push(`<h${level}>${inline.html}</h${level}>`);
      continue;
    }

    // 4. Horizontal Rule (---, ***, ___)
    if (/^(\*{3,}|-{3,}|_{3,})$/.test(trimmed)) {
      flushList();
      docContent.push({ type: "horizontalRule" });
      htmlParts.push("<hr />");
      continue;
    }

    // 5. Blockquote (> quote)
    if (line.startsWith(">")) {
      flushList();
      const quoteText = line.replace(/^>\s?/, "").trim();
      const inline = parseInlineMarkdown(quoteText);

      docContent.push({
        type: "blockquote",
        content: [
          {
            type: "paragraph",
            content: inline.nodes.length > 0 ? inline.nodes : [{ type: "text", text: quoteText }],
          },
        ],
      });
      htmlParts.push(`<blockquote><p>${inline.html}</p></blockquote>`);
      continue;
    }

    // 6. Bullet Lists (* item, - item, + item)
    const bulletMatch = line.match(/^(\*|-|\+)\s+(.*)$/);
    if (bulletMatch) {
      if (inList !== "bullet") {
        flushList();
        inList = "bullet";
      }
      const itemText = bulletMatch[2].trim();
      const inline = parseInlineMarkdown(itemText);
      listItems.push({
        type: "listItem",
        content: [
          {
            type: "paragraph",
            content: inline.nodes.length > 0 ? inline.nodes : [{ type: "text", text: itemText }],
          },
        ],
      });
      listHtmlParts.push(`<li>${inline.html}</li>`);
      continue;
    }

    // 7. Ordered Lists (1. item)
    const orderedMatch = line.match(/^(\d+)\.\s+(.*)$/);
    if (orderedMatch) {
      if (inList !== "ordered") {
        flushList();
        inList = "ordered";
      }
      const itemText = orderedMatch[2].trim();
      const inline = parseInlineMarkdown(itemText);
      listItems.push({
        type: "listItem",
        content: [
          {
            type: "paragraph",
            content: inline.nodes.length > 0 ? inline.nodes : [{ type: "text", text: itemText }],
          },
        ],
      });
      listHtmlParts.push(`<li>${inline.html}</li>`);
      continue;
    }

    // 8. Standard Paragraph
    flushList();
    const inline = parseInlineMarkdown(line);
    docContent.push({
      type: "paragraph",
      content: inline.nodes.length > 0 ? inline.nodes : [{ type: "text", text: line }],
    });
    htmlParts.push(`<p>${inline.html}</p>`);
  }

  flushList();

  // Handle unclosed code block at end of file
  if (inCodeBlock) {
    const codeContent = codeBlockLines.join("\n");
    docContent.push({
      type: "codeBlock",
      attrs: { language: codeBlockLang || null },
      content: codeContent ? [{ type: "text", text: codeContent }] : [],
    });
    htmlParts.push(
      `<pre><code class="language-${escapeHtml(codeBlockLang)}">${escapeHtml(codeContent)}</code></pre>`,
    );
  }

  // Ensure document is never empty
  if (docContent.length === 0) {
    docContent.push({ type: "paragraph", content: [] });
    htmlParts.push("<p></p>");
  }

  return {
    htmlContent: htmlParts.join(""),
    tiptapJson: { type: "doc", content: docContent },
    rawText: normText,
  };
}

/**
 * Converts Plain Text into HTML paragraphs and TipTap document model.
 */
export function convertPlainTextToDocument(plainText: string, _title?: string): {
  htmlContent: string;
  tiptapJson: TipTapDocNode;
  rawText: string;
} {
  const normText = (plainText || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const paragraphs = normText.split(/\n\s*\n/);

  const docContent: TipTapNode[] = [];
  const htmlParts: string[] = [];

  for (const para of paragraphs) {
    const cleanPara = para.trim();
    if (!cleanPara) continue;

    // Handle single newlines inside paragraph with line breaks
    const lines = cleanPara.split("\n");
    const pNodes: TipTapNode[] = [];
    const pSubHtml: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      if (i > 0) {
        pNodes.push({ type: "hardBreak" });
        pSubHtml.push("<br />");
      }
      pNodes.push({ type: "text", text: lines[i] });
      pSubHtml.push(escapeHtml(lines[i]));
    }

    docContent.push({
      type: "paragraph",
      content: pNodes,
    });
    htmlParts.push(`<p>${pSubHtml.join("")}</p>`);
  }

  if (docContent.length === 0) {
    docContent.push({ type: "paragraph", content: [] });
    htmlParts.push("<p></p>");
  }

  return {
    htmlContent: htmlParts.join(""),
    tiptapJson: { type: "doc", content: docContent },
    rawText: normText,
  };
}

/**
 * Converts HTML string into sanitized TipTap document model and clean HTML.
 */
export function convertHtmlToDocument(htmlText: string, _title?: string): {
  htmlContent: string;
  tiptapJson: TipTapDocNode;
  rawText: string;
} {
  // Strip malicious tags: scripts, objects, iframes, styles, links
  const sanitized = htmlText
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "")
    .replace(/\son\w+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/gi, "") // strip onerror, onclick, etc.
    .replace(/javascript:/gi, "");

  // Extract text and build structured paragraphs
  // Split on block-level tags: <p>, <div>, <h1>-<h6>, <br>, <li>
  const blocks = sanitized
    .replace(/<\/h[1-6]>/gi, "\n\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n");

  const cleanText = blocks.replace(/<[^>]*>/g, "").replace(/\n{3,}/g, "\n\n").trim();

  // Reuse plain text structured conversion for solid ProseMirror compatibility
  const converted = convertPlainTextToDocument(cleanText);

  return {
    htmlContent: sanitized.trim() || "<p></p>",
    tiptapJson: converted.tiptapJson,
    rawText: cleanText,
  };
}

/**
 * Lightweight ZIP extractor for locating and extracting files from unencrypted .docx archives.
 */
async function extractZipEntry(zipBytes: Uint8Array, entryName: string): Promise<Uint8Array | null> {
  const len = zipBytes.length;
  let offset = 0;

  while (offset + 30 <= len) {
    // Check for local file header signature: 0x04034b50 (PK\x03\x04)
    if (
      zipBytes[offset] === 0x50 &&
      zipBytes[offset + 1] === 0x4b &&
      zipBytes[offset + 2] === 0x03 &&
      zipBytes[offset + 3] === 0x04
    ) {
      const compression = zipBytes[offset + 8] | (zipBytes[offset + 9] << 8);
      const compressedSize =
        zipBytes[offset + 18] |
        (zipBytes[offset + 19] << 8) |
        (zipBytes[offset + 20] << 16) |
        (zipBytes[offset + 21] << 24);
      const fileNameLen = zipBytes[offset + 26] | (zipBytes[offset + 27] << 8);
      const extraLen = zipBytes[offset + 28] | (zipBytes[offset + 29] << 8);

      const nameStart = offset + 30;
      const nameEnd = nameStart + fileNameLen;
      if (nameEnd > len) break;

      const currentName = new TextDecoder().decode(zipBytes.subarray(nameStart, nameEnd));
      const dataStart = nameEnd + extraLen;
      const dataEnd = dataStart + compressedSize;

      if (currentName === entryName) {
        if (dataEnd > len) break;
        const compressedData = zipBytes.subarray(dataStart, dataEnd);

        if (compression === 0) {
          // Stored uncompressed
          return compressedData;
        }

        if (compression === 8) {
          // Deflate compression
          if (typeof DecompressionStream !== "undefined") {
            try {
              const ds = new DecompressionStream("deflate-raw");
              const stream = new Response(new Blob([compressedData as unknown as BlobPart]).stream().pipeThrough(ds));
              const buf = await stream.arrayBuffer();
              return new Uint8Array(buf);
            } catch {
              // Try standard deflate stream
              try {
                const ds = new DecompressionStream("deflate");
                const stream = new Response(new Blob([compressedData as unknown as BlobPart]).stream().pipeThrough(ds));
                const buf = await stream.arrayBuffer();
                return new Uint8Array(buf);
              } catch {
                return null;
              }
            }
          }
        }
        return null;
      }

      offset = dataEnd;
    } else {
      offset++;
    }
  }

  return null;
}

/**
 * Converts a Microsoft Word DOCX binary byte array into clean HTML and TipTap document model.
 */
export async function convertDocxToDocument(
  docxBytes: Uint8Array,
  title?: string,
): Promise<{
  htmlContent: string;
  tiptapJson: TipTapDocNode;
  rawText: string;
}> {
  if (!docxBytes || docxBytes.length === 0) {
    throw new DriveImportError(
      "CORRUPTED_DOCUMENT",
      "DOCX file is empty (0 bytes)",
      "File contains no data",
      "Corrupted Document",
      "file",
    );
  }

  // Check for ZIP magic bytes: PK\x03\x04
  if (docxBytes.length < 4 || docxBytes[0] !== 0x50 || docxBytes[1] !== 0x4b) {
    throw new DriveImportError(
      "CORRUPTED_DOCUMENT",
      "Invalid DOCX file format: missing standard ZIP archive header",
      "The Word document is corrupted or not a valid .docx file",
      "Corrupted Document",
      "file",
    );
  }

  // Attempt to extract word/document.xml
  const xmlBytes = await extractZipEntry(docxBytes, "word/document.xml");

  if (!xmlBytes) {
    // If DecompressionStream is unavailable or document.xml not found,
    // scan for text segments or fallback to placeholder
    const textDecoder = new TextDecoder("utf-8", { fatal: false });
    const rawXml = textDecoder.decode(docxBytes);
    const textMatches = rawXml.match(/<w:t[^>]*>(.*?)<\/w:t>/g);

    if (textMatches && textMatches.length > 0) {
      const extractedText = textMatches
        .map((m) => m.replace(/<[^>]*>/g, ""))
        .join(" ")
        .trim();
      return convertPlainTextToDocument(extractedText, title);
    }

    throw new DriveImportError(
      "CORRUPTED_DOCUMENT",
      "Unable to read Word document contents from DOCX archive",
      "The document may be encrypted, password protected, or corrupted",
      "Corrupted Document",
      "file",
    );
  }

  const xmlStr = new TextDecoder().decode(xmlBytes);

  // Parse paragraphs <w:p>
  const docContent: TipTapNode[] = [];
  const htmlParts: string[] = [];
  const textParts: string[] = [];

  // Match all <w:p>...</w:p> blocks
  const pRegex = /<w:p\b[^>]*>([\s\S]*?)<\/w:p>/g;
  let pMatch: RegExpExecArray | null;

  while ((pMatch = pRegex.exec(xmlStr)) !== null) {
    const pXml = pMatch[1];

    // Detect heading style (e.g. <w:pStyle w:val="Heading1"/>)
    const styleMatch = pXml.match(/<w:pStyle\s+[^>]*w:val="Heading(\d)"/i);
    const headingLevel = styleMatch ? Number(styleMatch[1]) : 0;

    // Extract runs <w:r>
    const runRegex = /<w:r\b[^>]*>([\s\S]*?)<\/w:r>/g;
    let rMatch: RegExpExecArray | null;
    const inlineNodes: TipTapNode[] = [];
    const inlineHtmlParts: string[] = [];
    let pText = "";

    while ((rMatch = runRegex.exec(pXml)) !== null) {
      const rXml = rMatch[1];
      const isBold = /<w:b(\s*\/|>|\s+[^>]*\/>)/.test(rXml);
      const isItalic = /<w:i(\s*\/|>|\s+[^>]*\/>)/.test(rXml);

      // Extract text <w:t>...</w:t>
      const tMatch = rXml.match(/<w:t\b[^>]*>([\s\S]*?)<\/w:t>/);
      if (tMatch && tMatch[1]) {
        const text = tMatch[1];
        pText += text;

        const marks: Array<{ type: string }> = [];
        let rHtml = escapeHtml(text);

        if (isBold) {
          marks.push({ type: "bold" });
          rHtml = `<strong>${rHtml}</strong>`;
        }
        if (isItalic) {
          marks.push({ type: "italic" });
          rHtml = `<em>${rHtml}</em>`;
        }

        inlineNodes.push({
          type: "text",
          text,
          marks: marks.length > 0 ? marks : undefined,
        });
        inlineHtmlParts.push(rHtml);
      }
    }

    if (pText.trim().length > 0) {
      textParts.push(pText.trim());

      if (headingLevel >= 1 && headingLevel <= 6) {
        docContent.push({
          type: "heading",
          attrs: { level: headingLevel },
          content: inlineNodes,
        });
        htmlParts.push(`<h${headingLevel}>${inlineHtmlParts.join("")}</h${headingLevel}>`);
      } else {
        docContent.push({
          type: "paragraph",
          content: inlineNodes,
        });
        htmlParts.push(`<p>${inlineHtmlParts.join("")}</p>`);
      }
    }
  }

  if (docContent.length === 0) {
    docContent.push({ type: "paragraph", content: [] });
    htmlParts.push("<p></p>");
  }

  const rawText = textParts.join("\n\n");

  return {
    htmlContent: htmlParts.join(""),
    tiptapJson: { type: "doc", content: docContent },
    rawText,
  };
}

/**
 * Universal entrance point: converts a DecryptedDriveFile into a complete DocumentImportResult
 * ready for TipTap editor opening and collaborative document synchronization.
 */
export async function convertDriveFileToDocument(
  file: DecryptedDriveFile | { data: Uint8Array; name: string; mimeType: string },
): Promise<DocumentImportResult> {
  const classification = classifyDriveFile(file.mimeType, file.name);

  if (!classification.isDocument) {
    throw new DriveImportError(
      "UNSUPPORTED_DOCUMENT_FORMAT",
      `Cannot import "${file.name}" as document: format "${classification.normalizedMimeType}" is not a supported document type`,
      "Import is available for Markdown, Plain Text, HTML, and Word documents",
      "Unsupported Document",
      "mimeType",
    );
  }

  const title = sanitizeDocumentTitle(file.name);
  const docId = `doc_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;

  let converted: {
    htmlContent: string;
    tiptapJson: TipTapDocNode;
    rawText: string;
  };

  const subtype = classification.documentSubtype || "text";

  switch (subtype) {
    case "docx":
      converted = await convertDocxToDocument(file.data, title);
      break;
    case "markdown": {
      const text = new TextDecoder("utf-8").decode(file.data);
      converted = convertMarkdownToDocument(text, title);
      break;
    }
    case "html": {
      const text = new TextDecoder("utf-8").decode(file.data);
      converted = convertHtmlToDocument(text, title);
      break;
    }
    case "text":
    default: {
      const text = new TextDecoder("utf-8").decode(file.data);
      converted = convertPlainTextToDocument(text, title);
      break;
    }
  }

  const words = converted.rawText.trim() ? converted.rawText.trim().split(/\s+/).length : 0;
  const chars = converted.rawText.length;

  return {
    docId,
    title,
    format: subtype === "markdown" ? "markdown" : subtype === "html" ? "html" : "text",
    htmlContent: converted.htmlContent,
    tiptapJson: converted.tiptapJson,
    rawText: converted.rawText,
    sourceFileName: file.name,
    sourceMimeType: classification.normalizedMimeType,
    characterCount: chars,
    wordCount: words,
    createdAt: Date.now(),
  };
}
