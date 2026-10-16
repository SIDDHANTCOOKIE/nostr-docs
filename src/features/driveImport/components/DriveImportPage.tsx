/**
 * src/features/driveImport/components/DriveImportPage.tsx
 * Top-level route view for /drive-import and hash payload deep links.
 *
 * Dispatches to:
 * - TipTap Document Importer for Markdown, Text, HTML, DOCX
 * - In-App Standalone Preview for Images, Video, Audio, PDF
 * - Binary Download View for other binary types
 * - Error card with "Back to docs" button when links are malformed or missing
 */

import React, { useState } from "react";
import { useDriveImport } from "../hooks/useDriveImport";
import { ImportLoadingState } from "./ImportLoadingState";
import { MediaPreviewModal } from "./MediaPreviewModal";
import { BinaryDownloadView } from "./BinaryDownloadView";
import { classifyDriveFile } from "../converters/mimeClassifier";

export interface DriveImportPageProps {
  onBackToDocs?: () => void;
  onOpenInEditor?: (docId: string, title: string, content: string | Record<string, unknown>) => void;
}

export const DriveImportPage: React.FC<DriveImportPageProps> = ({
  onBackToDocs = () => {
    window.location.href = "/";
  },
  onOpenInEditor,
}) => {
  const { status, decryptedFile, importedDocument, error, progress, retry, downloadFile } =
    useDriveImport();
  const [showRawText, setShowRawText] = useState(false);

  // 1. Loading States (parsing, fetching, decrypting, reassembling, verifying)
  if (
    status === "parsing" ||
    status === "fetching" ||
    status === "decrypting" ||
    status === "reassembling" ||
    status === "verifying"
  ) {
    return (
      <ImportLoadingState
        progress={progress || undefined}
        fileName={decryptedFile?.name}
        totalSize={decryptedFile?.size}
      />
    );
  }

  // 2. Error State
  if (status === "error" || error) {
    const errorDetails = error?.toJSON() || {
      title: "Unable to Open Shared File",
      description: "An unexpected error occurred while processing the link.",
      actionGuidance: "Back to docs",
    };

    return (
      <div
        style={{
          maxWidth: "480px",
          margin: "64px auto",
          padding: "36px 32px",
          backgroundColor: "#ffffff",
          borderRadius: "16px",
          boxShadow: "0 10px 30px rgba(0, 0, 0, 0.08)",
          textAlign: "center",
          fontFamily: "system-ui, -apple-system, sans-serif",
        }}
        role="alert"
      >
        <div
          style={{
            width: "56px",
            height: "56px",
            borderRadius: "50%",
            backgroundColor: "#fef2f2",
            color: "#ef4444",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 16px auto",
            fontSize: "24px",
          }}
        >
          ⚠️
        </div>
        <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: "0 0 8px 0" }}>
          {errorDetails.title}
        </h2>
        <p style={{ fontSize: "14px", color: "#4b5563", margin: "0 0 24px 0", lineHeight: "1.5" }}>
          {errorDetails.description}
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          <button
            onClick={retry}
            style={{
              padding: "10px 20px",
              backgroundColor: "#2563eb",
              color: "#ffffff",
              border: "none",
              borderRadius: "8px",
              fontSize: "14px",
              fontWeight: "500",
              cursor: "pointer",
            }}
          >
            Retry Download
          </button>
          <button
            onClick={onBackToDocs}
            style={{
              padding: "10px 20px",
              backgroundColor: "transparent",
              color: "#4b5563",
              border: "1px solid #d1d5db",
              borderRadius: "8px",
              fontSize: "14px",
              cursor: "pointer",
            }}
          >
            ← {errorDetails.actionGuidance || "Back to docs"}
          </button>
        </div>
      </div>
    );
  }

  // 3. Decrypted Content Ready
  if (decryptedFile) {
    const classification = classifyDriveFile(decryptedFile.mimeType, decryptedFile.name);

    // Case A: Collaborative Document (Markdown, Plain Text, HTML, DOCX)
    if (classification.isDocument && importedDocument) {
      return (
        <div
          style={{
            maxWidth: "680px",
            margin: "48px auto",
            padding: "36px",
            backgroundColor: "#ffffff",
            borderRadius: "16px",
            boxShadow: "0 10px 40px rgba(0, 0, 0, 0.08)",
            fontFamily: "system-ui, -apple-system, sans-serif",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "20px" }}>
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "12px",
                backgroundColor: "#eff6ff",
                color: "#2563eb",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "24px",
              }}
            >
              📝
            </div>
            <div>
              <h2 style={{ fontSize: "20px", fontWeight: "600", color: "#111827", margin: 0 }}>
                {importedDocument.title}
              </h2>
              <span style={{ fontSize: "13px", color: "#6b7280" }}>
                {importedDocument.wordCount} words • {importedDocument.characterCount} characters •{" "}
                {importedDocument.format.toUpperCase()}
              </span>
            </div>
          </div>

          <p style={{ fontSize: "14px", color: "#4b5563", lineHeight: "1.6", marginBottom: "24px" }}>
            This document was shared from Formstr Drive and decrypted locally. You can import it into
            the TipTap editor to collaborate, or download the original file.
          </p>

          <div style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
            <button
              onClick={() => {
                if (onOpenInEditor) {
                  onOpenInEditor(
                    importedDocument.docId,
                    importedDocument.title,
                    importedDocument.htmlContent || (importedDocument.tiptapJson as unknown as Record<string, unknown>),
                  );
                } else {
                  // Fallback: copy or notify
                  window.location.href = `/doc/${importedDocument.docId}`;
                }
              }}
              style={{
                flex: 1,
                padding: "12px 24px",
                backgroundColor: "#2563eb",
                color: "#ffffff",
                border: "none",
                borderRadius: "8px",
                fontSize: "15px",
                fontWeight: "500",
                cursor: "pointer",
              }}
            >
              ✏️ Open in Document Editor
            </button>
            <button
              onClick={downloadFile}
              style={{
                padding: "12px 20px",
                backgroundColor: "#f3f4f6",
                color: "#374151",
                border: "1px solid #d1d5db",
                borderRadius: "8px",
                fontSize: "14px",
                cursor: "pointer",
              }}
            >
              ⬇️ Save File
            </button>
          </div>

          <div style={{ borderTop: "1px solid #e5e7eb", paddingTop: "16px" }}>
            <button
              onClick={() => setShowRawText((prev) => !prev)}
              style={{
                background: "none",
                border: "none",
                color: "#2563eb",
                fontSize: "13px",
                cursor: "pointer",
                padding: 0,
                marginBottom: "12px",
              }}
            >
              {showRawText ? "▲ Hide Content Preview" : "▼ Show Content Preview"}
            </button>
            {showRawText && (
              <pre
                style={{
                  maxHeight: "300px",
                  overflowY: "auto",
                  padding: "16px",
                  backgroundColor: "#f9fafb",
                  borderRadius: "8px",
                  fontSize: "13px",
                  color: "#374151",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {importedDocument.rawText}
              </pre>
            )}
          </div>
        </div>
      );
    }

    // Case B: Interactive Media (Image, Video, Audio, PDF)
    if (classification.isMedia) {
      return <MediaPreviewModal file={decryptedFile} onBackToDocs={onBackToDocs} />;
    }

    // Case C: Generic Binary
    return <BinaryDownloadView file={decryptedFile} onBackToDocs={onBackToDocs} />;
  }

  // 4. Default Idle State
  return (
    <div style={{ textAlign: "center", padding: "64px 20px", fontFamily: "sans-serif" }}>
      <p style={{ color: "#6b7280" }}>Waiting for link...</p>
    </div>
  );
};
