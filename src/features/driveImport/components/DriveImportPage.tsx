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

import React from "react";
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
            fontWeight: 700,
          }}
        >
          !
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
            {errorDetails.actionGuidance || "Back to docs"}
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
      const buttonBase = {
        padding: "9px 18px",
        borderRadius: "8px",
        fontSize: "14px",
        fontWeight: 500,
        cursor: "pointer",
        whiteSpace: "nowrap" as const,
      };
      return (
        <div
          style={{
            maxWidth: "860px",
            width: "100%",
            margin: "32px auto",
            padding: "0 20px",
            boxSizing: "border-box",
            fontFamily: "system-ui, -apple-system, sans-serif",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: "12px 20px",
              marginBottom: "16px",
            }}
          >
            <div style={{ minWidth: 0 }}>
              <h2
                style={{
                  fontSize: "20px",
                  fontWeight: 600,
                  color: "#111827",
                  margin: "0 0 2px 0",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {importedDocument.title}
              </h2>
              <span style={{ fontSize: "13px", color: "#6b7280" }}>
                {importedDocument.wordCount.toLocaleString()} words · Imported from Formstr Drive
              </span>
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                onClick={downloadFile}
                style={{
                  ...buttonBase,
                  backgroundColor: "#ffffff",
                  color: "#374151",
                  border: "1px solid #d1d5db",
                }}
              >
                Download
              </button>
              <button
                onClick={() => {
                  if (onOpenInEditor) {
                    onOpenInEditor(
                      importedDocument.docId,
                      importedDocument.title,
                      importedDocument.markdown,
                    );
                  }
                }}
                style={{
                  ...buttonBase,
                  backgroundColor: "#2563eb",
                  color: "#ffffff",
                  border: "1px solid #2563eb",
                }}
              >
                Open in editor
              </button>
            </div>
          </div>

          <iframe
            title="Document preview"
            sandbox=""
            srcDoc={`<!doctype html><meta charset="utf-8"><style>body{font:15px/1.65 Georgia,'Times New Roman',serif;color:#1f2937;margin:0;padding:32px 40px}h1,h2,h3{font-family:system-ui,sans-serif;line-height:1.25}table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border:1px solid #d1d5db;padding:6px 10px;vertical-align:top}p{margin:0 0 .8em}</style>${importedDocument.htmlContent}`}
            style={{
              display: "block",
              width: "100%",
              height: "calc(100vh - 150px)",
              minHeight: "360px",
              border: "1px solid #e5e7eb",
              borderRadius: "10px",
              backgroundColor: "#ffffff",
              boxShadow: "0 1px 3px rgba(0, 0, 0, 0.06)",
            }}
          />
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
