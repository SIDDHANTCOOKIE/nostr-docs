/**
 * src/features/driveImport/components/ImportLoadingState.tsx
 * Progress indicator for Formstr Drive deep link ingestion, download, and decryption.
 */

import React from "react";
import type { DecryptionProgress } from "../types";

export interface ImportLoadingStateProps {
  progress?: DecryptionProgress;
  fileName?: string;
  totalSize?: number;
}

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export const ImportLoadingState: React.FC<ImportLoadingStateProps> = ({
  progress,
  fileName,
  totalSize,
}) => {
  const stage = progress?.stage || "fetching";
  const bytesReceived = progress?.bytesReceived || 0;
  const total = progress?.totalBytes || totalSize || 0;
  const percent = total > 0 ? Math.min(100, Math.round((bytesReceived / total) * 100)) : 0;

  const stageLabels: Record<string, string> = {
    parsing: "Parsing link parameters...",
    fetching: "Downloading encrypted blob from storage...",
    decrypting: "Decrypting file contents...",
    reassembling: "Reassembling multi-chunk file...",
    verifying: "Verifying plaintext hash integrity...",
    complete: "Ready!",
    error: "Error occurred",
  };

  const currentLabel = stageLabels[stage] || "Processing shared file...";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "48px 24px",
        maxWidth: "480px",
        margin: "64px auto",
        backgroundColor: "#ffffff",
        borderRadius: "12px",
        boxShadow: "0 4px 20px rgba(0, 0, 0, 0.08)",
        textAlign: "center",
        fontFamily: "system-ui, -apple-system, sans-serif",
      }}
      role="status"
      aria-live="polite"
    >
      <div
        style={{
          width: "48px",
          height: "48px",
          border: "4px solid #f0f0f0",
          borderTop: "4px solid #3b82f6",
          borderRadius: "50%",
          animation: "spin 1s linear infinite",
          marginBottom: "24px",
        }}
      />
      <h3 style={{ margin: "0 0 8px 0", fontSize: "18px", color: "#111827" }}>
        {currentLabel}
      </h3>
      {fileName && (
        <p style={{ margin: "0 0 16px 0", fontSize: "14px", color: "#6b7280" }}>
          {fileName} {total > 0 && `(${formatBytes(total)})`}
        </p>
      )}

      {total > 0 && (
        <div style={{ width: "100%", marginTop: "8px" }}>
          <div
            style={{
              height: "8px",
              backgroundColor: "#e5e7eb",
              borderRadius: "4px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                width: `${percent}%`,
                height: "100%",
                backgroundColor: "#3b82f6",
                transition: "width 0.2s ease-in-out",
              }}
            />
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              fontSize: "12px",
              color: "#9ca3af",
              marginTop: "4px",
            }}
          >
            <span>{formatBytes(bytesReceived)}</span>
            <span>{percent}%</span>
            <span>{formatBytes(total)}</span>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
