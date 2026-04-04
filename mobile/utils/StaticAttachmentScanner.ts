import {
  AttachmentInput,
  AttachmentRiskLevel,
  AttachmentStaticIndicator,
} from "@/utils/attachmentAnalysisTypes";

function makeIndicator(
  attachmentId: string,
  suffix: string,
  title: string,
  detail: string,
  severity: AttachmentRiskLevel,
  category: AttachmentStaticIndicator["category"]
): AttachmentStaticIndicator {
  return {
    id: `${attachmentId}-${suffix}`,
    title,
    detail,
    severity,
    category,
  };
}

function extensionOf(fileName: string) {
  const match = fileName.toLowerCase().match(/\.([a-z0-9]{2,6})$/i);
  return match ? match[1] : "unknown";
}

function normalizeTypeLabel(extension: string) {
  const labels: Record<string, string> = {
    pdf: "PDF document",
    exe: "Windows executable",
    zip: "ZIP archive",
    rar: "RAR archive",
    "7z": "7-Zip archive",
    docx: "Word document",
    docm: "Macro-enabled Word document",
    xlsx: "Excel workbook",
    xlsm: "Macro-enabled Excel workbook",
    js: "JavaScript file",
    html: "HTML file",
  };
  return labels[extension] || `${extension.toUpperCase()} file`;
}

export function getAttachmentTypeRisk(extension: string): {
  score: number;
  level: AttachmentRiskLevel;
} {
  const map: Record<string, { score: number; level: AttachmentRiskLevel }> = {
    exe: { score: 36, level: "critical" },
    js: { score: 32, level: "high" },
    html: { score: 28, level: "high" },
    zip: { score: 24, level: "high" },
    rar: { score: 24, level: "high" },
    "7z": { score: 24, level: "high" },
    docm: { score: 26, level: "high" },
    xlsm: { score: 26, level: "high" },
    pdf: { score: 14, level: "medium" },
    docx: { score: 14, level: "medium" },
    xlsx: { score: 14, level: "medium" },
    unknown: { score: 8, level: "medium" },
  };
  return map[extension] || map.unknown;
}

export function scanAttachmentStatically(attachment: AttachmentInput) {
  const fileName = attachment.fileName.trim();
  const extension = extensionOf(fileName);
  const typeRisk = getAttachmentTypeRisk(extension);
  const indicators: AttachmentStaticIndicator[] = [
    makeIndicator(
      attachment.id,
      "type",
      "File type risk",
      `${normalizeTypeLabel(extension)} attachments are commonly used in phishing delivery chains.`,
      typeRisk.level,
      "file-type"
    ),
  ];
  const notes = attachment.notes?.toLowerCase() || "";
  const lowerFileName = fileName.toLowerCase();

  if (/\.(pdf|docx|xlsx|txt|jpg|png)\.(exe|js|html|scr|bat|cmd|ps1)$/i.test(lowerFileName)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "double-extension",
        "Double extension detected",
        `The filename "${fileName}" disguises an executable behind a document-like extension.`,
        "critical",
        "obfuscation"
      )
    );
  }

  if (/(final[_-]?final|invoice|statement|update|urgent|payment|account)/i.test(lowerFileName)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "naming",
        "Suspicious filename pattern",
        `The filename "${fileName}" uses urgency or document-themed wording often seen in phishing lures.`,
        "medium",
        "filename"
      )
    );
  }

  if (/(https?:\/\/|login|verify|reset password|portal)/i.test(notes) && /^(pdf|docx|docm)$/i.test(extension)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "embedded-link",
        "Embedded external link",
        "Attachment notes suggest an external link or login destination embedded in the document.",
        "high",
        "embedded-link"
      )
    );
  }

  if (/macro|vba|enable editing|enable content/i.test(notes) || /^(docm|xlsm)$/i.test(extension)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "macro",
        "Macro-enabled behavior",
        "This attachment appears capable of macro execution or social engineering to enable active content.",
        "high",
        "macro"
      )
    );
  }

  if (/password|encrypted|protected/i.test(notes) || (/^(zip|rar|7z)$/i.test(extension) && /password/i.test(lowerFileName))) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "archive-protection",
        "Archive evasion signal",
        "Password-protected or encrypted archives are commonly used to bypass automated inspection.",
        "high",
        "archive"
      )
    );
  }

  if (/^(zip|rar|7z)$/i.test(extension)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "archive-container",
        "Archive container attachment",
        "Archive files can hide multiple payloads or nested phishing content inside a single attachment.",
        "medium",
        "archive"
      )
    );
  }

  if (/hidden|obfuscat|script|payload/i.test(notes) && /^(zip|rar|7z|html|js|exe)$/i.test(extension)) {
    indicators.push(
      makeIndicator(
        attachment.id,
        "hidden-executable",
        "Hidden executable pattern",
        "Attachment notes suggest concealed executable or script behavior inside a delivery container.",
        "critical",
        "obfuscation"
      )
    );
  }

  const staticRiskScore = Math.min(
    100,
    typeRisk.score +
      indicators.slice(1).reduce((total, indicator) => {
        const weight = indicator.severity === "critical" ? 22 : indicator.severity === "high" ? 16 : 9;
        return total + weight;
      }, 0)
  );

  return {
    fileType: extension,
    fileTypeLabel: normalizeTypeLabel(extension),
    indicators,
    staticRiskScore,
  };
}
