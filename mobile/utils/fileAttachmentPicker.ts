import * as DocumentPicker from "expo-document-picker";
import { EncodingType, readAsStringAsync } from "expo-file-system/legacy";

import { AttachmentFileUpload } from "@/utils/types";

const TEXT_LIKE_EXTENSIONS = new Set(["txt", "html", "htm", "js", "json", "xml", "csv", "md"]);
const MAX_TEXT_READ_BYTES = 262144;

function extensionOf(fileName: string) {
  const match = fileName.toLowerCase().match(/\.([a-z0-9]{1,8})$/i);
  return match ? match[1] : "unknown";
}

function inferHintsFromMetadata(fileName: string, extension: string, mimeType?: string | null) {
  const lowerName = fileName.toLowerCase();
  const hints = ["picked from device"];

  if (/invoice|statement|update|urgent|payment|account|secure|verify|login/i.test(lowerName)) {
    hints.push("suspicious filename");
  }

  if (/^(zip|rar|7z)$/i.test(extension)) {
    hints.push("archive container");
  }

  if (/^(docm|xlsm)$/i.test(extension)) {
    hints.push("macro enabled format");
  }

  if (/^(js|html|exe|ps1|bat|cmd|scr)$/i.test(extension)) {
    hints.push("script or executable format");
  }

  if (mimeType?.includes("pdf") || extension === "pdf") {
    hints.push("document attachment");
  }

  return hints;
}

function inferHintsFromContent(content: string) {
  const hints: string[] = [];

  if (/https?:\/\//i.test(content)) {
    hints.push("embedded login link");
  }

  if (/(window\.location|document\.location|location\.href|redirect)/i.test(content)) {
    hints.push("redirect");
  }

  if (/(fetch\(|axios|xmlhttprequest|navigator\.sendbeacon|websocket|api\.)/i.test(content)) {
    hints.push("network call");
  }

  if (/(login|verify|password|credential|account|bank)/i.test(content)) {
    hints.push("credential capture");
  }

  if (/(powershell|cmd\.exe|wscript|cscript|shell|exec\(|spawn\()/i.test(content)) {
    hints.push("execution");
  }

  if (/(download|payload|install|dropper)/i.test(content)) {
    hints.push("payload download");
  }

  if (/(registry|startup|scheduled task|autorun|modify system)/i.test(content)) {
    hints.push("system modification");
  }

  return hints;
}

async function deriveAttachmentLine(asset: DocumentPicker.DocumentPickerAsset) {
  const extension = extensionOf(asset.name);
  const hints = inferHintsFromMetadata(asset.name, extension, asset.mimeType);

  const canReadText =
    TEXT_LIKE_EXTENSIONS.has(extension) ||
    asset.mimeType?.startsWith("text/") ||
    asset.mimeType === "application/json";

  if (canReadText && typeof asset.size === "number" && asset.size <= MAX_TEXT_READ_BYTES) {
    try {
      const content = await readAsStringAsync(asset.uri, { encoding: EncodingType.UTF8 });
      hints.push(...inferHintsFromContent(content));
    } catch {
      hints.push("content preview unavailable");
    }
  }

  const uniqueHints = [...new Set(hints)];
  return uniqueHints.length > 0
    ? `${asset.name} || ${uniqueHints.join(", ")}`
    : asset.name;
}

export async function pickAttachmentSelection(): Promise<{
  files: AttachmentFileUpload[];
  lines: string[];
}> {
  const result = await DocumentPicker.getDocumentAsync({
    multiple: true,
    copyToCacheDirectory: true,
    type: "*/*",
  });

  if (result.canceled || !result.assets?.length) {
    return {
      files: [],
      lines: [],
    };
  }

  const files = result.assets.map((asset, index) => ({
    id: `${asset.name}-${asset.lastModified}-${index}`,
    name: asset.name,
    uri: asset.uri,
    mimeType: asset.mimeType,
    size: asset.size,
  }));
  const lines = await Promise.all(result.assets.map((asset) => deriveAttachmentLine(asset)));

  return {
    files,
    lines,
  };
}
