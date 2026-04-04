import { AttachmentInput } from "@/utils/attachmentAnalysisTypes";

function sanitizeLine(value: string) {
  return value.trim().replace(/\s+/g, " ");
}

export function parseAttachmentInput(rawValue: string): AttachmentInput[] {
  return rawValue
    .split(/\r?\n/)
    .map(sanitizeLine)
    .filter(Boolean)
    .map((line, index) => {
      const [namePart, ...rest] = line.split("||");
      const fileName = namePart.trim();
      const notes = rest.join("||").trim();
      const declaredTypeMatch = fileName.match(/\.([a-z0-9]{2,5})$/i);
      return {
        id: `attachment-${index + 1}-${fileName.toLowerCase()}`,
        fileName,
        declaredType: declaredTypeMatch ? declaredTypeMatch[1].toLowerCase() : null,
        notes: notes || null,
      };
    });
}
