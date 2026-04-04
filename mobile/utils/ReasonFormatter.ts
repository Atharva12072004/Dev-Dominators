import { ExplainabilitySection } from "@/utils/attachmentAnalysisTypes";

function dedupe(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

export function formatReasonSection(title: string, key: string, items: string[]): ExplainabilitySection | null {
  const cleaned = dedupe(items);
  if (cleaned.length === 0) {
    return null;
  }
  return { title, key, items: cleaned };
}

export function bucketBaseReasons(reasons: string[]) {
  const email: string[] = [];
  const url: string[] = [];
  const file: string[] = [];
  const other: string[] = [];

  reasons.forEach((reason) => {
    const lower = reason.toLowerCase();
    if (/(sender|gmail|inbox|domain|spoof|urgent language|reply-to|mail)/i.test(lower)) {
      email.push(reason);
      return;
    }
    if (/(url|link|browser|domain mismatch|redirect|login page|landing page|shortener|https?)/i.test(lower)) {
      url.push(reason);
      return;
    }
    if (/(file|attachment|document|macro|archive|pdf|doc|xls|zip|exe|html|script)/i.test(lower)) {
      file.push(reason);
      return;
    }
    other.push(reason);
  });

  return { email, url, file, other };
}
