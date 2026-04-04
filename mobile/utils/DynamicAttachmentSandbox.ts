import {
  AttachmentDynamicIndicator,
  AttachmentRiskLevel,
  AttachmentStaticIndicator,
  AttachmentTimelineStep,
} from "@/utils/attachmentAnalysisTypes";

function pushDynamic(
  collection: AttachmentDynamicIndicator[],
  attachmentId: string,
  suffix: string,
  title: string,
  detail: string,
  severity: AttachmentRiskLevel,
  behavior: AttachmentDynamicIndicator["behavior"]
) {
  collection.push({
    id: `${attachmentId}-${suffix}`,
    title,
    detail,
    severity,
    behavior,
    simulated: true,
  });
}

function pushStep(
  collection: AttachmentTimelineStep[],
  attachmentId: string,
  suffix: string,
  label: string,
  detail: string,
  severity: AttachmentRiskLevel
) {
  collection.push({
    id: `${attachmentId}-${suffix}`,
    label,
    detail,
    severity,
    simulated: true,
  });
}

export function simulateDynamicAttachmentSandbox(input: {
  attachmentId: string;
  fileName: string;
  fileType: string;
  notes?: string | null;
  staticIndicators: AttachmentStaticIndicator[];
}) {
  const { attachmentId, fileName, fileType, notes, staticIndicators } = input;
  const lowerNotes = notes?.toLowerCase() || "";
  const dynamicIndicators: AttachmentDynamicIndicator[] = [];
  const timeline: AttachmentTimelineStep[] = [];

  pushStep(timeline, attachmentId, "open", "File opened", `${fileName} is opened inside the safe demo sandbox.`, "low");

  const hasEmbeddedLink = staticIndicators.some((indicator) => indicator.category === "embedded-link");
  const hasMacro = staticIndicators.some((indicator) => indicator.category === "macro");
  const hasArchive = staticIndicators.some((indicator) => indicator.category === "archive");
  const hasObfuscation = staticIndicators.some((indicator) => indicator.category === "obfuscation");

  if (
    hasEmbeddedLink ||
    /browser|redirect|login|portal|credential/i.test(lowerNotes) ||
    /^(html)$/i.test(fileType)
  ) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "browser",
      "Browser launch attempt",
      "Simulated opening flow indicates the attachment would direct the user to an external web destination.",
      hasEmbeddedLink ? "high" : "medium",
      "browser-open"
    );
    pushStep(
      timeline,
      attachmentId,
      "extract-link",
      "Link extracted",
      "A simulated external link is extracted from the attachment content for browser handling.",
      "medium"
    );
    pushStep(
      timeline,
      attachmentId,
      "redirect",
      "Browser redirect simulated",
      "The sandbox predicts a redirect toward a credential harvesting or verification page.",
      "high"
    );
  }

  if (hasMacro || /macro|vba|script|powershell|exec/i.test(lowerNotes) || /^(js|exe|docm|xlsm)$/i.test(fileType)) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "execution",
      "Execution-like behavior",
      "Simulated runtime suggests the file would attempt code execution or scripted actions when opened.",
      "high",
      "execution"
    );
    pushStep(
      timeline,
      attachmentId,
      "execution",
      "Execution simulated",
      "The sandbox flags script or macro initiation without executing any real payload.",
      "high"
    );
  }

  if (hasArchive || hasObfuscation || /download|payload|dropper|install/i.test(lowerNotes) || /^(zip|rar|7z|exe)$/i.test(fileType)) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "payload",
      "Payload staging attempt",
      "Simulated behavior suggests the attachment could unpack or fetch a follow-on payload.",
      hasObfuscation ? "critical" : "high",
      "payload-download"
    );
    pushStep(
      timeline,
      attachmentId,
      "payload",
      "Additional payload simulated",
      "A follow-on download or unpack action is predicted from the attachment's structure.",
      hasObfuscation ? "critical" : "high"
    );
  }

  if (/network|callback|beacon|connect|remote/i.test(lowerNotes) || /^(html|js|exe)$/i.test(fileType)) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "network",
      "Suspicious network call",
      "The sandbox simulation expects outbound communication to a remote host after opening the file.",
      "high",
      "network-call"
    );
    pushStep(
      timeline,
      attachmentId,
      "network",
      "Outbound call simulated",
      "The runtime model predicts remote communication after the file is opened.",
      "high"
    );
  }

  if (/login|password|credential|verify account|bank/i.test(lowerNotes) || hasEmbeddedLink) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "credentials",
      "Credential capture flow",
      "The simulated user journey points to a fake login or account verification form.",
      "critical",
      "credential-capture"
    );
    pushStep(
      timeline,
      attachmentId,
      "credentials",
      "Phishing page detected",
      "A fake login experience is simulated as the likely end state of opening the attachment.",
      "critical"
    );
  }

  if (hasMacro || /registry|startup|scheduled task|modify system/i.test(lowerNotes) || /^(exe|js|docm|xlsm)$/i.test(fileType)) {
    pushDynamic(
      dynamicIndicators,
      attachmentId,
      "system",
      "System modification attempt",
      "The sandbox model predicts persistence or system configuration changes after execution.",
      "high",
      "system-modification"
    );
    pushStep(
      timeline,
      attachmentId,
      "system",
      "System changes simulated",
      "Persistence or configuration changes are flagged in the simulated runtime path.",
      "high"
    );
  }

  if (dynamicIndicators.length === 0) {
    pushStep(
      timeline,
      attachmentId,
      "benign",
      "No dangerous runtime behavior simulated",
      "The demo sandbox did not predict dangerous follow-on behavior beyond static risk.",
      "low"
    );
  }

  const dynamicRiskScore = Math.min(
    100,
    dynamicIndicators.reduce((total, indicator) => {
      const weight =
        indicator.severity === "critical" ? 22 : indicator.severity === "high" ? 16 : indicator.severity === "medium" ? 10 : 5;
      return total + weight;
    }, dynamicIndicators.length > 0 ? 8 : 0)
  );

  return {
    dynamicIndicators,
    timeline,
    dynamicRiskScore,
  };
}
