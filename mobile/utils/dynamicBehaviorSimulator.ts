import { AttackChainModel, SimulationEvent } from "@/utils/advancedIntelligenceTypes";

function colorSeverity(score: number) {
  if (score >= 70) {
    return "high" as const;
  }
  if (score >= 40) {
    return "medium" as const;
  }
  return "low" as const;
}

export function buildSimulationTimeline(chain: AttackChainModel): SimulationEvent[] {
  const [email, url, page, attachment] = chain.stages;
  return [
    {
      id: "simulation-email",
      stageKey: "email",
      title: "Lure opened",
      detail: `${email.status === "observed" ? "Observed" : "Simulated"} message lure is opened and trusted by the user.`,
      severity: colorSeverity(email.riskScore),
      icon: "mail",
    },
    {
      id: "simulation-link",
      stageKey: "url",
      title: "Embedded link triggered",
      detail: `${url.status === "observed" ? "Observed" : "Simulated"} redirect stage activates and moves the victim to an external destination.`,
      severity: colorSeverity(url.riskScore),
      icon: "link",
    },
    {
      id: "simulation-page",
      stageKey: "page",
      title: "Fake page loaded",
      detail: page.reason,
      severity: colorSeverity(page.riskScore),
      icon: "page",
    },
    {
      id: "simulation-credentials",
      stageKey: "page",
      title: "Credentials at risk",
      detail: "The victim is prompted to verify identity, sign in, or submit account details on the spoofed page.",
      severity: colorSeverity(Math.max(page.riskScore, url.riskScore)),
      icon: "lock",
    },
    {
      id: "simulation-payload",
      stageKey: "attachment",
      title: "Payload delivery attempt",
      detail:
        attachment.status === "observed"
          ? "The observed attachment or payload stage attempts the final delivery step."
          : "The final payload step is projected from the surrounding phishing flow.",
      severity: colorSeverity(attachment.riskScore),
      icon: attachment.status === "observed" ? "file" : "download",
    },
  ];
}
