import { AIPhishingAssessment, IntelligenceInput } from "@/utils/advancedIntelligenceTypes";

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function grammarPolishScore(text: string) {
  const sentences = text
    .split(/[.!?]+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
  if (sentences.length < 2) {
    return 0;
  }
  const consistentlyCapitalized = sentences.filter((sentence) => /^[A-Z]/.test(sentence)).length;
  return consistentlyCapitalized / sentences.length;
}

export function detectAIPhishing(input: IntelligenceInput): AIPhishingAssessment | null {
  const text = (
    ("raw_text" in input.result ? input.result.raw_text : "") ||
    ("preview" in input.result ? input.result.preview : "") ||
    input.result.ai_summary ||
    ""
  ).trim();

  if (!text) {
    return null;
  }

  let score = 12;
  const signals: string[] = [];

  if (/^dear (customer|user|member|valued customer)/i.test(text)) {
    score += 22;
    signals.push("generic greeting");
  }
  if (/kindly|please be informed|we regret to inform|immediate attention|urgent action/i.test(text)) {
    score += 14;
    signals.push("template language");
  }
  if (!/\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b/.test(text.replace(/^Dear Customer/i, ""))) {
    score += 12;
    signals.push("lack of personalization");
  }
  if (grammarPolishScore(text) >= 0.8) {
    score += 12;
    signals.push("overly polished grammar");
  }
  if (text.length >= 120 && !/[!]{2,}|[?]{2,}|[A-Z]{5,}/.test(text)) {
    score += 10;
    signals.push("consistent neutral tone");
  }
  if (/verify your account|confirm your identity|secure your profile|update your records/i.test(text)) {
    score += 16;
    signals.push("reusable phishing template phrasing");
  }
  if (input.result.provider_used) {
    score += 6;
    signals.push("AI-reviewed language consistency");
  }

  return {
    aiGeneratedLikelihood: clamp(score),
    signals: signals.slice(0, 5),
    rationale:
      signals.length > 0
        ? "The message style resembles polished, reusable phishing copy often seen in AI-assisted scams."
        : "The current text does not strongly resemble polished AI-generated phishing language.",
  };
}
