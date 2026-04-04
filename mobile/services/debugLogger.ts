export const debugLogger = {
  info(scope: string, message: string, meta?: unknown) {
    console.log(`[CyberShield][${scope}] ${message}`, meta ?? "");
  },
  warn(scope: string, message: string, meta?: unknown) {
    console.warn(`[CyberShield][${scope}] ${message}`, meta ?? "");
  },
  error(scope: string, message: string, meta?: unknown) {
    console.error(`[CyberShield][${scope}] ${message}`, meta ?? "");
  },
};

