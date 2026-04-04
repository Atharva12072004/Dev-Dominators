export type NativeFeatureSupport =
  | "fully_feasible_android"
  | "partially_feasible_android"
  | "fallback_only"
  | "limited_ios"
  | "not_feasible_ios";

export interface NativeCapabilityDescriptor {
  key: string;
  android: NativeFeatureSupport;
  ios: NativeFeatureSupport;
  notes: string;
}

