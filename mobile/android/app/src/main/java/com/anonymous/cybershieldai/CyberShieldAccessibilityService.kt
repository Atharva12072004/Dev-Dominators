package com.anonymous.cybershieldai

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent

class CyberShieldAccessibilityService : AccessibilityService() {
  override fun onAccessibilityEvent(event: AccessibilityEvent?) {
    // Android-first advanced path:
    // This service is intentionally minimal in the MVP. It exists so the app can detect
    // whether accessibility-based protection is enabled and expand into link detection later.
  }

  override fun onInterrupt() {
  }
}

