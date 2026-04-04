package com.anonymous.cybershieldai

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.modules.core.DeviceEventManagerModule

object CyberShieldEventEmitter {
  private var reactApplicationContext: ReactApplicationContext? = null

  fun registerContext(context: ReactApplicationContext) {
    reactApplicationContext = context
  }

  fun emitRealtimeEvent(
    eventName: String,
    sourceType: String,
    sourceApp: String?,
    text: String,
    preview: String,
    timestamp: String,
    url: String? = null,
    externalId: String? = null,
    isGrouped: Boolean = false,
    contentAvailable: Boolean = true
  ) {
    val context = reactApplicationContext ?: return
    if (!context.hasActiveReactInstance()) {
      return
    }

    val payload = Arguments.createMap().apply {
      putString("source_type", sourceType)
      putString("source_app", sourceApp)
      putString("text", text)
      putString("preview", preview)
      putString("timestamp", timestamp)
      putString("url", url)
      putString("external_id", externalId)
      putBoolean("is_grouped", isGrouped)
      putBoolean("content_available", contentAvailable)
    }

    context
      .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
      .emit(eventName, payload)
  }
}
