package com.anonymous.cybershieldai

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import android.text.TextUtils
import android.view.accessibility.AccessibilityManager
import androidx.core.content.ContextCompat
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

class CyberShieldAndroidModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  init {
    CyberShieldEventEmitter.registerContext(reactContext)
  }

  override fun getName(): String = "CyberShieldAndroidModule"

  @ReactMethod
  fun getNotificationAccessStatus(promise: Promise) {
    promise.resolve(isNotificationServiceEnabled())
  }

  @ReactMethod
  fun getSmsAccessStatus(promise: Promise) {
    val granted =
      ContextCompat.checkSelfPermission(reactContext, Manifest.permission.RECEIVE_SMS) ==
        PackageManager.PERMISSION_GRANTED
    promise.resolve(granted)
  }

  @ReactMethod
  fun getAccessibilityAccessStatus(promise: Promise) {
    promise.resolve(isAccessibilityServiceEnabled())
  }

  @ReactMethod
  fun openNotificationAccessSettings(promise: Promise) {
    val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    reactContext.startActivity(intent)
    promise.resolve(null)
  }

  @ReactMethod
  fun openAccessibilitySettings(promise: Promise) {
    val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    reactContext.startActivity(intent)
    promise.resolve(null)
  }

  @ReactMethod
  fun startRealtimeProtection(promise: Promise) {
    promise.resolve(true)
  }

  @ReactMethod
  fun stopRealtimeProtection(promise: Promise) {
    promise.resolve(true)
  }

  @ReactMethod
  fun addListener(eventName: String) {
  }

  @ReactMethod
  fun removeListeners(count: Int) {
  }

  private fun isNotificationServiceEnabled(): Boolean {
    val expectedComponentName = ComponentName(reactContext, CyberShieldNotificationListenerService::class.java)
    val enabledListeners = Settings.Secure.getString(
      reactContext.contentResolver,
      "enabled_notification_listeners"
    )
    return !enabledListeners.isNullOrBlank() &&
      enabledListeners.contains(expectedComponentName.flattenToString())
  }

  private fun isAccessibilityServiceEnabled(): Boolean {
    val accessibilityManager =
      reactContext.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    val enabledServices = accessibilityManager.getEnabledAccessibilityServiceList(
      AccessibilityServiceInfo.FEEDBACK_ALL_MASK
    )
    val expectedId = "${reactContext.packageName}/${CyberShieldAccessibilityService::class.java.name}"
    return enabledServices.any { TextUtils.equals(it.resolveInfo.serviceInfo.packageName + "/" + it.resolveInfo.serviceInfo.name, expectedId) }
  }
}

