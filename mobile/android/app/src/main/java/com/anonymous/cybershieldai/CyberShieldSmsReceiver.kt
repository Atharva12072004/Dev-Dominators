package com.anonymous.cybershieldai

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import java.time.Instant

class CyberShieldSmsReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
      return
    }

    val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
    if (messages.isEmpty()) {
      return
    }

    val body = messages.joinToString(separator = "") { it.messageBody ?: "" }.trim()
    if (body.isBlank()) {
      return
    }

    val sender = messages.firstOrNull()?.displayOriginatingAddress ?: "unknown"
    Log.d("CyberShieldAI", "SMS received from $sender: ${body.take(120)}")
    CyberShieldEventEmitter.emitRealtimeEvent(
      eventName = "smsReceived",
      sourceType = "sms",
      sourceApp = sender,
      text = body,
      preview = body.take(180),
      timestamp = Instant.now().toString(),
      externalId = "sms:${sender}:${messages.firstOrNull()?.timestampMillis ?: System.currentTimeMillis()}"
    )
  }
}
