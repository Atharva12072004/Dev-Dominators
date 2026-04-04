package com.anonymous.cybershieldai

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import java.time.Instant

class CyberShieldNotificationListenerService : NotificationListenerService() {
  private val gmailPackageName = "com.google.android.gm"
  private val smsPackageNames = setOf(
    "com.google.android.apps.messaging",
    "com.android.mms",
    "com.samsung.android.messaging",
    "com.miui.mms",
    "com.microsoft.android.smsorganizer",
    "com.truecaller"
  )
  private val granularChatPackages = setOf(
    "com.whatsapp",
    "com.instagram.android",
    "org.telegram.messenger",
    *smsPackageNames.toTypedArray()
  )
  private val gmailSystemPatterns = listOf(
    Regex("\\bsyncing\\b", RegexOption.IGNORE_CASE),
    Regex("\\bsyncing new email\\b", RegexOption.IGNORE_CASE),
    Regex("\\bchecking mail\\b", RegexOption.IGNORE_CASE),
    Regex("\\bsending\\b", RegexOption.IGNORE_CASE),
    Regex("\\bloading\\b", RegexOption.IGNORE_CASE),
    Regex("\\bupdating\\b", RegexOption.IGNORE_CASE),
    Regex("\\bdownloading\\b", RegexOption.IGNORE_CASE),
    Regex("\\bprogress\\b", RegexOption.IGNORE_CASE)
  )
  private val groupedPatterns = listOf(
    Regex("^\\d+\\s+messages?$", RegexOption.IGNORE_CASE),
    Regex("^\\d+\\s+new messages?$", RegexOption.IGNORE_CASE),
    Regex("^\\d+\\s+messages?\\s+from\\s+.+$", RegexOption.IGNORE_CASE),
    Regex("^\\d+\\s+new messages?\\s+from\\s+.+$", RegexOption.IGNORE_CASE),
    Regex("^\\d+\\s+chats?$", RegexOption.IGNORE_CASE),
    Regex("^\\d+\\s+new notifications?$", RegexOption.IGNORE_CASE)
  )
  private val smsSystemPatterns = listOf(
    Regex("\\bdoing work in the background\\b", RegexOption.IGNORE_CASE),
    Regex("\\bworking in the background\\b", RegexOption.IGNORE_CASE),
    Regex("\\bchat features\\b", RegexOption.IGNORE_CASE),
    Regex("\\bsyncing\\b", RegexOption.IGNORE_CASE),
    Regex("\\bbacking up\\b", RegexOption.IGNORE_CASE),
    Regex("\\bconnecting\\b", RegexOption.IGNORE_CASE)
  )

  override fun onNotificationPosted(sbn: StatusBarNotification) {
    val extras = sbn.notification.extras ?: return
    val title = extras.getCharSequence("android.title")?.toString().orEmpty()
    val text = extras.getCharSequence("android.text")?.toString().orEmpty()
    val bigText = extras.getCharSequence("android.bigText")?.toString().orEmpty()
    val subText = extras.getCharSequence("android.subText")?.toString().orEmpty()
    val summaryText = extras.getCharSequence("android.summaryText")?.toString().orEmpty()
    val infoText = extras.getCharSequence("android.infoText")?.toString().orEmpty()
    val tickerText = sbn.notification.tickerText?.toString().orEmpty()
    val category = sbn.notification.category.orEmpty()
    val channelId = sbn.notification.channelId.orEmpty()
    val groupKey = sbn.notification.group.orEmpty()
    val lines = extras.getCharSequenceArray("android.textLines")
      ?.mapNotNull { it?.toString() }
      ?.filter { it.isNotBlank() }
      .orEmpty()

    val isGroupSummaryFlag =
      (sbn.notification.flags and Notification.FLAG_GROUP_SUMMARY) == Notification.FLAG_GROUP_SUMMARY

    if (sbn.packageName == gmailPackageName) {
      val gmailNotificationBlob = listOf(title, text, bigText, subText, summaryText, infoText, tickerText)
        .filter { it.isNotBlank() }
        .joinToString(" ")
      val gmailSystemNotification =
        category.equals(Notification.CATEGORY_PROGRESS, ignoreCase = true) ||
        channelId.contains("sync", ignoreCase = true) ||
        channelId.contains("service", ignoreCase = true) ||
        gmailSystemPatterns.any { it.containsMatchIn(gmailNotificationBlob) }

      Log.d(
        "CyberShieldAI",
        "Gmail notification audit key=${sbn.key} id=${sbn.id} tag=${sbn.tag} title=${title.take(120)} text=${text.take(160)} bigText=${bigText.take(160)} subText=${subText.take(120)} category=$category channelId=$channelId groupKey=$groupKey isGroupSummary=$isGroupSummaryFlag postTime=${sbn.postTime} gmailSystemNotification=$gmailSystemNotification"
      )

      if (gmailSystemNotification) {
        Log.i(
          "CyberShieldAI",
          "Skipping Gmail system notification from phishing analysis. key=${sbn.key} title=${title.take(120)} text=${text.take(160)}"
        )
        return
      }

      Log.i(
        "CyberShieldAI",
        "Skipping Gmail Android notification content scan. Gmail API is the source of truth for email phishing detection. key=${sbn.key}"
      )
      return
    }

    val notificationBlob = listOf(title, text, bigText, subText, summaryText, infoText, tickerText)
      .filter { it.isNotBlank() }
      .joinToString(" ")
    val isServiceLikeNotification =
      category.equals(Notification.CATEGORY_PROGRESS, ignoreCase = true) ||
      category.equals(Notification.CATEGORY_SERVICE, ignoreCase = true) ||
      channelId.contains("service", ignoreCase = true) ||
      channelId.contains("background", ignoreCase = true) ||
      channelId.contains("sync", ignoreCase = true)

    if (smsPackageNames.contains(sbn.packageName)) {
      val isSmsSystemNotification =
        isServiceLikeNotification || smsSystemPatterns.any { it.containsMatchIn(notificationBlob) }
      if (isSmsSystemNotification) {
        Log.i(
          "CyberShieldAI",
          "Skipping SMS app system notification from phishing analysis. key=${sbn.key} title=${title.take(120)} text=${text.take(160)} category=$category channelId=$channelId"
        )
        return
      }
    }

    val candidateParts = uniqueMeaningfulParts(
      title,
      subText,
      summaryText,
      infoText,
      bigText.ifBlank { text },
      tickerText,
      lines.joinToString(" ")
    )
    val candidateMessage = candidateParts.joinToString(" ")
      .trim()

    if (candidateMessage.isBlank()) {
      return
    }

    val summaryCandidate = listOf(text, title, subText, summaryText, infoText)
      .firstOrNull { it.isNotBlank() }
      .orEmpty()
    val isSummaryLikeText = groupedPatterns.any { it.matches(summaryCandidate.trim()) }
    val isGrouped = isGroupSummaryFlag || isSummaryLikeText

    if (isGrouped && lines.isNotEmpty() && granularChatPackages.contains(sbn.packageName)) {
      Log.i(
        "CyberShieldAI",
        "Skipping grouped summary notification for ${sbn.packageName} because detailed message lines are available."
      )
      return
    }

    val message = if (isGrouped) summaryCandidate.ifBlank { candidateMessage } else candidateMessage

    Log.d(
      "CyberShieldAI",
      "Notification received from ${sbn.packageName}: key=${sbn.key} grouped=$isGrouped category=$category channelId=$channelId groupKey=$groupKey message=${message.take(120)}"
    )

    CyberShieldEventEmitter.emitRealtimeEvent(
      eventName = "notificationReceived",
      sourceType = "notification",
      sourceApp = sbn.packageName,
      text = message,
      preview = message.take(180),
      timestamp = Instant.now().toString(),
      externalId = "notification:${sbn.packageName}:${sbn.key}:${sbn.postTime}:${message.hashCode()}",
      isGrouped = isGrouped,
      contentAvailable = !isGrouped
    )
  }

  private fun uniqueMeaningfulParts(vararg parts: String): List<String> {
    val result = mutableListOf<String>()
    val normalizedSeen = mutableSetOf<String>()

    parts.forEach { raw ->
      val value = raw.trim()
      if (value.isBlank()) {
        return@forEach
      }

      val normalized = value.lowercase()
      if (normalizedSeen.contains(normalized)) {
        return@forEach
      }

      val isContained = result.any { existing ->
        val existingNormalized = existing.lowercase()
        existingNormalized.contains(normalized) || normalized.contains(existingNormalized)
      }
      if (isContained) {
        return@forEach
      }

      normalizedSeen.add(normalized)
      result.add(value)
    }

    return result
  }
}
