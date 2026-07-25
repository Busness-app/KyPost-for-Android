package com.urlxl.mail.data

import com.urlxl.mail.Email
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val mapperJson = Json { ignoreUnknownKeys = true }

fun EmailEntity.toUiEmail(): Email = Email(
    id = messageId,
    subject = subject,
    sender = sender,
    preview = preview,
    keywords = runCatching { mapperJson.decodeFromString<List<String>>(keywordsJson) }.getOrDefault(emptyList()).toSet(),
    folder = folder,
    sentTo = sentTo,
    cc = cc,
    bcc = bcc,
    body = body,
    label = label,
    status = status,
    atUtc = atUtc,
    hasAttachments = hasAttachments,
    sourceMode = sourceMode,
    pgpEncrypted = pgpEncrypted,
    pgpSigned = pgpSigned,
    pgpVerified = pgpVerified,
    pgpSignerFingerprint = pgpSignerFingerprint,
    pgpDecryptError = pgpDecryptError,
)

fun Email.toEntity(folder: String, sourceMode: String): EmailEntity = EmailEntity(
    messageId = id,
    folder = folder,
    sender = sender,
    sentTo = sentTo,
    cc = cc,
    bcc = bcc,
    subject = subject,
    preview = preview,
    body = body,
    label = label,
    keywordsJson = mapperJson.encodeToString(keywords.toList()),
    status = status,
    atUtc = atUtc,
    hasAttachments = hasAttachments,
    sourceMode = sourceMode,
    pgpEncrypted = pgpEncrypted,
    pgpSigned = pgpSigned,
    pgpVerified = pgpVerified,
    pgpSignerFingerprint = pgpSignerFingerprint,
    pgpDecryptError = pgpDecryptError,
)
