package org.kysecurity.mail.security

/** Whether a tapped attachment should be viewed ephemerally (no disk write at all) or saved to
 *  the public Downloads collection — see "Attachments" under Hostile Location Protection in the
 *  2026-07-22 security-hardening spec. */
enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }

fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =
    if (hostileLocationProtectionEnabled) AttachmentAction.VIEW_EPHEMERAL else AttachmentAction.SAVE_TO_DOWNLOADS
