package org.kysecurity.mail.security

/** Whether a tapped attachment should be viewed ephemerally (no disk write at all) or saved to
 *  the public Downloads collection — see "Attachments" under Hostile Location Protection in the
 *  2026-07-22 security-hardening spec. */
enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }

/**
 * What a *tap* on an attachment does. Always an ephemeral view, whatever the protection setting.
 *
 * Saving is still available, as [AttachmentAction.SAVE_TO_DOWNLOADS], but it is now a deliberate
 * second action with its own confirmation rather than the meaning of a single tap. The protection
 * setting decides whether saving is *offered at all*, which is the decision it was always for.
 */
fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =
    AttachmentAction.VIEW_EPHEMERAL

/** Whether "Save to Downloads" may be offered. Under Hostile Location Protection the contract is
 *  that attachment plaintext never touches disk, so it may not. */
fun attachmentSaveOffered(hostileLocationProtectionEnabled: Boolean): Boolean =
    !hostileLocationProtectionEnabled
