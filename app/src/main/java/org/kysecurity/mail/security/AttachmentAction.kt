package org.kysecurity.mail.security

/** Whether a tapped attachment should be viewed ephemerally (no disk write at all) or saved to the
 *  public Downloads collection — see "Attachments" under Hostile Location Protection in the
 *  2026-07-22 security-hardening spec. */
enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }

/**
 * What a *tap* on an attachment does: always an ephemeral view, whatever the protection setting.
 * Saving is a deliberate second action with its own confirmation, not the meaning of a single tap.
 */
fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =
    AttachmentAction.VIEW_EPHEMERAL

/** Whether "Save to Downloads" may be offered. Under Hostile Location Protection the contract is
 *  that attachment plaintext never touches disk, so it may not. */
fun attachmentSaveOffered(hostileLocationProtectionEnabled: Boolean): Boolean =
    !hostileLocationProtectionEnabled
