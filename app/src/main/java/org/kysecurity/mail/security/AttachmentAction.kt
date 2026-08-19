package org.kysecurity.mail.security

enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }

/** A tap always views ephemerally; saving is a separate, separately confirmed action. */
fun attachmentActionFor(hostileLocationProtectionEnabled: Boolean): AttachmentAction =
    AttachmentAction.VIEW_EPHEMERAL

/** Whether "Save to Downloads" may be offered. Under Hostile Location Protection the contract is
 *  that attachment plaintext never touches disk, so it may not. */
fun attachmentSaveOffered(hostileLocationProtectionEnabled: Boolean): Boolean =
    !hostileLocationProtectionEnabled
