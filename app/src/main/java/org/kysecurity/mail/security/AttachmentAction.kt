package org.kysecurity.mail.security

/** A tap always views ephemerally; saving is a separate, separately confirmed action. */
enum class AttachmentAction { VIEW_EPHEMERAL, SAVE_TO_DOWNLOADS }

/** Whether "Save to Downloads" may be offered. Under Hostile Location Protection the contract is
 *  that attachment plaintext never touches disk, so it may not. */
fun attachmentSaveOffered(hostileLocationProtectionEnabled: Boolean): Boolean =
    !hostileLocationProtectionEnabled
