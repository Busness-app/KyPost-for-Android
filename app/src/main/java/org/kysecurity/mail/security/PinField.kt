package org.kysecurity.mail.security

import android.widget.EditText
import java.util.Arrays

/** Clearing the Editable cannot scrub the TextView/IME copies, only the ones this app makes. */
internal fun EditText.consumePin(): CharArray {
    val editable = text
    val pin = CharArray(editable.length)
    editable.getChars(0, editable.length, pin, 0)
    editable.clear()
    return pin
}

internal suspend fun <T> CharArray.usePin(block: suspend (CharArray) -> T): T =
    try {
        block(this)
    } finally {
        Arrays.fill(this, ' ')
    }
