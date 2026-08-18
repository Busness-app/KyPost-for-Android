package org.kysecurity.mail.security

import android.widget.EditText
import java.util.Arrays

/**
 * Reads a PIN out of an [EditText] as a [CharArray] and clears the widget, so no `String` copy is
 * ever made.
 *
 * **Honest limit.** `Editable.clear()` truncates the widget's buffer, it does not scrub the
 * `char[]` behind it, and `TextView` keeps its own copies for layout and the IME. This removes the
 * copies this app makes; it cannot remove the ones the toolkit makes.
 */
internal fun EditText.consumePin(): CharArray {
    val editable = text
    val pin = CharArray(editable.length)
    editable.getChars(0, editable.length, pin, 0)
    editable.clear()
    return pin
}

/** Runs [block] with this PIN and zeroes it afterwards, whatever happens. */
internal suspend fun <T> CharArray.usePin(block: suspend (CharArray) -> T): T =
    try {
        block(this)
    } finally {
        Arrays.fill(this, ' ')
    }
