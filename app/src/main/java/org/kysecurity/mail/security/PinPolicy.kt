package org.kysecurity.mail.security

/** Minimum 8, not 6: the Keystore pepper forces on-device guessing, but 10^6 is only hours. */
object PinPolicy {
    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 12

    /** Runs of any length are caught by [isRun]; this covers repeat and date families it misses. */
    private val WEAK_PINS = setOf(
        // Repeating pairs and quads.
        "12121212", "21212121", "11223344", "44332211", "12341234", "43214321",
        "10101010", "01010101", "12002100", "13131313", "69696969",
        // Keypad walks.
        "14725836", "36925814", "15935780", "78945612", "95135780",
        // Dates people pick: 19xx/20xx years doubled, and common birth years.
        "19701970", "19801980", "19901990", "20002000", "20102010", "20202020",
        "01011990", "01012000", "12345678", "87654321",
    )

    sealed class Result {
        object Valid : Result()
        object TooShort : Result()
        object TooLong : Result()
        object NotNumeric : Result()
        object TooCommon : Result()
    }

    fun validate(pin: CharArray): Result = when {
        pin.size < MIN_LENGTH -> Result.TooShort
        pin.size > MAX_LENGTH -> Result.TooLong
        !pin.all { it.isDigit() } -> Result.NotNumeric
        pin.concatToString() in WEAK_PINS -> Result.TooCommon
        isRun(pin) -> Result.TooCommon
        else -> Result.Valid
    }

    private fun isRun(pin: CharArray): Boolean {
        val deltas = pin.toList().zipWithNext { a, b -> b - a }
        return deltas.all { it == 1 } || deltas.all { it == -1 } || deltas.all { it == 0 }
    }
}
