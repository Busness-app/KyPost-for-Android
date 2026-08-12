package org.kysecurity.mail.security

/**
 * What counts as an acceptable app-lock PIN.
 *
 * The lock wipes after [LockoutPolicy.WIPE_THRESHOLD] wrong attempts, so an attacker gets ten
 * guesses — which makes the handful of PINs that everybody picks a real risk rather than a
 * theoretical one. [WEAK_PINS] are the sequences and repeats that dominate every published
 * leaked-PIN dataset; all ten free guesses would otherwise land inside this list.
 *
 * Length is a range, not the hardcoded 6 it used to be: a longer PIN costs the user nothing and
 * is the only lever they have against [CredentialCipher]'s keyspace.
 *
 * The minimum is 8, not 6, because iteration count cannot defend a small keyspace. Both the PIN
 * verifier and the wrapping key are peppered with a non-exportable Keystore HMAC, which forces any
 * brute force to run on-device — but 10^6 is still only minutes to an hour of Keystore calls,
 * whereas 10^8 is days. Existing shorter PINs keep working ([AppLockStore.verifyPin] does not
 * re-check length); the floor applies when setting or changing one.
 */
object PinPolicy {
    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 12

    /**
     * Sized for [MIN_LENGTH] and up. The list used to hold only 6-digit values, which the raised
     * minimum turned into dead code — `validate` checks length first, so every entry was already
     * rejected as TooShort before the set was consulted.
     *
     * Pure ascending/descending/constant runs of any length are caught by [isRun] instead, so this
     * covers the repeating- and dated-pattern families that a run check cannot see.
     */
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

    fun validate(pin: String): Result = when {
        pin.length < MIN_LENGTH -> Result.TooShort
        pin.length > MAX_LENGTH -> Result.TooLong
        !pin.all { it.isDigit() } -> Result.NotNumeric
        pin in WEAK_PINS -> Result.TooCommon
        isRun(pin) -> Result.TooCommon
        else -> Result.Valid
    }

    /** Catches the longer ascending/descending runs the fixed [WEAK_PINS] list can't enumerate
     *  once PINs may be up to [MAX_LENGTH] digits (e.g. "23456789"). */
    private fun isRun(pin: String): Boolean {
        val deltas = pin.zipWithNext { a, b -> b - a }
        return deltas.all { it == 1 } || deltas.all { it == -1 } || deltas.all { it == 0 }
    }
}
