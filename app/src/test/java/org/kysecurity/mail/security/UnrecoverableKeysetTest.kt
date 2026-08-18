package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * The predicate that decides whether an encrypted store is destroyed or a failure is propagated.
 *
 * Getting it wrong is expensive in both directions: too broad and a full disk deletes the user's
 * private key, too narrow and a store the app can never read again is never reset, so
 * `AppLockStore.isLockEnabled()` throws out of `SecurityGraph`'s constructor and out of
 * `LockedActivity.onCreate` — the app cannot start at all.
 *
 * It has been too narrow. Matching `javaClass.simpleName` against `"InvalidProtocolBufferException"`
 * missed every nested subclass, whose `simpleName` is its own. On API 31 the corrupted keyset
 * surfaces as `InvalidWireTypeException`, so the recovery never ran and seventeen other suites went
 * down with it. On API 34 the same corruption produced the base type and everything passed, which
 * is exactly how it stayed hidden.
 *
 * The stand-ins below mirror the shape of Tink's shaded types — a base class named
 * `InvalidProtocolBufferException` that extends `IOException`, with nested subclasses — because the
 * real ones live in a shaded package this code must not import.
 */
class UnrecoverableKeysetTest {

    private open class InvalidProtocolBufferException(message: String) : IOException(message) {
        class InvalidWireTypeException : InvalidProtocolBufferException("invalid wire type")
        class TruncatedMessageException : InvalidProtocolBufferException("truncated")
    }

    @Test
    fun theBaseProtobufFailureIsUnrecoverable() {
        assertTrue(isUnrecoverableKeyset(InvalidProtocolBufferException("bad tag")))
    }

    /** The API 31 case, and the regression this test exists for. */
    @Test
    fun protobufSubclassesAreUnrecoverableToo() {
        assertTrue(isUnrecoverableKeyset(InvalidProtocolBufferException.InvalidWireTypeException()))
        assertTrue(isUnrecoverableKeyset(InvalidProtocolBufferException.TruncatedMessageException()))
    }

    @Test
    fun aWrappedSubclassIsFoundThroughTheCauseChain() {
        val wrapped = IOException(
            "could not read keyset",
            InvalidProtocolBufferException.InvalidWireTypeException(),
        )
        assertTrue(isUnrecoverableKeyset(wrapped))
    }

    @Test
    fun keyInvalidationIsUnrecoverable() {
        assertTrue(isUnrecoverableKeyset(GeneralSecurityException("key permanently invalidated")))
        assertTrue(isUnrecoverableKeyset(IOException("wrapped", GeneralSecurityException("gone"))))
    }

    /**
     * The other direction, which matters more: a transient storage failure must NOT be treated as
     * an unreadable keyset. Deleting a credential the user cannot get back is not an acceptable
     * response to the disk being full for a second.
     */
    @Test
    fun transientStorageFailuresAreRecoverable() {
        assertFalse(isUnrecoverableKeyset(IOException("No space left on device")))
        assertFalse(isUnrecoverableKeyset(java.io.FileNotFoundException("not mounted yet")))
        assertFalse(isUnrecoverableKeyset(IllegalStateException("something else entirely")))
    }

    /** A cause chain that loops must not hang the predicate. */
    @Test
    fun aSelfReferencingCauseTerminates() {
        val looping = object : IOException("loops") {
            override val cause: Throwable get() = this
        }
        assertFalse(isUnrecoverableKeyset(looping))
    }
}
