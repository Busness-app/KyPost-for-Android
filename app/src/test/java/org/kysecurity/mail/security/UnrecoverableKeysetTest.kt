package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.GeneralSecurityException

/** The stand-ins below mirror Tink's shaded types, which this code must not import. */
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

    @Test
    fun transientStorageFailuresAreRecoverable() {
        assertFalse(isUnrecoverableKeyset(IOException("No space left on device")))
        assertFalse(isUnrecoverableKeyset(java.io.FileNotFoundException("not mounted yet")))
        assertFalse(isUnrecoverableKeyset(IllegalStateException("something else entirely")))
    }

    @Test
    fun aSelfReferencingCauseTerminates() {
        val looping = object : IOException("loops") {
            override val cause: Throwable get() = this
        }
        assertFalse(isUnrecoverableKeyset(looping))
    }
}
