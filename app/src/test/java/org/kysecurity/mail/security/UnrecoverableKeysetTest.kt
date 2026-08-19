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

    /** THE REGRESSION THIS FILE NOW EXISTS FOR, and it used to assert the opposite.
     *
     *  `isUnrecoverableKeyset` answering true for any [GeneralSecurityException] made it a
     *  tautology over its own caller: `openEncryptedPrefs` caught that exact type and deleted the
     *  store. `KeyStoreException`, `InvalidKeyException` and `ProviderException`-adjacent faults
     *  are all subclasses, AndroidKeyStore raises them transiently around boot, and
     *  [AppLockStore.tripwireBroken] turns a deleted app-lock store into a full device wipe. One
     *  busy Keymaster therefore erased every message on the device.
     *
     *  Destruction now needs proof: an unparseable keyset (above) or a master key alias the
     *  Keystore CONFIRMS is absent. The alias half cannot run on the JVM — there is no
     *  AndroidKeyStore here, so `masterKeyAliasPresent()` answers null, "could not ask", which is
     *  also the answer that must not destroy anything. `EncryptedPrefsResetTest` covers the
     *  alias-is-really-gone path on a device. */
    @Test
    fun aBareKeystoreFailureIsNotProofOfAnythingAndMustNotResetTheStore() {
        assertFalse(isUnrecoverableKeyset(GeneralSecurityException("key permanently invalidated")))
        assertFalse(isUnrecoverableKeyset(IOException("wrapped", GeneralSecurityException("gone"))))
        assertFalse(isUnrecoverableKeyset(java.security.KeyStoreException("keystore is busy")))
        assertFalse(
            isUnrecoverableKeyset(
                GeneralSecurityException(
                    "the master key android-keystore://_androidx_security_master_key_ exists but is unusable",
                ),
            ),
        )
    }

    /** A protobuf failure still wins even when it is buried under a Keystore one. */
    @Test
    fun proofSurvivesBeingWrappedInAKeystoreFailure() {
        assertTrue(
            isUnrecoverableKeyset(
                GeneralSecurityException("could not read", InvalidProtocolBufferException("bad tag")),
            ),
        )
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
