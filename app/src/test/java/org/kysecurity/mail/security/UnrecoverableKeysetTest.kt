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
     *  A Keystore that will not answer is [MasterKeyState.UNKNOWN], and nothing is destroyed on
     *  it. That is also the only state this overload can reach, since there is no AndroidKeyStore
     *  on the JVM; the other two are driven explicitly below, and `EncryptedPrefsResetTest`
     *  exercises the real Keystore on a device. */
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

    /** A Keystore that cannot even be consulted is the case that shipped a device wipe. Whatever
     *  Tink said, and however permanent the wording sounds, the answer is "leave it alone". */
    @Test
    fun anUnreachableKeystoreDestroysNothingWhateverTheFailureLookedLike() {
        for (failure in ambiguousFailures) {
            assertFalse("$failure", isUnrecoverableKeyset(failure, MasterKeyState.UNKNOWN))
        }
    }

    /** THE CI FAILURE THIS OVERLOAD WAS INTRODUCED FOR. Tink reports a keyset carrying no key
     *  material as a bare `GeneralSecurityException("empty keyset")`, and one whose ciphertext no
     *  longer verifies as an unattributed decrypt failure — never as a parse failure. Under a
     *  master key just proven to encrypt and decrypt, neither can be the Keystore, so both are the
     *  stored bytes; without this row the store stayed unopenable and the app blocked forever. */
    @Test
    fun aWorkingMasterKeyMakesACryptoFailureProofAgainstTheStoredKeyset() {
        for (failure in ambiguousFailures) {
            assertTrue("$failure", isUnrecoverableKeyset(failure, MasterKeyState.WORKING))
        }
    }

    /** ...and the same working key must NOT convict the disk. An IOException with no crypto
     *  failure under it is a full partition or an unmounted one, and the keyset is still there. */
    @Test
    fun aWorkingMasterKeyStillDoesNotConvictTheDisk() {
        assertFalse(isUnrecoverableKeyset(IOException("No space left on device"), MasterKeyState.WORKING))
        assertFalse(isUnrecoverableKeyset(java.io.FileNotFoundException("not mounted"), MasterKeyState.WORKING))
        assertFalse(isUnrecoverableKeyset(IllegalStateException("something else"), MasterKeyState.WORKING))
    }

    /** An alias the Keystore confirms is gone can never decrypt anything again, crypto failure or
     *  not — there is nothing left to recover with. */
    @Test
    fun anAbsentAliasIsProofOnItsOwn() {
        assertTrue(isUnrecoverableKeyset(IOException("No space left on device"), MasterKeyState.ABSENT))
        assertTrue(isUnrecoverableKeyset(GeneralSecurityException("gone"), MasterKeyState.ABSENT))
    }

    /** Everything Tink hands back that says nothing on its own about which layer broke. */
    private val ambiguousFailures = listOf(
        GeneralSecurityException("empty keyset"),
        GeneralSecurityException("invalid keyset, corrupted key material"),
        GeneralSecurityException("decryption failed"),
        GeneralSecurityException("key permanently invalidated"),
        java.security.KeyStoreException("keystore is busy"),
        IOException("could not read keyset", GeneralSecurityException("empty keyset")),
    )
}
