package org.kysecurity.mail.pgp

/** A disposable ed25519 key generated with `gpg --quick-generate-key`, purely as a test fixture.
 *  [FINGERPRINT] is gpg's own reported fingerprint for it, so tests built on this pair confirm
 *  [PgpFingerprint.compute] agrees with a real, independent OpenPGP implementation rather than just
 *  round-tripping through the same Bouncy Castle code it is built on. Shared by every test that
 *  needs a genuinely parseable armored key. */
internal object TestPgpKey {
    const val FINGERPRINT = "164D 5B83 4E7F E927 2DC7 293B 6D78 ABF3 D917 9534"

    val ARMORED = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        mDMEalxKSBYJKwYBBAHaRw8BAQdAaLBvayt/AqeBFCxDOrvjb36gwol5tI+JU+6p
        vOR9sTO0KVBncEZpbmdlcnByaW50VGVzdCA8dGVzdEBleGFtcGxlLmludmFsaWQ+
        iJAEExYKADgWIQQWTVuDTn/pJy3HKTtteKvz2ReVNAUCalxKSAIbAwULCQgHAgYV
        CgkICwIEFgIDAQIeAQIXgAAKCRBteKvz2ReVNAUoAQCi9uhyZCB8aY/iupXHv0j9
        3HOkEbVmB1B/xRn+xdcu4gEAn2JbiIts/RVYYk8RXwTVp3zrksdrTZ1zBiBUC/ZH
        TQ8=
        =+uqe
        -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()
}
