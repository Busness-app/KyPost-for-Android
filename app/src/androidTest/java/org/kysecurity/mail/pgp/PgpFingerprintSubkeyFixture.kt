package org.kysecurity.mail.pgp

/** Disposable ed25519 primary + cv25519 subkey from gpg; FINGERPRINT is gpg's own value. */
internal object PgpFingerprintSubkeyFixture {
    const val FINGERPRINT = "258E 286A 8DF6 5855 DF40 3110 9606 EA6B 6061 F145"

    val ARMORED = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        mDMEan02TRYJKwYBBAHaRw8BAQdAZkjbBScLBLZ2rkaAX2X0Dq8cbOFVhg/VK5yc
        NUqbmvu0I1N1YmtleVByb2JlIDxwcm9iZUBleGFtcGxlLmludmFsaWQ+iJAEExYK
        ADgWIQQljihqjfZYVd9AMRCWBuprYGHxRQUCan02TQIbAQULCQgHAgYVCgkICwIE
        FgIDAQIeAQIXgAAKCRCWBuprYGHxRcDfAQDF3hc0O6nL3RYrnRiFgsRRkB6/7BRR
        TLKcCC+qJ9K47AEA5kE6FPCZaPLmun/i5bPNBPb1LQ0Z0On2nG1xaanXZgC4OARq
        fTZNEgorBgEEAZdVAQUBAQdAMQ8yZ+l4RODjmSjaMN+K9r3w1HSceqU9Bfw4MPxt
        ln4DAQgHiHgEGBYKACAWIQQljihqjfZYVd9AMRCWBuprYGHxRQUCan02TQIbDAAK
        CRCWBuprYGHxRUYmAQDPTnzFTUjsNvG5gRMu1oKcwllIWdsHpErEubmJLsG3NgD+
        LOTYXB06LrOKi5v3xX/RQOOyoWPdXd9zSJjI/MRDlAg=
        =oC88
        -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()
}
