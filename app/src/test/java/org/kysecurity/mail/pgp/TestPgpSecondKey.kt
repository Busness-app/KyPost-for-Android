package org.kysecurity.mail.pgp

/**
 * A second disposable, passphrase-free ed25519/cv25519 pair produced by `gpg`, so multi-recipient
 * tests can prove that *each* recipient can open the message rather than just the first.
 *
 * [TestPgpKey] cannot serve this purpose: it is a signing-only EdDSA key with no encryption subkey,
 * so it is not a usable encryption recipient at all.
 *
 * Never a real key. Regenerate with:
 * `gpg --batch --passphrase "" --quick-generate-key "SecondRecipientTest <second@example.invalid>" default default 0`
 */
internal object TestPgpSecondKey {

    val ARMORED_PUBLIC = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        
        mDMEantA0hYJKwYBBAHaRw8BAQdAkYTGprf6M3BnWSBhudzXPtE0uEfRdKFL/DrG
        8Uj4Bum0LFNlY29uZFJlY2lwaWVudFRlc3QgPHNlY29uZEBleGFtcGxlLmludmFs
        aWQ+iJAEExYKADgWIQTkVen3btUyBP9TPL1qixELvdckggUCantA0gIbAwULCQgH
        AgYVCgkICwIEFgIDAQIeAQIXgAAKCRBqixELvdckgiXdAP9fqAqnHvUQ4UGX94q1
        nEHM4T8UEQjrlLueL8COMbrJNwEAq+olwbjNBFan2dVTdu4mbIFW92dBuHTVZiau
        r1sFGQO4OARqe0DSEgorBgEEAZdVAQUBAQdAktFPYvB1lD8Y0iq7P8yc1OHRej3o
        xVNQ8CF2E3Fd/HkDAQgHiHgEGBYKACAWIQTkVen3btUyBP9TPL1qixELvdckggUC
        antA0gIbDAAKCRBqixELvdckglHSAQCt/vydza9tds8pnMSM2WoCJbcDRxtxtbTy
        OLkwshHnzAEAvtPtX9vBbz3DUWABq8kOHK2BlzJluGl9ycgEJMC8Xwk=
        =2K/C
        -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()

    val ARMORED_PRIVATE = """
        -----BEGIN PGP PRIVATE KEY BLOCK-----
        
        lFgEantA0hYJKwYBBAHaRw8BAQdAkYTGprf6M3BnWSBhudzXPtE0uEfRdKFL/DrG
        8Uj4BukAAP4n3F3oLkRieY9rq0ksZ5AlVSBVt+A4zfd9a0fc7apmYxCRtCxTZWNv
        bmRSZWNpcGllbnRUZXN0IDxzZWNvbmRAZXhhbXBsZS5pbnZhbGlkPoiQBBMWCgA4
        FiEE5FXp927VMgT/Uzy9aosRC73XJIIFAmp7QNICGwMFCwkIBwIGFQoJCAsCBBYC
        AwECHgECF4AACgkQaosRC73XJIIl3QD/X6gKpx71EOFBl/eKtZxBzOE/FBEI65S7
        ni/AjjG6yTcBAKvqJcG4zQRWp9nVU3buJmyBVvdnQbh01WYmrq9bBRkDnF0EantA
        0hIKKwYBBAGXVQEFAQEHQJLRT2LwdZQ/GNIquz/MnNTh0Xo96MVTUPAhdhNxXfx5
        AwEIBwAA/0bSqp9/+ij+NzbykVNngdxHdY0YbK9wUcLCJCA8iO1gERyIeAQYFgoA
        IBYhBORV6fdu1TIE/1M8vWqLEQu91ySCBQJqe0DSAhsMAAoJEGqLEQu91ySCUdIB
        AK3+/J3Nr212zymcxIzZagIltwNHG3G1tPI4uTCyEefMAQC+0+1f28FvPcNRYAGr
        yQ4crYGXMmW4aX3JyAQkwLxfCQ==
        =ysk8
        -----END PGP PRIVATE KEY BLOCK-----
    """.trimIndent()
}
