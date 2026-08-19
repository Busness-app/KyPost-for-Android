package org.kysecurity.mail.pgp

/** A disposable, passphrase-free ed25519/cv25519 pair produced by `gpg`. Never a real key. */
internal object TestPgpPrivateKey {
    const val FINGERPRINT = "B30A CD64 E04B 8E1B 0379  A320 1D6B DF09 3FAD 1D11"

    /** Decrypts to exactly [EXPECTED_PLAINTEXT], signed by this same key. */
    const val EXPECTED_PLAINTEXT = "Hello from a real OpenPGP message.\n"

    val ARMORED_PRIVATE = """
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        lFgEanXKfhYJKwYBBAHaRw8BAQdA2rBAx6x5YF+ObBFQBXF+/2csH6f0qPdhr1ag
        i2N5i44AAQCcI5HtSSpyFdm1apjsdPP/oSSL46Btyofhqqe7izRdLhHitCpQZ3BE
        ZWNyeXB0b3JUZXN0IDxkZWNyeXB0QGV4YW1wbGUuaW52YWxpZD6IkAQTFgoAOBYh
        BLMKzWTgS44bA3mjIB1r3wk/rR0RBQJqdcp+AhsDBQsJCAcCBhUKCQgLAgQWAgMB
        Ah4BAheAAAoJEB1r3wk/rR0RGwIA/3DvjicIsZAjVJYjTdPCsYrYbycQ6JUmtKEF
        zHjImBW4AQDinfWUlzlme+nnz+Ba//Axhd1mG5jbCzvbuBqdaFO0D5xdBGp1yoMS
        CisGAQQBl1UBBQEBB0B1Hj+iZWHELCD46VW53zsWvt/gaj5zmPw8Q3zTJRNydAMB
        CAcAAP9MfEiba0BwC3gPCGNnBSpVT6ItjQ2pBmc/6tkGpZmyOAyriHgEGBYKACAW
        IQSzCs1k4EuOGwN5oyAda98JP60dEQUCanXKgwIbDAAKCRAda98JP60dEYRUAP9v
        3DLng8XERhSTtj1xklvWLmm+PNj9sIfTevTwFlR1EwEAqFTrsMbz8SfXD5x0TvHL
        KrCer7RkZAcLVY8rcoru9Ao=
        =56KP
        -----END PGP PRIVATE KEY BLOCK-----
    """.trimIndent()

    val ARMORED_MESSAGE = """
        -----BEGIN PGP MESSAGE-----

        hF4DIE6jVovIid0SAQdAGRbD7Tnkx/XA3SYjkTeY5cHfPkY7TzOUolNd9Yw38Uow
        miO6k16SpQCyugWrXGUE9kpTuVLw6+i8hHTfwCl9asERt0cNvp3MLklxjmiTGgwO
        0sAaAYGxUQZ4CukpripClMv7C5F4u8MSa+PfHFYViEL/sie2alUtWEYijrcmpr8r
        DHjuFCddDnUBT70SA4DDt+VxwQdS7R5FgY9vUf/WgdcjnP6DZpua6LjegMyjgJg3
        1fd58ly3ZLkPGe3LzNzvJ9YouCZsvKaPYMeb3sw+VQL9ZQaNzD23zkSrvkwc2gQ1
        NCo8FMo5AKlEZKUkoL9euSY/d09tCpZlJk/hjEkizqw67Bjk/jzirNTWaZsGsf9y
        U5qTeneHshndLGw3O6ncuPQBWHANvJU07E/TmgQ=
        =/cZ5
        -----END PGP MESSAGE-----
    """.trimIndent()

    /** This same key pair's public half only, exported separately with `gpg --export` (not derived
     *  from [ARMORED_PRIVATE]) — the signer key a production caller actually holds, since the
     *  address book only ever binds public keys. See [PgpDecryptorTest]. */
    val ARMORED_PUBLIC = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        mDMEanXKfhYJKwYBBAHaRw8BAQdA2rBAx6x5YF+ObBFQBXF+/2csH6f0qPdhr1ag
        i2N5i460KlBncERlY3J5cHRvclRlc3QgPGRlY3J5cHRAZXhhbXBsZS5pbnZhbGlk
        PoiQBBMWCgA4FiEEswrNZOBLjhsDeaMgHWvfCT+tHREFAmp1yn4CGwMFCwkIBwIG
        FQoJCAsCBBYCAwECHgECF4AACgkQHWvfCT+tHREbAgD/cO+OJwixkCNUliNN08Kx
        ithvJxDolSa0oQXMeMiYFbgBAOKd9ZSXOWZ76efP4Fr/8DGF3WYbmNsLO9u4Gp1o
        U7QPuDgEanXKgxIKKwYBBAGXVQEFAQEHQHUeP6JlYcQsIPjpVbnfOxa+3+BqPnOY
        /DxDfNMlE3J0AwEIB4h4BBgWCgAgFiEEswrNZOBLjhsDeaMgHWvfCT+tHREFAmp1
        yoMCGwwACgkQHWvfCT+tHRGEVAD/b9wy54PFxEYUk7Y9cZJb1i5pvjzY/bCH03r0
        8BZUdRMBAKhU67DG8/En1w+cdE7xyyqwnq+0ZGQHC1WPK3KK7vQK
        =Cbik
        -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()

    /** Decrypts to a real PGP/MIME payload, unlike [ARMORED_MESSAGE]'s bare unparseable text.
     *
     *  Regenerate by importing [ARMORED_PRIVATE] into a throwaway `GNUPGHOME` and running, over a
     *  file containing `Content-Type: text/plain; charset=utf-8\r\n\r\nHello from a real OpenPGP
     *  message.\r\n`:
     *  `gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user 1D6BDF093FAD1D11
     *  --trust-model always --sign --encrypt --armor --recipient 1D6BDF093FAD1D11 -o out.asc
     *  plain.mime` */
    val ARMORED_MIME_MESSAGE = """
        -----BEGIN PGP MESSAGE-----

        hF4DIE6jVovIid0SAQdA5ua6l9wfANzlnQecHQ0D9rUipmHc8/vNT8fm3h/wu38w
        t3e5oQ02X6P7SpU6Ei+7T2Yta6eoaTNmtgTXox+fWktVOlg7U/t9+pRzrKMADfp/
        0sBOAbtAD6y7d+lepNAuDdaYgzEghz7s/y9ydJwpZm1tyxFpCkWt1aCZnIhGFuHT
        8jTC0vmnXylqaJMRO+mf0rqsJ7BY+llCKSQrMaonZhoBdKWvBM3Gnr3KOmhAEy8/
        e5vuXYxkTztLhs2J51D6uRyu60HxbQmKsz2J7UdqhLdaEdxupY94zH8sFZf5fEkg
        xLKizkrlGkrpCu55/O1alebV2VV8EaM7qLh8J9bkdNcgADO7y9UAU2P8VJfBKg8o
        e+4BbrTWLuH03boQtlUkuuvUvPVTBxt9lMtN8oDnsKMp87N6JCYCW82yqkwHxizO
        0ziPcaakdFDBOWrlUS5BjUwTvagnbIoT1izHOmDQVmop
        =kdmH
        -----END PGP MESSAGE-----
    """.trimIndent()

    /** Legacy Sym. Encrypted Data packet (tag 9), not tag 18: `gpg --rfc2440 --disable-mdc`. */
    const val UNPROTECTED_PLAINTEXT = "Unprotected legacy message.\n"

    val ARMORED_UNPROTECTED_MESSAGE = """
        -----BEGIN PGP MESSAGE-----

        hF4DIE6jVovIid0SAQdAWHqPbgM+XRAGZC+xKnEonHOJT093AlXrz6OuuPetnR4w
        nUccPxkOY2eWnMNe3r2wXcnqDpoum903e10u/uGyepidKhjAE+igYxAAvbshmjoL
        yUDXCoX+hCK3Ph7RbvZAGV5LW5c0wivJeaKewBT1ZhPoE6YXzJfsLt2YkXUTsYai
        zg6eRYlo3dLJ0eIyMpN2WPQG
        =3Eds
        -----END PGP MESSAGE-----
    """.trimIndent()

    /** The exact bytes [ARMORED_DETACHED_SIGNATURE] signs — a signed-but-not-encrypted message's
     *  readable body, RFC 3156 style. Verified against [ARMORED_PUBLIC] with `gpg --verify` before
     *  being wired into any test, independently of the Bouncy Castle code under test. */
    const val DETACHED_SIGNATURE_BODY = "Hello from a detached signature.\n"

    /** A detached signature over [DETACHED_SIGNATURE_BODY], made with this same key pair.
     *
     *  Regenerate by importing [ARMORED_PRIVATE] into a throwaway `GNUPGHOME` and running, over a
     *  file containing exactly [DETACHED_SIGNATURE_BODY]:
     *  `gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user 1D6BDF093FAD1D11
     *  --detach-sign --armor -o out.asc body.txt` */
    val ARMORED_DETACHED_SIGNATURE = """
        -----BEGIN PGP SIGNATURE-----

        iHUEABYKAB0WIQSzCs1k4EuOGwN5oyAda98JP60dEQUCanYIIgAKCRAda98JP60d
        EbWNAP9fwxWqBGi3C7s/omp5dfSZas7SdeapITPDfYGbIpYbgwEAsgZeCY4pI2zs
        vtCCtajHfEiFMQp00CyzHSuLbWNaBAg=
        =KR0w
        -----END PGP SIGNATURE-----
    """.trimIndent()
}
