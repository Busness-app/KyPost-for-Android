package org.kysecurity.mail.contacts.device

import android.app.Service
import android.content.Intent
import android.os.IBinder

class KyPostContactAuthenticatorService : Service() {
    private lateinit var authenticator: KyPostContactAuthenticator

    override fun onCreate() {
        super.onCreate()
        authenticator = KyPostContactAuthenticator(this)
    }

    override fun onBind(intent: Intent?): IBinder = authenticator.iBinder
}
