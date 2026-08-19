package org.kysecurity.mail.push

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** Exported forwarder for `kypost://native-pair`; keeps [PushPairingActivity] unexported. */
class PushPairingLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.data
        if (data != null) {
            startActivity(Intent(this, PushPairingActivity::class.java).setData(data))
        }
        finish()
    }
}
