package org.kysecurity.mail.push

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * The only public entry point for `kypost://native-pair` deep links. This activity renders
 * nothing and holds no pairing/device state — it exists purely so the exported surface area is
 * a thin, stateless forwarder rather than [PushPairingActivity] itself, which is not exported
 * and shows device ID and cached push history. Splitting the two closes a path where any
 * co-installed app could force-render that sensitive screen via an explicit-component intent,
 * since intent-filter data matching only gates implicit intent resolution, not explicit intents
 * naming the component directly.
 */
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
