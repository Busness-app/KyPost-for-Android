package org.kysecurity.mail.push

import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A pairing deep link must be consumed exactly once.
 *
 * `onNewIntent` cleared `intent.data` after consuming it and explained at length why — an
 * attacker's cancelled "replace your pairing with evil.tld" prompt resurfacing later, with no link
 * tap to explain it, after the user has been trained by a legitimate one. `onCreate` did not, and
 * `onCreate` is the path that is actually reached first: a browser or a co-installed app delivers
 * `kypost://native-pair` through `PushPairingLinkActivity` -> `startActivity`, which lands in
 * `onCreate`. `getIntent()` then keeps returning that Intent with its data intact, so every
 * rotation, dark-mode toggle and restore-after-eviction re-raised the prompt.
 *
 * Asserts the cleared Intent rather than counting dialogs: the dialog is what the user sees, but
 * the surviving `data` is the bug, and it is the thing a recreation reads.
 */
@RunWith(AndroidJUnit4::class)
class PairingDeepLinkReplayTest {

    private fun deepLinkIntent(): Intent =
        Intent(ApplicationProvider.getApplicationContext(), PushPairingActivity::class.java)
            .setData(Uri.parse("kypost://native-pair?srv=https%3A%2F%2Frelay.example.com"))

    @Test
    fun onCreateConsumesTheDeepLinkSoARecreationCannotReplayIt() {
        ActivityScenario.launch<PushPairingActivity>(deepLinkIntent()).use { scenario ->
            scenario.onActivity { activity ->
                assertNull(
                    "onCreate must clear intent.data, exactly as onNewIntent does",
                    activity.intent.data,
                )
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                assertNull(
                    "a recreation must not find a deep link left to re-consume",
                    activity.intent.data,
                )
            }
        }
    }
}
