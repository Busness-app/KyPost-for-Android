package com.urlxl.mail.pgp

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.urlxl.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Owns one ceremony for the lifetime of the screen, across rotations.
 *
 * No Activity in this app declares `configChanges`, so rotation destroys every screen. A ceremony
 * living in an Activity would, on rotation, mint and publish a *new* keypair and put a new code on
 * screen — invalidating the one the user had already started typing into their browser. The
 * ViewModel is what makes that survivable: it is created once and `run()` is started once.
 */
internal class DeviceEnrollmentViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow<EnrollmentUiState>(EnrollmentUiState.CheckingIdentity)
    val state: StateFlow<EnrollmentUiState> = _state.asStateFlow()

    /** True when no polling window is running. The Activity offers "Check again" on this, because
     *  `ShowingCode` means two different things depending on whether a window is open behind it. */
    private val _idle = MutableStateFlow(false)
    val idle: StateFlow<Boolean> = _idle.asStateFlow()

    /**
     * The live Activity, or null between one being destroyed and the next installing itself.
     *
     * `@Volatile` because it is written from the main thread and read from whatever dispatcher the
     * ceremony is suspended on.
     */
    @Volatile
    private var activitySealer: VaultSealer? = null

    private val ceremony = EnrollmentCeremony(
        identity = AndroidIdentitySource(application),
        transport = AndroidEnrollmentTransport(application),
        keys = AndroidEnrollmentKeys,
        // A proxy, not the Activity itself: the ViewModel outlives the Activity, and a captured
        // reference would keep a destroyed one alive and prompt on a dead window. With none
        // installed, seal() resolves straight to Cancelled. On a configuration change, the
        // outgoing Activity's own onDestroy cancels its live prompt and resumes this call as
        // Cancelled itself — androidx.biometric resets its callback to a no-op on destroy, so the
        // library will not report the rotation on its own.
        sealer = object : VaultSealer {
            override suspend fun seal(plaintext: ByteArray): SealOutcome =
                activitySealer?.seal(plaintext) ?: SealOutcome.Cancelled
        },
        mailCache = RoomDecryptedMailCache(application),
        clock = SystemEnrollmentClock,
        hostileLocationEnabled = {
            SecurityRuntime.graph(application).hostileLocationSettings.isEnabled()
        },
        hasSecureLockScreen = { hasSecureLockScreen(application) },
        onState = { _state.value = it },
    )

    init {
        viewModelScope.launch {
            try {
                ceremony.run()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    fun installSealer(sealer: VaultSealer?) {
        activitySealer = sealer
    }

    /** Reopens a polling window against the same keypair. Ignored while one is already running, so
     *  a double tap cannot start two. */
    fun checkAgain() {
        if (!_idle.value) return
        _idle.value = false
        viewModelScope.launch {
            try {
                ceremony.checkAgain()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    /**
     * The "user leaves" row of the exit table.
     *
     * `viewModelScope` has been cancelled by the time this runs, but cancellation is cooperative, not
     * immediate: a suspended poll or a live `BiometricPrompt` may still be unwinding when `teardown()`
     * executes. That is fine to proceed through regardless — the agreement key must not survive the
     * screen either way, and deleting it cannot corrupt an in-flight seal, because the seal
     * authenticates against the vault key, which `teardown()` never touches. It is idempotent and
     * destroys nothing if the ceremony never minted anything, because `EnrollmentKeyStore.deleteKeyPair()`'s
     * boolean feeds a `SecurityWipe.step` elsewhere and a deletion that never happened must not be
     * reported.
     */
    override fun onCleared() {
        ceremony.teardown()
        super.onCleared()
    }
}
