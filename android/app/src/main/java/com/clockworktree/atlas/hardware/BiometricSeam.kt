package com.clockworktree.atlas.hardware

import androidx.fragment.app.FragmentActivity

/**
 * BiometricSeam ↔ iOS Face ID / Touch ID (via `LocalAuthentication` / SE biometric-gated keys).
 *
 * Uses AndroidX `BiometricPrompt` to require a live biometric before a Keystore key is used.
 * Presence is the ENTRY gate held live — not re-asked per operation (mirror the iOS reuse
 * window in SecureEnclaveStore). A CryptoObject binds the auth to a specific Keystore key so
 * the OS, not our code, performs the match — the biometric never enters app memory.
 *
 * STATUS: SCAFFOLD. `authenticate` is stubbed; wiring requires a FragmentActivity host and a
 * BiometricPrompt.CryptoObject built from KeystoreSeam's identity key.
 */
class BiometricSeam {

    sealed interface Result {
        data object Success : Result
        data class Error(val message: String) : Result
        data object Unavailable : Result
    }

    /**
     * Prompt for a live biometric and, on success, unlock the bound Keystore key.
     *
     * TODO:
     *   1. BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) gate.
     *   2. Build BiometricPrompt with a PromptInfo (title "Unlock Atlas", BIOMETRIC_STRONG).
     *   3. Pass a CryptoObject wrapping KeystoreSeam.sign's Signature so the match authorises
     *      exactly that key-op.
     *   4. Hold presence for the session; drop it on background / liveness break.
     */
    fun authenticate(
        @Suppress("UNUSED_PARAMETER") activity: FragmentActivity,
        @Suppress("UNUSED_PARAMETER") onResult: (Result) -> Unit,
    ) {
        TODO("Wire AndroidX BiometricPrompt with a CryptoObject bound to the Keystore identity key")
    }
}
