package com.clockworktree.atlas.hardware

import android.content.Context

/**
 * CredentialManagerSeam ↔ iOS passkeys / FIDO2 (`RPClient` / ASAuthorization).
 *
 * Jetpack `CredentialManager` unifies passkeys (WebAuthn/FIDO2), passwords, and federated
 * sign-in. Atlas uses passkeys as an interoperable, phishing-resistant authenticator that the
 * node (relying party) verifies — one leg of the "certify interop via WebAuthn/FIDO2" direction
 * (see MEMORY: certification-model).
 *
 * STATUS: SCAFFOLD. Create/get flows are stubbed; both need a node-issued challenge + RP JSON.
 */
class CredentialManagerSeam(@Suppress("unused") private val context: Context) {

    /**
     * Register a passkey for this identity.
     * TODO: CredentialManager.create(context).createCredential(CreatePublicKeyCredentialRequest(
     *       requestJson = fromNode)) — the node builds the PublicKeyCredentialCreationOptions.
     */
    suspend fun createPasskey(@Suppress("UNUSED_PARAMETER") requestJsonFromNode: String): String {
        TODO("Wire CredentialManager.createCredential with a node-issued WebAuthn creation request")
    }

    /**
     * Authenticate with an existing passkey.
     * TODO: getCredential(GetCredentialRequest(GetPublicKeyCredentialOption(requestJson = fromNode)));
     *       return the assertion JSON for the node to verify.
     */
    suspend fun getPasskeyAssertion(@Suppress("UNUSED_PARAMETER") requestJsonFromNode: String): String {
        TODO("Wire CredentialManager.getCredential with a node-issued WebAuthn request")
    }
}
