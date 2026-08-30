package com.clockworktree.atlas.net

import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * NodeClient — the thin-client tunnel to the Atlas node/backend. Counterpart to iOS
 * `AtlasTunnelClient` / `AtlasRelayClient`, but deliberately THINNER.
 *
 * STRATEGY (locked): the node runs the heavy crypto (PoLE, epoch-wrap, ratchet, and the REAL
 * hybrid PQC KEM — ML-KEM-768 + X25519). This client does NOT re-implement any of it in Kotlin.
 * For now the transport is plain HTTP to the node on the LAN / relay; the PQC handshake that
 * wraps this transport is a TODO and, when built, should reuse the node's existing endpoints
 * (see backend/ and ios/AtlasApp/Session/AtlasTunnelClient.swift for the wire shapes:
 * GET kem/public-key, POST kem/complete, POST tunnel/message).
 *
 * FUTURE (shared core): rather than porting the KEM to Kotlin, the convergence target is a
 * shared Rust core exposed via UniFFI to Swift + Kotlin + Python — see android/README.md.
 *
 * STATUS: SCAFFOLD. `ping` is a real GET so connectivity is testable; `handshake` / `send`
 * are stubs with TODOs.
 */
class NodeClient(var baseUrl: String) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    /** Cheap connectivity check against the node. Returns true on any 2xx. */
    fun ping(path: String = "health"): Boolean = runCatchingBool {
        val req = Request.Builder().url(join(baseUrl, path)).get().build()
        http.newCall(req).execute().use { it.isSuccessful }
    }

    /**
     * PQC session handshake. TODO: GET kem/public-key, encapsulate to the node's hybrid KEM key,
     * POST kem/complete, and derive the shared tunnel key. This must NOT re-implement ML-KEM in
     * Kotlin — call the shared Rust core (UniFFI) once it exists, or delegate to a local helper
     * process. Until then, transport is unauthenticated HTTP (dev only).
     */
    suspend fun handshake() {
        TODO("Delegate PQC KEM to the shared core; POST kem/complete; derive the tunnel key")
    }

    /** Send an application payload over the (future) sealed tunnel.
     *  TODO: AES-256-GCM seal under the handshake key, POST tunnel/message. */
    suspend fun send(@Suppress("UNUSED_PARAMETER") plaintext: ByteArray): ByteArray {
        TODO("Seal under the tunnel key and POST tunnel/message")
    }

    private fun join(base: String, path: String) =
        base.trimEnd('/') + "/" + path.trimStart('/')

    private inline fun runCatchingBool(block: () -> Boolean): Boolean =
        try { block() } catch (_: Exception) { false }
}
