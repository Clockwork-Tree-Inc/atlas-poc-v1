package com.clockworktree.atlas.model

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import java.util.UUID

/**
 * UI-facing domain model for the Android thin client. These are LOCAL view models only —
 * the authoritative identity/space state lives on the node (see net/NodeClient). They mirror
 * the iOS app's `Profile` (persona), `AppSpace`, `SpaceItem`, and `ChatMessage`.
 *
 * Handles are shown as opaque hex CODES — the System-ID is never surfaced (see MEMORY:
 * identity/persona model). NOTHING here carries a "verified" flag: Real-ID verification is
 * not built, so a persona is at most a reserved Real-ID *slot*, never verified.
 */

/** Persona tier. Exactly ONE persona may hold the REAL_ID slot; the rest are ANONYMOUS. */
enum class PersonaTier { REAL_ID, ANONYMOUS }

/**
 * A persona ("profile") off the System-ID root. Each owns its OWN unlinkable space tree.
 * `handle` is the opaque code that identifies it in the UI.
 */
data class Persona(
    val handle: ByteArray,
    var displayName: String,
    val tier: PersonaTier,
) {
    /** Short hex code shown in the UI (never the System-ID). */
    fun codeHex(n: Int = 6): String =
        handle.take(n).joinToString("") { "%02x".format(it) }

    override fun equals(other: Any?) =
        other is Persona && handle.contentEquals(other.handle)
    override fun hashCode() = handle.contentHashCode()
}

/** Kinds a space can take — the recursive vault/folder/chat/market tree. */
enum class SpaceKind { VAULT, FOLDER, CHAT, MARKET }

/** A leaf item stored inside a folder/vault (captured media, imported file, or document). */
data class SpaceItem(
    val id: String = UUID.randomUUID().toString(),
    val vaultName: String,
    /** image | video | audio | pdf | text | doc | file */
    val kind: String,
)

/** A single chat message. `isAgent` marks the AI "librarian" replies. */
data class ChatMessage(
    val id: String = UUID.randomUUID().toString(),
    val sender: String,
    val text: String,
    val isAgent: Boolean = false,
)

/**
 * A node in the recursive space tree. Observable so Compose recomposes when children/items/
 * messages change. Vault (root) -> folders / chats / market -> nested spaces, arbitrarily deep.
 */
class AppSpace(
    val id: String = UUID.randomUUID().toString(),
    name: String,
    val kind: SpaceKind,
) {
    var name by mutableStateOf(name)
    val children = mutableStateListOf<AppSpace>()
    val items = mutableStateListOf<SpaceItem>()
    val messages = mutableStateListOf<ChatMessage>()   // chat spaces only
    val members = mutableStateListOf<String>()         // chat spaces only

    /** Depth-first every chat under this space (for the consolidated Chats list). */
    fun allChats(): List<AppSpace> {
        val out = mutableListOf<AppSpace>()
        fun walk(s: AppSpace) {
            if (s.kind == SpaceKind.CHAT) out += s
            s.children.forEach(::walk)
        }
        walk(this)
        return out
    }

    /** Depth-first every vault/folder container (for capture-destination & document lists). */
    fun allFolders(): List<AppSpace> {
        val out = mutableListOf<AppSpace>()
        fun walk(s: AppSpace) {
            if (s.kind == SpaceKind.VAULT || s.kind == SpaceKind.FOLDER) out += s
            s.children.forEach(::walk)
        }
        walk(this)
        return out
    }
}
