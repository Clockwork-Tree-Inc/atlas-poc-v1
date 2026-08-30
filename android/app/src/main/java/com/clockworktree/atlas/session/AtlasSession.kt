package com.clockworktree.atlas.session

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import com.clockworktree.atlas.model.AppSpace
import com.clockworktree.atlas.model.ChatMessage
import com.clockworktree.atlas.model.Persona
import com.clockworktree.atlas.model.PersonaTier
import com.clockworktree.atlas.model.SpaceItem
import com.clockworktree.atlas.model.SpaceKind
import java.security.SecureRandom

/**
 * The shared app state — the Android counterpart to iOS `AtlasSession`.
 *
 * DELIBERATELY THIN: this holds UI state and orchestrates the hardware seams + node tunnel.
 * It does NOT re-implement the Atlas crypto (PoLE, epoch-wrap, ratchet, PQC KEM) — that runs
 * on the node/backend and is reached over the tunnel (see net/NodeClient). Where a value would
 * come from real crypto, it is a LOCAL stand-in and marked as such.
 *
 * Persona rules enforced here (mirror of iOS Home):
 *   - at most ONE Real-ID slot (PersonaTier.REAL_ID); the base persona is ANONYMOUS.
 *   - NOTHING is ever "verified" — Real-ID verification is not built.
 */
class AtlasSession : ViewModel() {

    // ---- enrolment gate -------------------------------------------------------------------

    var enrolled by mutableStateOf(false)
        private set

    var username by mutableStateOf("")

    // ---- system-health stand-ins (would come from node / seams) ---------------------------

    /** Living engine "running" — TODO: driven by the node session + SensorSeam gating. */
    var running by mutableStateOf(false)
        private set

    /** Live presence — TODO: driven by SensorSeam (ambient) and/or BleSeam (ring pulse). */
    var presenceLive by mutableStateOf(false)
    var presenceLocked by mutableStateOf(false)

    /** Node connectivity — TODO: driven by NodeClient handshake state. */
    var nodeConnected by mutableStateOf(false)
    var nodeUrl by mutableStateOf("http://10.0.2.2:8000")   // 10.0.2.2 = host loopback from the emulator

    var ratchetTicks by mutableStateOf(0)
        private set

    val log = mutableStateListOf<String>()

    // ---- personas -------------------------------------------------------------------------

    val personas = mutableStateListOf<Persona>()
    var currentPersona by mutableStateOf<Persona?>(null)
        private set

    /** The single Real-ID slot, if the user reserved it. */
    val realIdPersona: Persona? get() = personas.firstOrNull { it.tier == PersonaTier.REAL_ID }
    val pseudonyms: List<Persona> get() = personas.filter { it.tier != PersonaTier.REAL_ID }

    /**
     * Real-ID verification is NOT BUILT. This is intentionally always false so no surface can
     * render "verified". Do not wire this to a local toggle — verification requires the eID
     * reader + node attestation that don't exist yet.
     */
    fun isVerified(@Suppress("UNUSED_PARAMETER") p: Persona): Boolean = false
    val isCurrentProfileVerified: Boolean get() = false

    // ---- per-persona space trees ----------------------------------------------------------

    private val roots = HashMap<String, AppSpace>()
    var defaultCaptureFolderId by mutableStateOf<String?>(null)
        private set

    /** UI revision bump so lists recompose after a nested-tree mutation. */
    var graphRevision by mutableStateOf(0)
        private set

    private fun personaKey(p: Persona) = p.codeHex(8)

    fun rootFor(p: Persona): AppSpace = roots.getOrPut(personaKey(p)) {
        AppSpace(name = "Vault", kind = SpaceKind.VAULT).also { root ->
            root.children += AppSpace(name = "Media", kind = SpaceKind.FOLDER)
        }
    }

    val currentRoot: AppSpace? get() = currentPersona?.let { rootFor(it) }

    fun defaultCaptureFolder(): AppSpace? {
        val root = currentRoot ?: return null
        val id = defaultCaptureFolderId
        return root.allFolders().firstOrNull { it.id == id }
            ?: root.allFolders().firstOrNull()
    }

    fun setDefaultCaptureFolder(id: String) { defaultCaptureFolderId = id }

    // ---- lifecycle ------------------------------------------------------------------------

    /** Completes enrolment. In the real flow this is gated by the anti-bot proof + ring bind
     *  + biometric identity creation; here it just flips the gate and seeds a base persona. */
    fun completeEnrolment() {
        if (personas.isEmpty()) {
            val base = makePersona(username.ifBlank { "you" }, PersonaTier.ANONYMOUS)
            currentPersona = base
        }
        enrolled = true
        running = true
        log += "enrolled (thin-client stand-in — node session not yet started)"
    }

    fun disenrol() {
        enrolled = false
        running = false
        presenceLive = false
        log += "locked / disenrolled — live keys would be wiped here"
    }

    // ---- persona ops ----------------------------------------------------------------------

    fun switchPersona(p: Persona) { currentPersona = p }

    /** Add a persona. Only ONE Real-ID slot is allowed; a second request is ignored. */
    fun createPersona(name: String, tier: PersonaTier = PersonaTier.ANONYMOUS): Persona? {
        if (tier == PersonaTier.REAL_ID && realIdPersona != null) return null
        val p = makePersona(name, tier)
        if (currentPersona == null) currentPersona = p
        return p
    }

    private fun makePersona(name: String, tier: PersonaTier): Persona {
        // Local random handle. TODO: the node derives the real per-context pseudonym from the
        // System-ID; this stand-in is UI-only and not cryptographically unlinkable.
        val handle = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val p = Persona(handle, name, tier)
        personas += p
        return p
    }

    // ---- space ops ------------------------------------------------------------------------

    fun createSpace(kind: SpaceKind, name: String, parent: AppSpace): AppSpace {
        val s = AppSpace(name = name, kind = kind)
        parent.children.add(s)
        graphRevision++
        return s
    }

    fun addItem(name: String, kind: String, folder: AppSpace): SpaceItem {
        val item = SpaceItem(vaultName = name, kind = kind)
        folder.items.add(item)
        graphRevision++
        return item
    }

    fun moveItem(item: SpaceItem, from: AppSpace, to: AppSpace) {
        if (from.items.remove(item)) { to.items.add(item); graphRevision++ }
    }

    // ---- chat / librarian -----------------------------------------------------------------

    fun sendMessage(chat: AppSpace, text: String) {
        chat.messages.add(ChatMessage(sender = username.ifBlank { "you" }, text = text))
        aiReplyIfPresent(chat, text)
    }

    fun addChatMember(chat: AppSpace, name: String) {
        if (name.isNotBlank() && name !in chat.members) {
            chat.members.add(name)
            chat.messages.add(ChatMessage(sender = "system", text = "$name added."))
        }
    }

    fun addAgent(chat: AppSpace) {
        val label = "${if (username.isBlank()) "your" else "$username’s"} agent"
        if (label !in chat.members) {
            chat.members.add(label)
            chat.messages.add(ChatMessage(sender = "system", text = "$label added.", isAgent = true))
        }
    }

    /**
     * Phone-tier LIBRARIAN stub. Mirrors iOS: if an AI agent is in the chat, it SURFACES + CITES
     * items from the local corpus — it never invents an answer. The real retrieval+citation
     * (local corpus + open ethical library + node/commons escalation) is a TODO; this returns a
     * deterministic, honestly-labelled stand-in over the current persona's own items.
     */
    private fun aiReplyIfPresent(chat: AppSpace, query: String) {
        val agent = chat.members.firstOrNull { it.lowercase().contains("agent") } ?: return
        val corpus = currentRoot?.allFolders()?.flatMap { it.items }.orEmpty()
        val hits = corpus.filter { it.vaultName.contains(query, ignoreCase = true) }.take(5)
        val reply = if (hits.isEmpty()) {
            "Nothing in your library matched that. I surface + cite real works — I don’t " +
                "invent answers. (Retrieval + open-library search + generative summary are TODO.)"
        } else {
            "Found ${hits.size} cited item(s) in your library (deterministic search — not synthesized):\n\n" +
                hits.joinToString("\n") { "• ${it.vaultName} — ${username.ifBlank { "you" }}" } +
                "\n\n_Open-library search + generative summary layer on top once the node is wired._"
        }
        chat.messages.add(ChatMessage(sender = agent, text = reply, isAgent = true))
    }

    // ---- document editor ------------------------------------------------------------------

    /** Save a provenanced document. TODO: the node seals + attests authorship; here we only
     *  store a local item so the flow is exercisable. Author = the signing persona, never typed. */
    fun saveDocument(space: AppSpace, title: String, @Suppress("UNUSED_PARAMETER") body: String,
                     existingVaultName: String?) {
        val base = title.trim().ifEmpty { "Untitled" }
        val vaultName = existingVaultName ?: "$base.atlasdoc"
        if (existingVaultName == null) addItem(vaultName, "doc", space)
        log += "document saved (local stand-in): $vaultName — sealing/attestation is a node TODO"
    }
}
