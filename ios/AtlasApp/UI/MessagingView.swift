import SwiftUI
import AtlasCore

/// A CHAT — lives inside the space it was started in. It works IMMEDIATELY, on your own:
/// you can start a chat with yourself, jot to it, and add members (people, companies, or an
/// AI agent) into this space's context. No "waiting for the group to come online" wall — the
/// relay/roster/live-key plumbing is a network concern that lives on the Developer tab, not
/// here. Messages are held on the chat space itself.
struct MessagingView: View {
    @EnvironmentObject var session: AtlasSession
    @ObservedObject var chat: AppSpace
    @State private var draft = ""
    @State private var showAddMember = false
    @State private var newMember = ""
    @ObservedObject private var llm = LocalLLM.shared
    @State private var aiThinking = false
    @State private var showAddAgent = false
    @State private var agentName = "Atlas"
    @State private var aiAllowed: Set<String> = []

    private var aiAllowKey: String { "atlas.aiallow.\(chat.id.uuidString)" }
    private func loadAIAllowed() {
        aiAllowed = Set(UserDefaults.standard.stringArray(forKey: aiAllowKey) ?? [])
    }
    private func allowAI(_ m: String) {
        aiAllowed.insert(m)
        UserDefaults.standard.set(Array(aiAllowed), forKey: aiAllowKey)
        chat.messages.append(ChatMessage(sender: "system", text: "\(m) may now use the AI (revocable; every use is attributed).", isAgent: true))
    }
    private func revokeAI(_ m: String) {
        aiAllowed.remove(m)
        UserDefaults.standard.set(Array(aiAllowed), forKey: aiAllowKey)
        chat.messages.append(ChatMessage(sender: "system", text: "\(m)'s AI use revoked.", isAgent: true))
    }

    var body: some View {
        VStack(spacing: 0) {
            membersBar
            messageList
            if aiThinking || (!llm.ready && llm.status != "idle") {
                aiStatusBar
            }
            inputBar
        }
        .navigationTitle(chat.name)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { loadAIAllowed(); mirrorRelay() }
        .onChange(of: session.relayMessages.count) { _, _ in mirrorRelay() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button { showAddMember = true } label: { Label("Add person / company", systemImage: "person.badge.plus") }
                    Button { agentName = "Atlas"; showAddAgent = true } label: { Label("Add AI agent", systemImage: "sparkles") }
                } label: { Image(systemName: "person.2.badge.plus") }
            }
        }
        .alert("Add to chat", isPresented: $showAddMember) {
            TextField("Name or company", text: $newMember)
            Button("Add") { addMember(newMember); newMember = "" }
            Button("Cancel", role: .cancel) { newMember = "" }
        }
        .alert("Name your AI agent", isPresented: $showAddAgent) {
            TextField("Agent name", text: $agentName)
            Button("Add") { addAgent(agentName) }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("In a group it only replies when you address it by name; in a chat with just the two of you it always replies.")
        }
    }

    private var membersBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                chip(session.username.isEmpty ? "you" : session.username, icon: "person.fill")
                ForEach(chat.members, id: \.self) { m in
                    chip(m, icon: m.hasSuffix(" (AI)") ? "sparkles" : "person.fill")
                        .contextMenu {
                            if !m.hasSuffix(" (AI)") {
                                // GROUP AUTHORITY: the owner grants this participant use of the
                                // agent (provenanced per invocation; revocable instantly). They
                                // borrow USE, never the owner's authority/scopes.
                                if aiAllowed.contains(m) {
                                    Button(role: .destructive) { revokeAI(m) } label: {
                                        Label("Revoke AI use", systemImage: "sparkles.slash")
                                    }
                                } else {
                                    Button { allowAI(m) } label: {
                                        Label("Allow AI use", systemImage: "sparkles")
                                    }
                                }
                            }
                        }
                }
            }
            .padding(.horizontal).padding(.vertical, 8)
        }
        .background(Color(.secondarySystemBackground))
    }

    private func chip(_ name: String, icon: String) -> some View {
        Label(name, systemImage: icon)
            .font(.caption).padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color(.tertiarySystemBackground)).clipShape(Capsule())
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if chat.messages.isEmpty {
                        Text("No messages").font(.callout).foregroundStyle(.secondary).padding()
                    }
                    ForEach(chat.messages) { m in bubble(m).id(m.id) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 8)
            }
            .onChange(of: chat.messages.count) { _, _ in
                if let last = chat.messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }

    /// Live feedback while the on-device model downloads (first run) or generates.
    private var aiStatusBar: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(aiThinking && llm.ready ? "thinking…" : llm.status)
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
        .background(Color(.secondarySystemBackground))
    }

    private var inputBar: some View {
        HStack {
            TextField("Message", text: $draft, axis: .vertical).textFieldStyle(.roundedBorder)
                .onSubmit(sendIt)
            Button { sendIt() } label: { Image(systemName: "arrow.up.circle.fill").font(.title2) }
                .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(8)
    }

    private func bubble(_ m: ChatMessage) -> some View {
        let mine = m.sender == (session.username.isEmpty ? "you" : session.username)
        return HStack {
            if mine { Spacer() }
            VStack(alignment: .leading, spacing: 2) {
                if !mine { Text(m.sender).font(.caption2).foregroundStyle(m.isAgent ? .purple : .secondary) }
                Text(markdown(m.text))            // renders clickable citation links + snippets
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(mine ? Color.accentColor.opacity(0.9) : Color(.secondarySystemBackground))
            .foregroundStyle(mine ? .white : .primary)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            if !mine { Spacer() }
        }
        .padding(.horizontal, 10)
    }

    /// Mirror messages received over the live relay into this open chat (deduped by id), so a
    /// message another human sent from their phone actually appears here. (1:1 two-phone case;
    /// per-chat routing of a flat group is tracked in #45.)
    private func mirrorRelay() {
        // One relay stream feeds many LOCAL chats. Until each chat is bound to a specific peer/group,
        // only surface relayed messages in a chat that actually has OTHER human participants — so a
        // note-to-self or a freshly-started chat doesn't echo the live conversation. (True per-
        // conversation routing — a chat↔group id — is the deeper fix.)
        let me = session.username.isEmpty ? "you" : session.username
        let hasOthers = chat.members.contains { $0 != me && !$0.hasSuffix(" (AI)") }
        guard hasOthers else { return }
        let existing = Set(chat.messages.map { $0.id })
        for m in session.relayMessages where !existing.contains(m.id) {
            chat.messages.append(m)
        }
    }

    private func sendIt() {
        let t = draft.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return }
        // Panic phrase: if the text IS the panic phrase, fire the witness silently and swallow it —
        // nothing is sent, nothing changes on screen (no tell to anyone watching).
        if session.checkPanicPhrase(t) { draft = ""; return }
        chat.messages.append(ChatMessage(sender: session.username.isEmpty ? "you" : session.username, text: t, isAgent: false))
        session.persistGraph()   // persist the chat immediately while presence is live (#18)
        session.send(t)          // relay to any live peers over the Zurich relay (no-op if none online)
        draft = ""
        aiReplyIfPresent(to: t)
    }

    /// Render message text as markdown (so citation links are tappable), preserving newlines.
    private func markdown(_ s: String) -> AttributedString {
        (try? AttributedString(markdown: s,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(s)
    }

    /// Phone-tier LIBRARIAN: if an AI agent is in this chat, answer by SURFACING + CITING real
    /// authored works from your library — never a made-up answer. (Retrieval+citation on-device;
    /// real generative summary + node/commons corpus escalation layer on later.)
    private func aiReplyIfPresent(to query: String) {
        // Only AGENT members (named "<name> (AI)") reply, and only when ADDRESSED: in a group the
        // message must name the agent; in a solo chat (just you + the agent) it always replies —
        // so the agent never answers messages meant for people.
        let agents = chat.members.filter { $0.hasSuffix(" (AI)") }
        guard let agentLabel = agents.first else { return }
        let name = String(agentLabel.dropLast(5))                     // strip " (AI)"
        let humans = chat.members.filter { !$0.hasSuffix(" (AI)") }
        let addressed = query.lowercased().contains(name.lowercased())
        guard humans.isEmpty || addressed else { return }
        // GROUP AI = USABLE BY EVERYONE: an agent added to a group chat is open to every participant.
        // Each member invokes it from their own device (which runs the local model and relays the
        // answer to all), so no owner-only gate — anyone in the chat can use the AI.

        // Only SEARCH + CITE when the message asks to look something up / do something. Otherwise the
        // model just converses (no link dump for "hello").
        let doSearch = wantsSearch(query)
        aiThinking = true
        Task {
            var hits: [LibrarianHit] = []
            var grounding = ""
            if doSearch {
                let local = Librarian.retrieve(query, localCorpus(), topK: 5)
                let web = await WebLibrary.search(query, limit: 4)
                // HONEST CITATION: only hits genuinely RELEVANT to the question are fed to the
                // model and cited. A whole-sentence search returns noise (ask about Turing, get a
                // Family Guy episode) — junk must never be dressed up as the answer's sources.
                // If nothing relevant survives, the model answers alone and NO source is attached.
                let need = max(1, min(2, meaningfulWords(query).count))
                hits = Array((local + web).filter { relevance(query, $0) >= need }
                    .sorted { relevance(query, $0) > relevance(query, $1) }
                    .prefix(4))
                grounding = hits.map { h -> String in
                    let s = h.snippet.isEmpty ? "" : ": " + String(h.snippet.prefix(200))
                    return "- \(h.title) — \(h.author)\(s)"
                }.joined(separator: "\n")
            }
            let prompt = grounding.isEmpty ? query
                : "\(query)\n\n[Sources you may use and cite — do not go beyond these]\n\(grounding)"
            let answer = await LocalLLM.shared.respond(to: prompt)
            let sources = hits.isEmpty ? "" : "\n\n—\n" + hits.map { h in
                h.url.isEmpty ? "• \(h.title) — \(h.author)" : "• [\(h.title)](\(h.url)) — \(h.author)"
            }.joined(separator: "\n")
            // AI-SURFACING (pull, not push): if the ask names a need, surface genuinely-matching market
            // listings — relevance-ranked, no ads, no pay-to-rank. Only when the query looked like a task.
            let market = doSearch ? session.surfaceListings(for: query).prefix(3) : []
            let marketBlock = market.isEmpty ? "" : "\n\n— From the market —\n" + market.map { l in
                "• \(l.title) — \(l.access == .free ? "free" : "\(l.priceAtlas) ATLAS")"
            }.joined(separator: "\n")
            await MainActor.run {
                aiThinking = false
                let agentName = "\(name) (agent)"
                chat.messages.append(ChatMessage(sender: agentName, text: answer + sources + marketBlock, isAgent: true))
                session.persistGraph()
                // Relay the AI's answer to peers so BOTH people see it (only the invoker's AI
                // runs — mirrored incoming messages never re-trigger the peer's AI).
                session.send(answer + sources, as: agentName, isAgent: true)
            }
        }
    }

    /// How many meaningful query words appear in a hit's title+snippet — the cite-worthiness bar.
    /// Stopwords don't count, so "who taught machines to think" scores on machines/think/taught,
    /// never on "who"/"the".
    private static let stopWords: Set<String> = ["the", "a", "an", "of", "to", "is", "are", "was",
        "were", "who", "what", "when", "where", "how", "why", "did", "do", "does", "me", "my",
        "your", "find", "search", "for", "about", "tell", "and", "or", "in", "on", "at", "it",
        "that", "this", "you", "i"]

    private func meaningfulWords(_ s: String) -> Set<String> {
        Set(s.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init)).subtracting(Self.stopWords)
    }

    private func relevance(_ query: String, _ h: LibrarianHit) -> Int {
        let text = (h.title + " " + h.snippet).lowercased()
        return meaningfulWords(query).filter { text.contains($0) }.count
    }

    /// True only when the message has search intent (look something up / do something). Plain chat —
    /// greetings, statements — returns false, so the model just converses with no retrieval.
    private func wantsSearch(_ q: String) -> Bool {
        let s = q.lowercased()
        if s.contains("?") { return true }
        let triggers = ["search", "find", "look up", "lookup", "look for", "what is", "what are",
                        "what's", "who is", "who's", "who are", "tell me about", "explain", "define",
                        "how do", "how to", "where ", "when ", "cite", "source", "show me"]
        return triggers.contains(where: { s.contains($0) })
    }

    /// The phone's private corpus = your authored works across the current persona's space tree.
    private func localCorpus() -> [CorpusItem] {
        guard let root = session.currentRoot else { return [] }
        let author = session.username.isEmpty ? "you" : session.username
        var items: [CorpusItem] = []
        func walk(_ s: AppSpace) {
            for it in s.items {
                items.append(CorpusItem(id: Data(it.vaultName.utf8), author: author,
                                        title: it.vaultName, tags: [it.kind]))
            }
            for c in s.children { walk(c) }
        }
        walk(root)
        return items
    }

    private func addMember(_ name: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty, !chat.members.contains(n) else { return }
        chat.members.append(n)
        chat.messages.append(ChatMessage(sender: "system", text: "\(n) added.", isAgent: false))
    }

    private func addAgent(_ name: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        let label = "\(n.isEmpty ? "Atlas" : n) (AI)"
        guard !chat.members.contains(label) else { return }
        chat.members.append(label)
        chat.messages.append(ChatMessage(sender: "system",
            text: "\(label) added — address it by name (or it's just the two of you). Loading the on-device model…",
            isAgent: true))
        Task { await LocalLLM.shared.ensureLoaded() }   // load the bundled model now
        session.persistGraph()
    }
}
