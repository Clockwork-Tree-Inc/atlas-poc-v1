import SwiftUI
import AtlasCore

// MARK: - MARKET — every product lives here (free + paid, all media); storefront exposed,
// full product gated (buy / request / subscription). Local until the node swarm syncs it.

struct MarketScreen: View {
    @EnvironmentObject var session: AtlasSession
    @State private var showList = false
    @State private var query = ""
    @State private var freeOnly = false
    @State private var sortByPrice = false

    private var filtered: [MarketListing] {
        var out = (query.isEmpty && !freeOnly)
            ? session.marketListings
            : session.surfaceListings(for: query, freeOnly: freeOnly)
        if sortByPrice {
            out = out.sorted { ($0.access == .free ? 0 : $0.priceAtlas) < ($1.access == .free ? 0 : $1.priceAtlas) }
        }
        return out
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle("Free only", isOn: $freeOnly)
                    Toggle("Sort by price (low → high)", isOn: $sortByPrice)
                } header: {
                    Text("Filter")
                } footer: {
                    Text("Search + filters find genuine matches by relevance — no ads, no pay-to-rank. Your agent surfaces the same matches when you tell it what you need.")
                }
                Section(query.isEmpty && !freeOnly ? "Listings" : "Matches (\(filtered.count))") {
                    if filtered.isEmpty {
                        Text(session.marketListings.isEmpty
                             ? "Nothing listed yet — tap + to put something on the market (free items welcome)."
                             : "No matches. Try different words or clear the filters.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ForEach(filtered, id: \.sig) { l in
                        NavigationLink { MarketDetailView(listing: l) } label: {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(l.title).font(.headline)
                                    Spacer()
                                    Text(l.access == .free ? "FREE" : "\(l.priceAtlas) ATLAS")
                                        .font(.caption.bold())
                                        .foregroundStyle(l.access == .free ? .green : .orange)
                                }
                                if !l.merch.blurb.isEmpty {
                                    Text(l.merch.blurb).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Market")
            .searchable(text: $query, prompt: "Search the market — what do you need?")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showList = true } label: { Image(systemName: "plus") }
                }
            }
            .sheet(isPresented: $showList) { ListItemSheet().environmentObject(session) }
        }
        .id(session.currentPersona?.handle)
    }
}

/// The storefront view: exposed merchandising + the acquire gate. The full product ref is released
/// ONLY through the market gate (free / author grant / subscription).
struct MarketDetailView: View {
    @EnvironmentObject var session: AtlasSession
    let listing: MarketListing
    @State private var opened: String?
    @State private var denied = false

    var body: some View {
        List {
            Section {
                Text(listing.title).font(.title2.bold())
                if !listing.merch.blurb.isEmpty { Text(listing.merch.blurb).font(.headline) }
                if !listing.merch.description.isEmpty { Text(listing.merch.description) }
                Text("by \(String(listing.author.prefix(12)))… · \(listing.license)")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            if !listing.merch.preview.isEmpty {
                Section("Free preview") { Text(listing.merch.preview).font(.callout) }
            }
            Section {
                if let opened {
                    Label("Unlocked — \(opened)", systemImage: "lock.open.fill").foregroundStyle(.green)
                } else if listing.access == .free {
                    Button {
                        opened = try? Storefront.openFull(listing, requester: session.currentPersona?.handle ?? Data())
                    } label: { Label("Open (free)", systemImage: "arrow.down.circle.fill") }
                } else {
                    Button {
                        // acquisition routes through the market gate: without a grant or
                        // subscription this DENIES — payment settles via the payment module.
                        do { opened = try Storefront.openFull(listing, requester: session.currentPersona?.handle ?? Data()) }
                        catch { denied = true }
                    } label: {
                        Label(listing.access == .buy ? "Buy — \(listing.priceAtlas) ATLAS" : "Request access",
                              systemImage: "cart.fill")
                    }
                    if denied {
                        Text("Gated — acquire through the market (buy/request, or subscribe to this creator). Payment rails arrive with the node.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
                ShareLink(item: Storefront.marketLink(listing.id())) {
                    Label("Share market link", systemImage: "square.and.arrow.up")
                }
            }
        }
        .navigationTitle("Listing")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct ListItemSheet: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var blurb = ""
    @State private var desc = ""
    @State private var preview = ""
    @State private var tags = ""
    @State private var price = 0
    @State private var access: AccessMode = .free
    @State private var license = "all-rights-reserved"

    var body: some View {
        NavigationStack {
            Form {
                Section("Product") {
                    TextField("Title", text: $title)
                    TextField("Tags (comma-separated)", text: $tags)
                    Picker("License", selection: $license) {
                        Text("All rights reserved").tag("all-rights-reserved")
                        Text("CC-BY (open, attributed)").tag("cc-by")
                        Text("Content license (paid)").tag("content:quote")
                    }
                }
                Section("Storefront — what shoppers see before paying") {
                    TextField("Blurb (one line)", text: $blurb)
                    TextField("Description", text: $desc, axis: .vertical)
                    TextField("Free preview (excerpt)", text: $preview, axis: .vertical)
                }
                Section("Access") {
                    Picker("Mode", selection: $access) {
                        Text("Free").tag(AccessMode.free)
                        Text("Buy").tag(AccessMode.buy)
                        Text("Request").tag(AccessMode.request)
                    }
                    if access == .buy { Stepper("Price: \(price) ATLAS", value: $price, in: 0...100000) }
                }
            }
            .navigationTitle("List on market")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("List") {
                        session.listOnMarket(
                            title: title, tags: tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) },
                            license: license, priceAtlas: price, access: access, blurb: blurb,
                            description: desc, preview: preview,
                            contentRef: "vault://\(title)")
                        dismiss()
                    }
                    .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}

// MARK: - FEED — a follow-based newsletter for all media. Follow = free posts; subscribe = paid.

struct FeedScreen: View {
    @EnvironmentObject var session: AtlasSession
    @State private var draft = ""
    @State private var tier: PostTier = .free
    @State private var followHex = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Follow someone (free) to see their posts; subscribe (paid) to unlock their paid posts. Local until your node syncs the network.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Post") {
                    TextField("Say something…", text: $draft, axis: .vertical)
                    Picker("Tier", selection: $tier) {
                        Text("Free (followers)").tag(PostTier.free)
                        Text("Paid (subscribers)").tag(PostTier.paid)
                    }
                    Button("Post") {
                        let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !t.isEmpty else { return }
                        session.postToFeed(caption: t, tier: tier)
                        // see your own posts: follow yourself once
                        if let h = session.currentPersona?.handle.map({ String(format: "%02x", $0) }).joined() {
                            session.followAuthor(h)
                        }
                        draft = ""
                    }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                Section("Follow") {
                    HStack {
                        TextField("Author handle (hex)", text: $followHex)
                            .font(.caption.monospaced()).autocorrectionDisabled()
                        Button("Follow") {
                            let h = followHex.trimmingCharacters(in: .whitespaces)
                            guard !h.isEmpty else { return }
                            session.followAuthor(h); followHex = ""
                        }
                    }
                }
                Section("Timeline") {
                    let posts = session.feedTimeline()
                    if posts.isEmpty {
                        Text("Nothing yet — post something, or follow an author.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ForEach(posts) { p in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(String(p.author.prefix(12)) + "…").font(.caption.monospaced()).foregroundStyle(.secondary)
                                if p.tier == .paid {
                                    Text("PAID").font(.caption2.bold()).foregroundStyle(.orange)
                                }
                                Spacer()
                                Text(Date(timeIntervalSince1970: TimeInterval(p.ts)), style: .time)
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            Text(p.caption)
                            if !p.marketRef.isEmpty {
                                Text(p.marketRef).font(.caption).foregroundStyle(.tint)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Feed")
        }
        .id("\(session.currentPersona?.handle.map { String(format: "%02x", $0) }.joined() ?? "")-\(session.feedRevision)")
    }
}
