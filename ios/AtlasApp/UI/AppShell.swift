import SwiftUI
import AtlasCore

/// One destination in the left nav rail.
private struct NavDest: Identifiable {
    let id: String
    let title: String
    let icon: String
    let make: () -> AnyView
}

/// App shell — a LEFT-SIDE vertical, scrollable, user-reorderable nav rail instead of a bottom tab
/// bar with a "More (…)" overflow. Every destination is always visible (scroll if many). It
/// COLLAPSES to a thin icon-only strip (chevron at the top), pushing content wider. Long-press a
/// rail item — or tap the pencil — to enter edit mode and drag to reorder. Collapse + order persist.
struct AppShell: View {
    @EnvironmentObject var session: AtlasSession
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("atlas.nav.order.v1") private var savedOrder = ""
    @AppStorage("atlas.nav.collapsed") private var collapsed = false
    @State private var order: [String] = []
    @State private var selection = "home"
    @State private var editing = false

    private var dests: [NavDest] {
        [
            NavDest(id: "home", title: "Home", icon: "house.fill") { AnyView(HomeTabView(ring: session.ring)) },
            NavDest(id: "spaces", title: "Spaces", icon: "square.stack.3d.up.fill") { AnyView(SpacesTabView()) },
            NavDest(id: "chats", title: "Comms", icon: "bubble.left.and.bubble.right.fill") { AnyView(CommsTabView()) },
            NavDest(id: "contacts", title: "Contacts", icon: "person.2.fill") { AnyView(ContactsTabView()) },
            NavDest(id: "email", title: "Email", icon: "envelope.fill") { AnyView(EmailTabView()) },
            NavDest(id: "market", title: "Market", icon: "cart.fill") { AnyView(MarketScreen()) },
            NavDest(id: "wallet", title: "Wallet", icon: "wallet.pass.fill") { AnyView(WalletView()) },
            NavDest(id: "feed", title: "Feed", icon: "newspaper.fill") { AnyView(FeedScreen()) },
            NavDest(id: "capture", title: "Capture", icon: "camera.fill") { AnyView(CaptureTabView()) },
            NavDest(id: "office", title: "Office", icon: "doc.text.fill") { AnyView(OfficeTabView()) },
            NavDest(id: "records", title: "Records", icon: "lock.doc.fill") { AnyView(NavigationStack { RecordsView() }) },
            NavDest(id: "developer", title: "Developer", icon: "hammer.fill") { AnyView(DeveloperView()) },
        ]
    }

    private var byId: [String: NavDest] { Dictionary(uniqueKeysWithValues: dests.map { ($0.id, $0) }) }
    private var ordered: [NavDest] { order.compactMap { byId[$0] } }

    var body: some View {
        HStack(spacing: 0) {
            rail
            Divider()
            (byId[selection]?.make() ?? AnyView(EmptyView()))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .onAppear(perform: loadOrder)
        .onChange(of: scenePhase) { _, phase in
            // CONDITION-WIPE: drop the RAM-only live key when backgrounded; re-earn it on return.
            // Flush any debounced graph/chat write FIRST (before the key is wiped), so nothing is lost.
            if phase == .background { session.flushGraph(); session.wipeLiveKeys() }
            else if phase == .active, session.enrolled { session.startRatchet(); session.syncVoicePanic(); session.firePendingPanicIfAny() }
        }
    }

    private var rail: some View {
        VStack(spacing: 0) {
            // Collapse / expand — pushes the rail aside to a thin icon strip and back.
            Button { withAnimation(.easeInOut(duration: 0.2)) { collapsed.toggle(); if collapsed { editing = false } } } label: {
                Image(systemName: collapsed ? "chevron.right" : "chevron.left")
                    .font(.caption.bold()).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity).padding(.vertical, 8)
            }
            .buttonStyle(.plain)
            Divider()

            List {
                ForEach(ordered) { d in
                    Button { if !editing { selection = d.id } } label: { rowLabel(d) }
                        .buttonStyle(.plain)
                        .listRowInsets(EdgeInsets(top: 6, leading: 2, bottom: 6, trailing: 2))
                        .listRowBackground(selection == d.id && !editing ? Color.accentColor.opacity(0.12) : Color.clear)
                        .onLongPressGesture(minimumDuration: 0.4) { if !collapsed { withAnimation { editing = true } } }
                }
                .onMove(perform: moveItems)
            }
            .listStyle(.plain)
            .scrollIndicators(.hidden)
            .environment(\.editMode, .constant(editing && !collapsed ? .active : .inactive))

            if !collapsed {
                Divider()
                Button { withAnimation { editing.toggle() } } label: {
                    Image(systemName: editing ? "checkmark.circle.fill" : "pencil")
                        .font(.headline)
                        .foregroundStyle(editing ? Color.accentColor : Color.secondary)
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .buttonStyle(.plain)
            }
        }
        .frame(width: collapsed ? 48 : 80)
        .background(.ultraThinMaterial)
    }

    @ViewBuilder private func rowLabel(_ d: NavDest) -> some View {
        let active = selection == d.id && !editing
        if collapsed {
            Image(systemName: d.icon).font(.title3)
                .frame(maxWidth: .infinity).padding(.vertical, 6)
                .foregroundStyle(active ? Color.accentColor : Color.primary)
                .contentShape(Rectangle())
        } else {
            VStack(spacing: 4) {
                Image(systemName: d.icon).font(.title3)
                Text(d.title).font(.caption2).lineLimit(1).minimumScaleFactor(0.7)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 2)
            .foregroundStyle(active ? Color.accentColor : Color.primary)
            .contentShape(Rectangle())
        }
    }

    private func loadOrder() {
        let ids = savedOrder.split(separator: ",").map(String.init)
        var seen = Set<String>(); var out: [String] = []
        for id in ids where byId[id] != nil && !seen.contains(id) { out.append(id); seen.insert(id) }
        for d in dests where !seen.contains(d.id) { out.append(d.id) }   // surface any newly-added dests
        order = out
        if byId[selection] == nil { selection = order.first ?? "home" }
    }

    private func moveItems(from: IndexSet, to: Int) {
        order.move(fromOffsets: from, toOffset: to)
        savedOrder = order.joined(separator: ",")
    }
}
