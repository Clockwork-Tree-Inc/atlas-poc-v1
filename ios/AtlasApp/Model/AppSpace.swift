import Foundation

/// THE APP-SIDE SPACE SPINE — "everything is a space."
///
/// A space is recursive, kinded, and policied: it has a NAME, a KIND, a PERSISTENCE
/// tier, ITEMS (media/files/docs), MESSAGES (if it's a chat), MEMBERS, and CHILD spaces
/// (each itself a space). The profile's root is a `vault` space; you nest folders, chats,
/// groups inside it without limit. A chat LIVES inside the space it was started in — and
/// the Chats tab just walks the graph to collect every chat you're in.
///
/// A class + `ObservableObject` so a view observing one space refreshes when something is
/// added underneath it.
final class AppSpace: ObservableObject, Identifiable {
    let id: UUID
    let name: String
    let kind: SpaceKind
    let persistence: Persistence
    @Published var children: [AppSpace]
    @Published var items: [SpaceItem]        // media / files / docs held directly in this space
    @Published var messages: [ChatMessage]   // populated when kind == .chat
    @Published var members: [String]         // who's in this space's context (names; may include an AI agent)

    init(id: UUID = UUID(), name: String, kind: SpaceKind, persistence: Persistence,
         children: [AppSpace] = [], items: [SpaceItem] = [],
         messages: [ChatMessage] = [], members: [String] = []) {
        self.id = id
        self.name = name
        self.kind = kind
        self.persistence = persistence
        self.children = children
        self.items = items
        self.messages = messages
        self.members = members
    }

    /// Every chat at or below this space (depth-first) — the Chats tab uses this to
    /// consolidate all chats across the whole space graph.
    func allChats() -> [AppSpace] {
        var out: [AppSpace] = kind == .chat ? [self] : []
        for c in children { out.append(contentsOf: c.allChats()) }
        return out
    }

    /// Find a space by id anywhere in the subtree (for resolving the default capture folder).
    func find(_ target: UUID) -> AppSpace? {
        if id == target { return self }
        for c in children { if let hit = c.find(target) { return hit } }
        return nil
    }

    /// Every folder/vault (container) at or below this space — used to pick a capture folder.
    func allFolders() -> [AppSpace] {
        var out: [AppSpace] = (kind == .vault || kind == .folder) ? [self] : []
        for c in children { out.append(contentsOf: c.allFolders()) }
        return out
    }
}

/// Value-based navigation (`NavigationLink(value:)` + `navigationDestination`) so pushed
/// screens survive the ~1s ratchet re-renders instead of popping. Identity = the stable `id`.
extension AppSpace: Hashable {
    static func == (l: AppSpace, r: AppSpace) -> Bool { l.id == r.id }
    func hash(into h: inout Hasher) { h.combine(id) }
}

/// One item held directly in a space — a captured/imported file, sealed in the AtlasCore
/// vault under live presence. `vaultName` is the key to open it; `kind` drives the icon.
struct SpaceItem: Identifiable, Hashable {
    let id: UUID
    let vaultName: String      // key into the sealed AtlasCore vault
    let kind: String           // image | video | audio | pdf | text | file
    init(id: UUID = UUID(), vaultName: String, kind: String) {
        self.id = id; self.vaultName = vaultName; self.kind = kind
    }
    var display: String { vaultName }
}

/// One line in a chat space.
struct ChatMessage: Identifiable, Hashable {
    let id: UUID
    let sender: String         // a name, or an AI agent's label
    let text: String
    let isAgent: Bool
    init(id: UUID = UUID(), sender: String, text: String, isAgent: Bool) {
        self.id = id; self.sender = sender; self.text = text; self.isAgent = isAgent
    }
}

/// What a space IS — the renderer switches on this. NO "group" kind: there are just
/// CHATS, and a chat is 1-to-1 or group depending on how many members it has (humans, AI
/// agents, companies).
enum SpaceKind: String, CaseIterable, Identifiable {
    case vault, folder, chat, market
    var id: String { rawValue }

    var label: String {
        switch self {
        case .vault:  return "Vault"
        case .folder: return "Folder"
        case .chat:   return "Chat"
        case .market: return "Market"
        }
    }

    var systemImage: String {
        switch self {
        case .vault:  return "lock.square.stack.fill"
        case .folder: return "folder.fill"
        case .chat:   return "message.fill"
        case .market: return "cart.fill"
        }
    }

    /// The default persistence tier a freshly-created space of this kind lands on.
    var defaultPersistence: Persistence {
        switch self {
        case .vault:  return .device
        case .folder: return .device
        case .chat:   return .cloud
        case .market: return .server
        }
    }
}

/// WHERE a space lives — its durability/hosting tier.
enum Persistence: String, CaseIterable, Identifiable {
    case device, cloud, hosted, server
    var id: String { rawValue }

    var label: String {
        switch self {
        case .device: return "on device"
        case .cloud:  return "cloud"
        case .hosted: return "hosted"
        case .server: return "server"
        }
    }
}

// MARK: - Sealed persistence (Codable snapshot)

/// A Codable snapshot of a space subtree so the graph can be persisted **sealed in the vault**
/// (never plaintext on disk — space names and chat text are sensitive). IDs are preserved so
/// references (e.g. the default-capture-folder pointer) survive a reload.
struct SpaceDTO: Codable {
    var id: UUID
    var name: String
    var kind: String          // SpaceKind.rawValue
    var persistence: String   // Persistence.rawValue
    var children: [SpaceDTO]
    var items: [ItemDTO]
    var messages: [MessageDTO]
    var members: [String]
}

struct ItemDTO: Codable { var id: UUID; var vaultName: String; var kind: String }
struct MessageDTO: Codable { var id: UUID; var sender: String; var text: String; var isAgent: Bool }

/// A sealed snapshot of a persona's whole space graph plus its default-capture-folder pointer —
/// the unit persisted (sealed in the vault) so chats/spaces/folders survive relaunch (#18).
struct GraphSnapshot: Codable {
    var space: SpaceDTO
    var defaultCaptureFolderID: UUID?
    var defaultCaptureByType: [String: UUID]?   // per-type capture defaults (photo/video/audio/document)
}

extension AppSpace {
    /// Snapshot this subtree for sealed persistence.
    func snapshot() -> SpaceDTO {
        SpaceDTO(id: id, name: name, kind: kind.rawValue, persistence: persistence.rawValue,
                 children: children.map { $0.snapshot() },
                 items: items.map { ItemDTO(id: $0.id, vaultName: $0.vaultName, kind: $0.kind) },
                 messages: messages.map { MessageDTO(id: $0.id, sender: $0.sender, text: $0.text, isAgent: $0.isAgent) },
                 members: members)
    }

    /// Rebuild a subtree from a snapshot (IDs preserved).
    convenience init(dto: SpaceDTO) {
        self.init(id: dto.id,
                  name: dto.name,
                  kind: SpaceKind(rawValue: dto.kind) ?? .folder,
                  persistence: Persistence(rawValue: dto.persistence) ?? .device,
                  children: dto.children.map { AppSpace(dto: $0) },
                  items: dto.items.map { SpaceItem(id: $0.id, vaultName: $0.vaultName, kind: $0.kind) },
                  messages: dto.messages.map { ChatMessage(id: $0.id, sender: $0.sender, text: $0.text, isAgent: $0.isAgent) },
                  members: dto.members)
    }
}
