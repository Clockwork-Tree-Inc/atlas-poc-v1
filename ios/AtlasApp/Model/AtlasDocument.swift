import Foundation

/// A block-based, provenanced document (novels, articles, notes). Serialized to JSON, sealed
/// in the vault, and attested at create/save (verified-human authorship). Blocks are text,
/// link, image, or video — image/video reference vault items. External services would be link
/// blocks, never live web embeds (that boundary is enforced elsewhere).
struct DocBlock: Codable, Identifiable, Hashable {
    var id = UUID()
    var type: BlockType
    var text: String = ""       // text body, or link label / caption
    var url: String = ""        // link URL
    var vaultName: String = ""  // image / video item reference

    enum BlockType: String, Codable { case text, link, image, video }
}

struct AtlasDocument: Codable {
    var title: String
    var blocks: [DocBlock]

    static func empty(title: String) -> AtlasDocument {
        AtlasDocument(title: title, blocks: [DocBlock(type: .text, text: "")])
    }
    func encoded() -> Data { (try? JSONEncoder().encode(self)) ?? Data() }
    static func decode(_ data: Data) -> AtlasDocument? { try? JSONDecoder().decode(AtlasDocument.self, from: data) }
}
