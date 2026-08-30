import SwiftUI
import UIKit
import CoreText

/// PDF generation with an ATLAS PROVENANCE stamp. Renders a title + body to a paginated US-Letter
/// PDF and prints a provenance footer on every page: the author, their did:cid, the content hash,
/// and the persona's signature over that hash. So the PDF is self-describing and tamper-evident —
/// anyone can recompute the hash and check the signature. (Full C2PA-manifest embedding is the next
/// step; this is the signed, verifiable floor built on the authorship keys we already have.)
enum PDFExport {

    static func make(title: String, body: String, authorLabel: String, did: String,
                     contentHashHex: String, signatureHex: String) -> Data {
        let pageW: CGFloat = 612, pageH: CGFloat = 792, margin: CGFloat = 54
        let footerH: CGFloat = 26
        let bounds = CGRect(x: 0, y: 0, width: pageW, height: pageH)
        let renderer = UIGraphicsPDFRenderer(bounds: bounds)

        let attr = NSMutableAttributedString(
            string: title + "\n\n",
            attributes: [.font: UIFont.boldSystemFont(ofSize: 22), .foregroundColor: UIColor.label])
        attr.append(NSAttributedString(
            string: body,
            attributes: [.font: UIFont.systemFont(ofSize: 12), .foregroundColor: UIColor.label]))

        let framesetter = CTFramesetterCreateWithAttributedString(attr)
        let footer = "ATLAS provenance · \(authorLabel) · \(did.prefix(30))… · sha3:\(contentHashHex.prefix(16))… · sig:\(signatureHex.prefix(16))…"
        let footerAttrs: [NSAttributedString.Key: Any] = [
            .font: UIFont.systemFont(ofSize: 7), .foregroundColor: UIColor.secondaryLabel]

        return renderer.pdfData { ctx in
            var start = 0
            let total = attr.length
            repeat {
                ctx.beginPage()
                let cg = ctx.cgContext
                let textRect = CGRect(x: margin, y: margin, width: pageW - 2 * margin,
                                      height: pageH - 2 * margin - footerH)
                // CoreText draws in a flipped coordinate space — isolate that transform.
                cg.saveGState()
                cg.textMatrix = .identity
                cg.translateBy(x: 0, y: pageH)
                cg.scaleBy(x: 1, y: -1)
                let flippedRect = CGRect(x: textRect.minX, y: pageH - textRect.maxY,
                                         width: textRect.width, height: textRect.height)
                let frame = CTFramesetterCreateFrame(framesetter, CFRangeMake(start, 0),
                                                     CGPath(rect: flippedRect, transform: nil), nil)
                CTFrameDraw(frame, cg)
                let visible = CTFrameGetVisibleStringRange(frame)
                start += visible.length
                cg.restoreGState()
                // Footer in normal UIKit coordinates.
                (footer as NSString).draw(in: CGRect(x: margin, y: pageH - margin, width: pageW - 2 * margin, height: footerH),
                                          withAttributes: footerAttrs)
            } while start < total && start > 0
        }
    }
}

/// UIActivity share sheet for a generated file (PDF export, log export, …).
struct ActivityShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
