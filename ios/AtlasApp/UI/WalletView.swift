import SwiftUI
import AtlasCore

/// PoLE wallet — "the game of living." Your presence receipts (proof you sampled genuine live
/// entropy) and your earnings from stores that PAY you to look at their products. PoLE is what makes
/// the paid-attention loop un-fakeable: only a proven live source earns, once.
struct WalletView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var toast = ""

    var body: some View {
        List {
            summarySection
            offersSection
            receiptsSection
            explainerSection
        }
        .navigationTitle("Wallet")
        .onAppear { if session.attentionOffers.isEmpty { session.loadAttentionOffers() } }
        .overlay(alignment: .bottom) {
            if !toast.isEmpty {
                Text(toast).font(.callout.bold()).padding(.horizontal, 16).padding(.vertical, 10)
                    .background(.ultraThinMaterial, in: Capsule()).padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
    }

    private var summarySection: some View {
        Section {
            HStack {
                stat("Earned", "\(session.attentionEarnings) ⏣", .green)
                Divider()
                stat("Presence", presenceLabel, .blue)
                Divider()
                stat("Receipts", "\(session.presenceReceipts.count)", .primary)
            }
            .frame(maxWidth: .infinity)
            HStack(spacing: 8) {
                Image(systemName: session.poleMinting ? "waveform.path.ecg" : "pause.circle")
                    .foregroundStyle(session.poleMinting ? .green : .secondary)
                    .symbolEffect(.pulse, options: .repeating, isActive: session.poleMinting)
                Text(session.poleMinting
                     ? "PoLE live — your presence is recording itself on the clock"
                     : "Presence paused — PoLE records automatically while the app is alive")
                    .font(.caption)
            }
        } header: {
            Text("Your living")
        } footer: {
            Text("You never sign anything. PoLE runs on a clock: while the app stays alive on location + sensors, it continuously mints receipts committing to genuine LIVE ENTROPY — unfakeable, unreproducible, identity-free. They back your UBI eligibility and let stores pay you for real attention.")
        }
    }

    private var offersSection: some View {
        Section {
            if session.attentionOffers.isEmpty {
                Text("No offers right now.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(session.attentionOffers.enumerated()), id: \.offset) { _, offer in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(String(decoding: offer.productID, as: UTF8.self))
                        Text("pays you to look").font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { let r = await session.viewAndEarn(offer); flash(r) }
                    } label: {
                        Text("View +\(offer.reward) ⏣").font(.callout.bold())
                    }
                    .buttonStyle(.borderedProminent).tint(.green)
                }
            }
        } header: {
            Text("Stores that pay you to look")
        } footer: {
            Text("The inverse of ads: you're compensated for your attention, not harvested. You get paid once per offer, and only because you're a proven live human — a bot can't farm this.")
        }
    }

    private var receiptsSection: some View {
        Section("Presence receipts") {
            if session.presenceReceipts.isEmpty {
                Text("None yet — tap “Record presence now.”").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(session.presenceReceipts.prefix(20).enumerated()), id: \.offset) { _, r in
                HStack {
                    Image(systemName: r.signers.count >= 2 ? "checkmark.seal.fill" : "waveform")
                        .foregroundStyle(r.signers.count >= 2 ? .green : .blue)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(r.windowEnd - r.windowStart)s presence")
                        Text(r.signers.count >= 2 ? "\(r.signers.count) streams — corroborated" : "1 stream")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(idHex(r.id())).font(.caption2.monospaced()).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var explainerSection: some View {
        Section {
            Text("PoLE = Proof of Living Entropy. Being a present, living human is the source of value here — the economy pays you for existing and attending, and the same live entropy that proves you're real also feeds your keys. Multi-stream receipts (e.g. + a wearable) are the strongest.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func stat(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.headline).foregroundStyle(color)
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity)
    }

    private var presenceLabel: String {
        let s = session.totalPresenceSeconds
        return s >= 60 ? "\(s / 60)m" : "\(s)s"
    }

    private func idHex(_ d: Data) -> String { String(d.map { String(format: "%02x", $0) }.joined().prefix(8)) }

    private func flash(_ s: String) {
        withAnimation { toast = s }
        Task { try? await Task.sleep(nanoseconds: 1_600_000_000); await MainActor.run { withAnimation { toast = "" } } }
    }
}
