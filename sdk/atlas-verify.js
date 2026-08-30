// Atlas verify — a tiny, dependency-free JS client for the verified-human endpoint.
// Node 18+ (built-in fetch) or any modern browser. See docs/VERIFY_QUICKSTART.md.
//
//   import { isLiveHuman } from "./atlas-verify.js";
//   if (await isLiveHuman("https://node.clockwork-tree.com", token, { minTier: 2 })) {
//     // a live human, tier >= 2, verified offline by signature
//   }

/**
 * POST a presented Atlas credential to /verify/presence and return the verdict object:
 * { valid, verified_human, assurance_tier, epoch, subject }.
 * `publicKey` is optional — the node resolves the presenter from the token's DID if registered.
 */
export async function verifyPresence(nodeUrl, token, { format = "vc", audience, minTier = 1, publicKey } = {}) {
  const body = { format, token, min_tier: minTier };
  if (audience != null) body.audience = audience;
  if (publicKey != null) body.public_key = publicKey;
  const res = await fetch(nodeUrl.replace(/\/+$/, "") + "/verify/presence", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`verify failed: HTTP ${res.status}`);
  return res.json();
}

/** True iff the token proves a live human at assurance tier >= minTier. */
export async function isLiveHuman(nodeUrl, token, opts = {}) {
  return Boolean((await verifyPresence(nodeUrl, token, opts)).valid);
}
