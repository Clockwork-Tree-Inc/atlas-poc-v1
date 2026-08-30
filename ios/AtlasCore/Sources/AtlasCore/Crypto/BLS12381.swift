import CBlst
import Foundation

/// Thin bridge to the vendored blst library (supranational BLS12-381 pairings), the on-device backend
/// for the anonymous-credential stack (Pointcheval-Sanders — see AnonCred.swift). blst is built portable
/// (pure C, no assembly) so it runs on macOS and iOS arm64.
public enum BLS12381 {

    /// Sanity check that the vendored blst links and computes a pairing on this platform: e(G1, G2) != 1.
    public static func pairingSelfCheck() -> Bool {
        var pAff = blst_p1_affine(); blst_p1_to_affine(&pAff, blst_p1_generator())
        var qAff = blst_p2_affine(); blst_p2_to_affine(&qAff, blst_p2_generator())
        var ml = blst_fp12()
        blst_miller_loop(&ml, &qAff, &pAff)
        var f = blst_fp12()
        blst_final_exp(&f, &ml)
        return !blst_fp12_is_one(&f)
    }
}
