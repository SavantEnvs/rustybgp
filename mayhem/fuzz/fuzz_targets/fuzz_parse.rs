// In-process libFuzzer harness for RustyBGP's BGP wire-message decoder.
//
// The fuzz surface is `rustybgp-packet` — the crate that turns raw bytes off the
// wire into a `ParsedMessage` (OPEN / UPDATE / NOTIFICATION / KEEPALIVE /
// ROUTE-REFRESH), the exact code an untrusted BGP peer can drive. We feed the
// fuzzer's bytes straight into `PeerCodec::parse_message` (no file I/O, no
// network — bytes come only from the fuzzer per SPEC §6.2 item 13), then, on a
// successful parse, run the RFC 7606 `validate_message` normalization path too
// (both eBGP and iBGP), which is the second half of the receive pipeline.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rustybgp_packet::bgp::{Family, FamilyState, PeerCodec};
use rustybgp_packet::validate_message;

fuzz_target!(|data: &[u8]| {
    let mut codec = PeerCodec::new();
    // Negotiate a spread of address families so the MP_REACH_NLRI / MP_UNREACH_NLRI
    // decode paths (IPv4/IPv6 unicast, VPN, EVPN, flowspec) are reachable instead of
    // being rejected up front as un-negotiated.
    for f in [
        Family::IPV4,
        Family::IPV6,
        Family::IPV4_VPN,
        Family::IPV6_VPN,
        Family::L2VPN_EVPN,
        Family::IPV4_FLOWSPEC,
    ] {
        codec.set_family(f, FamilyState::default());
    }

    if let Ok(parsed) = codec.parse_message(data) {
        // Exercise the validate/normalize path for both peer types; consume the
        // returned iterator so the work is not optimized away.
        if let Ok(iter) = validate_message(parsed.clone(), true) {
            for _m in iter {}
        }
        if let Ok(iter) = validate_message(parsed, false) {
            for _m in iter {}
        }
    }
});
