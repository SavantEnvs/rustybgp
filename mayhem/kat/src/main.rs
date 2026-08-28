// KAT (known-answer test) oracle probe for the RustyBGP Mayhem integration.
//
// Drives rustybgp-packet's PUBLIC decode API (`PeerCodec::parse_message`) on
// FIXED, hand-built BGP wire messages and prints exact, deterministic values.
// mayhem/test.sh runs this binary and greps the exact expected lines (SPEC §6.3
// anti-reward-hacking): a PATCH that neuters the parser (or this probe) changes
// or eliminates the output and the oracle FAILS. This is the SAME code path the
// fuzz target explores. No file I/O, no network.

use rustybgp_packet::bgp::{Notification, ParsedMessage, PeerCodec};

// Build a BGP message: 16-byte all-ones marker + 2-byte length + 1-byte type +
// body. `len` is the total on-wire length written into the header length field.
fn msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = 19 + body.len();
    let mut v = vec![0xFF; 16];
    v.push((total >> 8) as u8);
    v.push((total & 0xff) as u8);
    v.push(msg_type);
    v.extend_from_slice(body);
    v
}

fn main() {
    let mut codec = PeerCodec::new();

    // KAT1: a well-formed KEEPALIVE (type 4, empty body) must decode as Keepalive.
    let keepalive = msg(4, &[]);
    let k = codec
        .parse_message(&keepalive)
        .expect("KAT1: KEEPALIVE must parse");
    println!("KAT1 keepalive={}", matches!(k, ParsedMessage::Keepalive));

    // KAT2: an OPEN (type 1): version=4, AS=200, holdtime=90, BGP-id=1.2.3.4,
    // no optional parameters. Assert the parsed header field values exactly.
    let open_body = [
        0x04, // version 4
        0x00, 0xC8, // AS 200
        0x00, 0x5A, // holdtime 90
        0x01, 0x02, 0x03, 0x04, // router id 1.2.3.4 == 0x01020304
        0x00, // opt param len 0
    ];
    let open = msg(1, &open_body);
    match codec.parse_message(&open).expect("KAT2: OPEN must parse") {
        ParsedMessage::Open(o) => {
            println!(
                "KAT2 as={} holdtime={} routerid={}",
                o.as_number,
                o.holdtime.seconds(),
                o.router_id
            );
        }
        _ => panic!("KAT2: expected an OPEN message"),
    }

    // KAT3: a NOTIFICATION (type 3): code=6 (Cease), subcode=4. Assert accessors.
    let notif = msg(3, &[0x06, 0x04]);
    match codec.parse_message(&notif).expect("KAT3: NOTIFICATION must parse") {
        ParsedMessage::Notification(n) => {
            println!(
                "KAT3 code={} subcode={}",
                n.notification_code(),
                n.notification_subcode()
            );
        }
        _ => panic!("KAT3: expected a NOTIFICATION message"),
    }

    // KAT4: a malformed OPEN (type 1) that is truncated to just the 19-byte header
    // MUST be rejected (below the 29-byte OPEN minimum). This is an error-path
    // oracle: a neutered parser that "accepts everything" also fails this KAT.
    let truncated_open = msg(1, &[]);
    let rejected: bool = matches!(codec.parse_message(&truncated_open), Err(_));
    // Reference the type so an over-eager optimizer can't drop the decode.
    let _ = Notification::from_notification(1, 1, vec![]);
    println!("KAT4 reject={rejected}");
}
