# Finding: `u16` add-overflow panic parsing a malformed BGP UPDATE

- **Target:** `fuzz_parse` (rustybgp-packet BGP wire decoder)
- **Reproducer:** `crash-repro.bin` (36 bytes) — a BGP UPDATE (type 2) whose
  Withdrawn Routes Length and Total Path Attribute Length fields are chosen so
  their sum overflows `u16`.
- **Crash:** `thread panicked at packet/src/bgp.rs:2904:32: attempt to add with overflow`

## Cause

`PeerCodec::parse_message`, UPDATE branch (`packet/src/bgp.rs:2904`):

```rust
let withdrawn_len = c.read_u16::<NetworkEndian>().unwrap();      // attacker-controlled
...
let attr_len = c.read_u16::<...>()...;                           // attacker-controlled
if buf.len() < (withdrawn_len + attr_len + MINIMUM_UPDATE_LENGTH as u16).into() {
    return Err(malformed());
}
```

`withdrawn_len`, `attr_len` and `MINIMUM_UPDATE_LENGTH as u16` are all `u16`, so
`withdrawn_len + attr_len + ...` is computed in `u16` and overflows for large
field values (e.g. `withdrawn_len = 0xFFFF`). Note the *earlier* length check at
line 2897 correctly promotes to `usize` (`withdrawn_len as usize + MINIMUM_UPDATE_LENGTH`);
line 2904 does not.

## Impact

- With overflow checks on (debug / `--debug-assertions`, the OSS-Fuzz Rust fuzzing
  profile), a single crafted UPDATE panics the decoder → session task abort (DoS).
- In a release build (overflow checks off, RustyBGP's default) the addition wraps
  silently, so the intended "message long enough for the declared lengths" bounds
  check is bypassed for the overflowing case — a correctness hole in input
  validation rather than a panic.

## One-line fix

Promote to `usize` before adding, matching line 2897:

```rust
if buf.len() < withdrawn_len as usize + attr_len as usize + MINIMUM_UPDATE_LENGTH {
    return Err(malformed());
}
```

## Notes

Not masked in the harness (per the porting brief: crashes/OOMs are real findings
and must not be guarded). Kept OUT of `testsuite/` so it is never replayed as a
seed. Verified: `/mayhem/fuzz_parse -runs=1 crash-repro.bin` panics at the line
above.
