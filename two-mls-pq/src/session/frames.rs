//! Frame layer of the session wire protocol: the plaintext tag bytes, the
//! side-band frame classification the host routes on, and every
//! length-prefixed frame encoder/decoder. Pure functions over bytes — no
//! session state. The attacker-facing parsers live here in one audited
//! place (see `read_sections`), with the fuzz entry point at the bottom.

use super::*;

// ── The tag space ───────────────────────────────────────────────────────────────────
// Every wire blob is discriminated by its first byte, so these values are ONE global
// space — but they are declared in three places, because each tag lives with the thing it
// tags: `APQ_TAG` (0x01) in the `apq` crate, `INITIAL_ENVELOPE_TAG` (0x05) in
// `key_packages` (it rides the invitation channel and is not a session frame), and the
// rest here. Ownership is local; allocation is global. That split is the hazard: a
// collision is a silent wire misclassification rather than a compile error, and the file
// you read when adding a session frame is not the file that declares the envelope tag.
//
// The invariants below hold across all three sites; `tests::tag_space_holds` enforces them.
//   * DISTINCT — see above. This is not hypothetical: 0x15 was once claimed by both the
//     envelope tag and a new side-band frame, because the space had no single record.
//   * ODD — an MLSMessage begins with ProtocolVersion 0x0001 (big-endian), so its first
//     byte is always 0x00. Reserving the entire even space is what lets a tagged frame and
//     a bare MLS message be told apart from byte 0 alone, and what makes the message
//     frame's staple slot self-discriminating (welcome 0x01 vs. commit 0x00) with no
//     discriminator byte of its own.
//
// The space is BANDED. Each band owns a contiguous range of odd bytes, is packed from its
// start, and keeps its remaining room at the end:
//   0x01–0x03  message path      — APQWelcome, message frame. FULL, and closed by design:
//                                  the message path has exactly one shape.
//   0x05–0x0F  A.1 establishment — envelope (invitation channel), pre-establishment staple.
//                                  2 of 6; the hybrid nested envelope would land here.
//   0x11–0x2F  PQ side-band      — exactly the tags `pq_frame_kind` classifies, in lifecycle
//                                  order: bootstrap, then ratchet, then re-key. 8 of 16.
//
// Banding is what makes "the side-band is 0x11–0x2F" a claim that survives growth, and it
// was bought by a renumber: the tags were allocation-ordered, so appending the A.4 bind past
// the end left the side-band non-contiguous and silently falsified five "0x05–0x11" range
// shorthands across the code and book. Prefer `pq_frame_kind` to a range test regardless —
// but a range written in prose should at least not be a lie.
//
// The room is free in both directions that could have cost something. On the wire: header
// encryption seals every blob, so a tag is never observed and a sparse space fingerprints
// nothing. In the tests: `tag_space_holds` asserts density WITHIN a band and membership
// against that band's bounds, so room at a band's end is legal while appending PAST the end
// still fails. The reserve costs no enforcement — which is why the sizes can be generous.
// They are reserves, not predictions: only the message path's fullness is a design claim.
//
// To add a flow: append at the end of its band — no renumber, that is what the room is for —
// then add it to `tests::BANDS` and update the book's `wire-format.md` table and
// `BINDING_CONTRACT_VERSION`. Only a band that FILLS forces the bands below it to move.

// APQWelcome wire format (0x01) + encode/decode live in the `apq` crate (imported above).
// The APQWelcome appears both as a standalone frame (invitation channel, and optional
// standalone delivery of the acceptor's return welcome) and as the message frame's staple
// slot until the sender's first commit exists.
//
// Message frame: [0x03 tag][staple][Upd(sender) proposal][app], each section u32-LE
// length-prefixed and NEVER empty (see encode_message_frame). The one message-path frame:
// `staple` is the sender's latest send-group classical commit, re-stapled on every frame
// until superseded — or the send group's APQWelcome until the first commit exists. The
// slot self-discriminates by first byte (an APQWelcome starts 0x01, an MLSMessage 0x00).
// A rotation is not a frame kind: it is a commit whose authenticated_data carries the new
// ClientId (ratchet commits have empty AD). Per A.2 the sender commits in its OWN send
// group; the receiver applies the stapled commit to its recv group idempotently and stages
// the stapled Upd for app approval.
pub(crate) const MESSAGE_FRAME_TAG: u8 = 0x03;

// ── Band: A.1 establishment (0x05–0x0F, 2 of 6 used) ────────────────────────────────
// 0x05 is `key_packages::INITIAL_ENVELOPE_TAG` — declared there, not here, because an
// envelope is not a session frame. It heads this band; the staple below packs in behind it,
// and the room past 0x07 is where a hybrid nested envelope would go.

/// §A.1 pre-establishment app staple: `[0x07][BSG-cl PrivateMessage]` — the initiator's
/// app message riding a §A.1 envelope's `stapled_message` section before its recv group
/// exists (the 0x03 message frame is structurally unavailable then: its proposal section
/// is mandatory and there is no recv group to propose into). Travels ONLY inside the
/// HPKE envelope on the invitation channel — never header-sealed, so it is deliberately
/// NOT an `opened_frame_kind`; the host hands it to `process_incoming` after the join.
pub(crate) const PRE_ESTABLISHMENT_APP_TAG: u8 = 0x07;

// ── Band: PQ side-band (0x11–0x2F, 8 of 16 used) ────────────────────────────────────
// Exactly the tags `pq_frame_kind` classifies, ordered by lifecycle: a session bootstraps
// its deferred PQ half once (A.4), then ratchets it repeatedly (A.3), and re-keys it
// occasionally (A.5). Note the section numbers do NOT follow that order — the spec numbers
// are historical; renumbering them is a separate, deferred change.

/// A.4 bootstrap: this side's PQ key package, sent so the peer can stand up its deferred
/// send-group PQ half.
pub(crate) const PQ_BOOTSTRAP_KP_TAG: u8 = 0x11;

/// A.4 bootstrap reply: the new PQ group's welcome. PQ-groups-only — no classical commit
/// rides here; the initiator's bind (0x15) is what reaches a classical group.
pub(crate) const PQ_BOOTSTRAP_WELCOME_TAG: u8 = 0x13;

/// A.4 bootstrap bind — the round's terminal frame, and structurally A.3's bind (0x1B):
/// `[pq partial-commit][classical commit][app]`. The initiator sends it after joining the
/// welcomed group, and it differs from A.3's only in where the injected secret came from —
/// an exporter off the newly joined group rather than a KEM exchange. That secret is
/// derivable only from INSIDE that group, so a bind that applies at all proves the
/// initiator joined: A.4's receipt is a side effect of entropy it had to chain anyway.
pub(crate) const PQ_BOOTSTRAP_BIND_TAG: u8 = 0x15;

// PQ ratchet (architecture-diagrams PR #2 §A.3), cryptokit only:
// 0x17 carries the initiator's ML-KEM encapsulation key, 0x19 the responder's ciphertext,
// 0x1B the bind = [pq partial-commit][classical commit][app], all length-prefixed.
pub(crate) const PQ_EK_TAG: u8 = 0x17;
pub(crate) const PQ_CT_TAG: u8 = 0x19;
pub(crate) const PQ_BIND_TAG: u8 = 0x1B;

// A.5 rekey (architecture-diagrams §A.5), cryptokit only — updatePath commits run on the
// PQ groups alone so the classical ratchet is never blocked behind a large ML-KEM
// updatePath. 0x1D carries the initiator's Upd' proposal for the responder's send-PQ;
// 0x1F = [Commit'][counter-Upd'-or-empty], length-prefixed — the responder's reply
// carries its counter-proposal, the initiator's final commit an empty slot. Each Commit'
// cross-injects a PSK exported from the opposite PQ send group; the bumped pq_epoch
// reconciles into APQInfo at the next A.3 bind (no AppDataUpdate rides these commits).
pub(crate) const PQ_REKEY_UPD_TAG: u8 = 0x1D;
pub(crate) const PQ_REKEY_COMMIT_TAG: u8 = 0x1F;

/// Encode a pre-establishment app staple: `[0x07][app message bytes]`.
pub(crate) fn encode_pre_establishment_app(app: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + app.len());
    out.push(PRE_ESTABLISHMENT_APP_TAG);
    out.extend_from_slice(app);
    out
}

/// The eight PQ side-band frame kinds the host routes through `TwoMlsPqSession::ingest`
/// (the `begin`/`ingest`/`advance` surface in the AbstractTwoMLS adapter). Exported so the
/// host classifies a frame from THIS binary via [`pq_frame_kind`] instead of hardcoding the
/// tag bytes: the tags stay defined once, above, and a renumber can no longer drift out of
/// sync with a hand-copied host switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PqFrameKind {
    /// 0x05 — A.3 ratchet: the initiator's ML-KEM encapsulation key.
    RatchetEphemeralKey,
    /// 0x07 — A.3 ratchet: the responder's ciphertext.
    RatchetCiphertext,
    /// 0x09 — A.3 ratchet: the bind (`[pq partial-commit][classical commit][app]`).
    RatchetBind,
    /// 0x0B — A.4 bootstrap: this side's PQ key package.
    BootstrapKeyPackage,
    /// 0x0D — A.4 bootstrap: the reply (the new PQ group's welcome).
    BootstrapWelcome,
    /// 0x15 — A.4 bootstrap: the initiator's terminal bind
    /// (`[pq partial-commit][classical commit][app]`), which also confirms the welcome.
    BootstrapBind,
    /// 0x0F — A.5 rekey: the initiator's Upd' proposal.
    RekeyUpdate,
    /// 0x11 — A.5 rekey: the responder's `[Commit'][counter-Upd'-or-empty]` reply.
    RekeyCommit,
}

/// How [`TwoMlsPqSession::pq_pending_outbound`] seals the retained frame it hands out.
///
/// The frame is retained as PLAINTEXT and sealed per hand-out, so the host chooses whether
/// repeated hand-outs of one frame carry the same wire bytes. The choice is the host's
/// because only the host knows how it transmits: the trade is unlinkability against a
/// stable base, and neither is safer in general.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SideBandSealing {
    /// Seal afresh on every hand-out — a new random nonce, so repeated sends of one
    /// retained frame are distinct on the wire and a passive observer cannot correlate
    /// them (a stalled round would otherwise repeat byte-identical ciphertext).
    ///
    /// Correct for a host that transmits the frame WHOLE. Sealing is a small AEAD over a
    /// short frame, so the per-send cost is noise.
    Fresh,
    /// Seal once and hand out identical bytes for as long as the retained frame is
    /// unchanged.
    ///
    /// Required by a host that CHUNKS: chunks are cut from the sealed bytes, and pieces cut
    /// from two different seals never reassemble — the base must hold still across a pass.
    /// The cost is exactly the correlation `Fresh` avoids: repeated sends are
    /// byte-identical, marking a re-send to anyone watching.
    ///
    /// Stability is scoped to the FRAME, not to time: the moment the round advances and
    /// this side produces its next frame, the next hand-out is a fresh seal of the new
    /// frame — which is what a chunking host wants (an in-flight pass for a superseded
    /// frame is worthless). The cached seal is live-only and does not ride the archive, so
    /// a restore restarts the pass with a new base; a host must be able to re-chunk anyway,
    /// since that is what a lost pass demands.
    Stable,
}

/// Classify a PQ side-band frame by its leading tag byte (`message[0]`). Returns `None` for
/// any byte that is not one of the seven side-band tags — the host treats that as a malformed
/// side-band frame. Single source of truth for the wire tags: the host dispatches on the
/// returned kind rather than matching raw bytes it would otherwise have to keep in sync here.
#[uniffi::export]
pub fn pq_frame_kind(tag: u8) -> Option<PqFrameKind> {
    Some(match tag {
        PQ_EK_TAG => PqFrameKind::RatchetEphemeralKey,
        PQ_CT_TAG => PqFrameKind::RatchetCiphertext,
        PQ_BIND_TAG => PqFrameKind::RatchetBind,
        PQ_BOOTSTRAP_KP_TAG => PqFrameKind::BootstrapKeyPackage,
        PQ_BOOTSTRAP_WELCOME_TAG => PqFrameKind::BootstrapWelcome,
        PQ_BOOTSTRAP_BIND_TAG => PqFrameKind::BootstrapBind,
        PQ_REKEY_UPD_TAG => PqFrameKind::RekeyUpdate,
        PQ_REKEY_COMMIT_TAG => PqFrameKind::RekeyCommit,
        _ => return None,
    })
}

/// What `open_incoming` found once the header seal was removed — the routing signal the
/// plaintext tag byte carried before header encryption hid it. The host dispatches on
/// this: `Message` to `process_incoming`, `PqSideBand` to the named `pq_*` entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OpenedFrameKind {
    /// A standalone welcome (`0x01`) or message frame (`0x03`) — route the opened frame
    /// to `process_incoming`, which handles both by their now-decrypted leading tag.
    Message,
    /// A PQ side-band frame — route the opened frame to the `pq_*` method named by `kind`.
    PqSideBand { kind: PqFrameKind },
}

/// The result of removing a frame's header seal: the plaintext frame plus its routing
/// kind. The frame is the exact bytes the pre-header-encryption entry points expect.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OpenedFrame {
    pub kind: OpenedFrameKind,
    pub frame: Vec<u8>,
}

/// Classify an opened (plaintext) frame by its leading tag. `None` for any byte that is
/// neither a message-path nor a side-band tag — a successfully-decrypted-but-unrecognized
/// frame, treated as malformed.
pub(crate) fn opened_frame_kind(tag: u8) -> Option<OpenedFrameKind> {
    match tag {
        APQ_TAG | MESSAGE_FRAME_TAG => Some(OpenedFrameKind::Message),
        other => pq_frame_kind(other).map(|kind| OpenedFrameKind::PqSideBand { kind }),
    }
}

/// Append `part` to `out` as a u32-LE length-prefixed section.
pub(crate) fn push_section(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

/// Read exactly `N` u32-LE length-prefixed sections from `body` (the frame payload *after* the
/// 1-byte tag), rejecting truncation and any trailing bytes. Single source of truth for the
/// length-prefixed framing used by all bundle/commit frames, so the bounds checks live in one
/// audited place rather than being re-derived per frame type.
fn read_sections<const N: usize>(body: &[u8]) -> Result<[Vec<u8>; N]> {
    let mut rest = body;
    let mut out: [Vec<u8>; N] = std::array::from_fn(|_| Vec::new());
    for slot in out.iter_mut() {
        if rest.len() < 4 {
            return Err(TwoMlsPqError::Mls);
        }
        let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err(TwoMlsPqError::Mls);
        }
        *slot = rest[..len].to_vec();
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(out)
}

pub(crate) fn encode_pq_bind(
    pq_commit: Vec<u8>,
    classical_commit: Vec<u8>,
    app: Vec<u8>,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + 4 + pq_commit.len() + 4 + classical_commit.len() + 4 + app.len());
    out.push(PQ_BIND_TAG);
    push_section(&mut out, &pq_commit);
    push_section(&mut out, &classical_commit);
    push_section(&mut out, &app);
    out
}

/// Encode the A.4 bootstrap reply: `[0x0D][pq_welcome…]`. PQ-groups-only per the spec — no
/// classical commit rides along; the initiator's bind (0x15) carries the classical half.
pub(crate) fn encode_bootstrap_welcome(pq_welcome: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + pq_welcome.len());
    out.push(PQ_BOOTSTRAP_WELCOME_TAG);
    out.extend_from_slice(&pq_welcome);
    out
}

pub(crate) fn decode_bootstrap_welcome(bytes: &[u8]) -> Result<Vec<u8>> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BOOTSTRAP_WELCOME_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(rest.to_vec())
}

/// Encode the A.4 bootstrap bind: `[0x15][pq_commit][classical_commit][app]` — A.3's bind
/// shape (`encode_pq_bind`) under its own tag, so the two rounds' terminal frames cannot be
/// confused at the door.
pub(crate) fn encode_bootstrap_bind(
    pq_commit: Vec<u8>,
    classical_commit: Vec<u8>,
    app: Vec<u8>,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + 4 + pq_commit.len() + 4 + classical_commit.len() + 4 + app.len());
    out.push(PQ_BOOTSTRAP_BIND_TAG);
    push_section(&mut out, &pq_commit);
    push_section(&mut out, &classical_commit);
    push_section(&mut out, &app);
    out
}

pub(crate) fn decode_bootstrap_bind(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BOOTSTRAP_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [pq_commit, classical_commit, app] = read_sections::<3>(rest)?;
    Ok((pq_commit, classical_commit, app))
}

pub(crate) fn decode_pq_bind(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [pq_commit, classical_commit, app] = read_sections::<3>(rest)?;
    Ok((pq_commit, classical_commit, app))
}

/// Encode an A.5 rekey Commit' frame: `[0x11][commit][counter-Upd'-or-empty]`.
pub(crate) fn encode_pq_rekey_commit(commit: Vec<u8>, counter_proposal: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + commit.len() + counter_proposal.len());
    out.push(PQ_REKEY_COMMIT_TAG);
    push_section(&mut out, &commit);
    push_section(&mut out, &counter_proposal);
    out
}

pub(crate) fn decode_pq_rekey_commit(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_REKEY_COMMIT_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [commit, counter_proposal] = read_sections::<2>(rest)?;
    Ok((commit, counter_proposal))
}

/// The one message-path frame (0x03): `[staple][Upd(sender) proposal][app]`, every
/// section non-empty. `staple` is the sender's latest send-group classical commit — or
/// the send group's APQWelcome until the first commit exists — re-sent on every frame so
/// any single received frame brings the peer up to the sender's current epoch.
pub(crate) fn encode_message_frame(staple: &[u8], proposal: Vec<u8>, app: Vec<u8>) -> Vec<u8> {
    debug_assert!(!staple.is_empty() && !proposal.is_empty() && !app.is_empty());
    let mut out = Vec::with_capacity(1 + 12 + staple.len() + proposal.len() + app.len());
    out.push(MESSAGE_FRAME_TAG);
    push_section(&mut out, staple);
    push_section(&mut out, &proposal);
    push_section(&mut out, &app);
    out
}

pub(crate) fn decode_message_frame(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != MESSAGE_FRAME_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    let [staple, proposal, app] = read_sections::<3>(rest)?;
    // No section is optional in this format: an empty section is a retired-shape or
    // malformed frame, rejected here rather than surfacing as a downstream MLS error.
    if staple.is_empty() || proposal.is_empty() || app.is_empty() {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((staple, proposal, app))
}

/// Fuzzing entry for the message-frame decoder — the attacker-facing frame parser (see
/// `fuzz/fuzz_targets/message_frame_decode.rs`). Not API; hidden and exposed only so the
/// out-of-workspace fuzz crate can reach the otherwise-private decoder.
#[doc(hidden)]
pub fn fuzz_decode_message_frame(bytes: &[u8]) {
    let _ = decode_message_frame(bytes);
}

/// The message frame's proposal section is self-describing: `[u32-LE proposing-len]
/// [proposing][proposal message]`, where `proposing` is the ClientId the Upd's new
/// leaf carries (the sender's rotation candidate, or its current identity on a routine
/// round). The receiver surfaces it in `QueuedRemoteProposal.proposing` BEFORE the
/// proposal touches any group, and `queue_proposal` verifies it against the Update's
/// actual leaf credential — lying is caught before the proposal enters a cache.
pub(crate) fn encode_proposal_section(proposing: &[u8], proposal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + proposing.len() + proposal.len());
    out.extend_from_slice(&(proposing.len() as u32).to_le_bytes());
    out.extend_from_slice(proposing);
    out.extend_from_slice(proposal);
    out
}

pub(crate) fn decode_proposal_section(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if bytes.len() < 4 {
        return Err(TwoMlsPqError::Mls);
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let rest = &bytes[4..];
    if len == 0 || rest.len() <= len {
        return Err(TwoMlsPqError::Mls);
    }
    Ok((rest[..len].to_vec(), rest[len..].to_vec()))
}

#[cfg(test)]
mod pq_frame_kind_tests {
    use super::*;

    #[test]
    fn classifies_every_side_band_tag() {
        assert_eq!(
            pq_frame_kind(PQ_EK_TAG),
            Some(PqFrameKind::RatchetEphemeralKey)
        );
        assert_eq!(
            pq_frame_kind(PQ_CT_TAG),
            Some(PqFrameKind::RatchetCiphertext)
        );
        assert_eq!(pq_frame_kind(PQ_BIND_TAG), Some(PqFrameKind::RatchetBind));
        assert_eq!(
            pq_frame_kind(PQ_BOOTSTRAP_KP_TAG),
            Some(PqFrameKind::BootstrapKeyPackage)
        );
        assert_eq!(
            pq_frame_kind(PQ_BOOTSTRAP_BIND_TAG),
            Some(PqFrameKind::BootstrapBind)
        );
        assert_eq!(
            pq_frame_kind(PQ_REKEY_UPD_TAG),
            Some(PqFrameKind::RekeyUpdate)
        );
        assert_eq!(
            pq_frame_kind(PQ_REKEY_COMMIT_TAG),
            Some(PqFrameKind::RekeyCommit)
        );
    }

    #[test]
    fn rejects_non_side_band_tags() {
        // Bare-MLS first byte, the APQWelcome and message-frame tags, evens inside the
        // side-band band, the pre-establishment staple tag (0x07 — envelope-interior only),
        // the envelope tag (0x05 — invitation channel only), a RESERVED odd byte inside the
        // side-band band (0x21 — in range, not allocated), the establishment band's reserve
        // (0x09), and a byte past every band (0x31) are not side-band frames.
        for tag in [
            0x00,
            APQ_TAG,
            MESSAGE_FRAME_TAG,
            0x12,
            0x1A,
            PRE_ESTABLISHMENT_APP_TAG,
            crate::key_packages::INITIAL_ENVELOPE_TAG,
            0x09,
            0x21,
            0x31,
            0xFF,
        ] {
            assert_eq!(
                pq_frame_kind(tag),
                None,
                "tag {tag:#x} must not classify as side-band"
            );
        }
    }

    /// One band of the tag space: a range of odd bytes owned by a single concern, packed
    /// from `start`, with its unused room at the end (`end` is the last byte it may claim,
    /// not the last it uses).
    struct Band {
        name: &'static str,
        start: u8,
        end: u8,
        tags: &'static [(u8, &'static str)],
    }

    /// Every allocated tag byte and the constant that owns it — the allocation record for a
    /// space declared across three sites (see the note at the top of this file). Ownership
    /// stays local; this is the one place the whole space is visible at once, and the book's
    /// `wire-format.md` table is its prose half.
    ///
    /// A row here is not decoration: `tag_space_holds` is what turns a duplicate byte from a
    /// wire bug caught in review into a failing build. Add a row when you add a tag — at the
    /// END of its band, into the room the band already reserves.
    const BANDS: &[Band] = &[
        Band {
            name: "message path",
            start: 0x01,
            end: 0x03,
            // Full, and closed by design: the message path has exactly one shape.
            tags: &[
                (APQ_TAG, "apq::APQ_TAG"),
                (MESSAGE_FRAME_TAG, "MESSAGE_FRAME_TAG"),
            ],
        },
        Band {
            name: "A.1 establishment",
            start: 0x05,
            end: 0x0F,
            tags: &[
                (
                    crate::key_packages::INITIAL_ENVELOPE_TAG,
                    "key_packages::INITIAL_ENVELOPE_TAG",
                ),
                (PRE_ESTABLISHMENT_APP_TAG, "PRE_ESTABLISHMENT_APP_TAG"),
            ],
        },
        Band {
            name: "PQ side-band",
            start: 0x11,
            end: 0x2F,
            // Lifecycle order: bootstrap once, then ratchet, then re-key.
            tags: &[
                (PQ_BOOTSTRAP_KP_TAG, "PQ_BOOTSTRAP_KP_TAG"),
                (PQ_BOOTSTRAP_WELCOME_TAG, "PQ_BOOTSTRAP_WELCOME_TAG"),
                (PQ_BOOTSTRAP_BIND_TAG, "PQ_BOOTSTRAP_BIND_TAG"),
                (PQ_EK_TAG, "PQ_EK_TAG"),
                (PQ_CT_TAG, "PQ_CT_TAG"),
                (PQ_BIND_TAG, "PQ_BIND_TAG"),
                (PQ_REKEY_UPD_TAG, "PQ_REKEY_UPD_TAG"),
                (PQ_REKEY_COMMIT_TAG, "PQ_REKEY_COMMIT_TAG"),
            ],
        },
    ];

    #[test]
    fn tag_space_holds() {
        let all: Vec<(u8, &str)> = BANDS.iter().flat_map(|b| b.tags.iter().copied()).collect();
        let mut prev_end = 0x00u8;

        for band in BANDS {
            // Bands are disjoint and ascending, so a byte belongs to at most one concern and
            // "band X is A..=B" reads off this table.
            assert!(
                band.start > prev_end,
                "the {} band starts at {:#04x}, at or before the previous band's end {prev_end:#04x}",
                band.name,
                band.start
            );
            assert_eq!(band.start % 2, 1, "the {} band must start odd", band.name);
            assert_eq!(band.end % 2, 1, "the {} band must end odd", band.name);
            prev_end = band.end;

            for (i, (tag, name)) in band.tags.iter().enumerate() {
                // Packed from the band's start with no holes. An MLSMessage's first byte is
                // always 0x00 (ProtocolVersion 0x0001, BE), so `start` being odd makes every
                // tag odd: the even space stays reserved, which is what separates a tagged
                // frame from bare MLS by byte 0 alone, and lets the staple slot
                // self-discriminate (welcome 0x01 vs. commit 0x00).
                let expected = band.start + 2 * i as u8;
                assert_eq!(
                    *tag, expected,
                    "{name} is at {tag:#04x} but slot {i} of the {} band is {expected:#04x} — \
                     a band is packed from its start; its room goes at the end",
                    band.name
                );
                // The room is finite. Appending past the end is the mistake banding exists to
                // stop, and it is what a dense-whole-space check used to catch.
                assert!(
                    *tag <= band.end,
                    "{name} ({tag:#04x}) is past the end of the {} band ({:#04x}) — the band \
                     is full, so the bands below it must move",
                    band.name,
                    band.end
                );
            }
        }

        for (tag, name) in &all {
            let dupes: Vec<_> = all
                .iter()
                .filter(|(other, _)| other == tag)
                .map(|(_, n)| *n)
                .collect();
            let _ = name;
            assert_eq!(
                dupes.len(),
                1,
                "{tag:#04x} is allocated more than once: {dupes:?}"
            );
        }
    }

    /// The classifier routes exactly the side-band band's allocated tags — checked over all
    /// 256 bytes, so neither a reserved byte that quietly started classifying nor a stray
    /// `pq_frame_kind` arm outside the band can survive. Set equality is the real invariant;
    /// the range in prose is a summary of it, which is why this compares against the
    /// registry rather than against `0x11..=0x2F` (the band's reserved bytes are in range but
    /// unallocated, and must not classify).
    #[test]
    fn side_band_band_matches_the_classifier() {
        let band = BANDS
            .iter()
            .find(|b| b.name == "PQ side-band")
            .expect("the side-band band");
        for tag in 0x00..=0xFFu8 {
            let allocated = band.tags.iter().any(|(t, _)| *t == tag);
            assert_eq!(
                pq_frame_kind(tag).is_some(),
                allocated,
                "{tag:#04x}: the classifier and the {} band's registry disagree",
                band.name
            );
        }
    }
}
