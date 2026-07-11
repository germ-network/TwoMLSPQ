//! Frame layer of the session wire protocol: the plaintext tag bytes, the
//! side-band frame classification the host routes on, and every
//! length-prefixed frame encoder/decoder. Pure functions over bytes — no
//! session state. The attacker-facing parsers live here in one audited
//! place (see `read_sections`), with the fuzz entry point at the bottom.

use super::*;

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

// PQ ratchet (architecture-diagrams PR #2 §A.3), cryptokit only:
// 0x05 carries the initiator's ML-KEM encapsulation key, 0x07 the responder's ciphertext,
// 0x09 the bind = [pq partial-commit][classical commit][app], all length-prefixed.
pub(crate) const PQ_EK_TAG: u8 = 0x05;
pub(crate) const PQ_CT_TAG: u8 = 0x07;
pub(crate) const PQ_BIND_TAG: u8 = 0x09;

/// A.4 bootstrap: this side's PQ key package, sent so the peer can stand up its deferred
/// send-group PQ half.
pub(crate) const PQ_BOOTSTRAP_KP_TAG: u8 = 0x0B;

/// A.4 bootstrap reply: the new PQ group's welcome (PQ-groups-only; no classical commit).
pub(crate) const PQ_BOOTSTRAP_BIND_TAG: u8 = 0x0D;

// A.5 rekey (architecture-diagrams §A.5), cryptokit only — updatePath commits run on the
// PQ groups alone so the classical ratchet is never blocked behind a large ML-KEM
// updatePath. 0x0F carries the initiator's Upd' proposal for the responder's send-PQ;
// 0x11 = [Commit'][counter-Upd'-or-empty], length-prefixed — the responder's reply
// carries its counter-proposal, the initiator's final commit an empty slot. Each Commit'
// cross-injects a PSK exported from the opposite PQ send group; the bumped pq_epoch
// reconciles into APQInfo at the next A.3 bind (no AppDataUpdate rides these commits).
pub(crate) const PQ_REKEY_UPD_TAG: u8 = 0x0F;
pub(crate) const PQ_REKEY_COMMIT_TAG: u8 = 0x11;

/// The seven PQ side-band frame kinds the host routes through `TwoMlsPqSession::ingest`
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
    BootstrapBind,
    /// 0x0F — A.5 rekey: the initiator's Upd' proposal.
    RekeyUpdate,
    /// 0x11 — A.5 rekey: the responder's `[Commit'][counter-Upd'-or-empty]` reply.
    RekeyCommit,
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

/// Encode the A.4 bootstrap reply: `[0x0D][pq_welcome…]`. PQ-groups-only per the spec —
/// no classical commit rides along; ASG-PQ binds into ASG-cl at the next A.3 ratchet.
pub(crate) fn encode_bootstrap_bind(pq_welcome: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + pq_welcome.len());
    out.push(PQ_BOOTSTRAP_BIND_TAG);
    out.extend_from_slice(&pq_welcome);
    out
}

pub(crate) fn decode_bootstrap_bind(bytes: &[u8]) -> Result<Vec<u8>> {
    let (&tag, rest) = bytes.split_first().ok_or(TwoMlsPqError::Mls)?;
    if tag != PQ_BOOTSTRAP_BIND_TAG {
        return Err(TwoMlsPqError::Mls);
    }
    Ok(rest.to_vec())
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
        // Bare-MLS first byte, the APQWelcome and message-frame tags, gaps/evens between
        // side-band tags, and the first unused odd value are not side-band frames.
        for tag in [0x00, APQ_TAG, MESSAGE_FRAME_TAG, 0x0A, 0x12, 0x13, 0xFF] {
            assert_eq!(
                pq_frame_kind(tag),
                None,
                "tag {tag:#x} must not classify as side-band"
            );
        }
    }
}
