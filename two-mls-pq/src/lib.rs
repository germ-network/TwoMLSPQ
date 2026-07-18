uniffi::setup_scaffolding!();

mod invitation;
mod key_package_store;
pub mod key_packages;
mod providers;
mod psk;
pub mod session;
mod suite;
#[cfg(test)]
#[macro_use]
mod test_macros;
#[cfg(test)]
mod demo;
#[cfg(test)]
mod test_utils;

pub use session::TwoMlsPqSession;

use std::sync::Arc;

#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Record-shape contract stamp. Uniffi's load-time checks cover *function*
/// signatures but NOT `uniffi::Record` field layouts or error-enum variants: a
/// Record can change shape with every checksum unchanged, and a mismatched
/// binding + binary pair then mis-reads FFI buffers at the first call touching
/// the changed type (runtime trap mid-flow) instead of failing at startup.
///
/// RULE: bump this on ANY shape change to a `#[derive(uniffi::Record)]` struct
/// or the error enum in this crate. The vendored Swift binding's consumer
/// (AbstractTwoMLS) asserts the value at first construction, so a stale
/// binding/binary pairing fails fast with an actionable message.
// v2 (2026-07-07): TwoMlsPqDigest removed — digests are raw 32-byte SHA-256 values
// (`Vec<u8>` fields on PrepareEncryptResult / QueuedRemoteProposal and in the
// queue_proposal / proposal_context signatures).
// v3 (2026-07-07): TwoMlsPqError gained `UnsupportedCipherSuite` (an injected crypto
// provider cannot supply a required cipher suite; surfaces at client construction).
// v4 (2026-07-08): TwoMlsPqError gained `CipherSuiteMismatch` (peer key package/welcome
// suite pair does not match the session's fixed suite); `MlsCipherSuite::is_supported`
// renamed to `is_combiner_pq` (the name always meant "is the PQ combiner suite").
// v5 (2026-07-09): TwoMlsPqError gained `InvitationSpent` (a single-use invitation's key
// package has already been consumed; `generate_invitation` also gained a `last_resort` flag,
// but that function-signature change is caught by uniffi's own load-time checksum).
// v6 (2026-07-10): wire format v2 — one message frame (0x03) with a mandatory
// commit-or-welcome staple replaces BUNDLED/PARTIAL/STAPLED_WELCOME; PQ side-band tags
// renumbered to 0x05–0x11 (classify via `pq_frame_kind`, never raw bytes). TwoMlsPqError
// gained `EpochDesync` and `UnexpectedWelcome`. Semantics: `remote_commit` is surfaced
// only on the frame whose staple first applied; `prepare_to_encrypt(Some(_))` returns
// `SessionNotReady` until a peer frame has been processed.
// v7 (2026-07-10): header encryption — every rendezvous-channel frame leaves the library
// sealed (`EncryptResult.cipher_text`, `pending_outbound`, `pq_take_pending_outbound`, and
// the `pq_*_begin` returns are opaque blobs). The host removes the seal with the new
// `open_incoming(blob) -> Option<OpenedFrame { kind, frame }>` and routes `frame` by
// `kind` (`OpenedFrameKind`) to the existing plaintext entry points. The initiator's
// initial welcome on the invitation channel is unchanged (host envelopes via
// `hpke_seal_to_key_package`).
// v8 (2026-07-10): initiate-side envelope — `initiate` gains an `app_payload:
// Option<Vec<u8>>` parameter and now returns its initial welcome via `pending_outbound`
// already HPKE-enveloped (`[app_payload ∥ APQWelcome_A]` sealed to the peer's KP′); the
// new `TwoMlsPqInvitation::open_initial(blob) -> InitialFrame { app_payload, welcome }`
// opens it (decrypt-only, does not consume the invitation), replacing the raw
// `hpke_open` + manual compose the host did before.
// v9 (2026-07-10): establishment-time principal selection — `TwoMlsPqInvitation::receive`
// gains `new_client_id: Option<Vec<u8>>`: the spawned session's send group is created
// under a freshly-minted dedicated principal (no rotation commit; the welcome's creator
// leaf carries the dedicated id), replacing the receive → stage_rotation →
// prepare_to_encrypt(Some(_)) first-frame dance that the peer_confirmed gate now
// (correctly) refuses. Semantics: joining the peer's send group adopts the creator
// leaf's ClientId as `their_principal_state`, and the delivery that performed the join
// surfaces it as `remote_commit.new_sender` when it differs from the invitation
// identity — on the message frame whose staple joined, AND on a standalone welcome
// (`process_incoming` then returns `Some(DecryptResult { remote_commit, .. })` instead
// of `None`; re-deliveries and unchanged-principal joins stay `None`). TwoMlsPqError
// gained `InvalidClientId` (an empty principal id supplied to `receive(new_client_id:)`
// or `stage_rotation` — empty is reserved as the ratchet-commit AD discriminator).
// Hardening: every join and applied peer commit now enforces the protocol's two-party
// group shape (a crafted welcome/commit/proposal carrying extra leaves is rejected as
// `Mls`).
// Also in v9 (2026-07-10, group rules): `receive` gains `expected_remote: Option<Vec<u8>>`
// — the identity the caller already expects the welcome from; a mismatched key package is
// rejected as the new `RemoteIdentityMismatch` BEFORE any invitation state is claimed.
// Unconditionally, the welcome's creator leaf must now match the supplied key package at
// `receive`/`accept`, and an A.4 bootstrap key package must name the established peer
// (both `RemoteIdentityMismatch`). Commits are now filtered against the TwoMLS operation
// whitelist on both build and receive (creation = exactly one Add; steady state = at most
// one peer-leaf Update + external PSKs; everything else rejected as `Mls`), and a stapled
// or A.5 proposal that is not the peer's own-leaf Update is rejected at ingest
// (`ProposalRejected`).
// Also in v9 (2026-07-10, the TwoMLS AS): credential rotation is PROPOSAL-DRIVEN.
// `stage_rotation` mints a candidate (several may be staged; my_principal_state is
// Pending while any are); `prepare_to_encrypt(Some(id))` selects which candidate this
// round's Upd proposes (it no longer commits a rotation — the unilateral AD-announced
// rotation commit is gone, and rotation may ride the very first frame);
// `QueuedRemoteProposal.proposing` now carries the CANDIDATE credential the Upd's
// leaf bears; `queue_proposal` approval authorizes it; the approver's commit
// canonicalizes it (`committed_remote_client_id`, `their_principal_state`), and the
// staple back swaps the proposer onto the winner (`remote_commit.new_recipient`,
// Sync). Leaf credentials genuinely move in leaves now; `new_sender` derives from the
// observed leaf change (commit AD is no longer read). TwoMlsPqError gained
// `CredentialRejected` (AS refusal, retryable from a staple). The session archive
// carries the AS sequences and staged candidates (SESSION_ARCHIVE_VERSION -> 5; v4
// blobs fail ArchiveInvalid per prerelease policy).
// Also in v9 (2026-07-10, candidate lifecycle): staged rotation candidates are never
// evicted (a sent candidate the peer may still commit is retained until
// canonicalization); overflow beyond the in-flight window parks in a single deferred
// slot and is proposed on the next routine round. `queue_proposal` validates then
// `clear_proposal_cache`s (nothing is cached until the fold re-applies it), so a
// rejected call is a no-op and replacing the running tally is a clean overwrite; the
// tally is dropped when the send epoch advances via an A.3 bind. New exported getter
// `queued_remote_successor() -> Option<ClientId>` surfaces the current tally.
//
// v10 (2026-07-10, draft-02 conformance, phase A): every group carries an `APQInfo`
// GroupContext extension written at creation (both group ids — the acceptor's PQ id
// pre-allocated for A.4 — mode, suites, creation epochs with EPOCH_UNBOUND sentinels
// for a deferred half); joins verify it (a welcome without one fails
// `ApqInfoMismatch` — new error variant — as a downgrade attempt) plus -02 §4.2.1
// membership consistency. Every FULL commit (the A.3 bind's two halves, and full-pair
// creation commits) carries an `AppDataUpdate` (0x0008) proposal attesting the absolute
// post-commit epochs of both groups; receivers verify both copies agree and match the
// actual epochs before decrypting the stapled app message. A.5 re-key commits must NOT
// carry one (pq_epoch reconciles at the next A.3 bind — the documented Germ extension).
// Leaves now advertise the APQInfo extension type (0xF0A1) and AppDataUpdate proposal
// type, so v1 combiner key packages and v5 archives are rejected
// (COMBINER_KEY_PACKAGE_VERSION -> 2: the payload is now the -02 §7 APQKeyPackage TLS
// shape inside the version byte; SESSION_ARCHIVE_VERSION -> 6, pure compatibility cut).
// v11 (2026-07-10, draft-02 conformance, phase B): the apq_psk / cross-party PSKs are now the
// conformant application PSKs — SafeExportSecret(component_id) off the mls-rs exporter tree +
// DeriveSecret("psk_id"/"psk"), imported with psk_type=application(3) via add_application_psk
// (the fork's safe_extensions feature; pin bumped to the germ-shadow-safe-exporter rev). The
// A.3 injected secret S stays an external PSK. Ledger/archive reshaped (SESSION_ARCHIVE_VERSION
// -> 7). The exporter tree consumes each component's leaf once per epoch, so the session
// exports at most once per (send group, epoch) and memoizes via the ledger.
// v12 (2026-07-11, event-driven cross-party injection): the cross-party TwoMLS-PSK is
// re-injected only when the peer's group has ADVANCED since we last bound it (a full commit /
// A.3 bind on the classical side, a PQ commit on the A.5 side), not procedurally on every
// commit — so a commit with no new peer entropy to entangle with carries no cross-party PSK.
// The transient PSK memo is replaced by epoch watermarks (SESSION_ARCHIVE_VERSION -> 8).
// v13 (2026-07-11, push-based persistence): the pull `archive()` is REMOVED from the FFI on
// both TwoMlsPqSession and TwoMlsPqInvitation (its move-not-copy contract re-armed AEAD nonce
// reuse — security review H1). The live object now PUSHES its state to a foreign `ArchiveSink`
// (new `with_foreign` trait + `BlobKind{Core,Checkpoint}`) after every mutation; attach it with
// the new `install_sink`. Session restore is the new `restore(core, checkpoint)` (the
// two-blob model — classical mutations rewrite a `core` blob omitting the ML-KEM trees, PQ ops
// write a full `checkpoint`); invitation restore stays `new(archive)`. New read-only `state_seq()`
// on both. EncryptResult gained `depends_on_seq` (persist-before-transmit correlation), and
// TwoMlsPqError gained `SinkAlreadyInstalled` (install_sink is once-only). SESSION_ARCHIVE_VERSION
// -> 9, INVITATION_VERSION -> 3. Persisted state is not portable — regenerate sessions and
// invitations.
// v14 (2026-07-12): PrepareEncryptResult gained `proposal_message` — the raw staged
// Upd(self) proposal (the bytes whose SHA-256 is `proposal_hash`), returned from the same
// critical section as the hash so a host binding a signature to the proposal (the anchor
// agent handoff) gets bytes and digest atomically; there is deliberately NO staged-slot
// getter (a decoupled read could return an Upd a later prepare staged). No wire, archive,
// or semantic change — a pure Record shape change.
// v15 (2026-07-12): AppBinding — an OPTIONAL app-state binding welded into a session at
// creation and immutable for its lifetime: opaque app-supplied bytes (a DIGEST of the
// app's immutable relationship identity; the crate never interprets them) carried in a
// new AppBinding GroupContext extension (0xF0A2, the APQInfo mechanism) on both classical
// halves; the PQ halves inherit coverage via the APQInfo half-binding. `initiate` gains
// `app_binding`, `accept`/`receive` gain `expected_app_binding` (verified on the joined
// welcome BEFORE any invitation state is claimed — a wrong-relationship welcome leaves
// the invitation fully reusable; a binding-carrying welcome against a `None` expectation
// is rejected, never silently accepted), the return group mirrors the verified incoming
// binding, and the initiator's return-welcome join requires equality with its own send
// group's binding (absence is a strip/downgrade attempt). New read-back
// `app_binding() -> Result<Option<Vec<u8>>>` lets a restored session's owner re-verify.
// An EMPTY binding is reserved as invalid (`None` is the unbound state), and PQ halves
// must carry none (the binding lives on the classical halves; a smuggled PQ-half copy is
// rejected at join). TwoMlsPqError gained `AppBindingMismatch`, appended as the last
// variant so no existing case renumbers (the shape change this bump stamps). Leaves
// now advertise the extension type: COMBINER_KEY_PACKAGE_VERSION -> 3 and
// INVITATION_VERSION -> 4 (prerelease hard cut — old published key packages and
// invitation archives are rejected; regenerate and re-pair). Session archives are
// unaffected (the binding is optional and rides the persisted group state).
// v16 (2026-07-13, §A.1 pre-establishment sends): the initiator sends app messages
// immediately after `initiate`, before the acceptor's return welcome (architecture
// book: Protocol Flows §A.1) — `prepare_to_encrypt` pre-establishment is a NO-OP prepare
// (`proposal_message` EMPTY; `proposal_hash` is the WELCOME digest — the one carve-out
// on the v14 hash==sha256(message) guarantee) and `encrypt` emits a fresh §A.1 envelope
// per frame, HPKE-sealed to the retained peer KP′, stapling the app message.
// Envelope wire v2: tagged `[0x15][u32 kem_len][kem][ct]`; plaintext is four optional
// u32-LE length-prefixed sections `[app_payload][welcome][return_kp][stapled_message]`
// under the either/or rule (a host app_payload is establishment-SELF-SUFFICIENT and
// replaces the bare sections). `initiate` LOST its `app_payload` parameter (a payload
// that signs over the welcome cannot exist before initiate returns) — attach with the
// new `set_initial_app_payload` / `set_initial_return_key_package` (initiator-only,
// pre-establishment-only, regenerate `pending_outbound`; CAPTURE AFTER ATTACH — the
// retained state rides the archive so a birth-captured replier restores send-ready);
// new read-only `initial_welcome()`. `InitialFrame` reshaped (all four sections,
// `welcome` now Optional); new exported `decode_initial_plaintext` parses an
// HPKE-opened plaintext (token/dedup keying: the STABLE PREFIX — app_payload when
// present, else welcome — identical across one initiator's re-staples; all
// consequential state keys off the signed, JOINED welcome via the invitation's
// `processed` ledger — the other sections are unauthenticated hints). The stapled app
// message is `[0x13][ASG-cl PrivateMessage]` (tag renumbered to 0x09 since; sealed in
// the initiator's send group), handed to `process_incoming` AFTER the
// join (application-message-only result). Establishment clears the retained state (the
// cutover in `process_welcome`). Archive layout versions RESET to the pre-release
// floor alongside this layout change (SESSION_ARCHIVE and INVITATION both -> 1; the
// accumulated ladders carried no compatibility value — history stays in git): ALL
// persisted sessions and invitations regenerate. The v15 key-package wire cut
// (COMBINER_KEY_PACKAGE_VERSION 3, a published artifact, not an archive) is untouched.
// v18 (2026-07-15, every round ends in a stapled bind; 17 was burned by an interim build
// of this same work and is skipped):
// - Side-band frames are RETAINED for re-send (a frame lost in transport stalled its round
//   with no way to heal): new `pq_pending_outbound(sealing: SideBandSealing)` peeks the
//   sealed frame without consuming it (`Fresh` re-seals per hand-out, `Stable` holds the
//   base still for chunking); new `DuplicateSideBand` error classifies a re-sent frame for
//   a step already taken as a discardable duplicate. A.4 is a well-formed three-leg round
//   (KP' -> Welcome' -> bind) registered in the single side-band slot alongside A.3/A.5.
// - A BIND IS THE STAPLE, not a frame. A.3's and A.4's closing leg commits the PQ half
//   pathlessly and OWES the classical half, which rides the binder's next classical COMMIT
//   as the message-frame staple in draft-02 §7 `APQPrivateMessage` form — re-sent until
//   superseded, so a lost bind heals by the staple's own machinery. `pq_ratchet_bind` /
//   `pq_bootstrap_bind` LOSE their `app` parameter (the app travels on the committing
//   round's own message frame); `pq_ratchet_apply` / `pq_bootstrap_apply` are DELETED (the
//   bind arrives via `process_incoming`) — all caught by uniffi's checksum. NOT caught by
//   it, and the reason this bumps: the staple slot gained a third form, `[0x05]`
//   APQPrivateMessage alongside `[0x00]` commit and `[0x01]` APQWelcome.
// - A.5 takes the same shape: Upd' (proposal — replaces the proposer's leaf, and carries
//   the initiator's credential handoff) -> Commit' (the round's one updatePath commit —
//   replaces the committer's leaf, now also the responder's own-leaf credential catch-up)
//   -> a stapled ACK (pathless partial commit; a conformant FULL commit pair whose
//   attestation reconciles the bumped pq_epoch in-round). The counter-Upd' is gone:
//   `PQ_REKEY_COMMIT` carries one payload, `pq_rekey_apply` is initiator-only and returns
//   `Result<()>`, and one A.5 round re-keys ONE group — the turn alternation brings the
//   other group's round next.
// - Retirement does not exist: every large frame is answered by a bind and every round's
//   terminal leg is a staple, so retained frames clear on the ordinary round-complete rule
//   and nothing re-sends forever. (An interim build withdrew spent frames on a peer
//   application receipt; the receipt machinery is gone because nothing needs it.)
// - Wire: `PQ_BIND` and `PQ_BOOTSTRAP_BIND` are deleted with their `PqFrameKind` variants
//   (a bind is not a side-band frame), the message-path band GROWS to admit
//   `apq::APQ_PRIVATE_MESSAGE_TAG`, and every band below shifts — message path 0x01-0x05
//   (FULL: welcome 0x01, message frame 0x03, private-message staple form 0x05), A.1
//   establishment 0x07-0x11 (envelope 0x05->0x07, pre-establishment staple 0x07->0x09),
//   PQ side-band 0x13-0x31 in lifecycle order (bootstrap 0x13/0x15, ratchet 0x17/0x19,
//   re-key 0x1B/0x1D). A band's reserved bytes are unallocated and must not classify.
//   Hosts classify via `pq_frame_kind`, never raw bytes, so this is a wire cut only —
//   stale frames from older builds fail loudly. Archive layout versions are untouched
//   (pre-release hard cut; blobs from interim builds fail to decode and regenerate).
// v19 (2026-07-15, evidence-gating): a classical commit no longer requires an app-approved
// proposal. Rule 3 makes an owed PQ bind wait for a classical COMMIT, so while folding was
// the only way to commit, an app that received offers and never approved them stranded every
// PQ round at 2/1 forever — PQ liveness must not depend on approval policy. A round now
// commits when it folds an approved Upd (unchanged) OR when it owes a bind and is LICENSED:
// the peer's stapled Upd is built in its recv group — which IS our send group — so an offer
// bound to our current epoch proves the peer applied our previous commit. That license is
// what has always thrown the "at most one commit outstanding per direction" rule (a fold IS
// the evidence, since a stale-epoch offer is refused against the live send group); it is now
// tracked explicitly (`peer_applied_send_epoch`, archived) because a proposal-less commit has
// no fold to infer it from. The tracker is stamped only from an offer that passes that same
// validation — the raw epoch field is unsigned, so a spliced high-epoch offer cannot advance
// it. Committing past an unapplied commit would break single-frame
// healing AND supersede the only staple a bind's PQ half ever rides. Cadence-driven empty
// commits are deliberately NOT offered: our commit invalidates the peer's in-flight offer, so
// committing every licensed round would starve rotation for any host that deliberates.
// Host-visible: `did_commit` can be true with no `queue_proposal`, and
// `committed_remote_client_id` is now `None` on such a round — it reports what the commit
// CANONICALIZED, and a proposal-less commit canonicalizes nothing of the peer's. Archive
// layout gained a field (pre-release hard cut: old blobs fail to decode and regenerate).
// The book's Protocol Flows chapter states the property under "Evidence-gating".
// Also in v19: the two irrecoverable-failure paths a bind's owed state creates are now
// surfaced, not silent (neither is reachable from an honest flow — both take an internal
// MLS failure). `BindDischargeFailed` (fatal): the classical commit discharging a bind
// failed after the reservation was consumed and the exporter leaf spent — the round cannot
// be rebuilt, so it wears its own error, not the retriable one it would otherwise, and the
// host re-establishes. `BindApplyFailed` + `pq_receive_broken()`: applying a peer's bind
// staple failed after the round's secret was consumed, so RECEIVING is broken (every frame
// re-staples the same unappliable bind) while SENDING still works — in-memory only, so
// restoring the last persisted state heals it, and queryable so a host sets its own
// severity by role. Both variants appended to `TwoMlsPqError` (ordinals stable).
// Also in v19 (WIRE): the A.3 ciphertext (0x19) is no longer a bare ML-KEM ciphertext. The
// responder now picks a random injected secret and SEALS it to the initiator's EK under a
// key bound to the KEM shared secret AND a repeatable epoch export of the inject-group
// (`[u32 enc_len][enc][sealed]`). The initiator OPENS it before injecting — so a stale or
// misdirected ciphertext, which ML-KEM's implicit rejection would decapsulate to garbage and
// strand the round on, fails the AEAD tag explicitly and is rejected with the ephemeral and
// PQ leaf intact. Bonus: S is hybrid-secure (holds if either ML-KEM or the epoch secret does).
//
// v20: the establishment return key package is CLASSICAL-ONLY and the A.4 bootstrap KP is
// pre-committed (protocol-flows.md §A.1, the spec-ahead-of-code note now discharged).
// `receive`/`accept` take the initiator's bare classical MLS KeyPackage message (the dual
// combiner blob is gone from establishment — its PQ half fed nothing but a halves-agree
// check, and A.4 minted a fresh KP anyway) plus a REQUIRED 32-byte
// `bootstrap_kp_commitment` = SHA-256 of the initiator's PQ keyPackage, which the host
// carries inside its SIGNED establishment payload. `initiate` now mints that PQ KP up
// front with SESSION-OWNED custody — public bytes AND the KeyPackageSecret ride the
// session archive, the secret injected just-in-time into the current client's store at
// the bind join (the `inject_send_psks` pattern), so neither a restore nor a Phase 8
// client swap can strand the committed round —
// (`bootstrap_kp_commitment()` exposes the hash for the host's envelope),
// `pq_bootstrap_begin` sends the retained KP instead of fresh-minting, and
// `pq_bootstrap_respond` rejects a KP′ that does not hash to the commitment
// (`BootstrapKpMismatch`, appended) — binding the ML-KEM key material to the host's
// signed establishment rather than resting it on classical channel auth alone. When a
// commitment is pinned, the hash check REPLACES the names-the-established-peer equality
// (it is strictly stronger — it pins the exact committed bytes, which contain the
// identity), so a KP′ under a since-rotated principal still lands (PQ leaves lag
// credentials by design; A.5 catches them up). `set_initial_return_key_package` takes the
// bare classical bytes. Archive layout changed (pre-release hard cut: old blobs fail to
// decode and regenerate): `initial_return_kp` is classical bytes, and the retained
// bootstrap KP + expected commitment ride it.
//
// v21 (2026-07-17): Part 3 — parallel KP′ delivery. The §A.1 envelope loses its OUTER tag
// byte: the blob is now the raw `[u32 kem_len][kem_output][ciphertext]` (`seal_hpke_blob`),
// and discrimination moves INSIDE to the HPKE plaintext's authenticated leading tag —
// `ESTABLISHMENT_VECTOR_TAG` (0x07, repurposing the retired outer `INITIAL_ENVELOPE_TAG`) for
// the 4-section establishment reply, `PQ_BOOTSTRAP_KP_TAG` (0x13) for the parallel bootstrap
// KP. `open_initial`/`decode_initial_plaintext` return `OpenedInitial`
// (`Establishment`/`BootstrapKp`); `initial_envelope_tag()` is retired (the host routes by
// channel, not first byte). `pq_bootstrap_envelope` emits the initiator's pre-committed KP′
// IN PARALLEL with the reply (fresh HPKE per send), so A.4 completes ~one round trip sooner.
// Wire-format change (the outer tag is gone, the plaintext gained an inner tag) — hence the
// bump.
//
// v22 (2026-07-17): the TwoMLS suite becomes ONE up-front declaration (`TwoMlsSuite`,
// internal) whose facets drive every crypto choice — the group pair (`APQ_SUITE`), the
// §A.1/A.4 envelope HPKE (PQ half), the header-encryption AEAD (classical half's
// ChaCha20-Poly1305; no longer an "independent variable"), and the protocol digest
// (classical half's SHA-256). The §A.1 envelope HPKE now BINDS the declared suite via
// AAD that is derived locally on both sides and NEVER transmitted:
// `[framing version (1)][classical u16 BE][pq u16 BE]` (`envelope_framing_aad()`,
// appended, replacing the retired `initial_envelope_tag()` in spirit — hosts on the
// split `hpke_open` + `decode_initial_plaintext` path must now pass it as `aad`). The
// blob shape is byte-for-byte unchanged; the cut is cryptographic: a v21 seal
// (`aad = None`) fails a v22 open's AEAD tag and vice versa (`DecryptionFailed` —
// deliberately opaque, the header-seal `try_open` contract; the crisp
// `CipherSuiteMismatch` stays where the suite is READABLE: KP validation, APQInfo at
// join, invitation/archive decode). This binds the CLASSICAL half too, which the HPKE
// operation alone never touches — downgrade binding at zero wire bytes.
const BINDING_CONTRACT_VERSION: u64 = 22;

/// See `BINDING_CONTRACT_VERSION`. Exported so the Swift layer can verify the
/// binding it was generated with matches the binary it loaded.
#[uniffi::export]
pub fn binding_contract_version() -> u64 {
    BINDING_CONTRACT_VERSION
}

/// ATProto DID-scoped client identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ClientId {
    pub bytes: Vec<u8>,
}

/// The APQ epoch pair for the send group: the PQ side-band epoch and the classical
/// (traditional) message epoch. Zeros until the corresponding group exists.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApqEpochs {
    pub pq_epoch: u64,
    pub classical_epoch: u64,
}

/// MLS group identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MlsGroupId {
    pub bytes: Vec<u8>,
}

/// Paired MLS group identifiers for the classical and PQ halves of one Combiner direction.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CombinerGroupId {
    pub classical: MlsGroupId,
    pub pq: MlsGroupId,
}

/// Session identifier derived from both parties' client IDs at init time.
/// Both sides can derive the same ID independently, preventing identity
/// confusion when both parties initiate simultaneously.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SessionId {
    pub bytes: Vec<u8>,
}

/// Transport rendezvous channel identifier.
/// Derived per epoch via `exportSecret(label="rendezvous", context="TwoMLS", len=32)`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RendezvousId {
    pub bytes: Vec<u8>,
}

// Digests cross this FFI as raw 32-byte values: SHA-256 over the stated object. That is
// this library's OWN wire convention (matching the classical backend's values, so both
// stacks bind the same bytes); the app layer wraps them in whatever typed-digest
// encoding it uses. No app-layer type tags or enum values appear on this surface.

/// Returned by `prepare_to_encrypt`. `proposal_message` is the staged Upd(self)
/// proposal, raw — the exact message the paired `encrypt` staples and the peer
/// independently digests; `proposal_hash` is its SHA-256. Both come from the same
/// critical section, so a host binding a signature to the proposal (the anchor agent
/// handoff signs `sha256(message)`, matching the classical backend) reads the bytes
/// here and owns the digest convention — with no staged-slot read that a later prepare
/// could have replaced. `encrypt` also binds `proposal_hash` into the app message's
/// authenticated data, and the receiver reports the same value as
/// `QueuedRemoteProposal.digest`. `did_commit` is false when stuck in a prior epoch
/// (no pending remote proposal to commit).
///
/// PRE-ESTABLISHMENT carve-out (v15): an initiated session with no recv group yet
/// prepares a NO-OP round — `proposal_message` is EMPTY (there is no recv group to
/// stage an Upd into) and `proposal_hash` is the sha256 of the birth WELCOME instead,
/// binding each pre-establishment app message to its establishment vector. The peer
/// stages nothing from such frames (`DecryptResult.proposal` is absent).
#[derive(Debug, uniffi::Record)]
pub struct PrepareEncryptResult {
    pub proposal_message: Vec<u8>,
    pub proposal_hash: Vec<u8>,
    /// The peer credential this round's commit CANONICALIZED, or `None` when it
    /// canonicalized none — including on a committing round that folded nothing (a bind
    /// discharging on its own; see `did_commit`). Not a synonym for `did_commit`.
    pub committed_remote_client_id: Option<ClientId>,
    pub did_commit: bool,
}

/// Returned by `encrypt`. `epochs` is the send group's APQ pair at send time —
/// the PQ side-band epoch (0 while that half is deferred) and the classical
/// message epoch the ciphertext was produced in.
#[derive(Debug, uniffi::Record)]
pub struct EncryptResult {
    pub cipher_text: Vec<u8>,
    pub sender: ClientId,
    pub recipient: ClientId,
    pub epochs: ApqEpochs,
    /// The persistence `state_seq` this frame depends on: the seq at which the commit it
    /// staples was persisted. If the frame publishes new stored-private-key material (it
    /// staples a fresh commit), the app should wait until it has durably persisted this seq
    /// before transmitting — otherwise a crash-restore could rewind past keys the peer will
    /// rely on. A routine app message re-staples an already-persisted commit, so its
    /// `depends_on_seq` is already durable and imposes no wait. See `ArchiveSink`.
    ///
    /// Boundary of the durability gate: only frames that publish key material are gated. A
    /// routine app frame advances the sender ratchet but is NOT gated on that advance being
    /// durable, so a crash-restore can rewind one generation and re-send it; MLS's per-message
    /// random `reuse_guard` (RFC 9420 §5.3) is what bounds AEAD nonce reuse there (~2⁻³² residual),
    /// not durability. This is deliberate — gating every app message on a disk write would be a
    /// latency killer, and only key-material frames carry the rewind hazard the gate exists for.
    pub depends_on_seq: u64,
}

/// Returned by `process_incoming`. Fields are `None` when not applicable to
/// the message type (e.g. `application_message` is absent for proposals/commits).
#[derive(Debug, uniffi::Record)]
pub struct DecryptResult {
    pub application_message: Option<MlsSenderMessage>,
    pub proposal: Option<QueuedRemoteProposal>,
    pub remote_commit: Option<CommitResult>,
}

/// Decrypted application message with its verified sender identity.
#[derive(Debug, uniffi::Record)]
pub struct MlsSenderMessage {
    pub app_message_data: Vec<u8>,
    pub sender_client_id: ClientId,
    pub epoch: u64,
}

/// A remote proposal queued for app-layer acceptance. `sender` sent the
/// proposal; `proposing` is the client being proposed (differs when a client
/// proposes its own rotation). `digest` is the SHA-256 of the proposal message
/// (equal to the sender's `PrepareEncryptResult.proposal_hash`); `context` is
/// the SHA-256 of the receive group's group id, used for ordering against the
/// app-level sequence number.
#[derive(Debug, Clone, uniffi::Record)]
pub struct QueuedRemoteProposal {
    pub digest: Vec<u8>,
    pub sender: ClientId,
    pub proposing: ClientId,
    pub context: Vec<u8>,
}

/// Result of processing a remote commit. `new_sender` is `None` in
/// steady-state commits where only the recipient rotated.
#[derive(Debug, uniffi::Record)]
pub struct CommitResult {
    pub new_sender: Option<ClientId>,
    pub new_recipient: ClientId,
}

/// Credential state for one send direction. `Pending` means a rotation commit
/// was sent but the opposing side has not yet committed their half.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PrincipalState {
    Sync { client_id: ClientId },
    Pending { old: ClientId, new: ClientId },
}

impl PrincipalState {
    /// The current active client ID: the live identity for `Sync`, the pre-rotation one for `Pending`.
    pub fn client_id(&self) -> ClientId {
        match self {
            Self::Sync { client_id } | Self::Pending { old: client_id, .. } => client_id.clone(),
        }
    }
}

/// Opaque serialised state as pushed to an [`ArchiveSink`]. Sessions restore from the
/// two newest slots via `TwoMlsPqSession.restore(core:checkpoint:)`; invitations from
/// their monolithic checkpoint via `TwoMlsPqInvitation.restore(archive:)`.
#[derive(Debug, uniffi::Record)]
pub struct Archive {
    pub bytes: Vec<u8>,
}

/// Which persistence slot a pushed blob targets — see [`ArchiveSink`]. `Core` holds
/// everything except the two ML-KEM ratchet trees and is rewritten on every classical
/// mutation; `Checkpoint` is the complete state (incl. the PQ trees) and is written on every
/// PQ-touching mutation and at birth. Each slot is upserted atomically and independently, and
/// a `Core` is only ever consistent with the latest `Checkpoint` (the PQ trees never change
/// between checkpoints), so restore needs no cross-slot transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BlobKind {
    Core,
    Checkpoint,
}

/// Foreign-implemented persistence hook: the object PUSHES its new state after every
/// state-advancing mutation, inverting the old pull-`archive()` model (which was a move, not a
/// copy — misusing it re-armed AEAD nonce reuse). Pass one per object at construction (or
/// `None` to opt out, e.g. in tests).
///
/// Contract on the implementer:
/// - `persist` is called OUTSIDE the object lock, on the calling Rust thread. It MUST be
///   enqueue-only and non-blocking, and MUST NOT synchronously re-enter this library.
/// - Exactly one blob per call. Atomically upsert the slot named by `kind` (write-temp-rename,
///   or a DB row) — a single-object write, never a multi-object one.
/// - Persists can arrive out of order; keep the newest `seq` per `kind`.
/// - `archive` is PLAINTEXT SECRET MATERIAL (signing keys, epoch secrets, KEM material) — seal
///   it before writing (the key belongs in the platform keystore).
///
/// Driving the object: mutate each session/invitation SEQUENTIALLY — one state-advancing FFI
/// call at a time per object. The seq/blob-kind model assumes this. Concurrent mutation of one
/// object can interleave pushes; the worst case a lost or out-of-order checkpoint across a crash
/// then restores fail-closed (`ArchiveInvalid`), never a stale-PQ splice — an availability loss,
/// not a safety one.
///
/// Transmission stays the app's concern: outbound frames carry `depends_on_seq`, and the app
/// waits until it has durably persisted that `seq` before transmitting frames that publish
/// stored-private-key material. "Durably persisted seq N" means CONTIGUOUSLY up to N — persist
/// blobs in `seq` order so a durable `Core` at seq N implies the earlier `Checkpoint` bearing the
/// PQ keys is durable too.
#[uniffi::export(with_foreign)]
pub trait ArchiveSink: Send + Sync {
    fn persist(&self, seq: u64, kind: BlobKind, archive: Vec<u8>);
}

#[derive(Debug, uniffi::Record)]
pub struct EpochRendezvous {
    pub epoch: u64,
    pub rendezvous_id: RendezvousId,
}

/// Combiner group IDs and per-epoch rendezvous channels the transport should
/// listen on. Returned by `should_listen_on`.
#[derive(Debug, uniffi::Record)]
pub struct ListenChannels {
    pub send_group: CombinerGroupId,
    pub rendezvous_by_epoch: Vec<EpochRendezvous>,
}

/// MLS cipher suite identified by its IANA-registered u16 value (RFC 9420 §17.1).
/// Private-range values (0xF000–0xFFFF) are used for suites pending IANA assignment.
#[derive(Debug, uniffi::Object)]
pub struct MlsCipherSuite {
    value: u16,
}

impl MlsCipherSuite {
    // RFC 9420 §17.1
    pub const DHKEM_X25519_AES128: u16 = 0x0001;
    pub const DHKEM_P256_AES128: u16 = 0x0002;
    pub const DHKEM_X25519_CHACHA: u16 = 0x0003;
    pub const DHKEM_X448_AES256: u16 = 0x0004;
    pub const DHKEM_P521_AES256: u16 = 0x0005;
    pub const DHKEM_X448_CHACHA: u16 = 0x0006;
    pub const DHKEM_P384_AES256: u16 = 0x0007;
    // Private range (0xF000–0xFFFF) — pending IANA assignment
    /// MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519 (0xFDEA, FIPS 203).
    /// Private-range value; not assigned by draft-ietf-mls-pq-ciphersuites.
    pub const ML_KEM_768: u16 = 0xFDEA;
}

#[uniffi::export]
impl MlsCipherSuite {
    /// Construct from a raw IANA cipher suite value.
    #[uniffi::constructor]
    pub fn new(value: u16) -> Arc<Self> {
        Arc::new(Self { value })
    }

    /// MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519 (0xFDEA, FIPS 203)
    #[uniffi::constructor]
    pub fn ml_kem_768() -> Arc<Self> {
        Arc::new(Self {
            value: Self::ML_KEM_768,
        })
    }

    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
    #[uniffi::constructor]
    pub fn x25519_aes128() -> Arc<Self> {
        Arc::new(Self {
            value: Self::DHKEM_X25519_AES128,
        })
    }

    /// MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003)
    #[uniffi::constructor]
    pub fn x25519_chacha() -> Arc<Self> {
        Arc::new(Self {
            value: Self::DHKEM_X25519_CHACHA,
        })
    }

    /// The raw IANA-registered (or private-range) u16 value.
    pub fn value(&self) -> u16 {
        self.value
    }

    /// True if this suite is the post-quantum component of the declared Combiner pair
    /// (`TwoMlsSuite::CURRENT.pair().pq` — ML-KEM-768 today), the PQ half TwoMLS handles.
    /// Use `is_combiner_classical` to identify the classical half before routing — do not
    /// route a Combiner classical KP to mls-rs-uniffi-ios. Reads the declared suite, not a
    /// local constant, so these routing predicates track a future suite variant.
    ///
    /// (Renamed from `is_supported` in binding contract v4: the name always meant "is the PQ
    /// combiner suite", not "is a supported suite".)
    pub fn is_combiner_pq(&self) -> bool {
        self.value == u16::from(crate::suite::TwoMlsSuite::CURRENT.pair().pq)
    }

    /// True if this suite is the classical component of the declared Combiner pair
    /// (`TwoMlsSuite::CURRENT.pair().classical` — 0x0003 today). When a key package with
    /// this suite is paired with the declared PQ key package, both belong to TwoMLS as a
    /// `CombinerKeyPackage` — do not route the classical half to mls-rs-uniffi-ios
    /// independently.
    pub fn is_combiner_classical(&self) -> bool {
        self.value == u16::from(crate::suite::TwoMlsSuite::CURRENT.pair().classical)
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TwoMlsPqError {
    #[error("MLS group error")]
    Mls,
    #[error("invalid key package")]
    InvalidKeyPackage,
    #[error("missing welcome")]
    MissingWelcome,
    #[error("PSK binding failure")]
    PskBinding,
    #[error("combiner key package carries no post-quantum cipher suite")]
    PqNotAvailable,
    #[error("session not established")]
    SessionNotEstablished,
    #[error("session not ready for encryption")]
    SessionNotReady,
    #[error("proposal rejected by app layer")]
    ProposalRejected,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("archive corrupt or incompatible")]
    ArchiveInvalid,
    #[error("welcome already consumed for this remote")]
    DuplicateWelcome,
    /// A side-band frame for a step this side has already taken — the PQ analogue of
    /// `DuplicateWelcome`. Expected traffic, not a fault: the sender retains the round's
    /// frame and re-sends it until the step advances (see
    /// `SessionInner::pending_pq_outbound`), so the tail of every round is a frame the
    /// receiver has already applied. The app should discard it.
    ///
    /// Distinct from `SessionNotReady`, which a host must be free to read as a ROUTING
    /// signal (a frame offered at the wrong door), and from `Mls`, a frame that never
    /// parsed. Raised only where the state proves the step is done; a merely ill-timed
    /// frame still reports `SessionNotReady`. Like every side-band guard it is checked
    /// before the persist choke point, so a duplicate is a true no-op.
    #[error("side-band frame already applied")]
    DuplicateSideBand,
    /// A single-use (not last-resort) invitation whose key package has already been consumed
    /// by an accepted session. Distinct from `DuplicateWelcome` (a per-remote replay guard):
    /// a spent invitation rejects *every* further `receive`, from any remote. The app should
    /// discard it. A last-resort invitation never reports this.
    #[error("single-use invitation key package already consumed")]
    InvitationSpent,
    /// The build's crypto provider cannot supply a required cipher suite — a build or
    /// provider-configuration bug caught at client construction (see
    /// `two-mls-pq/src/providers.rs`), never a runtime condition of a healthy binary.
    #[error("crypto provider does not support the required cipher suite")]
    UnsupportedCipherSuite,
    /// A peer key package or welcome carries a cipher-suite pair that does not match the
    /// session's fixed suite (or is not a coherent APQ combination). Distinct from
    /// `PqNotAvailable` (peer offers no PQ half at all) and `UnsupportedCipherSuite` (a local
    /// provider gap): here the peer's suites are the wrong ones.
    #[error("cipher suite mismatch")]
    CipherSuiteMismatch,
    /// A stapled commit is for a *future* epoch of the receive group: the peer has advanced
    /// more than one commit past us, and the bridging commit no longer rides any frame (only
    /// the sender's latest commit staples). Not transient, and not recoverable in-library —
    /// there is no reconnect at this layer. The recovery is OUT-OF-SESSION: the host
    /// re-establishes a fresh session (restore cannot heal it; the persisted state is
    /// desynced too). Distinct from `DecryptionFailed`, which covers malformed or (possibly
    /// reordered, hence retriable) unprocessable frames.
    #[error("stapled commit is ahead of the receive group; re-establish the session")]
    EpochDesync,
    /// A welcome arrived that differs from the one this session's receive group was joined
    /// from. Re-deliveries of the *same* welcome are normal and skipped silently (the peer
    /// re-staples it until its first commit); a different welcome on a live session is a
    /// mis-route or an unexpected re-invite.
    #[error("a different welcome arrived for an already-joined receive group")]
    UnexpectedWelcome,
    /// A principal ClientId supplied for announcement on the wire is empty. Empty is
    /// reserved: the rotation-commit discriminator is "empty authenticated_data = ratchet
    /// commit", so an empty id could never be announced or observed by the peer. Raised by
    /// `TwoMlsPqInvitation::receive(new_client_id: Some(vec![]))` and
    /// `stage_rotation(vec![])`.
    #[error("principal client id must be non-empty")]
    InvalidClientId,
    /// An establishment identity failed to match: the remote's key package does not carry
    /// the identity the caller said it expects (`receive(expected_remote:)` — checked
    /// before any invitation state is claimed, so the invitation stays fully reusable),
    /// the welcome's creator leaf does not match the supplied key package, or an A.4
    /// bootstrap key package names a principal that is not the established peer.
    #[error("remote identity does not match the expected principal")]
    RemoteIdentityMismatch,
    /// A credential failed the Authentication Service: an Update proposing an
    /// unauthorized successor, a commit moving a leaf outside the app-defined
    /// sequence, or a canonicalized credential naming no staged candidate. Retryable
    /// where it arises from a staple — the staple re-rides every frame, so
    /// authorize-and-reprocess recovers the round.
    #[error("credential succession rejected by the authentication service")]
    CredentialRejected,
    /// The draft -02 bookkeeping failed verification: an `APQInfo` GroupContext extension
    /// is missing or inconsistent across a pair's halves (a welcome without one is a
    /// downgrade attempt), an A.4 group id does not match the id pre-allocated at
    /// establishment, or an `AppDataUpdate` epoch attestation does not match the actual
    /// post-commit epochs of both groups.
    #[error("APQInfo missing or inconsistent")]
    ApqInfoMismatch,
    /// `install_sink` was called on an object that already has a persistence sink. Install
    /// once, right after construction or restore — a second call would silently orphan the
    /// first sink (its store would go stale with no further pushes), so it fails fast instead.
    #[error("a persistence sink is already installed")]
    SinkAlreadyInstalled,
    /// The `AppBinding` app-state binding failed verification: a welcome's binding does
    /// not equal the caller's `expected_app_binding` (absent-when-expected is a
    /// wrong-relationship welcome or a strip — the same downgrade shape a missing APQInfo
    /// signals), a welcome carries a binding the caller did not expect (never silently
    /// accepted — pass the binding you can verify), the return welcome's binding does not
    /// equal the initiating session's own, a PQ half carries one (the binding lives on
    /// the classical halves only), the extension is present but undecodable, or an EMPTY
    /// binding was supplied (reserved as invalid — an accidentally empty digest must not
    /// mint a bound-to-nothing session; `None` is the unbound state).
    /// On `TwoMlsPqInvitation::receive` this is raised before any invitation state is
    /// claimed, so the invitation stays fully reusable for the genuine welcome.
    //
    #[error("AppBinding missing, unexpected, or inconsistent")]
    AppBindingMismatch,
    /// FATAL: the classical commit that was discharging an owed bind failed AFTER the
    /// reservation was consumed. The PQ round cannot be rebuilt — the exporter leaf is
    /// spent and `owed_bind` is gone — and the failed state persists, so no retry
    /// recovers it: the peer waits in its responded state forever and this session's PQ
    /// binding is permanently broken. Not reachable from any honest flow (it takes an
    /// internal MLS failure mid-commit); surfaced loudly, as its own variant, precisely
    /// so a host never mistakes it for the retriable error it would otherwise wear.
    /// Route to re-establishment.
    #[error("bind discharge failed after the reservation was consumed; re-establish")]
    BindDischargeFailed,
    /// Receiving on this session is broken: applying a peer's bind staple failed after
    /// the round's secret was consumed, so the staple — which the peer re-sends on every
    /// frame until its next commit, which evidence-gating now forbids it — can never
    /// apply, and every inbound frame carrying it fails before its app message is
    /// touched. SENDING still works. Unlike [`Self::BindDischargeFailed`] this is
    /// in-memory only (inbound processing persists on success), so restoring from the
    /// last persisted state recovers the round. Not reachable from an honest peer; how
    /// critical it is depends on what the session is for, which is why it is queryable
    /// (`pq_receive_broken`) rather than only thrown.
    #[error("bind apply failed with the round secret consumed; receive is broken until restore")]
    BindApplyFailed,
    /// The A.4 bootstrap key package does not match the commitment pinned at
    /// establishment. The acceptor received `H(initiator's PQ keyPackage)` inside the
    /// signed establishment payload (threaded in via `receive(bootstrap_kp_commitment:)`),
    /// and the KP′ that arrived on the side-band hashes to something else — a substituted
    /// or tampered key package, never honest traffic (the initiator sends exactly the KP
    /// it committed to at `initiate`). Also raised for a malformed commitment supplied to
    /// `receive` (wrong length — it could never match anything). Rejected before any
    /// group is stood up, so the session state is untouched and the genuine KP′ still
    /// completes the round.
    ///
    //
    // Deliberately the LAST variant: uniffi numbers error cases by position, so appending
    // keeps every prior variant's ordinal stable. Keep appending future variants here (the
    // contract bump already forces binding/binary pairing, but there is no reason to
    // renumber the survivors).
    #[error("bootstrap key package does not match the establishment commitment")]
    BootstrapKpMismatch,
}

/// The protocol digest over `bytes` — the single hashing primitive behind every
/// digest this crate emits (proposal digests, ordering contexts, session ids).
/// A facet of the declared suite (`TwoMlsSuite::CURRENT.digest`, SHA-256 today),
/// dispatched infallibly. One implementation, so the "both sides derive the same
/// value" invariants cannot split across call sites. The name stays `sha256`
/// while the current suite's hash is SHA-256; a suite whose digest differs
/// renames it.
pub(crate) fn sha256(bytes: &[u8]) -> Vec<u8> {
    crate::suite::TwoMlsSuite::CURRENT.digest(bytes)
}

/// Derive the session identifier for a pair of clients.
/// Both sides compute the same value from the same inputs regardless of who
/// initiated, allowing CommProtocol to deduplicate concurrent session initiations.
#[uniffi::export]
pub fn derive_session_id(my_id: ClientId, their_id: ClientId) -> Result<SessionId> {
    let (first, second) = if my_id.bytes <= their_id.bytes {
        (my_id.bytes, their_id.bytes)
    } else {
        (their_id.bytes, my_id.bytes)
    };

    let mut input = first;
    input.extend_from_slice(&second);

    Ok(SessionId {
        bytes: sha256(&input),
    })
}

impl From<mls_rs::error::MlsError> for TwoMlsPqError {
    fn from(_: mls_rs::error::MlsError) -> Self {
        TwoMlsPqError::Mls
    }
}

impl From<apq::CombinerError> for TwoMlsPqError {
    fn from(e: apq::CombinerError) -> Self {
        match e {
            apq::CombinerError::Mls => TwoMlsPqError::Mls,
            apq::CombinerError::InvalidKeyPackage => TwoMlsPqError::InvalidKeyPackage,
            apq::CombinerError::MissingWelcome => TwoMlsPqError::MissingWelcome,
            apq::CombinerError::DecryptionFailed => TwoMlsPqError::DecryptionFailed,
            apq::CombinerError::ArchiveInvalid => TwoMlsPqError::ArchiveInvalid,
            apq::CombinerError::UnsupportedCipherSuite => TwoMlsPqError::UnsupportedCipherSuite,
            apq::CombinerError::CipherSuiteMismatch => TwoMlsPqError::CipherSuiteMismatch,
            apq::CombinerError::ApqInfoMismatch => TwoMlsPqError::ApqInfoMismatch,
            apq::CombinerError::AppBindingMismatch => TwoMlsPqError::AppBindingMismatch,
        }
    }
}

pub type Result<T> = std::result::Result<T, TwoMlsPqError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn client_id(bytes: &[u8]) -> ClientId {
        ClientId {
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn test_derive_session_id_is_symmetric() -> Result<()> {
        let alice = client_id(b"alice");
        let bob = client_id(b"bob");
        assert_eq!(
            derive_session_id(alice.clone(), bob.clone())?.bytes,
            derive_session_id(bob, alice)?.bytes
        );
        Ok(())
    }

    #[test]
    fn test_derive_session_id_differs_for_different_pairs() -> Result<()> {
        let alice = client_id(b"alice");
        let bob = client_id(b"bob");
        let carol = client_id(b"carol");
        assert_ne!(
            derive_session_id(alice.clone(), bob)?.bytes,
            derive_session_id(alice, carol)?.bytes
        );
        Ok(())
    }
}
