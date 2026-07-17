# Wire Format

Session-path blobs are tagged frames — no bare MLS messages ride the wire. The §A.1
**invitation-channel envelope is the exception**: it is a raw HPKE blob with **no outer tag**
(`[u32-LE kem_output_len][kem_output][ciphertext]`), because the transport channel already
routes it to the HPKE opener and an outer discriminator would only fingerprint which frames
carry PQ material. Discrimination moves INSIDE, to the authenticated leading tag of the
HPKE plaintext (see "The §A.1 envelope" below).

| Tag | Value | Meaning |
|-----|-------|---------|
| `APQ_TAG` | `0x01` | APQ Welcome (invitation channel; also the message frame's staple-slot welcome form) |
| `MESSAGE_FRAME_TAG` | `0x03` | The message frame: `[staple][proposal][app]` — the only message-path frame |
| `APQ_PRIVATE_MESSAGE_TAG` | `0x05` | Draft-02 §7 `APQPrivateMessage` — the staple slot's bind form. Declared in `apq` |
| `ESTABLISHMENT_VECTOR_TAG` | `0x07` | Inner leading tag of the §A.1 establishment vector (an HPKE-plaintext byte, not an outer wire tag). Declared in `key_packages` |
| `PRE_ESTABLISHMENT_APP_TAG` | `0x09` | §A.1 app staple, envelope-interior only: `[0x09][BSG-cl PrivateMessage]` |
| `PQ_BOOTSTRAP_KP_TAG` | `0x13` | Bootstrap: PQ key package for the deferred send-group half |
| `PQ_BOOTSTRAP_WELCOME_TAG` | `0x15` | Bootstrap: the new PQ group's Welcome (PQ-groups-only; no classical commit) |
| `PQ_EK_TAG` | `0x17` | PQ ratchet: ML-KEM encapsulation key |
| `PQ_CT_TAG` | `0x19` | PQ ratchet: ML-KEM ciphertext |
| `PQ_REKEY_UPD_TAG` | `0x1B` | PQ re-key: initiator's `Upd'` proposal |
| `PQ_REKEY_COMMIT_TAG` | `0x1D` | PQ re-key: the responder's `Commit'` |

There is no bind tag: a round's closing bind is the **message-frame staple** (the
`APQPrivateMessage` above), not a side-band frame, so every side-band frame is answered by
its round's next leg.

The table is the prose half of the registry; `frames::tests::BANDS` is the executable
half, and the two must agree. The space spans **three declaration sites**, because each tag
lives with the thing it tags: `APQ_TAG` and `APQ_PRIVATE_MESSAGE_TAG` in the `apq` crate,
`ESTABLISHMENT_VECTOR_TAG` in `key_packages` (an inner HPKE-plaintext tag, not a session
frame), and the rest in `session::frames`. Ownership is local; allocation is global — which
is exactly how `0x15` once got claimed twice, by a reader of `frames.rs` for whom the
establishment-vector tag was invisible.

## The §A.1 envelope

The envelope blob has **no outer tag** — `[u32-LE kem_output_len][kem_output][ciphertext]`,
a raw HPKE seal. The two §A.1 frame kinds share this identical outer shape and are told apart
only AFTER HPKE-open, by the authenticated leading tag of the plaintext:

- `ESTABLISHMENT_VECTOR_TAG` (`0x07`) → the establishment reply — four u32-LE
  length-prefixed sections `[app_payload][welcome][return_key_package][stapled_message]`.
- `PQ_BOOTSTRAP_KP_TAG` (`0x13`) → the parallel-delivered A.4 bootstrap KP frame, carried
  verbatim (`[0x13][KP′]`) — the same side-band frame steady-state A.4 uses, only its outer
  framing differs (HPKE envelope here vs. header-sealed side-band later).

This is the same discipline the whole tag space follows: the transport path limits which keys
the receiver decrypts with, then the inner authenticated tag guides parsing — like the `0x03`
message frame's staple slot self-discriminating on its first byte (`0x01` welcome vs. `0x00`
commit). An outer tag would be observable and would fingerprint which frames carry PQ
material; there is nothing it could disambiguate that the channel does not already. The
initiator re-seals under a fresh HPKE ephemeral on every send (reply and bootstrap KP alike),
so a stable inner KP′ never produces a linkable blob.

**The seal binds the declared suite via untransmitted AAD (contract 22).** Both sides derive
`[framing version (1)][classical u16 BE][pq u16 BE]` — the declared suite's wire bytes
(`envelope_framing_aad()`) — and pass it as the HPKE `aad`; it never travels (RFC 9180 `aad`
is a seal/open input, not part of the ciphertext, so only byte-equality matters). A peer whose
declared pair or framing version differs fails the AEAD tag as `DecryptionFailed` —
deliberately opaque, the header seal's "indistinguishable by construction" contract — which
downgrade-binds the WHOLE pair, classical half included (the HPKE operation alone only ever
touches the PQ half), at zero wire and zero plaintext bytes. The suite needs no *signaling*
here: each half of a posted `APQKeyPackage` names its cipher suite in the KeyPackage's
cleartext framing, and the suite of an inbound envelope is defined by which posted KP (→
which invitation) it was sealed to. Hosts on the split `hpke_open` +
`decode_initial_plaintext` path must supply `envelope_framing_aad()`; `open_initial` derives
it internally. See [Cipher Suites](./cipher-suites.md) for the declared suite and its facets.

The space is **banded**. Each band owns a contiguous range of odd bytes, is packed from its
start, and keeps its remaining room at the end:

| Band | Range | Used | Contents |
|------|-------|------|----------|
| Message path | `0x01`–`0x05` | 3 / 3 | APQWelcome, message frame, APQPrivateMessage staple form. Full, and closed by design — the message path has exactly these shapes |
| A.1 establishment | `0x07`–`0x11` | 2 / 6 | establishment-vector inner tag, pre-establishment staple. The hybrid nested envelope would land in the room |
| PQ side-band | `0x13`–`0x31` | 6 / 16 | exactly what `pq_frame_kind` classifies, in lifecycle order: bootstrap, ratchet, re-key |

Banding is what makes "the side-band is `0x13`–`0x31`" a claim that survives growth. It was
bought by a renumber: the tags were allocation-ordered, so appending A.4's bind past the end
left the side-band non-contiguous and silently falsified five range shorthands across the
code and this book. A range in prose should at least not be a lie. (The bands themselves
have since shifted once — the message path FILLED when the bind became the staple's third
form, which is exactly the case where the bands below move.)

The room is free in both directions that could have cost something. On the wire, header
encryption seals every blob, so a tag is never observed and a sparse space fingerprints
nothing. In the tests, `tag_space_holds` asserts density *within* a band and membership
against that band's bounds — so room at a band's end is legal, while appending past the end
still fails. **The reserve costs no enforcement, which is why the sizes can be generous.**
They are reserves, not predictions: only the message path's fullness is a design claim.

A band's reserved bytes are **unallocated and must not classify**, so the side-band's
invariant is set equality against the registry — `side_band_band_matches_the_classifier`
checks `pq_frame_kind` against it over all 256 bytes. A range test would be unsound here: a
reserved byte is *in* `0x13`–`0x31`, so "in range ⟺ classified" would wave through a reserve
that quietly started routing.

Note the side-band's lifecycle order does **not** match the spec's section numbers (A.4
bootstrap precedes A.3 ratchet) — the section numbers are historical, and renumbering them
is a separate change.

Each multi-section frame uses a `u32`-LE length prefix per embedded field. Hosts
classify PQ side-band frames via the exported `pq_frame_kind` (never by matching raw
tag bytes); everything that is not a side-band frame or a standalone welcome routes to
`process_incoming`.

## The message frame: always staple the commit

The message path has exactly one shape, `[0x03][staple][proposal][app]`, with **no
optional sections**:

- **`staple`** — the sender's latest send-group classical commit, re-stapled on
  **every** frame until superseded; the send group's APQWelcome until the first
  commit exists; or — when the commit discharged an owed bind — the draft-02 §7
  `APQPrivateMessage` carrying the classical commit **and** its PQ partner (the
  classical half is unusable without the `apq_psk` only the PQ half supplies, so
  the two travel as one). Any single received frame therefore brings the peer up
  to the sender's current epoch: losing the frame that first carried a commit no
  longer strands the direction — the next frame heals it, and a lost bind heals
  by the same re-send. (Multi-commit gaps still exceed one staple; that is
  re-establish territory.)
- **`proposal`** — the routine `Upd(sender)` addressed to the peer's send group,
  staged on every round, including principal-rotation rounds.
- **`app`** — the application message; its authenticated data is
  `sha256(proposal)` on every round.

The staple slot self-discriminates by its first byte: an APQWelcome starts `0x01`,
an `MLSMessage` starts `0x00` (its two-byte `ProtocolVersion`), and an
`APQPrivateMessage` starts `0x05` — the wrapper tag exists precisely because the
draft struct's own first byte is its inner `MLSPrivateMessage`'s `0x00`, which the
slot could not tell from a bare commit. The receiver processes staples
**idempotently** — a welcome for an already-joined group and a commit older than
the receive group's epoch are cheap skips; a commit *ahead* of the receive group
surfaces `EpochDesync` before the app ciphertext is touched.

**Rotation is not a frame kind.** A principal rotation is a commit whose
authenticated data carries the new `ClientId` (ratchet commits have empty AD — that
is the whole discriminator). It rides the same message frame, stages the same
routine proposal, and folds any queued peer proposal it finds cached.

## Why re-stapling stays cheap

Commits *can* be large, but the protocol keeps the classical staple small by design:
classical stapled commits carry **no PQ keys** — PQ work rides partial PQ commits on
the side-band (no updatePath), and big ML-KEM updatePaths are isolated to A.5 on the
PQ groups alone. So the steady-state staple is a classical two-member commit, a few
hundred bytes.

The unavoidably large staples are the APQ welcomes, and only until the first commit:

- the **acceptor** staples only a classical-half welcome (~1 KB) — its PQ group is
  deferred to the A.4 bootstrap for exactly this reason;
- the **initiator** re-staples its full two-half APQ welcome (ML-KEM-sized, several
  KB) on every frame until its first commit — a window that is app-gated (it closes
  when the first peer proposal is approved and committed) and whose repeats the peer
  skips idempotently.

## Message-frame anatomy

For a fixed 43-byte payload, a steady-state rotation frame (`CURVE25519_CHACHA`,
awslc) is **1341 B**, opened from its header seal and split on the `u32`-LE section
prefixes (`benches/sizes.rs` prints this split):

| Section | Bytes | Contents |
|---------|------:|----------|
| `staple` (commit) | 651 | the classical rotation commit `MLSMessage` (a `PublicMessage`): its `UpdatePath` (the rotated leaf + one path node), **one** by-value proposal — the 73 B APQ PSK — plus the commit's signature, confirmation, and membership tags |
| `proposal` (`Upd`) | 395 | `[u32 proposingLen][ClientId][Upd(sender)]` — a full leaf **by value**, ~357 B of it the `Upd` `MLSMessage` |
| `app` | 254 | the application `PrivateMessage` (43 B payload + ~211 B MLS framing) |
| framing | 41 | frame tag (1) + three `u32` section prefixes (12) + header-seal nonce and tag (28) |

Two things that look like waste are not:

- **The commit folds by reference, never by value.** An approved peer `Upd` is
  cached (`process_incoming`) and committed by its ~32-byte `ProposalRef`; the only
  proposal the commit carries *by value* is the small APQ PSK. `benches/sizes.rs`
  opens the staple and asserts the by-value proposal bytes stay under 200, so a
  regression that started inlining the fold — turning that 73 B into a leaf-sized
  ~360 B — fails the bench immediately. (By hand: `MlsMessage::proposals_by_value()`
  on an opened staple returns the PSK and nothing leaf-sized.)
- **The leaf-sized cost is the two groups, not a double-carry.** A rotation touches
  both send groups: the sender's own via the commit's `UpdatePath` leaf, and the
  peer's via the by-value `Upd(sender)` in the `proposal` section (which the peer
  folds by reference on *its* next commit). Each leaf crosses the wire once; the
  `newSender` invariant is what makes it every message. Shrinking it is a
  protocol-level choice (rotate less often, or stop mirroring every self-update into
  the peer's group), not a by-reference fix — the commit is already by reference.

## Why the tags are odd

All tags are **odd** — the rule that lets a tagged frame and an MLS message be told
apart from their first byte alone. An `MLSMessage` begins with its two-byte
`ProtocolVersion` (MLS 1.0 = `0x0001`, big-endian), so its **first byte is always
`0x00`**, and `0x00` is even by construction. The invariant now does double duty: it
is also what makes the message frame's staple slot self-discriminating (welcome
`0x01` vs. commit `0x00`) without a separate discriminator byte. The entire even space stays
unused and in reserve. Extending the protocol is *not* "take the next unused odd value" —
that is what broke contiguity once already; it is "append at the end of the right band, into
the room the band already reserves." Only a band that fills forces the bands below it to
move.

## Draft-02 conformance inside the frames

The Germ tags above are the *transport* envelope; inside them the MLS payloads carry
the `draft-ietf-mls-combiner-02` structures directly. The apq crate conforms to the
draft, and the Germ frames **enclose** the draft-02 wire shapes rather than replacing
them.

- **APQInfo** — a GroupContext extension (type `0xF0A1`) present in both halves of each
  APQ group and carried automatically in every Welcome's GroupInfo. It names both group
  ids, the mode, both cipher suites, and the creation-time epochs; it is written once at
  creation and never rewritten, and joiners verify it against the groups they actually
  joined (see [group rules](./group-rules.md), rule 7).
- **AppDataUpdate** — a custom proposal (type `0x0008`) that rides both commits of every
  FULL commit, attesting the new epochs of both halves. Receivers verify the two copies
  agree and match the actual post-commit epochs before any app data is decrypted.
- **Combiner key package (v2)** — the `CombinerKeyPackage` payload adopts the draft's §7
  `APQKeyPackage { t_key_package, pq_key_package }` TLS encoding inside Germ's version
  framing. A v1 (pre-conformance) key package is rejected outright.

The conformance cutover is a hard version bump — `COMBINER_KEY_PACKAGE_VERSION = 2`,
`SESSION_ARCHIVE_VERSION = 8`, `BINDING_CONTRACT_VERSION = 12` — because every occupied
leaf must now advertise the new extension (`0xF0A1`) and proposal (`0x0008`) types, and
a leaf that cannot support them is rejected rather than silently degraded.

## Invariants

The tag values are part of the on-wire protocol; pre-release, a renumber is allowed
(this format renumbered the PQ side-band from `0x0B–0x17` and deleted the retired
`0x07` reservation along with the old `BUNDLED`/`PARTIAL`/`STAPLED_WELCOME` frames —
stale frames from older builds fail loudly in the decoders; the whole space was renumbered
again into the bands above). When adding a message type, append it at the **end of its
band** — into the room, so nothing else moves — **add a row to `frames::tests::BANDS`** and
to the table above, add matching `encode_*`/`decode_*` helpers following the `u32`-LE
length-prefix pattern, and extend `pq_frame_kind` if it is a side-band frame — hosts
dispatch on the classifier, so a frame kind that never reaches it is invisible to them.
Bump `BINDING_CONTRACT_VERSION` if any value moves: a renumber is a wire cut.

If a band ever fills, the bands below it move. That is cheap here because nothing outside
`frames.rs` names a tag by value — hosts classify via `pq_frame_kind`, and the crate
references the constants — but it is a wire cut, which is what the room exists to postpone.
`tag_space_holds` enforces the bands (disjoint, odd-bounded, packed from the start, inside
their bounds) and names the colliding constants when it fires.
