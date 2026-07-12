# Concepts

## The object model: one mls-rs client vs. three TwoMLSPQ objects

mls-rs centralizes everything behind one long-lived `Client` per credential: it
generates key packages, creates and joins groups, and owns the storage providers
(key packages, group state, PSKs) that every operation reads and writes. Persisting
an mls-rs application means persisting that one client's providers, and all
operations for a credential funnel through the one object.

TwoMLSPQ deliberately breaks this up into three app-facing objects, each owning
exactly the state its job needs:

- **`TwoMlsPqPrincipal`** — the principal: a credential-scoped signing identity. Its job
  is minting key packages and invitations and holding their private material only until it
  is captured into an invitation (`generate_invitation` purges the principal's own copies).
  It is not a hub for group operations.
- **`TwoMlsPqInvitation`** — a self-contained receiving capability: one published
  combiner key package's private material, the signing identity, and the
  consumed-remote replay guard. It turns welcomes into sessions with no live client
  and survives restarts through its own archive. TwoMLS manages the key package's
  lifetime itself rather than via mls-rs's on-the-wire last-resort extension: a
  *last-resort* invitation retains its key package to accept many welcomes, while a
  *single-use* one consumes it (dropping the private material from the archive) after
  the first accepted session.
- **`TwoMlsPqSession`** — one established pairwise channel: the two send groups
  (each an APQ group — see below) and the per-round state.

### Naming

TwoMLSPQ keeps its own vocabulary rather than borrowing mls-rs's `Client` (the invitation
and session each *contain* mls-rs clients, so "client" would be ambiguous) or
CommProtocol's `Agent` (this crate is CommProtocol-agnostic):

| mls-rs | TwoMLSPQ | role |
|---|---|---|
| `Client` | **`TwoMlsPqPrincipal`** | credential-scoped signer; mints invitations & sessions |
| `KeyPackage` | **`TwoMlsPqInvitation`** | one published key package's private material |
| group | **`TwoMlsPqSession`** | one established pairwise channel |

A *principal* is 1:1 with the MLS Basic Credential. CommProtocol calls the same entity an
**agent** (delegated from its `Identity`/`Anchor`); that `Agent ↔ Principal` correspondence
is documented at the AbstractTwoMLS boundary, so this layer never says "agent."

Internally the invitation and the session still drive mls-rs clients — the
invitation rebuilds a stateless one from its captured material on each `receive`,
and a session holds the client backing its groups (plus the successor client staged
by a principal rotation) — but those are hidden plumbing, never handed to the app.

The consequence is that persistence is **per-object, not per-client**, and it is
**push-based**: rather than the app pulling a snapshot when it chooses, each stateful
object PUSHES its new state to an app-provided sink after every state-advancing mutation.
The app attaches one `ArchiveSink` per object with `install_sink`, and the object calls
`persist(seq, kind, bytes)` from inside the mutation. There is no mls-rs-style "restore
the client and find your groups again" path — you restore an invitation
(`TwoMlsPqInvitation.restore(archive)`) or a session
(`TwoMlsPqSession.restore(core, checkpoint)`).

Push, not pull, closes a soundness gap. The old pull `archive()` was a *move, not a
copy* — using the live object after snapshotting it, then restoring, rewound the sender
ratchet and re-derived AEAD keys/nonces against a real transcript (security review
finding H1). Pushing after every mutation keeps the persisted state always current
without the app ever holding a stale-yet-live snapshot. The pull getter survives only as
an in-crate test/fuzz helper, off the FFI.

A session's state splits by **encode cost**: the ML-KEM ratchet trees dominate the encode
(≈1.2 KB per node) and change only on a PQ operation, while classical mutations are cheap
and frequent. So a session pushes one of two blob kinds:

- **`Core`** — everything *except* the two ML-KEM trees (identity, both classical group
  snapshots, the PSK ledger, the listen map, a staged rotation, parked frames, meta).
  Written on every *classical* mutation.
- **`Checkpoint`** — the complete state, *including* the PQ trees. Written on every
  *PQ-touching* mutation and once at `install_sink`.

Each blob is a single atomic push, so the sink needs no cross-object transaction, and
because the PQ trees never change between checkpoints a `Core` is always consistent with
the latest `Checkpoint`. Restore reconciles the two (PQ halves from the checkpoint, the
rest by whichever blob has the higher `state_seq`) and **fails closed** if their PQ-epoch
manifests disagree. An invitation carries no ML-KEM trees, so it is monolithic — it only
ever pushes a `Checkpoint`.

Concretely, a session encodes by **enumerating its groups**: each of its (up to four)
MLS groups is exported per group through the group object and the storage handle captured
when that group was created or joined (`apq`'s `CombinerGroup::export_state` /
`export_classical` for a `Core` / `load_combiner_group`), never by snapshotting a
client's whole store. This keeps encoding correct across principal rotation — rotation
swaps the session's internal client, and a group's state keeps flowing through the handle
it was born with.

The same ownership rule covers PSKs: the session keeps a small ledger of its send
group's recent cross-party TwoMLS-PSKs and **live-injects** them into the stores a
group actually resolves from, immediately before building or processing the commit
that references them; retired and one-shot entries are deleted afterwards, so the
mls-rs secret stores are ephemeral plumbing that holds nothing the session doesn't.
The ledger resolves frames that crossed one of our commits (which reference an epoch
mls-rs can no longer export), and — being session-owned state — it rides in every pushed
blob (`Core` and `Checkpoint` alike; it is not a PQ tree), so a restored session (whose
rebuilt client's PSK stores start empty; the key-package stores are preloaded from the
blob) still resolves them.

## Two asymmetric send groups

A classical MLS group is symmetric: every member can commit. TwoMLSPQ instead gives
each party a group they alone send on:

- **Group_A** — Alice's send group. Alice commits and encrypts; Bob joins and decrypts.
- **Group_B** — Bob's send group. Bob commits and encrypts; Alice joins and decrypts.

This makes the two directions independent and lets each side advance its own key
material without coordinating a shared committer.

## The APQ group

Each send group above is really an **APQ group**: a classical half (`0x0003`) and an
ML-KEM-768 half (`0xFDEA`). The two halves are bound by injecting a PSK derived from
the PQ half into the classical half at creation; a second, cross-party PSK ties each
party's send group to the group it receives on. An attacker must
break *both* halves to break the session — so the classical half keeps protecting
traffic even if ML-KEM were to fail, and vice-versa. This is the hybrid property,
achieved at the group level (the construction follows `draft-ietf-mls-combiner-02`;
in code an APQ group is the `apq` crate's `CombinerGroup`). See
[PSK Binding](./psk-binding.md).

## Basic credentials and the TwoMLS AS

The MLS leaf identity is the principal's opaque ClientId, wrapped in a Basic
Credential. Basic credentials carry no external trust, so **CommProtocol still makes
every trust decision** — it validates identities out of band, decides which remote
proposals to accept, and binds a per-round proposal hash into the plaintext. What the
library now adds is an Authentication Service that **enforces** those decisions
inside MLS: each leaf's credential may evolve only along the app-defined sequence
(candidates ride the ratchet's Upd proposals; approving one via `queue_proposal` IS
the authorization; the commit canonicalizes it — see
[The Rules of a TwoMLS Group](./group-rules.md)). TwoMLSPQ still stages and reports;
the app still decides; the AS makes a bypassed decision cryptographically
unrepresentable.

## The CommProtocol boundary

TwoMLSPQ receives a principal's signing keys (what CommProtocol calls an *agent*'s keys)
and returns key packages, ciphertexts, and
structured results (`DecryptResult`, `PrepareEncryptResult`, …). Everything above —
DIDs, anchor signatures, key discovery from a PDS, sequencing/ordering of proposals,
transport — belongs to CommProtocol. Keeping that line sharp is why the API is
deliberately small and stateless about identity.
