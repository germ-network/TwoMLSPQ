//
//  CoreTypes.swift
//  TwoMLSPQ
//
//  The value/"currency" types the PQ surface returns and threads. These used to be nested
//  under the `AbstractTwoMLS` namespace; the split moved them here (top-level in the
//  `TwoMLSPQ` module) so this package carries no dependency on the abstract shim protocols.
//  The `AbstractTwoMLS` package's protocols reference these via `import TwoMLSPQ`.
//
//  Note: digests and routing ids cross this surface as opaque, self-describing `Data` (see
//  PQDigest.swift). They are still load-bearing crypto vocabulary — the proposal digest's
//  33-byte tagged form is signed into the cross-party agent handoff — but the bytes were always
//  the contract, not the Swift type, so this package vends bytes and owns their kind tags.
//  That is what lets a suite change ship from here alone.
//

import Foundation

// MARK: - Opaque id aliases

// Backend-opaque `Data` ids. `AbstractTwoMLS` keeps its own identical aliases, so
// `AbstractTwoMLS.ClientID` and `TwoMLSPQ.ClientID` are the same `Data` type and interoperate.
public typealias ClientID = Data
public typealias GroupID = Data
/// 32-byte exported secret naming a listen/post address.
public typealias RendezvousID = Data
public typealias RawSuites = UInt16

// MARK: - Persistence

/// The app's persistence hook. `persist` is invoked synchronously on the mutating call's thread,
/// outside the object's lock: it MUST be enqueue-only and non-blocking, and MUST NOT re-enter the
/// library. Atomically upsert the ONE slot named per call (write-temp-rename or a DB row); keep
/// the newest `seq` per slot — persists can arrive out of order. `bytes` is PLAINTEXT SECRET
/// MATERIAL (long-term signing keys included) — seal it before writing; the sealing key belongs
/// in the platform keystore. (Persistence infrastructure the PQ product owns — not part of the
/// cross-backend shim; the `Archivable` protocol in `AbstractTwoMLS` references it via `import`.)
public protocol PersistenceSink: Sendable {
	func persist(seq: UInt64, slot: PersistedSlot, bytes: Data)
}

/// Which persistence slot a pushed blob targets. `core` holds everything but the ML-KEM
/// ratchet trees and is rewritten on every classical mutation; `checkpoint` is the complete
/// state, written on PQ-touching mutations and as the install-time baseline. A `core` is only
/// ever consistent with the latest `checkpoint`, so restore needs no cross-slot transaction.
public enum PersistedSlot: Sendable, Equatable, Hashable, Codable {
	case core
	case checkpoint
}

// MARK: - Principal state

/// Credential state for one send direction. `.pending` means a candidate is staged/proposed
/// but the peer's approval + commit has not yet canonicalized it.
///
/// STATE IS TRUTH, EVENTS ARE HINTS: `remoteCommit.newSender`/`.newRecipient` fire once, on the
/// frame where the transition applied — and are LOST if that frame's app message fails after its
/// staple applied. After a retriable `processIncoming` failure, reconcile identity from
/// `theirPrincipalState`, not from missed events.
public enum PrincipalState: Sendable, Equatable, Hashable {
	case sync(ClientID)
	case pending(old: ClientID, new: ClientID)
}

// MARK: - Header decode result

public enum HeaderDecryptResult {
	/// A frame whose welcome this invitation already turned into a session: an exact
	/// re-delivery, or (PQ, §A.1) a LATER pre-establishment frame from the same sender carrying
	/// a fresh stapled message. `mlsMessageData` is the backend-opaque decrypted payload — hand
	/// it verbatim to the spawned session's `forwarded(headerDecrypted:)`, which acknowledges the
	/// replay and returns any newly-delivered stapled message.
	/// `groupId` is a tagged 256-bit identifier (`PQIdentifier`) — adopters persist these bytes
	/// as spawned-session lookup keys, so pass them around verbatim.
	case forward(groupId: GroupID, mlsMessageData: Data)
	case appWelcome(
		//opaque token for this welcome; pass it back verbatim to `receive`
		welcomeToken: WelcomeToken,
		appWelcome: Data,
		//the sender's early-delivered app message riding the establishment frame (classical
		//parity; PQ staples the sender's current message on EVERY pre-establishment frame) —
		//thread it into `receive`, which opens it fail-open with the join
		stapledPrivateMessage: Data?
	)
}

// MARK: - Welcome token

/// Opaque token linking a decoded welcome to its `receive`: `decodeHeader` mints one (in
/// `.appWelcome`), `receive` consumes it. The type *is* the contract — a caller hands back
/// exactly what `decodeHeader` returned and cannot substitute a recomputed digest, which would
/// silently break replay-forward routing (the token keys the invitation's forward table).
/// No public initializer: only a backend mints one.
public struct WelcomeToken: Sendable, Equatable, Hashable {
	/// The underlying digest, tagged (`PQDigest`) — readable (e.g. as a storage key), not
	/// forgeable into a token from outside the package. These are also the bytes handed to the
	/// FFI as the opaque spawn token.
	public let digest: Data

	/// `package` so the backend adapter and in-package tests mint tokens; the app can't.
	/// Derive the digest with `PQDigest.over(_:)` — a hand-rolled hash produces a token the
	/// crate's forward table will not match.
	package init(_ digest: Data) { self.digest = digest }
}
