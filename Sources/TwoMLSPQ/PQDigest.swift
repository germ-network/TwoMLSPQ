//
//  PQDigest.swift
//  TwoMLSPQ
//
//  This package's digest vocabulary: SELF-DESCRIBING tagged bytes that TwoMLSPQ
//  derives and compares, and that everyone else carries as opaque `Data`.
//
//  WHY THIS IS NOT `CommProtocol.TypedDigest`. The digest algorithm is a facet of
//  the crate's `TwoMlsSuite` (see rust/two-mls-pq/src/suite.rs — "the hash behind
//  every digest this crate emits"), so the kind tag must version with the crate,
//  not with an identity-layer enum in another package. Naming a shared Swift type
//  put the tag namespace in CommProtocol's hands, which meant a new suite could
//  not ship without a CommProtocol release first. The bytes were always the real
//  contract — the 33-byte tagged form is what the cross-party agent handoff signs
//  over — so the bytes are what this package vends.
//
//  WHAT CONSUMERS OWE. Nothing but carriage: hand these bytes back verbatim.
//  Comparison authority stays here (`queueProposal` re-checks against the crate's
//  staged proposal; the handoff verifier rebuilds its signature body from a
//  locally derived reference digest). A caller that recomputes a digest with its
//  own hash instead of `over(_:)` silently diverges at the first suite change —
//  which is exactly what `digestDerivationMatchesTheCrate` in the test suite pins.
//
//  BYTE COMPATIBILITY. `tag` is 0x01 — the value CommProtocol's `DigestTypes`
//  assigns SHA-256 — so every byte this package emits is identical to what the
//  old `TypedDigest.wireFormat` produced. Spawn tokens (keys of the crate's
//  archived forward table) and app-persisted routing keys keep matching across
//  the migration. Do not renumber.
//

import CryptoKit
import Foundation

/// Derivation and framing for the digests this package emits.
///
/// The value type is plain `Data` in the tagged wire form — `[kind][digest]` —
/// deliberately: an opaque carrier cannot be asked to interpret it, and no
/// consumer needs a nominal type to hold bytes it only passes back.
public enum PQDigest {
	/// The suite's digest kind. One value today, matching the crate's single
	/// declared suite; a new suite's digest is a NEW tag, never a redefinition
	/// of this one (old tagged values stay parseable — append-only, like any
	/// identifier format).
	static let tag: UInt8 = 0x01

	/// Content width of `tag`'s algorithm.
	static let width = 32

	/// The tagged wire width: `[kind]` + digest.
	static let wireWidth = width + 1

	/// Derive the suite's digest over `body`, tagged.
	///
	/// The ONE place this package names a hash algorithm on the Swift side; it
	/// mirrors the crate's `TwoMlsSuite::CURRENT.digest`. That duplication across
	/// the language boundary is deliberate (no FFI round trip: digests key AAD and
	/// replay ledgers, so deriving one must not be able to fail) and is pinned by
	/// the canary test rather than by a shared declaration.
	///
	/// Callers that must byte-match a crate-emitted digest — establishment welcome
	/// digests, anything fed to a signature body alongside `proposalHash` — MUST
	/// derive it here rather than hashing themselves.
	public static func over(_ body: Data) -> Data {
		var tagged = Data([tag])
		tagged.append(raw(over: body))
		return tagged
	}

	/// The untagged digest, for the FFI (which carries raw 32-byte values — the
	/// crate holds no app-layer kind tags).
	static func raw(over body: Data) -> Data {
		Data(SHA256.hash(data: body))
	}

	/// Lift a raw FFI digest into the tagged form. The FFI's documented convention
	/// is a bare 32-byte digest of the stated object; the kind tag is applied here.
	static func lift(ffi raw: Data) throws(SessionError) -> Data {
		guard raw.count == width else {
			throw SessionError(
				code: .internalError,
				detail: "FFI digest convention violation: expected \(width) bytes, "
					+ "got \(raw.count)")
		}
		var tagged = Data([tag])
		tagged.append(raw)
		return tagged
	}

	/// Strip the tag off a caller-supplied digest on its way to the FFI.
	///
	/// Retyping the surface to `Data` moved this check from the type system to
	/// runtime: the caller now CAN hand over the wrong bytes. Graded
	/// `.internalError` — the same code the old `LinearEncodingError` path
	/// produced — because the only honest source of these bytes is this package.
	static func strip(_ tagged: Data) throws(SessionError) -> Data {
		guard tagged.count == wireWidth, tagged.first == tag else {
			throw SessionError(
				code: .internalError,
				detail: "not a TwoMLSPQ digest: expected \(wireWidth) bytes tagged "
					+ "0x\(String(tag, radix: 16)), got \(tagged.count) bytes tagged "
					+ "0x\(tagged.first.map { String($0, radix: 16) } ?? "none") — "
					+ "pass back the bytes this package emitted, unmodified")
		}
		return tagged.dropFirst()
	}
}

/// Framing for the 256-bit routing identifiers this package surfaces
/// (`HeaderDecryptResult.forward`'s group id).
///
/// Tagged for the same reason digests are — and pinned to 0x02, CommProtocol's
/// `DataIdentifier.Widths.bits256`, because adopters persist these bytes as
/// lookup keys for spawned sessions. Renumbering would orphan every stored key.
enum PQIdentifier {
	static let bits256Tag: UInt8 = 0x02
	static let bits256Width = 32

	/// Tag a raw 32-byte crate identifier for the public surface.
	static func tagged256(_ raw: Data) throws(SessionError) -> Data {
		guard raw.count == bits256Width else {
			throw SessionError(
				code: .internalError,
				detail: "FFI identifier convention violation: expected "
					+ "\(bits256Width) bytes, got \(raw.count)")
		}
		var tagged = Data([bits256Tag])
		tagged.append(raw)
		return tagged
	}
}
