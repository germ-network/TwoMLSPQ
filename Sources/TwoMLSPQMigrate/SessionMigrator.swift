import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import TwoMLSPQBinding
import TwoMLSPQSession

// MARK: - Session migrator (GER-2433 C1)
//
// The session-level analogue of `InvitationMigrator`: reads a Rust session's
// migration export (`TwoMlsPqSession.migrationExport`, the GER-2433 C1 FFI)
// and mints a native session `SecretArchive` via twomlspq-swift's
// `SessionMigration.mintArchive`. The mint restores every group half from its
// format-2 snapshot and trial-restores a checkpoint-kind archive, so a
// mis-mapped part fails LOUDLY here — the differential test (see
// TwoMLSPQMigrateTests) turns that into a migration regression gate.
//
// Unlike the invitation mint this one is NOT provider-free: the per-group
// ingress restores each snapshot with its half's `CipherSuiteProvider`.
// Everything cross-module is qualified — both packages define
// `BlobKind`/`ClientID`-shaped names.

/// Migrates a legacy Rust session to a native, unsealed session
/// `SecretArchive` — the app seals before persisting (this inherits the Rust
/// `ArchiveSink` contract: the export carries PLAINTEXT secret material and
/// the caller owns its sealing).
@available(iOS 26, macOS 26, *)
public enum SessionMigrator {
	/// Map a raw FFI session migration export onto twomlspq-swift's
	/// `MigratedSession` and mint the archive. Mint a `.checkpoint` for the
	/// full state (PQ trees inline); a `.core` pairs with it in the app's
	/// reconcile slots exactly as the native return cadence's blobs do (a
	/// core alone is never restorable — the mint skips its trial restore).
	///
	/// - Throws: `TwoMLSError.archiveInvalid` (from the mint, the checked
	///   `componentId` narrowing, or a duplicate key in an epoch-keyed export
	///   list) if any exported part fails its cross-check — the Rust export,
	///   not this mapping, is the suspect.
	public static func mintArchive(
		kind: TwoMLSPQSession.BlobKind,
		from export: TwoMLSPQBinding.SessionMigrationExport,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> SecretArchive {
		try TwoMLSPQSession.SessionMigration.mintArchive(
			kind: kind,
			parts: migratedSession(export),
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)
	}

	/// Byte-map the whole export. Every field is verbatim from the export —
	/// the mint's restores and cross-checks are the safety net for a wrong map.
	private static func migratedSession(
		_ export: TwoMLSPQBinding.SessionMigrationExport
	) throws -> TwoMLSPQSession.MigratedSession {
		try TwoMLSPQSession.MigratedSession(
			stateSeq: export.stateSeq,
			initiated: export.initiated,
			identity: migratedIdentity(export.identity),
			auth: TwoMLSPQSession.MigratedAuth(
				mine: partySequence(export.authMine),
				theirs: partySequence(export.authTheirs)),
			sendGroup: groupHalf(export.sendGroup),
			recvGroup: export.recvGroup.map(groupHalf),
			currentStaple: export.currentStaple,
			pendingProposal: export.pendingProposal.map {
				TwoMLSPQSession.MigratedProposal(
					proposing: $0.proposing, message: $0.message, hash: $0.hash)
			},
			joinedWelcomeDigest: export.joinedWelcomeDigest,
			bootstrapKPSecret: export.bootstrapKpSecret.map {
				try TwoMLSPQSession.MigratedBootstrapKPSecret(
					leafSecretKey: SecretBytes(bytes: $0.leafSecretKey),
					initSecretKey: SecretBytes(bytes: $0.initSecretKey),
					keyPackage: $0.keyPackage)
			},
			expectedBootstrapKPCommitment: export.expectedBootstrapKpCommitment,
			pqTurnMine: export.pqTurnMine,
			owedBind: export.owedBind.map {
				TwoMLSPQSession.MigratedOwedBind(
					pqCommitMessage: $0.pqCommit, tEpoch: $0.tEpoch,
					pqEpoch: $0.pqEpoch)
			},
			pqInflight: export.pqInflight.map(pqInflight),
			pendingSideBand: export.pendingSideBand,
			peerAppliedSendEpoch: export.peerAppliedSendEpoch,
			lastCrossInjected: export.lastCrossInjected,
			lastCrossInjectedPQ: export.lastCrossInjectedPq,
			lastSendPQExported: export.lastSendPqExported,
			offeredProposal: export.offeredProposal.map(digestedProposal),
			queuedProposal: export.queuedProposal.map(digestedProposal),
			stagedUpdates: export.stagedUpdates.map {
				TwoMLSPQSession.MigratedStagedUpdate(
					digest: $0.digest, message: $0.message)
			},
			sendCrossPSKLedger: pskLedger(export.sendCrossPskLedger),
			spawnToken: export.spawnToken,
			listenRendezvous: epochMap(export.listenRendezvous),
			recvHeaderKeys: epochMap(export.recvHeaderKeys),
			recvHeaderKeysPQ: epochMap(export.recvHeaderKeysPq),
			sendAttachmentLedger: attachmentMap(export.sendAttachmentLedger),
			recvAttachmentLedger: attachmentMap(export.recvAttachmentLedger),
			initialTheirKP: export.initialTheirKp.map {
				(classical: $0.classical, pq: $0.pq)
			},
			recvLeafPrincipal: try export.pqLeafCustody.map {
				try recvLeafPrincipal($0, identity: export.identity)
			},
			owesEstablishmentEnvelope: export.owesEstablishmentEnvelope)
	}

	/// The Rust session no longer holds the invitation's classical signer —
	/// mls-rs drops it at the recv-classical catch-up this export requires —
	/// so the classical slot carries the identity's own pair instead. That is
	/// exactly what the converged recv-classical leaf presents.
	///
	/// This makes native's classical custody arm for `recvLeafPrincipal`
	/// (`classicalSigningKey(presenting:)`) unreachable for a session this
	/// mapper produces: that arm is gated on `recvLeafPrincipal.signatureKey`
	/// matching the presented key, but this mapper sets it to
	/// `identity.signatureKey` — the SAME value the identity arm above it
	/// already matches first. The recv-leaf catch-up arms, which read the
	/// classical custody key directly, never fire either: they require the
	/// recv-classical leaf to still lag the canonical identity and to present
	/// `clientID` (the invitation id), and this export requires that leaf to
	/// have converged. Only the PQ half of this mixed record is ever read back
	/// out (`pqSigningKey(presenting:)`'s `recvLeafPrincipal` arm, where
	/// `pqSignatureKey` is the genuinely different custodied key).
	private static func recvLeafPrincipal(
		_ custody: TwoMLSPQBinding.SessionMigrationPqLeafCustody,
		identity: TwoMLSPQBinding.SessionMigrationIdentity
	) throws -> TwoMLSPQSession.MigratedRecvLeafPrincipal {
		try TwoMLSPQSession.MigratedRecvLeafPrincipal(
			clientID: custody.clientId,
			signingKey: SecretBytes(bytes: identity.signingKey),
			signatureKey: identity.signatureKey,
			pqSigningKey: SecretBytes(bytes: custody.pqSigningKey),
			pqSignatureKey: custody.pqSignatureKey)
	}

	private static func migratedIdentity(
		_ identity: TwoMLSPQBinding.SessionMigrationIdentity
	) throws -> TwoMLSPQSession.MigratedSessionIdentity {
		try TwoMLSPQSession.MigratedSessionIdentity(
			clientID: identity.clientId,
			signingKey: SecretBytes(bytes: identity.signingKey),
			signatureKey: identity.signatureKey,
			pqSigningKey: SecretBytes(bytes: identity.pqSigningKey),
			pqSignatureKey: identity.pqSignatureKey,
			classicalLeafSecretKey: SecretBytes(bytes: identity.classicalLeafSecretKey),
			classicalInitSecretKey: identity.classicalInitSecretKey.map {
				try SecretBytes(bytes: $0)
			},
			pqLeafSecretKey: SecretBytes(bytes: identity.pqLeafSecretKey),
			// The native session path never carries a PQ init secret (cleared
			// at `initiate` before any archive can exist); the mint rejects one
			// unconditionally, and the Rust export never emits one.
			pqInitSecretKey: nil,
			classicalKeyPackage: identity.classicalKeyPackage,
			pqKeyPackage: identity.pqKeyPackage)
	}

	private static func groupHalf(
		_ half: TwoMLSPQBinding.SessionMigrationGroupHalf
	) -> TwoMLSPQSession.MigratedGroupHalf {
		TwoMLSPQSession.MigratedGroupHalf(
			classical: SecretArchive(decodingPlaintext: half.classical),
			pq: half.pq.map { SecretArchive(decodingPlaintext: $0) })
	}

	private static func partySequence(
		_ sequence: TwoMLSPQBinding.SessionMigrationPartySequence
	) -> TwoMLSPQSession.MigratedPartySequence {
		TwoMLSPQSession.MigratedPartySequence(
			history: sequence.history,
			authorizedNext: sequence.authorizedNext,
			pinned: sequence.pinned)
	}

	private static func digestedProposal(
		_ proposal: TwoMLSPQBinding.SessionMigrationDigestedProposal
	) -> TwoMLSPQSession.MigratedDigestedProposal {
		TwoMLSPQSession.MigratedDigestedProposal(
			digest: proposal.digest,
			proposing: proposal.proposing,
			message: proposal.message)
	}

	private static func pqInflight(
		_ inflight: TwoMLSPQBinding.SessionMigrationPqInflight
	) throws -> TwoMLSPQSession.MigratedPQInflight {
		switch inflight {
		case .bootstrapInitiated:
			return .bootstrapInitiated
		case .bootstrapResponded:
			return .bootstrapResponded
		case .initiating(let secretKey, let ek):
			return try .initiating(secretKey: SecretBytes(bytes: secretKey), ek: ek)
		case .responding(let secret, let wireCt):
			return try .responding(secret: SecretBytes(bytes: secret), wireCT: wireCt)
		case .rekeyInitiated(let updMessage):
			return .rekeyInitiated(updMessage: updMessage)
		case .rekeyResponded:
			return .rekeyResponded
		}
	}

	/// Rebuild the cross-party PSK ledger as a dictionary, narrowing
	/// `componentId` (Rust `u32`, native `UInt16`) checked — an overflowing or
	/// duplicated entry is a corrupt export, so this throws `archiveInvalid`,
	/// never traps.
	private static func pskLedger(
		_ entries: [TwoMLSPQBinding.SessionMigrationPskEntry]
	) throws -> [UInt64: TwoMLSPQSession.MigratedExportedPsk] {
		var ledger: [UInt64: TwoMLSPQSession.MigratedExportedPsk] = [:]
		for entry in entries {
			guard ledger[entry.epoch] == nil,
				let componentID = UInt16(exactly: entry.componentId)
			else {
				throw TwoMLSPQSession.TwoMLSError.archiveInvalid
			}
			ledger[entry.epoch] = try TwoMLSPQSession.MigratedExportedPsk(
				componentID: componentID,
				pskID: entry.pskId,
				psk: SecretBytes(bytes: entry.psk))
		}
		return ledger
	}

	/// Rebuild one epoch-keyed window as a dictionary. A duplicate epoch means
	/// the export is corrupt (the Rust windows are `BTreeMap`s) or
	/// caller-fabricated; both are data faults, so this throws — never traps.
	private static func epochMap(
		_ entries: [TwoMLSPQBinding.SessionMigrationEpochEntry]
	) throws -> [UInt64: Data] {
		var map: [UInt64: Data] = [:]
		for entry in entries {
			guard map[entry.epoch] == nil else {
				throw TwoMLSPQSession.TwoMLSError.archiveInvalid
			}
			map[entry.epoch] = entry.bytes
		}
		return map
	}

	private static func attachmentMap(
		_ entries: [TwoMLSPQBinding.SessionMigrationEpochEntry]
	) throws -> [UInt64: SecretBytes] {
		var map: [UInt64: SecretBytes] = [:]
		for entry in entries {
			guard map[entry.epoch] == nil else {
				throw TwoMLSPQSession.TwoMLSError.archiveInvalid
			}
			map[entry.epoch] = try SecretBytes(bytes: entry.bytes)
		}
		return map
	}
}
