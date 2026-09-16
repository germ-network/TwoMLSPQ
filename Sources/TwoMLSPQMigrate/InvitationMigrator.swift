import Foundation
import SecretBytes
import TwoMLSPQBinding
import TwoMLSPQSession

// MARK: - Invitation migrator (GER-2372 R3)
//
// The bridge from the legacy Rust engine to the native one: reads a Rust
// invitation's migration export (GER-2484 R2, `TwoMlsPqInvitation.migrationExport`)
// and mints a native invitation `SecretArchive` via R1's
// `InvitationMigration.mintArchive`. The Rust engine stays a read-only legacy
// decoder (dual-read / single-write): this target only reads exports and maps
// bytes; it never writes back into the Rust side.
//
// The mint cross-checks every secret against its KeyPackage public, so a
// mis-mapped field fails LOUDLY here (`.archiveInvalid`) rather than restoring
// and failing opaquely at first use — a differential test (see
// TwoMLSPQMigrateTests) turns that into a migration regression gate.
//
// Both this package and twomlspq-swift define `Invitation`-shaped and
// `ClientID`-shaped names; everything cross-module is qualified below.

/// Migrates a legacy Rust invitation to a native, unsealed invitation
/// `SecretArchive` — the app seals before persisting (this inherits the Rust
/// `ArchiveSink` contract: the export carries PLAINTEXT secret material and
/// the caller owns its sealing).
@available(iOS 26, macOS 26, *)
public enum InvitationMigrator {
	/// Map a raw FFI migration export onto R1's `MigratedIdentity` and mint the
	/// archive.
	///
	/// The export's table lists rebuild as dictionaries; the mint re-sorts the
	/// arrays bytewise, so table order is irrelevant here. A spent single-use
	/// invitation (export `identity == nil`) mints an `identity: nil` archive —
	/// the native restore then refuses `openInitial` with `.invitationSpent`.
	///
	/// - Throws: `TwoMLSError.archiveInvalid` (from the mint, or from a duplicate
	///   key in an export table — the record has a public initializer, so its
	///   contents are caller data, and corrupt data surfaces as an error, not a
	///   trap) if any exported part fails its cross-check — the Rust export, not
	///   this mapping, is the suspect.
	public static func mintArchive(from export: TwoMLSPQBinding.MigrationExport)
		throws -> SecretArchive
	{
		let identity = try export.identity.map {
			try migratedIdentity($0, clientID: export.clientId)
		}
		return try TwoMLSPQSession.InvitationMigration.mintArchive(
			clientID: export.clientId,
			lastResort: export.lastResort,
			stateSeq: export.stateSeq,
			identity: identity,
			forwardTable: try dictionary(export.forwardTable),
			processedWelcomes: try dictionary(export.processedWelcomes),
			bootstrapRouting: try dictionary(export.bootstrapRouting),
			consumedRemotes: Set(export.consumedRemotes))
	}

	/// Byte-map the identity record. Every field is verbatim from the export —
	/// the mint's cross-checks (publics re-derived from secrets, KeyPackage
	/// parses, credential binding) are the safety net for a wrong map.
	private static func migratedIdentity(
		_ identity: TwoMLSPQBinding.MigrationIdentity,
		clientID: Data
	) throws -> TwoMLSPQSession.MigratedIdentity {
		// R1's `MigratedIdentity` carries its own `clientID` (checked against both
		// KeyPackages' credentials and the invitation-level one at mint); the Rust
		// identity record has none, so it lifts from the export top level.
		try TwoMLSPQSession.MigratedIdentity(
			clientID: clientID,
			signingKey: SecretBytes(bytes: identity.signingKey),
			signatureKey: identity.signatureKey,
			pqSigningKey: SecretBytes(bytes: identity.pqSigningKey),
			pqSignatureKey: identity.pqSignatureKey,
			classicalLeafSecretKey: SecretBytes(bytes: identity.classicalLeafSecretKey),
			classicalInitSecretKey: SecretBytes(bytes: identity.classicalInitSecretKey),
			pqLeafSecretKey: SecretBytes(bytes: identity.pqLeafSecretKey),
			pqInitSecretKey: SecretBytes(bytes: identity.pqInitSecretKey),
			classicalKeyPackage: identity.classicalKeyPackage,
			pqKeyPackage: identity.pqKeyPackage)
	}

	/// Rebuild one routing table as a dictionary. A duplicate key means the
	/// export is corrupt (the Rust tables are `BTreeMap`s) or caller-fabricated;
	/// both are data faults, so this throws `archiveInvalid` — never traps.
	private static func dictionary(
		_ entries: [TwoMLSPQBinding.MigrationTableEntry]
	) throws -> [Data: Data] {
		var table: [Data: Data] = [:]
		for entry in entries {
			guard table[entry.key] == nil else {
				throw TwoMLSError.archiveInvalid
			}
			table[entry.key] = entry.classicalGroupId
		}
		return table
	}
}
