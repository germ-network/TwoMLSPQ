import CryptoKit
import Foundation
import Testing
import AbstractTwoMLS

struct APIDemo {
	let localClient: any AbstractTwoMLS.Client
	let remoteInvitation: any AbstractTwoMLS.Invitation

	init() throws {
		//don't yet have an implementation we can slot in here
		throw DemoErrors.notImplemented
	}
	@Test func apiDemo() async throws {
		//local fetches the remote keyPackage
		let encodedRemoteKpkg = remoteInvitation.encodedKeyPackage

		//local parses the keyPackage
		let keyPackageSuite = type(of: localClient).parseKeyPackageSuite(
			encoded: encodedRemoteKpkg
		)

		guard type(of: localClient).supportedSuites.contains(keyPackageSuite) else {
			throw DemoErrors.notImplemented
		}

		let (sendGroupArchive, sendWelcome, myKeyPackage) = try localClient.reply(
			keyPackageMessage: encodedRemoteKpkg
		)

		//construct the TwoMLS group and encrypted, combined welcome
		let mockAppWelcome = MockAppWelcome(
			mySendGroupWelcome: sendWelcome,
			   myKeyPackage: myKeyPackage
		   )
		let (localSendGroupArchive, encryptedCombinedWelcome) = localClient.createTwoMLSGroup(
			remoteAgentId: remoteInvitation.clientId,
			mySendGroupArchive: sendGroupArchive,
			theirKeyPackageMessage: encodedRemoteKpkg,
			appWelcome: JSONEncoder().encode(mockAppWelcome)
		)

		let localSendGroup = type(of: localClient).Invitation.Session.init(
			archive: localSendGroupArchive
		)
	}

	struct MockAppWelcome: Codable, Sendable {
		let mySendGroupWelcome: Data
		let myKeyPackage: Data
	}
}

enum DemoErrors: LocalizedError {
	case notImplemented

	package var errorDescription: String? {
		switch self {
		case .notImplemented: "Not implemented"
		}
	}
}

extension AbstractTwoMLS.ClientID {
	static func mock() -> Self {
		SymmetricKey(size: .bits256).rawRepresentation
	}
}
