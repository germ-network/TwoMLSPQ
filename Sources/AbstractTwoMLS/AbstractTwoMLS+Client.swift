//
//  AbstractTwoMLS+Client.swift
//  AbstractTwoMLS
//
//  Created by Mark @ Germ on 6/22/26.
//
//  Declares the AbstractTwoMLS namespace and the Client / Invitation
//  entry-point protocols.
//

import CommProtocol
import Foundation

public enum AbstractTwoMLS {
	public typealias ClientID = Data
	public typealias GroupID = Data

	public typealias RawSuites = UInt16

	//should be 32 bytes
	public typealias RendezvousID = Data

	public protocol Client {
		associatedtype Invitation: AbstractTwoMLS.Invitation where Invitation.Client == Self

		init(clientId: ClientID) throws

		func makeInvitation() throws -> Invitation.Archive

		static func parseKeyPackageSuite(encoded: Data) -> RawSuites

		static var supportedSuites: [RawSuites] { get }

		//two-step reply
		//first step, sets up a send group from a remote keyPackage
		func reply(keyPackageMessage: Data) throws -> (
			sendGroupArchive: Invitation.Session.Archive,
			welcomeMessage: Data,
			//to form the com
			myKeyPackage: Data
		)

		//using the output of the above to form an AppWelcome, can then package
		//and encrypt the AppWelcome to the remote
		func createTwoMLSGroup(
			remoteAgentId: ClientID,
			mySendGroupArchive: Invitation.Session.Archive,
			//extract the leaf node HPKE key to encrypt the initial message
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws -> (
			Invitation.Session.Archive,
			encryptedCombinedWelcome: Data
		)
	}

	//object backing one keyPackage
	public protocol Invitation: Archivable {
		associatedtype Client: AbstractTwoMLS.Client where Client.Invitation == Self
		associatedtype Session: AbstractTwoMLS.Session where Session.Invitation == Self

		init(clientId: ClientID) throws
		var clientId: ClientID { get }
		var encodedKeyPackage: Data { get }

		//two-step receive
		//the invitation object recalls the used groupIds
		func decodeHeader(ciphertext: Data) throws -> HeaderDecryptResult

		func receive(
			sendGroupWelcome: Data,
			combinedWelcomeDigest: TypedDigest,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID,
		) throws -> (Session.Archive, plaintext: Data?)
	}

	public enum HeaderDecryptResult {
		case forward(groupId: DataIdentifier, mlsMessageData: Data)
		case appWelcome(
			//digest of the MLSApplication message within the header encryption
			appWelcomeDigest: TypedDigest,
			appWelcome: Data,
			stapledPrivateMessage: Data?
		)
	}
}
