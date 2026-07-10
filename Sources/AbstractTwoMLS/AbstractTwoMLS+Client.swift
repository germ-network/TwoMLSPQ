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

		//nil when `encoded` is not a parseable (combiner or bare MLS) key package
		static func parseKeyPackageSuite(encoded: Data) -> RawSuites?

		static var supportedSuites: [RawSuites] { get }

		//two-step reply: step one sets up a send group from a remote keyPackage.
		//Returns the live session (Archivable once session persistence lands) plus
		//the welcome and this side's published key package for the return group.
		func reply(keyPackageMessage: Data) throws -> (
			sendGroup: Invitation.Session,
			welcomeMessage: Data,
			myKeyPackage: Data
		)

		//step two: package and encrypt the AppWelcome formed from the above
		//to the remote
		func createTwoMLSGroup(
			remoteAgentId: ClientID,
			mySendGroup: Invitation.Session,
			//extract the leaf node HPKE key to encrypt the initial message
			theirKeyPackageMessage: Data,
			appWelcome: Data
		) throws -> (
			Invitation.Session,
			encryptedCombinedWelcome: Data
		)
	}

	//object backing one keyPackage
	public protocol Invitation: Archivable {
		associatedtype Client: AbstractTwoMLS.Client where Client.Invitation == Self
		associatedtype Session: AbstractTwoMLS.Session

		init(clientId: ClientID) throws
		var clientId: ClientID { get }
		var encodedKeyPackage: Data { get }

		//two-step receive
		//the invitation object recalls the used groupIds
		func decodeHeader(ciphertext: Data) throws -> HeaderDecryptResult

		//Unifies the card and anchor receive flows: after validating the decoded
		//AppWelcome/AnchorWelcome, the app passes back the remote's published key
		//package and authenticated client id extracted from it; the conformance
		//binds the two — the key package's credential must match the authenticated
		//identity. `remoteKeyPackage` is opaque to the abstraction (the PQ combiner
		//encodes both halves). Returns the live session, Archivable via
		//`session.archive` once session persistence lands in the backend.
		func receive(
			sendGroupWelcome: Data,
			remoteKeyPackage: Data,
			remoteClientId: ClientID,
			welcomeToken: WelcomeToken,
			stapledMessage: Data?,
			newClientId: AbstractTwoMLS.ClientID,
		) throws -> (Session, plaintext: Data?)
	}

	public enum HeaderDecryptResult {
		case forward(groupId: DataIdentifier, mlsMessageData: Data)
		case appWelcome(
			//opaque token for this welcome; pass it back verbatim to `receive`
			welcomeToken: WelcomeToken,
			appWelcome: Data,
			stapledPrivateMessage: Data?
		)
	}
}
