//
//  TestSupport.swift
//  TwoMLSPQ
//
//  Shared helpers for the concrete/FFI test suites.
//

import CommProtocol
import CryptoKit
import Foundation
import TwoMLSPQ

extension ClientID {
	/// A random 32-byte client id, standing in for an app-minted identity.
	static func mock() -> Self {
		SymmetricKey(size: .bits256).rawRepresentation
	}
}
