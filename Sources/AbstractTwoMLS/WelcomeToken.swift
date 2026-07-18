//
//  WelcomeToken.swift
//  AbstractTwoMLS
//

import CommProtocol
import Foundation

extension AbstractTwoMLS {
	/// Opaque token linking a decoded welcome to its `receive`: `decodeHeader` mints one
	/// (in `.appWelcome`), `receive` consumes it. The type *is* the contract — a caller
	/// hands back exactly what `decodeHeader` returned and cannot substitute a recomputed
	/// digest, which would silently break replay-forward routing (the token keys the
	/// invitation's forward table). No public initializer: only a backend mints one.
	public struct WelcomeToken: Sendable, Equatable, Hashable {
		/// The underlying digest — readable (e.g. as a storage key), not forgeable into a
		/// token from outside the package.
		public let digest: TypedDigest

		/// `package` so the backend adapter and in-package tests mint tokens; the app can't.
		package init(_ digest: TypedDigest) { self.digest = digest }

		/// Wire bytes handed to the FFI as the opaque spawn token.
		var wireFormat: Data { digest.wireFormat }
	}
}
