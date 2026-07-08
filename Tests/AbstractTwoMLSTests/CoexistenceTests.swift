import Foundation
// Both UniFFI libraries imported into the same test binary, as separate modules.
import MLSrsClassic  // legacy classical mls-rs-uniffi-ios
import Testing
import TwoMLSPQ  // post-quantum two-mls-pq

// Proves the two Rust/UniFFI libraries coexist in one binary: a live object from each,
// side by side, each exercising its own runtime (independent RustBuffer / no duplicate
// `rust_eh_personality`). Requires TwoMLSPQ to be linked as a dynamic framework.
@Test func twoLibrariesCoexistSideBySide() throws {
	// Object from the PQ library. The ClientId is now opaque identity bytes — the agent
	// signing key is generated internally, so no key material is passed in.
	let pqClient = try TwoMlsPqIdentity(clientId: Data([0x01, 0x02, 0x03]))
	let pqId = pqClient.clientId()
	#expect(!pqId.bytes.isEmpty)

	// Object from the legacy classical library — alive at the same time.
	let keypair = try generateSignatureKeypair(cipherSuite: .curve25519ChaCha)
	let config = clientConfigDefault()
	let legacyClient = ClientFfi(
		id: Data([0xAA, 0xBB, 0xCC]),
		signatureKeypair: keypair,
		clientConfig: config
	)

	// Exercise each runtime again with both objects live.
	let pqIdAgain = pqClient.clientId()
	#expect(pqId.bytes == pqIdAgain.bytes)
	_ = legacyClient
}
