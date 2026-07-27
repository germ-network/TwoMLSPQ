---
"@germ-network/two-mls-pq": minor
---

Remove `derive_session_id`

A session pins its identifier at its **founding** pair — the invitation identity
the initiator addressed — and never moves it again. The client ids it was derived
from do move: a principal rotation replaces them, and a born-dedicated acceptor
never operated under its founding id at all. So a caller re-deriving the id from
the ids it currently holds got a value that silently disagreed with the one the
session carries, and the disagreement surfaced after a rotation, in whatever
local state had been keyed by it.

Removed rather than deprecated, because a deprecation is an instruction to
substitute and no substitution is value-preserving here: swapping in the session
accessor changes the bytes for exactly the sessions that had drifted, while
ignoring the warning keeps a value that does not match the session. The call
answered two different questions, and they have different answers:

- *"What is this session's id?"* — `TwoMlsPqSession::active_session_id()`. The
  stored founding value: identical on both sides, available from construction,
  preserved across archive restore.
- *"What is a stable key for this pair, before a session exists?"* — compute your
  own digest. It was only `SHA-256(min(a,b) ‖ max(a,b))` over two public
  `ClientId`s, with nothing secret and nothing protocol-specific in it, so it
  never needed to live in this crate. Just don't call the result a session id: it
  stops matching the session's as soon as either party rotates.

The derivation itself survives crate-internally as `pair_session_id`, called only
by the two constructors, which are the only places the founding pair is in scope.

Binding contract 30 → 31, with no wire or error-variant change. Removing an
exported function drops its FFI symbol, so the vendored binding is re-synced here
and must be paired with a matching binary. Swift consumers of the `TwoMLSPQ`
product are unaffected: the generated binding is an internal target, so this
function was never reachable from the vended surface.
