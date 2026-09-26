// A non-empty stub so the `TwoMLSPQMigrate` target still has a source when the
// deployed-pin differential run (TWOMLSPQ_PIN_BINDING=1) excludes the two real migrators,
// which cannot compile against the pin's pre-migration-export FFI. Compiled always, so it
// is not itself a conditional source.
enum TwoMLSPQMigratePinStub {}
