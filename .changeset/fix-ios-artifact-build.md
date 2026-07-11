---
"@germ-network/two-mls-pq": patch
---

Fix the iOS XCFramework build (restore the CryptoKit iOS-build fixes)

v0.0.12's artifact build panicked in mls-rs-crypto-cryptokit's build.rs ("Libraries require RPath!"). The `germ-shadow-safe-exporter` branch had never picked up the CryptoKit iOS-build fixes the previous pin (`3743c75`) carried: newer Xcode toolchains report `librariesRequireRPath` for varying deployment targets, and that guard is spurious for this artifact — the cdylib ships inside an `@rpath/…framework`, so rpath-based loading is exactly what is wanted. The bumped mls-rs pin restores those fixes (panic → warning; `MIN_IOS_DEPLOYMENT_TARGET` stays 17.0, so the bridge still compiles for iOS 17+ deployment). No library code changes; binding contract, session archive, and key package versions are unchanged from 0.0.12 (which shipped no artifacts).
