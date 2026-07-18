#!/usr/bin/env swift
//
// Dynamic framework-bundle build. Maintained alongside scripts/buildIosDynamic.sh — the two
// are a Swift/shell pair with divergent histories, kept functionally in sync. The shell is
// the CI/release path; this Swift build additionally accepts CLI overrides so the SAME script
// can build any UniFFI crate's dynamic framework (folded in from the former
// build-dynamic-xcframework.swift). With no flags it reproduces the shell script's default
// TwoMLSPQ / cryptokit build byte-for-byte.
//
// Produces a dynamic (cdylib) xcframework packaged as `.framework` bundles so TwoMLSPQ can
// coexist in one app with the legacy classical static MLSrs lib:
//   1. dynamic (cdylib) keeps Rust std's symbols internal — avoids the
//      `duplicate symbol _rust_eh_personality` link error.
//   2. framework packaging keeps `module.modulemap` INSIDE the framework
//      (<module>.framework/Modules/), not in the shared build `include/` dir — a
//      `-library … -headers …` xcframework dumps it into include/ and collides with the
//      other uniffi xcframework ("Multiple commands produce …/include/module.modulemap").
//
// The framework + clang module name must equal the imported module (`import two_mls_pqFFI` →
// two_mls_pqFFI.framework), because Clang resolves a framework module by the bundle name.
//
// Cargo/rustup run in the workspace (rust/) via a per-process cwd, so its .cargo/config.toml
// and rust-toolchain.toml — both discovered from the process cwd, not the manifest — take
// effect; the bindings and xcframework are written at the repo root (absolute paths), where
// the Swift package consumes them.
//
//   swift scripts/buildIos.swift \
//       [--module two_mls_pqFFI] [--crate two-mls-pq] [--lib-name libtwo_mls_pq] \
//       [--framework TwoMLSPQ] [--features cryptokit] [--bundle-id network.germ.TwoMLSPQ] \
//       [--min-ios 17.0] [--min-macos 15.0] [--no-macos] [--bindings bindings] [--output buildIos]
//
import Foundation

// MARK: - Configuration (CLI-overridable; defaults reproduce the shell script's build)

struct Config {
    var module = "two_mls_pqFFI"       // framework + clang module name (== `import <module>`)
    var crate = "two-mls-pq"           // cargo package
    var libName = "libtwo_mls_pq"      // cargo cdylib stem: <libName>.dylib
    var framework = "TwoMLSPQ"         // xcframework name
    var features = "cryptokit"         // the single provider feature to build
    var bundleID: String?              // defaults to network.germ.<framework>
    var minIOS = "17.0"
    var minMacOS = "15.0"
    var includeMacOS = true
    var bindingsDir = "bindings"       // relative to repo root (or absolute)
    var buildDir = "buildIos"          // relative to repo root (or absolute)

    var resolvedBundleID: String { bundleID ?? "network.germ.\(framework)" }
}

func parseConfig(_ argv: [String]) -> Config {
    var cfg = Config()
    var i = 0
    func value(_ key: String) -> String {
        guard i + 1 < argv.count else { print("missing value for \(key)"); exit(2) }
        i += 1
        return argv[i]
    }
    while i < argv.count {
        switch argv[i] {
        case "--module": cfg.module = value("--module")
        case "--crate", "--package": cfg.crate = value("--crate")
        case "--lib-name", "--crate-lib": cfg.libName = value("--lib-name")
        case "--framework": cfg.framework = value("--framework")
        case "--features": cfg.features = value("--features")
        case "--bundle-id": cfg.bundleID = value("--bundle-id")
        case "--min-ios": cfg.minIOS = value("--min-ios")
        case "--min-macos": cfg.minMacOS = value("--min-macos")
        case "--no-macos": cfg.includeMacOS = false
        case "--bindings": cfg.bindingsDir = value("--bindings")
        case "--output": cfg.buildDir = value("--output")
        case "--help", "-h":
            print("""
            usage: swift scripts/buildIos.swift [options]
              --module M       framework + clang module name (default two_mls_pqFFI)
              --crate C        cargo package (default two-mls-pq)
              --lib-name L     cargo cdylib stem (default libtwo_mls_pq)
              --framework F    xcframework name (default TwoMLSPQ)
              --features FEATS cargo --features value (default cryptokit)
              --bundle-id ID   CFBundleIdentifier (default network.germ.<framework>)
              --min-ios V      iOS MinimumOSVersion (default 17.0)
              --min-macos V    macOS deployment target (default 15.0)
              --no-macos       skip the macOS slice
              --bindings DIR   binding output dir (default bindings)
              --output DIR     xcframework output dir (default buildIos)
            """)
            exit(0)
        default:
            print("unknown argument: \(argv[i]) (see --help)"); exit(2)
        }
        i += 1
    }
    return cfg
}

let cfg = parseConfig(Array(CommandLine.arguments.dropFirst()))
let module = cfg.module
let libName = cfg.libName
let frameworkName = cfg.framework

let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let cargo = home.appending(path: ".cargo/bin/cargo").path
let rustup = home.appending(path: ".cargo/bin/rustup").path

// Repo root = this script's parent's parent (scripts/buildIos.swift). Resolve against the cwd
// so it works whether invoked as `swift scripts/buildIos.swift` or `./scripts/buildIos.swift`.
let scriptURL = URL(
    fileURLWithPath: CommandLine.arguments[0],
    relativeTo: URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
).standardizedFileURL
let repoRoot = scriptURL.deletingLastPathComponent().deletingLastPathComponent().path
let workspace = "\(repoRoot)/rust"     // the Cargo workspace; cargo/rustup run here
let targetDir = "\(workspace)/target"  // cargo output root (rust/target)

func absUnderRoot(_ p: String) -> String { p.hasPrefix("/") ? p : "\(repoRoot)/\(p)" }
let bindingsDir = absUnderRoot(cfg.bindingsDir)
let buildDir = absUnderRoot(cfg.buildDir)
let fwDir = "\(buildDir)/frameworks"
let installName = "@rpath/\(module).framework/\(module)"
let buildFlags = ["--release", "--package", cfg.crate, "--no-default-features", "--features", cfg.features]

guard fm.fileExists(atPath: "\(workspace)/Cargo.toml") else {
    print("could not locate the Rust workspace at \(workspace) (derived repo root: \(repoRoot))."
        + " Run from the repo, e.g. `swift scripts/buildIos.swift`.")
    exit(1)
}

// Cross-compile targets — single source of truth, shared by rustup target-add and the
// per-target bridge purge. The `cargo build` calls stay spelled out (each carries its own
// deployment-target env), but must cover exactly these triples.
var targets = ["aarch64-apple-ios-sim", "aarch64-apple-ios", "x86_64-apple-ios"]
if cfg.includeMacOS { targets.append("aarch64-apple-darwin") }

// Swift-build shim dir (populated in the build section below). Once set, run() prepends it to
// PATH so the nested `swift build` inside mls-rs-crypto-cryptokit's build.rs resolves to our
// wrapper. Cleaned up on exit, mirroring the shell script's `trap … EXIT`.
var shimDirGlobal = ""
atexit { if !shimDirGlobal.isEmpty { try? FileManager.default.removeItem(atPath: shimDirGlobal) } }

// fatal: false mirrors the shell's `|| true` — a nonzero exit is reported on stderr but does
// not abort the build (used for best-effort steps like `cargo clean`). `cwd` runs the child
// in a given directory without disturbing this script's cwd (cargo/rustup use the workspace).
func run(_ launchPath: String, _ args: [String], cwd: String? = nil, env: [String: String] = [:],
         allow: [Int32] = [0], fatal: Bool = true) {
    let p = Process()
    var e = ProcessInfo.processInfo.environment
    if !shimDirGlobal.isEmpty { e["PATH"] = "\(shimDirGlobal):\(e["PATH"] ?? "")" }
    for (k, v) in env { e[k] = v }
    p.environment = e
    p.executableURL = URL(fileURLWithPath: launchPath)
    p.arguments = args
    if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd) }
    do { try p.run() } catch { print("failed to launch \(launchPath): \(error)"); exit(-1) }
    p.waitUntilExit()
    guard p.terminationStatus == 0 || allow.contains(p.terminationStatus) else {
        print("\(launchPath) \(args.joined(separator: " ")) failed: \(p.terminationStatus)")
        if fatal { exit(-1) }
        return
    }
}

// Capture stdout of a command (trimmed). Used to resolve the real `swift` for the shim.
func capture(_ launchPath: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: launchPath)
    p.arguments = args
    let pipe = Pipe(); p.standardOutput = pipe
    do { try p.run() } catch { print("failed to launch \(launchPath): \(error)"); exit(-1) }
    p.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return (String(data: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
}

func write(_ text: String, to path: String) {
    do { try text.write(toFile: path, atomically: true, encoding: .utf8) }
    catch { print("write \(path) failed: \(error)"); exit(-1) }
}

func mkdirs(_ path: String) {
    try? fm.createDirectory(atPath: path, withIntermediateDirectories: true)
}

func copy(_ from: String, _ to: String) {
    try? fm.removeItem(atPath: to)
    do { try fm.copyItem(atPath: from, toPath: to) }
    catch { print("copy \(from) -> \(to) failed: \(error)"); exit(-1) }
}

let modMap = """
framework module \(module) {
    header "\(module).h"
    export *
}
"""

func plist(minOS: String, platform: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>\(module)</string>
    <key>CFBundleIdentifier</key><string>\(cfg.resolvedBundleID)</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>\(module)</string>
    <key>CFBundlePackageType</key><string>FMWK</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>MinimumOSVersion</key><string>\(minOS)</string>
    <key>CFBundleSupportedPlatforms</key><array><string>\(platform)</string></array>
    </dict></plist>
    """
}

// Flat framework (iOS device / simulator)
func flatFramework(dylib: String, destParent: String, minOS: String, platform: String) {
    let dir = "\(destParent)/\(module).framework"
    mkdirs("\(dir)/Headers"); mkdirs("\(dir)/Modules")
    copy(dylib, "\(dir)/\(module)")
    run("/usr/bin/install_name_tool", ["-id", installName, "\(dir)/\(module)"])
    copy("\(bindingsDir)/\(module).h", "\(dir)/Headers/\(module).h")
    write(modMap, to: "\(dir)/Modules/module.modulemap")
    write(plist(minOS: minOS, platform: platform), to: "\(dir)/Info.plist")
}

// Versioned framework (macOS)
func versionedFramework(dylib: String, destParent: String) {
    let base = "\(destParent)/\(module).framework"
    let v = "\(base)/Versions/A"
    mkdirs("\(v)/Headers"); mkdirs("\(v)/Modules"); mkdirs("\(v)/Resources")
    copy(dylib, "\(v)/\(module)")
    run("/usr/bin/install_name_tool", ["-id", installName, "\(v)/\(module)"])
    copy("\(bindingsDir)/\(module).h", "\(v)/Headers/\(module).h")
    write(modMap, to: "\(v)/Modules/module.modulemap")
    write(plist(minOS: cfg.minMacOS, platform: "MacOSX"), to: "\(v)/Resources/Info.plist")
    func link(_ at: String, _ dest: String) {
        try? fm.removeItem(atPath: at)
        try? fm.createSymbolicLink(atPath: at, withDestinationPath: dest)
    }
    link("\(base)/Versions/Current", "A")
    link("\(base)/\(module)", "Versions/Current/\(module)")
    link("\(base)/Headers", "Versions/Current/Headers")
    link("\(base)/Modules", "Versions/Current/Modules")
    link("\(base)/Resources", "Versions/Current/Resources")
}

// ---- build ----

// Swift build-system shim. mls-rs-crypto-cryptokit's build.rs runs a bare `swift build` and
// links libcryptokit-bridge.a from the legacy SwiftPM layout. Xcode 16.3+/Swift 6.4 default
// the engine to "swiftbuild", which emits elsewhere, so the link fails with "could not find
// native static library cryptokit-bridge". We can't pass flags into that nested invocation,
// so shim `swift build` on PATH (prepended in run()) to force the legacy "native" engine.
let realSwift = capture("/usr/bin/xcrun", ["-f", "swift"])
shimDirGlobal = "\(NSTemporaryDirectory())twomlspq-shim-\(ProcessInfo.processInfo.processIdentifier)"
mkdirs(shimDirGlobal)
write("""
#!/usr/bin/env bash
if [ "${1:-}" = "build" ]; then
    shift
    exec "\(realSwift)" build --build-system native "$@"
fi
exec "\(realSwift)" "$@"
""", to: "\(shimDirGlobal)/swift")
run("/bin/chmod", ["+x", "\(shimDirGlobal)/swift"])

run(rustup, ["target", "add"] + targets, cwd: workspace, allow: [0, 1])

// Clean intermediates only. The published artifacts (<framework>.xcframework + .zip) are NOT
// removed here: downstream consumes buildIos/<framework>.xcframework directly (the Swift
// package's LOCAL DEV path), so the old artifact must survive a failed build. New output is
// staged and swapped in atomically at the end.
let stageDir = "\(buildDir)/.stage"
try? fm.removeItem(atPath: fwDir)
try? fm.removeItem(atPath: stageDir)
mkdirs(buildDir); mkdirs(fwDir); mkdirs(stageDir)

// Purge stale CryptoKit-bridge builds. A host `cargo test --features cryptokit` (or any host
// build) leaves macOS-target Swift objects in the bridge's SwiftPM cache that cargo's
// fingerprinting does not notice; a later iOS cross-build then embeds macOS objects into
// mls-rs-crypto-cryptokit's rlib and fails at link with "building for 'iOS-simulator', but
// linking in object file built for 'macOS'". Dropping the bridge cache and the crate's
// build artifacts forces a correct per-target rebuild (costs seconds per target).
//
// CAUTION: ~/.cargo/git/checkouts is machine-global shared state. This purge is safe for a
// single serial build but is NOT concurrency-safe: a parallel build in another worktree — or
// a CI job on a shared runner — against the same mls-rs rev can race it. Do not run this in
// parallel with another cryptokit build on the same machine.
let checkouts = home.appending(path: ".cargo/git/checkouts").path
var purged = 0
for dir in (try? fm.contentsOfDirectory(atPath: checkouts)) ?? [] where dir.hasPrefix("mls-rs-") {
    let revsBase = "\(checkouts)/\(dir)"
    for rev in (try? fm.contentsOfDirectory(atPath: revsBase)) ?? [] {
        let bridge = "\(revsBase)/\(rev)/mls-rs-crypto-cryptokit/cryptokit-bridge/.build"
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: bridge, isDirectory: &isDir), isDir.boolValue else { continue }
        print("purge: removing stale bridge cache \(bridge)")
        try? fm.removeItem(atPath: bridge)
        purged += 1
    }
}
if purged == 0 {
    FileHandle.standardError.write(Data("purge: WARNING — no cryptokit-bridge .build cache matched; the mls-rs dependency layout may have changed and this purge is now a no-op\n".utf8))
}
// fatal: false so a clean failure can't abort the build, but stderr stays visible: a broken
// package spec (e.g. after a crate rename) now surfaces instead of being swallowed.
for triple in targets {
    print("purge: cargo clean mls-rs-crypto-cryptokit (\(triple))")
    run(cargo, ["clean", "-p", "mls-rs-crypto-cryptokit", "--release", "--target", triple], cwd: workspace, fatal: false)
}

// Release cdylib builds (iOS device + simulator [+ macOS]).
run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-ios-sim"], cwd: workspace)
run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-ios"], cwd: workspace, env: ["IPHONEOS_DEPLOYMENT_TARGET": cfg.minIOS])
run(cargo, ["build"] + buildFlags + ["--target=x86_64-apple-ios"], cwd: workspace)
if cfg.includeMacOS {
    run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-darwin"], cwd: workspace, env: ["MACOSX_DEPLOYMENT_TARGET": cfg.minMacOS])
}

run(cargo, ["run", "-p", "uniffi-bindgen", "--bin", "uniffi-bindgen",
            "generate", "--library", "\(targetDir)/aarch64-apple-ios/release/\(libName).dylib",
            "--language", "swift", "--out-dir", bindingsDir], cwd: workspace)

// iOS device
flatFramework(dylib: "\(targetDir)/aarch64-apple-ios/release/\(libName).dylib",
              destParent: "\(fwDir)/ios", minOS: cfg.minIOS, platform: "iPhoneOS")

// iOS simulator (lipo arm64 + x86_64)
mkdirs("\(fwDir)/sim-build")
run("/usr/bin/lipo", ["-create", "-output", "\(fwDir)/sim-build/\(libName).dylib",
                      "\(targetDir)/aarch64-apple-ios-sim/release/\(libName).dylib",
                      "\(targetDir)/x86_64-apple-ios/release/\(libName).dylib"])
flatFramework(dylib: "\(fwDir)/sim-build/\(libName).dylib",
              destParent: "\(fwDir)/sim", minOS: cfg.minIOS, platform: "iPhoneSimulator")

// macOS
if cfg.includeMacOS {
    versionedFramework(dylib: "\(targetDir)/aarch64-apple-darwin/release/\(libName).dylib",
                       destParent: "\(fwDir)/macos")
}

// Assemble + zip in the staging dir, then swap into place only on success, so a failed run
// never destroys the previously published artifact.
var xcframeworkArgs = [
    "-create-xcframework",
    "-framework", "\(fwDir)/ios/\(module).framework",
    "-framework", "\(fwDir)/sim/\(module).framework",
]
if cfg.includeMacOS {
    xcframeworkArgs += ["-framework", "\(fwDir)/macos/\(module).framework"]
}
xcframeworkArgs += ["-output", "\(stageDir)/\(frameworkName).xcframework"]
run("/usr/bin/xcodebuild", xcframeworkArgs)

// -y preserves the macOS versioned framework's symlinks (Versions/Current, etc.) instead of
// dereferencing them into duplicated content. zip has no cwd flag, so run it with cwd = the
// stage dir to keep <framework>.xcframework at the archive root.
run("/usr/bin/zip", ["-ry", "\(frameworkName).xcframework.zip", "\(frameworkName).xcframework"], cwd: stageDir)

let publishedFw = "\(buildDir)/\(frameworkName).xcframework"
let publishedZip = "\(buildDir)/\(frameworkName).xcframework.zip"
try? fm.removeItem(atPath: publishedFw)
try? fm.removeItem(atPath: publishedZip)
do {
    try fm.moveItem(atPath: "\(stageDir)/\(frameworkName).xcframework", toPath: publishedFw)
    try fm.moveItem(atPath: "\(stageDir)/\(frameworkName).xcframework.zip", toPath: publishedZip)
} catch { print("artifact swap failed: \(error)"); exit(-1) }

// Checksum before stage teardown so its output — which the release recipe consumes — is never
// gated behind cleanup. Run from the workspace (no Package.swift), matching the shell script.
run("/usr/bin/swift", ["package", "compute-checksum", publishedZip], cwd: workspace)
try? fm.removeItem(atPath: stageDir)
