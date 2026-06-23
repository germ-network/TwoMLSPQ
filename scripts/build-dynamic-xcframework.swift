#!/usr/bin/env swift

//
//  build-dynamic-xcframework.swift
//  AbstractTwoMLS tooling
//
//  Builds a *dynamic* .framework xcframework from a UniFFI Rust crate.
//
//  A dynamic framework keeps its `module.modulemap` inside the bundle
//  (<Module>.framework/Modules/), so Xcode never copies it into the shared
//  Build/Products/<config>/include/ directory. That is what lets two UniFFI
//  wrappers (two_mls_pqFFI + mls_rs_uniffi_iosFFI) coexist in one package
//  without the "Multiple commands produce .../include/module.modulemap" error
//  you get from static-library xcframeworks.
//
//  IMPORTANT: the framework bundle name must equal the imported module name
//  (`import two_mls_pqFFI` → two_mls_pqFFI.framework), because Clang resolves a
//  framework module by matching the bundle name.
//
//  Prereq: the crate's Cargo.toml declares `crate-type = ["cdylib"]` so the
//  produced dylib is self-contained (Rust std + system deps linked in).
//
//  Usage:
//    ./scripts/build-dynamic-xcframework.swift \
//        --module two_mls_pqFFI \
//        --crate-lib libtwo_mls_pq \
//        --header bindings/two_mls_pqFFI.h \
//        --bundle-id network.germ.two_mls_pqFFI \
//        --version 0.0.1
//
//  Run once per crate (TwoMLSPQ, mls-rs-uniffi).
//

import Foundation

// MARK: - Configuration

struct Config {
    var module: String                 // == imported module == framework bundle name
    var crateLib: String               // cargo cdylib stem, e.g. "libtwo_mls_pq"
    var header: String                 // uniffi-bindgen header path
    var bundleID: String
    var version: String
    var minIOS: String = "17.0"
    var outputDir: String = "build"

    // Triples per xcframework slice.
    var iosDevice: [String] = ["aarch64-apple-ios"]
    var iosSim: [String] = ["aarch64-apple-ios-sim", "x86_64-apple-ios"]
    var macos: [String] = ["aarch64-apple-darwin", "x86_64-apple-darwin"]

    var framework: String { "\(module).framework" }

    static func parse(_ args: [String]) throws -> Config {
        var map: [String: String] = [:]
        var i = 0
        while i < args.count {
            let key = args[i]
            guard key.hasPrefix("--") else { i += 1; continue }
            guard i + 1 < args.count else { throw Err("missing value for \(key)") }
            map[String(key.dropFirst(2))] = args[i + 1]
            i += 2
        }
        func required(_ name: String) throws -> String {
            guard let v = map[name] else { throw Err("missing required --\(name)") }
            return v
        }
        let module = try required("module")
        var cfg = Config(
            module: module,
            crateLib: try required("crate-lib"),
            header: try required("header"),
            bundleID: map["bundle-id"] ?? "network.germ.\(module)",
            version: map["version"] ?? "0.0.1"
        )
        if let v = map["min-ios"] { cfg.minIOS = v }
        if let v = map["output"] { cfg.outputDir = v }
        if let v = map["no-macos"], v == "true" { cfg.macos = [] }
        return cfg
    }
}

// MARK: - Errors & shell

struct Err: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { self.description = message }
}

let fm = FileManager.default

@discardableResult
func run(_ tool: String, _ arguments: [String], cwd: String? = nil) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = [tool] + arguments
    if let cwd { process.currentDirectoryURL = URL(fileURLWithPath: cwd) }
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.standardError
    print("∙ \(tool) \(arguments.joined(separator: " "))")
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw Err("`\(tool)` failed with status \(process.terminationStatus)")
    }
    return String(data: data, encoding: .utf8) ?? ""
}

func remove(_ path: String) throws {
    if fm.fileExists(atPath: path) { try fm.removeItem(atPath: path) }
}

func makeDir(_ path: String) throws {
    try fm.createDirectory(atPath: path, withIntermediateDirectories: true)
}

// MARK: - Framework assembly

func dylibPath(_ cfg: Config, target: String) -> String {
    "target/\(target)/release/\(cfg.crateLib).dylib"
}

func writeModuleMap(_ cfg: Config, to modulesDir: String) throws {
    let contents = """
    framework module \(cfg.module) {
        header "\(cfg.module).h"
        export *
    }

    """
    try contents.write(toFile: "\(modulesDir)/module.modulemap", atomically: true, encoding: .utf8)
}

func writeInfoPlist(_ cfg: Config, to path: String, supportedPlatform: String?) throws {
    var plist: [String: Any] = [
        "CFBundleExecutable": cfg.module,
        "CFBundleIdentifier": cfg.bundleID,
        "CFBundleName": cfg.module,
        "CFBundlePackageType": "FMWK",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleShortVersionString": cfg.version,
        "CFBundleVersion": cfg.version,
    ]
    if let supportedPlatform {
        plist["MinimumOSVersion"] = cfg.minIOS
        plist["CFBundleSupportedPlatforms"] = [supportedPlatform]
    }
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: URL(fileURLWithPath: path))
}

/// iOS / simulator: flat framework bundle.
func assembleFlat(_ cfg: Config, dylib: String, into dir: String, platform: String) throws {
    let fw = "\(dir)/\(cfg.framework)"
    try remove(fw)
    try makeDir("\(fw)/Headers")
    try makeDir("\(fw)/Modules")
    try fm.copyItem(atPath: dylib, toPath: "\(fw)/\(cfg.module)")
    try run("install_name_tool", ["-id", "@rpath/\(cfg.framework)/\(cfg.module)", "\(fw)/\(cfg.module)"])
    try fm.copyItem(atPath: cfg.header, toPath: "\(fw)/Headers/\(cfg.module).h")
    try writeModuleMap(cfg, to: "\(fw)/Modules")
    try writeInfoPlist(cfg, to: "\(fw)/Info.plist", supportedPlatform: platform)
}

/// macOS: versioned framework bundle (Versions/A + symlinks).
func assembleVersioned(_ cfg: Config, dylib: String, into dir: String) throws {
    let fw = "\(dir)/\(cfg.framework)"
    try remove(fw)
    let vA = "\(fw)/Versions/A"
    try makeDir("\(vA)/Headers")
    try makeDir("\(vA)/Modules")
    try makeDir("\(vA)/Resources")
    try fm.copyItem(atPath: dylib, toPath: "\(vA)/\(cfg.module)")
    try run("install_name_tool",
            ["-id", "@rpath/\(cfg.framework)/Versions/A/\(cfg.module)", "\(vA)/\(cfg.module)"])
    try fm.copyItem(atPath: cfg.header, toPath: "\(vA)/Headers/\(cfg.module).h")
    try writeModuleMap(cfg, to: "\(vA)/Modules")
    try writeInfoPlist(cfg, to: "\(vA)/Resources/Info.plist", supportedPlatform: nil)
    try fm.createSymbolicLink(atPath: "\(fw)/Versions/Current", withDestinationPath: "A")
    try fm.createSymbolicLink(atPath: "\(fw)/\(cfg.module)", withDestinationPath: "Versions/Current/\(cfg.module)")
    try fm.createSymbolicLink(atPath: "\(fw)/Headers", withDestinationPath: "Versions/Current/Headers")
    try fm.createSymbolicLink(atPath: "\(fw)/Modules", withDestinationPath: "Versions/Current/Modules")
    try fm.createSymbolicLink(atPath: "\(fw)/Resources", withDestinationPath: "Versions/Current/Resources")
}

func lipo(_ dylibs: [String], output: String) throws {
    try makeDir((output as NSString).deletingLastPathComponent)
    try run("lipo", ["-create"] + dylibs + ["-output", output])
}

// MARK: - Main

func main() throws {
    let cfg = try Config.parse(Array(CommandLine.arguments.dropFirst()))
    let out = cfg.outputDir
    try remove(out)
    try makeDir(out)

    // 1. Build a cdylib for every triple.
    let allTargets = cfg.iosDevice + cfg.iosSim + cfg.macos
    for target in allTargets {
        _ = try? run("rustup", ["target", "add", target])   // best-effort
        try run("cargo", ["build", "--release", "--target", target])
    }

    // 2. Assemble one framework per slice.
    var frameworkArgs: [String] = []

    // iOS device (single arch → no lipo needed)
    let iosDeviceDir = "\(out)/ios"
    try assembleFlat(cfg, dylib: dylibPath(cfg, target: cfg.iosDevice[0]),
                     into: iosDeviceDir, platform: "iPhoneOS")
    frameworkArgs += ["-framework", "\(iosDeviceDir)/\(cfg.framework)"]

    // iOS simulator (lipo arm64 + x86_64)
    let simFat = "\(out)/sim-lipo/\(cfg.crateLib).dylib"
    try lipo(cfg.iosSim.map { dylibPath(cfg, target: $0) }, output: simFat)
    let iosSimDir = "\(out)/sim"
    try assembleFlat(cfg, dylib: simFat, into: iosSimDir, platform: "iPhoneSimulator")
    frameworkArgs += ["-framework", "\(iosSimDir)/\(cfg.framework)"]

    // macOS (optional)
    if !cfg.macos.isEmpty {
        let macFat = "\(out)/mac-lipo/\(cfg.crateLib).dylib"
        try lipo(cfg.macos.map { dylibPath(cfg, target: $0) }, output: macFat)
        let macDir = "\(out)/macos"
        try assembleVersioned(cfg, dylib: macFat, into: macDir)
        frameworkArgs += ["-framework", "\(macDir)/\(cfg.framework)"]
    }

    // 3. Create the xcframework.
    let xcframework = "\(cfg.module).xcframework"
    try remove(xcframework)
    try run("xcodebuild", ["-create-xcframework"] + frameworkArgs + ["-output", xcframework])

    // 4. Strip extended attributes and AppleDouble sidecars BEFORE signing so the
    //    code-signature seal stays valid through a zip / re-extract round trip.
    //    macOS archive tooling stores a file's xattrs as a sibling `._<name>`
    //    AppleDouble file; when SwiftPM unpacks the downloaded artifact those
    //    reappear inside <framework>/Modules (e.g. `._module.modulemap`). They are
    //    not part of the seal, so `codesign --verify` reports "a sealed resource is
    //    missing or invalid" and Xcode fails with
    //    "The signature of <module>.xcframework cannot be verified."
    try run("xattr", ["-cr", xcframework])
    try run("find", [xcframework, "-name", "._*", "-delete"])

    // 5. Sign (ad-hoc), zip, checksum. `--norsrc --noextattr` keeps the archive
    //    free of the AppleDouble entries that would otherwise re-pollute the bundle.
    try run("codesign", ["--force", "--sign", "-", "--timestamp=none", xcframework])
    let zip = "\(cfg.module).xcframework.zip"
    try remove(zip)
    try run("ditto", ["--norsrc", "--noextattr", "-c", "-k", "--keepParent", xcframework, zip])
    let checksum = try run("swift", ["package", "compute-checksum", zip]).trimmingCharacters(in: .whitespacesAndNewlines)

    print("""

    ✅ Built \(xcframework)
       zip:      \(zip)
       checksum: \(checksum)

    Update Package.swift binaryTarget:
       url:      .../\(zip)
       checksum: \(checksum)
    """)
}

do {
    try main()
} catch {
    FileHandle.standardError.write(Data("✗ \(error)\n".utf8))
    exit(1)
}
