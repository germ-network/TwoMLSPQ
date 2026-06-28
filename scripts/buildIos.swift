#!/usr/bin/env swift
//
// Dynamic framework-bundle build (Swift port of scripts/buildIosDynamic.sh).
//
// Produces a dynamic (cdylib) xcframework packaged as `.framework` bundles so TwoMLSPQ can
// coexist in one app with the legacy classical static MLSrs lib:
//   1. dynamic (cdylib) keeps Rust std's symbols internal — avoids the
//      `duplicate symbol _rust_eh_personality` link error.
//   2. framework packaging keeps `module.modulemap` INSIDE the framework
//      (two_mls_pqFFI.framework/Modules/), not in the shared build `include/` dir — a
//      `-library … -headers …` xcframework dumps it into include/ and collides with the
//      other uniffi xcframework ("Multiple commands produce …/include/module.modulemap").
//
// Framework + clang module is `two_mls_pqFFI` (matches generated `import two_mls_pqFFI`);
// the xcframework wrapper is `TwoMLSPQ.xcframework`.
//
import Foundation

let crate = "two-mls-pq"
let libName = "libtwo_mls_pq"          // cargo output: <libName>.dylib
let module = "two_mls_pqFFI"           // framework + clang module name
let frameworkName = "TwoMLSPQ"         // xcframework name
let bindingsDir = "./bindings"
let buildDir = "./buildIos"
let fwDir = "\(buildDir)/frameworks"
let installName = "@rpath/\(module).framework/\(module)"
let buildFlags = ["--release", "--package", crate, "--no-default-features", "--features", "cryptokit"]

let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let cargo = home.appending(path: ".cargo/bin/cargo").path
let rustup = home.appending(path: ".cargo/bin/rustup").path

func run(_ launchPath: String, _ args: [String], env: [String: String] = [:], allow: [Int32] = [0]) {
    let p = Process()
    var e = ProcessInfo.processInfo.environment
    for (k, v) in env { e[k] = v }
    p.environment = e
    p.executableURL = URL(fileURLWithPath: launchPath)
    p.arguments = args
    do { try p.run() } catch { print("failed to launch \(launchPath): \(error)"); exit(-1) }
    p.waitUntilExit()
    guard p.terminationStatus == 0 || allow.contains(p.terminationStatus) else {
        print("\(launchPath) \(args.joined(separator: " ")) failed: \(p.terminationStatus)")
        exit(-1)
    }
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
    <key>CFBundleIdentifier</key><string>network.germ.\(module)</string>
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
    write(plist(minOS: "15.0", platform: "MacOSX"), to: "\(v)/Resources/Info.plist")
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

run(rustup, ["target", "add", "aarch64-apple-ios-sim", "aarch64-apple-ios",
             "x86_64-apple-ios", "aarch64-apple-darwin"], allow: [0, 1])

try? fm.removeItem(atPath: "\(buildDir)/\(frameworkName).xcframework")
try? fm.removeItem(atPath: "\(buildDir)/\(frameworkName).xcframework.zip")
try? fm.removeItem(atPath: fwDir)
mkdirs(buildDir); mkdirs(fwDir)

// Release cdylib builds (iOS device + simulator + macOS).
run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-ios-sim"])
run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-ios"], env: ["IPHONEOS_DEPLOYMENT_TARGET": "17.0"])
run(cargo, ["build"] + buildFlags + ["--target=x86_64-apple-ios"])
run(cargo, ["build"] + buildFlags + ["--target=aarch64-apple-darwin"], env: ["MACOSX_DEPLOYMENT_TARGET": "15.0"])

run(cargo, ["run", "-p", "uniffi-bindgen", "--bin", "uniffi-bindgen",
            "generate", "--library", "target/aarch64-apple-ios/release/\(libName).dylib",
            "--language", "swift", "--out-dir", bindingsDir])

// iOS device
flatFramework(dylib: "target/aarch64-apple-ios/release/\(libName).dylib",
              destParent: "\(fwDir)/ios", minOS: "17.0", platform: "iPhoneOS")

// iOS simulator (lipo arm64 + x86_64)
mkdirs("\(fwDir)/sim-build")
run("/usr/bin/lipo", ["-create", "-output", "\(fwDir)/sim-build/\(libName).dylib",
                      "target/aarch64-apple-ios-sim/release/\(libName).dylib",
                      "target/x86_64-apple-ios/release/\(libName).dylib"])
flatFramework(dylib: "\(fwDir)/sim-build/\(libName).dylib",
              destParent: "\(fwDir)/sim", minOS: "17.0", platform: "iPhoneSimulator")

// macOS
versionedFramework(dylib: "target/aarch64-apple-darwin/release/\(libName).dylib",
                   destParent: "\(fwDir)/macos")

run("/usr/bin/xcodebuild", [
    "-create-xcframework",
    "-framework", "\(fwDir)/ios/\(module).framework",
    "-framework", "\(fwDir)/sim/\(module).framework",
    "-framework", "\(fwDir)/macos/\(module).framework",
    "-output", "\(buildDir)/\(frameworkName).xcframework",
])

guard fm.changeCurrentDirectoryPath(buildDir) else { print("cd \(buildDir) failed"); exit(-1) }
run("/usr/bin/zip", ["-r", "\(frameworkName).xcframework.zip", "\(frameworkName).xcframework"])
run("/usr/bin/swift", ["package", "compute-checksum", "\(frameworkName).xcframework.zip"])
