#!/usr/bin/env swift
import Foundation

struct ScriptTask {
    let path: URL
    let arguments: [String]
    let env: [String: String]

    init(path: URL, arguments: [String], env: [String: String] = [:]) {
        self.path = path
        self.arguments = arguments
        self.env = env
    }

    func run(allowingExitCodes codes: [Int32] = [0]) throws {
        let process = Process()
        var mutableEnv = ProcessInfo.processInfo.environment
        for (key, value) in env {
            mutableEnv[key] = value
        }
        process.environment = mutableEnv

        process.executableURL = path
        process.arguments = arguments

        try process.run()

        process.waitUntilExit()
        let terminationStatus = process.terminationStatus
        guard terminationStatus == 0 || codes.contains(terminationStatus) else {
            print("\(path) failed with exit code \(process.terminationStatus)")
            exit(-1)
        }
    }
}

let cargoBinPath = FileManager().homeDirectoryForCurrentUser.appending(
    path: ".cargo/bin/"
)

let cargoPath = cargoBinPath.appending(path: "cargo")

try ScriptTask(
    path: cargoBinPath.appending(path: "rustup"),
    arguments: ["target", "add", "aarch64-apple-ios-sim", "aarch64-apple-ios", "x86_64-apple-ios", "aarch64-apple-darwin"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./buildIos/MLSrs.xcframework"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./buildIos/MLSrs.xcframework.zip"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./buildIos/libtwo_mls_pq_sim_combined.a"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: cargoPath,
    arguments: ["clean"]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/mkdir"),
    arguments: ["buildIos"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: cargoPath,
    arguments: ["build"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: [
        "run", "-p", "uniffi-bindgen",
        "--bin", "uniffi-bindgen",
        "generate", "--library", "./target/debug/libtwo_mls_pq.dylib",
        "--language", "swift",
        "--out-dir", "./bindings",
    ]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios-sim"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios"],
    env: ["IPHONEOS_DEPLOYMENT_TARGET": "17.0"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-darwin"],
    env: ["MACOS_DEPLOYMENT_TARGET": "10_15"]
)
.run()

//XCode cloud servers run x86_64-apple-ios
try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=x86_64-apple-ios"]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/mv"),
    arguments: ["bindings/two_mls_pqFFI.modulemap", "bindings/module.modulemap"]
)
.run()

//We do want to use lipo to build a combined binary for arm and x86 simulator
//as XCode Cloud runs on x86
//https://forums.developer.apple.com/forums/thread/711294?answerId=722588022#722588022
try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/lipo"),
    arguments: [
        "-create",
        "-output", "buildIos/libtwo_mls_pq_sim_combined.a",
        "./target/aarch64-apple-ios-sim/release/libtwo_mls_pq.a",
        "./target/x86_64-apple-ios/release/libtwo_mls_pq.a",
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/xcodebuild"),
    arguments: [
        "-create-xcframework",
      
         //the simulator framework combining arm and x86_64 targets
        "-library", "./buildIos/libtwo_mls_pq_sim_combined.a", "-headers", "./bindings",
          //the ios framework
        "-library", "./target/aarch64-apple-ios/release/libtwo_mls_pq.a", "-headers",  "./bindings",
        "-library", "./target/aarch64-apple-darwin/release/libtwo_mls_pq.a", "-headers", "./bindings",
        "-output", "buildIos/MLSrs.xcframework",
    ]
)
.run()

guard FileManager.default.changeCurrentDirectoryPath("./buildIos") else {
    print("Couldn't change directory")
    exit(-1)
}

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/zip"),
    arguments: [
        "-r", "MLSrs.xcframework.zip", "MLSrs.xcframework",
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/swift"),
    arguments: [
        "package", "compute-checksum", "MLSrs.xcframework.zip",
    ]
)
.run()
