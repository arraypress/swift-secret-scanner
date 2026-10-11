// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecretScanner",
    // The git walkers shell out to git, which is a macOS assumption; the
    // text scanner itself is pure Foundation.
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "SecretScanner",
            targets: ["SecretScanner"]
        ),
    ],
    targets: [
        .target(
            name: "SecretScanner"
        ),
        .testTarget(
            name: "SecretScannerTests",
            dependencies: ["SecretScanner"]
        ),
    ]
)

// Swift 7's import rule, today: a file must import every module whose members
// it uses, rather than leaning on another file's imports.
for target in package.targets where target.type != .system && target.type != .binary && target.type != .plugin {
    target.swiftSettings = (target.swiftSettings ?? []) + [.enableUpcomingFeature("MemberImportVisibility")]
}
