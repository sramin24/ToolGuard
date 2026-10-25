// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ToolGuard",
    // The SDK is macOS 27, but this Mac runs macOS 26.6; see DECISIONS.md (D-001).
    platforms: [.macOS(.v26), .iOS(.v26)],
    products: [
        .library(name: "ToolGuard", targets: ["ToolGuard"]),
    ],
    targets: [
        .target(name: "ToolGuard"),
        .executableTarget(name: "Spike"),
        .testTarget(name: "ToolGuardTests", dependencies: ["ToolGuard"]),
    ],
    swiftLanguageModes: [.v6]
)
