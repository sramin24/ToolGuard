// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ToolGuard",
    // The SDK is macOS 27, but this Mac runs macOS 26.6; see DECISIONS.md (D-001).
    platforms: [.macOS(.v26), .iOS(.v26)],
    products: [
        .library(name: "ToolGuard", targets: ["ToolGuard"]),
        .library(name: "InboxKit", targets: ["InboxKit"]),
    ],
    targets: [
        .target(name: "ToolGuard"),
        .target(name: "InboxKit", dependencies: ["ToolGuard"], resources: [.copy("Fixtures")]),
        .executableTarget(name: "Spike", dependencies: ["ToolGuard", "InboxKit"]),
        .testTarget(name: "ToolGuardTests", dependencies: ["ToolGuard", "InboxKit"]),
    ],
    swiftLanguageModes: [.v6]
)
