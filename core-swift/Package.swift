// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DollyCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "DollyCore", targets: ["DollyCore"]),
        .executable(name: "dolly", targets: ["dolly"]),
    ],
    targets: [
        .target(name: "DollyCore"),
        // Command-line chat: the first end-to-end use of the core, and a real-network test tool.
        .executableTarget(name: "dolly", dependencies: ["DollyCore"]),
        // Self-contained checks (no XCTest / swift-testing), so they run on any Swift toolchain,
        // including a bare Command Line Tools install. Run with: swift run dolly-selftest
        .executableTarget(name: "dolly-selftest", dependencies: ["DollyCore"]),
    ]
)
