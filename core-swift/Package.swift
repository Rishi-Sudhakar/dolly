// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DollyCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "DollyCore", targets: ["DollyCore"])],
    targets: [
        .target(name: "DollyCore"),
        // Self-contained checks (no XCTest / swift-testing), so they run on any Swift toolchain,
        // including a bare Command Line Tools install. Run with: swift run dolly-selftest
        .executableTarget(name: "dolly-selftest", dependencies: ["DollyCore"]),
    ]
)
