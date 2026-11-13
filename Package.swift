// swift-tools-version: 5.8
import PackageDescription

// A small C ABI over upstream zsign. The CLI, archive handling and app-bundle
// wrapper are deliberately not part of this package.
let package = Package(
    name: "Zsign",
    platforms: [.iOS(.v12), .macOS(.v10_15)],
    products: [.library(name: "zsignc", targets: ["ZsignC"])],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git",
                 revision: "e61a288a9bc49a0358ab61614cac3d0553472254")
    ],
    targets: [
        .target(
            name: "ZsignC",
            dependencies: [.product(name: "OpenSSL", package: "OpenSSL-Package")],
            path: "src",
            exclude: ["zsign.cpp", "bundle.cpp", "bundle.h", "macho.cpp", "macho.h",
                      "certcheck.cpp", "certcheck.h", "metadata.cpp", "metadata.h",
                      "common/archive.cpp", "common/archive.h", "third-party"],
            sources: ["archo.cpp", "signing.cpp", "openssl.cpp", "library.cpp", "identity.cpp",
                      "common/fs.cpp", "common/json.cpp", "common/log.cpp",
                      "common/sha.cpp", "common/timer.cpp", "common/util.cpp"],
            publicHeadersPath: "include",
            cxxSettings: [.headerSearchPath("."), .headerSearchPath("common"),
                          .define("ZSIGN_SWIFTPM")]
        )
    ],
    cxxLanguageStandard: .cxx11
)
