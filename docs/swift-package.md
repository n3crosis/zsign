# Swift package: standalone library signing

This branch starts from original `zhlynn/zsign` master at
`9299685bab7ef99827e06e5dfda93af747386590` (see the Git history for the exact base).
It adds a narrow C ABI and SwiftPM manifest, rather than importing the older
app-signing wrapper from another fork. Upstream certificate-chain selection,
WWDR intermediates, CodeDirectory flags and special-slot behavior are retained.

## Import into an Apple app

Add this repository as a Swift package dependency, pinning a reviewed commit:

```swift
.package(url: "https://github.com/n3crosis/zsign.git",
         branch: "feat/swift-package")
```

Add `.product(name: "zsignc", package: "zsign")` to the consuming target, then:

```swift
import ZsignC
```

For reproducible releases, replace the branch requirement with the full commit
SHA. NX2Apple's existing `import ZsignC` and `zsignc` product names are unchanged.
Only its dependency revision needs updating. No Swift C++ interop mode, bridging
header, Objective-C wrapper or unsafe compiler flags are required.

The package supports iOS 12+ and macOS 10.15+ and pins OpenSSL-Package to
`e61a288a9bc49a0358ab61614cac3d0553472254`. SwiftPM links its OpenSSL XCFramework.
The static legacy provider is registered for older encrypted PKCS#12 exports.
The command-line executable, archive handling, certificate network checks and
app-bundle traversal are excluded from the package. Existing CLI build entry
points remain available separately.

## API contract

The public header is `src/include/ZSignLibrary.h`:

- `zsign_check_identity`: check local PKCS#12, profile certificate membership and team consistency.
- `zsign_sign_library`: sign a private staged thin arm64 dylib or bundle without external resource seals.
- `zsign_sign_library_with_resources`: sign a framework main image using its staged external Info.plist and CodeResources.
- `zsign_validate_imported_identity`: match an imported identity to the actual host CMS signer and return its leaf certificate.
- `zsign_copy_profile_content`: extract bounded embedded CMS SignedData content.
- `zsign_copy_signer_expiration`: read the sole signer certificate's expiration.

Signing does not turn a library into an app or resize a Mach-O file. A bounded
`LC_CODE_SIGNATURE` reservation must already occupy the end of the file. Only
that reservation is written. Malformed, encrypted, unsupported or insufficiently
sized inputs fail before writing. Discard the private staged copy after any I/O
failure, since a failed final write may be partial. Do not sign installed/live
images or invoke legacy zsign entry points concurrently with these calls.

The bridge preserves validated 4 KB or 16 KB CodeDirectory page geometry while
recomputing every code hash. An all-zero reservation defaults to 4 KB. Conflicting,
malformed or unsupported existing layouts are rejected; page size is never
increased just to squeeze a signature into a smaller reservation.

Frameworks need their external metadata sealed as well as their executable. Pass
its staged `Info.plist` and `_CodeSignature/CodeResources` paths to
`zsign_sign_library_with_resources`; their exact bytes are hashed into slots -1
and -3. Reads are bounded (1 MiB and 16 MiB), reject non-regular files/symlinks,
and cannot block on named pipes. A NULL/empty CodeResources path is allowed only
when the input signature has no resource seal. The bare-library API fails instead
of stripping external seals it cannot supply.

This API does not regenerate or validate the resource manifest. The caller must
ensure it matches all staged resources. Signing nested libraries or frameworks
can change resource hashes and nested-code requirements, so reusing an unchanged
manifest is not sufficient in that case. Validate the complete staged framework,
not only the executable copied outside its bundle.

Framework/library signatures contain neither XML nor DER entitlement blobs.
Entitlements are still emitted for `MH_EXECUTE` images by the existing executable
signing path. See Apple's [code-signature format guidance](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format).

These APIs check local consistency, not Apple trust, profile signature validity,
revocation, device eligibility or kernel acceptance. The host must validate those
before installing/loading the staged result. Never treat successful signing or
metadata extraction as authorization to run a binary.

## Portable validation

On Linux with C++11, OpenSSL 3 development files, pkg-config, Python 3 and the
`openssl` command:

```sh
./test/library/run_portable.sh
```

The tests generate disposable identities and synthetic Mach-O files. They cover
identity rejection, CMS content/signer extraction, legacy PKCS#12, bounds,
no-resize failures, repeated signing, 4 KB/16 KB hashes and independent CMS
verification. The larger synthetic fixture tests a 54,108,160-byte code region
with a 124,176-byte signature reservation. No proprietary binary or real signing
credentials are used.

Portable tests do not establish that Xcode builds the package or that iOS accepts
and loads the resulting signature. Apple-device validation remains a separate
integration step. No CI workflows are added or dispatched by this package work.
