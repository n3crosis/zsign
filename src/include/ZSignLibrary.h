#ifndef ZSIGN_LIBRARY_H
#define ZSIGN_LIBRARY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Return 0 on success, -1 on failure. Error text is optional and never contains
 * credentials. Inputs must be NUL-terminated. Signing/identity-check calls are serialized.
 * The caller supplies a private staged, thin arm64 dylib/bundle, never a live
 * installed image. No resizing or app wrapping occurs. Signing/validation errors
 * before the final write leave it unchanged; an I/O failure can partially write
 * the staged file, which the caller must discard. Successful signing is NOT
 * Apple profile trust or kernel validation. The caller must perform both before
 * installing. Do not call legacy zsign APIs concurrently with this API. */
int zsign_check_identity(const char *pkcs12, const char *password,
    const char *profile, const char *team, char *error, size_t capacity);
int zsign_sign_library(const char *path, const char *pkcs12, const char *password,
    const char *profile, const char *team, const char *identifier,
    char *error, size_t capacity);
// Extracts bounded embedded CMS SignedData content, never a raw plist or XML scan.
// Returns 0 on success, 1 on malformed/missing content or insufficient capacity.
// Does not verify the CMS signature or establish Apple profile trust.
int zsign_copy_profile_content(const unsigned char *profile, size_t profile_size,
    unsigned char *content, size_t capacity, size_t *content_size);
// Local consistency checks only, not Apple trust, revocation or device eligibility.
// Returns 0 on success, 1 invalid identity, 2 invalid host CMS, 3 signer mismatch.
// On success, writes the P12 leaf certificate in DER form to certificate.
int zsign_validate_imported_identity(const unsigned char *pkcs12, size_t pkcs12_size,
    const char *password, const unsigned char *host_cms, size_t host_cms_size,
    unsigned char *certificate, size_t capacity, size_t *certificate_size);
// Returns the sole CMS SignerInfo certificate's notAfter as UNIX seconds.
// Returns 0 on success, 1 for missing/malformed/ambiguous signer or date.
// Output is reset to zero on failure. CMS is bounded to 16 MiB.
// Metadata only: does not verify CMS signature, Apple trust or revocation.
int zsign_copy_signer_expiration(const unsigned char *cms, size_t cms_size,
    int64_t *expiration_unix_seconds);
#ifdef __cplusplus
}
#endif
#endif
