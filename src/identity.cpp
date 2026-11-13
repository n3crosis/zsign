#include "include/ZSignLibrary.h"
#include "common.h"
#include "openssl.h"
#if defined(ZSIGN_SWIFTPM)
#include <OpenSSL/cms.h>
#include <OpenSSL/pkcs12.h>
#include <OpenSSL/x509.h>
#include <OpenSSL/err.h>
#else
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#endif
#include <cstring>
#include <memory>
#include <vector>


static int zsign_validate_imported_identity_impl(const unsigned char *pkcs12, size_t pkcs12_size,
    const char *password, const unsigned char *host_cms, size_t host_cms_size,
    unsigned char *certificate, size_t capacity, size_t *certificate_size) {
    if (certificate_size) *certificate_size = 0;
    if (!pkcs12 || !pkcs12_size || pkcs12_size > 1024 * 1024 || !password ||
        !certificate || !certificate_size) return 1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    (void)ZSignAsset::InitializeProviders();
#endif
    const unsigned char *cursor = pkcs12;
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
        d2i_PKCS12(nullptr, &cursor, static_cast<long>(pkcs12_size)), PKCS12_free);
    if (!p12 || cursor != pkcs12 + pkcs12_size) return 1;
    EVP_PKEY *raw_key = nullptr;
    X509 *raw_cert = nullptr;
    const int parsed = PKCS12_parse(p12.get(), password, &raw_key, &raw_cert, nullptr);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
    if (parsed != 1 || !key || !cert || X509_check_private_key(cert.get(), key.get()) != 1 ||
        X509_cmp_current_time(X509_get0_notBefore(cert.get())) >= 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert.get())) <= 0) return 1;
    if (!host_cms || !host_cms_size || host_cms_size > 16 * 1024 * 1024) return 2;
    cursor = host_cms;
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(host_cms_size)), CMS_ContentInfo_free);
    if (!cms || cursor != host_cms + host_cms_size) return 2;
    // Match SignerInfo to embedded certificates. Do not pick the first certificate
    // in the bag, which may be an intermediate or unrelated certificate.
    if (CMS_set1_signers_certs(cms.get(), nullptr, 0) != 1) return 2;
    STACK_OF(X509) *signers = CMS_get0_signers(cms.get());
    if (!signers) return 2;
    const int count = sk_X509_num(signers);
    X509 *signer = count == 1 ? sk_X509_value(signers, 0) : nullptr;
    const int size = i2d_X509(cert.get(), nullptr);
    const int signer_size = signer ? i2d_X509(signer, nullptr) : -1;
    bool equal = false;
    if (size > 0 && signer_size == size) {
        std::vector<unsigned char> imported(size), installed(size);
        auto *a = imported.data();
        auto *b = installed.data();
        equal = i2d_X509(cert.get(), &a) == size && i2d_X509(signer, &b) == size && imported == installed;
    }
    sk_X509_free(signers); // Certificates remain owned by CMS_ContentInfo.
    if (!signer) return 2;
    if (!equal) return 3;
    if (static_cast<size_t>(size) > capacity) return 1;
    auto *output = certificate;
    if (i2d_X509(cert.get(), &output) != size) return 1;
    *certificate_size = static_cast<size_t>(size);
    return 0;
}

static int zsign_copy_profile_content_impl(const unsigned char *profile, size_t profile_size,
    unsigned char *content, size_t capacity, size_t *content_size) {
    if (content_size) *content_size = 0;
    if (!profile || !profile_size || profile_size > 4 * 1024 * 1024 ||
        !content || !content_size) return 1;
    const unsigned char *cursor = profile;
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(profile_size)), CMS_ContentInfo_free);
    if (!cms || cursor != profile + profile_size ||
        OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed) return 1;
    ASN1_OCTET_STRING **payload = CMS_get0_content(cms.get());
    if (!payload || !*payload) return 1;
    const int size = ASN1_STRING_length(*payload);
    const unsigned char *bytes = ASN1_STRING_get0_data(*payload);
    if (!bytes || size <= 0 || static_cast<size_t>(size) > capacity || size > 4 * 1024 * 1024) return 1;
    std::memcpy(content, bytes, static_cast<size_t>(size));
    *content_size = static_cast<size_t>(size);
    return 0;
}

static int zsign_copy_signer_expiration_impl(const unsigned char *data, size_t size,
    int64_t *expiration_unix_seconds) {
    if (expiration_unix_seconds) *expiration_unix_seconds = 0;
    if (!data || !size || size > 16 * 1024 * 1024 || !expiration_unix_seconds) return 1;
    const unsigned char *cursor = data;
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(size)), CMS_ContentInfo_free);
    if (!cms || cursor != data + size ||
        OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed) return 1;
    STACK_OF(CMS_SignerInfo) *signers = CMS_get0_SignerInfos(cms.get());
    if (!signers || sk_CMS_SignerInfo_num(signers) != 1) return 1;
    auto freeCerts = [](STACK_OF(X509) *certs) { sk_X509_pop_free(certs, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(freeCerts)> certs(CMS_get1_certs(cms.get()), freeCerts);
    if (!certs) return 1;
    X509 *signer = nullptr;
    for (int i = 0; i < sk_X509_num(certs.get()); ++i) {
        X509 *candidate = sk_X509_value(certs.get(), i);
        if (CMS_SignerInfo_cert_cmp(sk_CMS_SignerInfo_value(signers, 0), candidate) == 0) {
            if (signer) return 1; // More than one certificate matches this signer ID.
            signer = candidate;
        }
    }
    if (!signer) return 1;
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> epoch(ASN1_TIME_set(nullptr, 0), ASN1_TIME_free);
    int days = 0, seconds = 0;
    if (!epoch || ASN1_TIME_diff(&days, &seconds, epoch.get(), X509_get0_notAfter(signer)) != 1) return 1;
    *expiration_unix_seconds = static_cast<int64_t>(days) * 86400 + seconds;
    return 0;
}

// Keep C++ allocation failures and the OpenSSL thread error queue behind the C ABI.
extern "C" int zsign_validate_imported_identity(const unsigned char *pkcs12, size_t pkcs12_size,
    const char *password, const unsigned char *host_cms, size_t host_cms_size,
    unsigned char *certificate, size_t capacity, size_t *certificate_size) {
    int result = 1;
    try { result = zsign_validate_imported_identity_impl(pkcs12, pkcs12_size, password,
        host_cms, host_cms_size, certificate, capacity, certificate_size); }
    catch (...) { if (certificate_size) *certificate_size = 0; }
    ERR_clear_error();
    return result;
}
extern "C" int zsign_copy_profile_content(const unsigned char *profile, size_t profile_size,
    unsigned char *content, size_t capacity, size_t *content_size) {
    int result = 1;
    try { result = zsign_copy_profile_content_impl(profile, profile_size, content, capacity, content_size); }
    catch (...) { if (content_size) *content_size = 0; }
    ERR_clear_error();
    return result;
}
extern "C" int zsign_copy_signer_expiration(const unsigned char *cms, size_t cms_size,
    int64_t *expiration_unix_seconds) {
    int result = 1;
    try { result = zsign_copy_signer_expiration_impl(cms, cms_size, expiration_unix_seconds); }
    catch (...) { if (expiration_unix_seconds) *expiration_unix_seconds = 0; }
    ERR_clear_error();
    return result;
}
