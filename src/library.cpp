#include "include/ZSignLibrary.h"
#include "common.h"
#include "archo.h"
#include "openssl.h"
#if defined(ZSIGN_SWIFTPM)
#include <OpenSSL/pkcs12.h>
#include <OpenSSL/cms.h>
#include <OpenSSL/err.h>
#else
#include <openssl/pkcs12.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#endif
#include <memory>
#include <mutex>

namespace {
std::mutex libraryMutex;
struct QuietLog {
    int previous = ZLog::GetLogLevel();
    QuietLog() { ZLog::SetLogLever(ZLog::E_NONE); }
    ~QuietLog() { ZLog::SetLogLever(previous); }
};
struct File { int fd; ~File() { if (fd >= 0) close(fd); } };
template<class T, void (*Free)(T*)> using Owned = std::unique_ptr<T, decltype(Free)>;
int fail(char *error, size_t capacity, const char *message) {
    if (error && capacity) std::snprintf(error, capacity, "%s", message);
    ERR_clear_error();
    return -1;
}
bool readFile(const char *path, std::vector<unsigned char>& data,
              size_t limit = 16 * 1024 * 1024) {
    File file{open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)};
    struct stat st;
    if (file.fd < 0 || fstat(file.fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > limit) return false;
    data.resize(st.st_size);
    return pread(file.fd, data.data(), data.size(), 0) == (ssize_t)data.size();
}
struct SecretBytes {
    std::vector<unsigned char> bytes;
    ~SecretBytes() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
} // namespace

bool ZSignAsset::InitStandalone(const char *p12path, const char *password,
                                const char *profile, const char *team) {
    SecretBytes p12bytes;
    std::vector<unsigned char> profilebytes;
    if (!readFile(p12path, p12bytes.bytes) || !readFile(profile, profilebytes)) return false;
    if (!ZSignAsset::InitializeProviders()) return false;
    const unsigned char *cursor = p12bytes.bytes.data();
    Owned<PKCS12, PKCS12_free> p12(d2i_PKCS12(nullptr, &cursor, p12bytes.bytes.size()), PKCS12_free);
    if (!p12 || cursor != p12bytes.bytes.data() + p12bytes.bytes.size()) return false;
    EVP_PKEY *key = nullptr; X509 *cert = nullptr; STACK_OF(X509) *chain = nullptr;
    int parsed = PKCS12_parse(p12.get(), password, &key, &cert, &chain);
    m_evpPKey = key; m_x509Cert = cert; m_caCerts = chain;
    if (!parsed || !key || !cert || !X509_check_private_key(cert, key) ||
        X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert)) <= 0) return false;
    char ou[129] = {}, cn[1025] = {};
    int oulen = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationalUnitName, ou, sizeof ou);
    int cnlen = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof cn);
    if (oulen <= 0 || oulen > 128 || std::string(ou, oulen) != team || cnlen <= 0 || cnlen > 1024) return false;
    cursor = profilebytes.data();
    Owned<CMS_ContentInfo, CMS_ContentInfo_free> cms(d2i_CMS_ContentInfo(nullptr, &cursor, profilebytes.size()), CMS_ContentInfo_free);
    if (!cms || cursor != profilebytes.data() + profilebytes.size() ||
        OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed) return false;
    ASN1_OCTET_STRING **content = CMS_get0_content(cms.get());
    if (!content || !*content || (*content)->length <= 0) return false;
    jvalue provision;
    if (!provision.read_plist(std::string((char*)(*content)->data, (*content)->length)) ||
        std::string(provision["TeamIdentifier"][0].as_cstr()) != team) return false;
    bool member = false;
    for (size_t i = 0; i < provision["DeveloperCertificates"].size(); ++i) {
        std::string der = provision["DeveloperCertificates"][i].as_data();
        const unsigned char *pos = (const unsigned char*)der.data();
        Owned<X509, X509_free> candidate(d2i_X509(nullptr, &pos, der.size()), X509_free);
        if (candidate && pos == (const unsigned char*)der.data() + der.size() && X509_cmp(cert, candidate.get()) == 0) member = true;
    }
    if (!member) return false;
    m_strTeamId = team; m_strSubjectCN.assign(cn, cnlen);
    m_bSHA256Only = true; m_bSingleBinary = true;
    m_strEntitleData.clear();
    return true;
}
namespace {
static uint32_t u32(const unsigned char *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
static uint64_t u64(const unsigned char *p) { return u32(p) | uint64_t(u32(p + 4)) << 32; }
static uint32_t be32(const unsigned char *p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
static bool bounded(uint64_t offset, uint64_t size, uint64_t total) {
    return offset <= total && size <= total - offset;
}
// Inspect page geometry and required external seals, never reuse cached hashes.
// Apple CodeDirectory uses log2(bytes); 16 KB is supported on native arm64 pages.
static bool codePageSize(const unsigned char *p, size_t size, uint32_t codeLength,
                         uint8_t& pageSize, bool& hasInfoSeal, bool& hasResourceSeal) {
    pageSize = 12;
    hasInfoSeal = hasResourceSeal = false;
    if (size < 12) return false;
    if (std::all_of(p, p + size, [](unsigned char c) { return c == 0; })) return true;
    if (be32(p) != CSMAGIC_EMBEDDED_SIGNATURE) return false;
    uint32_t length = be32(p + 4), count = be32(p + 8);
    if (length < 12 || length > size || count > (length - 12) / 8) return false;
    uint32_t indexEnd = 12 + count * 8;
    unsigned seen = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t type = be32(p + 12 + i * 8), offset = be32(p + 16 + i * 8);
        if (offset < indexEnd || !bounded(offset, 8, length)) return false;
        const auto *cd = p + offset;
        uint32_t cdLength = be32(cd + 4);
        if (cdLength < 8 || !bounded(offset, cdLength, length)) return false;
        if (type != CSSLOT_CODEDIRECTORY &&
            (type < CSSLOT_ALTERNATE_CODEDIRECTORIES || type >= CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) continue;
        unsigned bit = 1u << (type == CSSLOT_CODEDIRECTORY ? 0 : 1 + type - CSSLOT_ALTERNATE_CODEDIRECTORIES);
        if ((seen & bit) || cdLength < 44 || be32(cd) != CSMAGIC_CODEDIRECTORY) return false;
        uint32_t version = be32(cd + 8);
        if (version < 0x20000 || version > 0x20600) return false;
        uint32_t headerSize = version >= 0x20600 ? 108 : version >= 0x20500 ? 96 :
            version >= 0x20400 ? 88 : version >= 0x20300 ? 64 :
            version >= 0x20200 ? 52 : version >= 0x20100 ? 48 : 44;
        if (cdLength < headerSize || (cd[39] != 12 && cd[39] != 14)) return false;
        if (seen && pageSize != cd[39]) return false;
        pageSize = cd[39];
        // Scatter/pre-encryption layouts are not used to choose a new page geometry.
        if ((version >= 0x20100 && be32(cd + 44)) ||
            (version >= 0x20500 && be32(cd + 92))) return false;
        if (be32(cd + 32) != codeLength ||
            (version >= 0x20300 && (be32(cd + 56) || be32(cd + 60)))) return false;
        uint32_t pageBytes = 1u << pageSize;
        uint32_t slots = be32(cd + 28), hashOffset = be32(cd + 16);
        uint8_t hashSize = cd[36], hashType = cd[37];
        if (!((hashType == 1 && hashSize == 20) || (hashType == 2 && hashSize == 32) ||
              (hashType == 3 && hashSize == 20) || (hashType == 4 && hashSize == 48))) return false;
        uint64_t specialBytes = uint64_t(be32(cd + 24)) * hashSize;
        if (slots != codeLength / pageBytes + (codeLength % pageBytes != 0) ||
            hashOffset < headerSize || specialBytes > hashOffset - headerSize ||
            !bounded(hashOffset, uint64_t(slots) * hashSize, cdLength)) return false;
        uint32_t stringsEnd = hashOffset - static_cast<uint32_t>(specialBytes);
        auto stringInHeader = [&](uint32_t start) {
            return start >= headerSize && start < stringsEnd && memchr(cd + start, 0, stringsEnd - start);
        };
        if (!stringInHeader(be32(cd + 20)) ||
            (version >= 0x20200 && be32(cd + 48) && !stringInHeader(be32(cd + 48)))) return false;
        // Nonzero special-slot hashes require corresponding actual input bytes.
        // Presence is not determined by nSpecialSlots alone: zero hashes are absent.
        auto slotPresent = [&](uint32_t slot) {
            if (be32(cd + 24) < slot) return false;
            const auto *hash = cd + hashOffset - slot * hashSize;
            return std::any_of(hash, hash + hashSize, [](unsigned char c) { return c != 0; });
        };
        hasInfoSeal = hasInfoSeal || slotPresent(1);
        hasResourceSeal = hasResourceSeal || slotPresent(3);
        seen |= bit;
    }
    return (seen & 1) != 0;
}
static bool library(int fd, uint32_t& signatureStart, uint32_t& signatureSize) {
    unsigned char h[32] = {};
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size < 32 ||
        st.st_size > 1024LL * 1024 * 1024 || pread(fd, h, sizeof h, 0) != sizeof h) return false;
    if (u32(h) != 0xfeedfacf || u32(h + 4) != 0x0100000c ||
        (u32(h + 12) != 6 && u32(h + 12) != 8)) return false;
    uint32_t count = u32(h + 16), bytes = u32(h + 20);
    if (bytes > 16 * 1024 * 1024 || count > bytes / 8 || !bounded(32, bytes, st.st_size)) return false;
    std::vector<unsigned char> commands(bytes);
    if (pread(fd, commands.data(), bytes, 32) != bytes) return false;
    size_t offset = 0;
    bool signature = false, text = false, linkedit = false;
    for (uint32_t i = 0; i < count; ++i) {
        if (!bounded(offset, 8, bytes)) return false;
        const auto *p = commands.data() + offset;
        uint32_t cmd = u32(p), length = u32(p + 4);
        if (length < 8 || length % 8 || !bounded(offset, length, bytes)) return false;
        if (cmd == 1) return false; // No 32-bit segments in the arm64 ABI.
        if (cmd == 0x19) {
            if (length < 72 ||
                !bounded(u64(p + 40), u64(p + 48), st.st_size)) return false;
            uint32_t sections = u32(p + 64);
            if (sections > (length - 72) / 80) return false;
            if (!strncmp((const char *)p + 8, "__TEXT", 16)) text = true;
            if (!strncmp((const char *)p + 8, "__LINKEDIT", 16)) linkedit = true;
            for (uint32_t j = 0; j < sections; ++j) {
                const auto *section = p + 72 + j * 80;
                if (!strncmp((const char *)section, "__info_plist", 16) &&
                    (u64(section + 40) > 1024 * 1024 ||
                     !bounded(u32(section + 48), u64(section + 40), st.st_size))) return false;
                uint32_t type = u32(section + 64) & 0xff;
                if (type != 1 && type != 12 && type != 18 &&
                    !bounded(u32(section + 48), u64(section + 40), st.st_size)) return false;
            }
        } else if (cmd == 0x21 || cmd == 0x2c) {
            if (length < 24 || u32(p + 16)) return false;
        } else if (cmd == 0x1d) {
            if (signature || length != 16) return false;
            uint32_t start = u32(p + 8), size = u32(p + 12);
            // Reserved signature space is required. Do not resize arbitrary images.
            if (start < 32 + bytes || size < 12 || start % 16 ||
                !bounded(start, size, st.st_size) || uint64_t(start) + size != uint64_t(st.st_size)) return false;
            signatureStart = start;
            signatureSize = size;
            signature = true;
        }
        offset += length;
    }
    return offset == bytes && signature && text && linkedit;
}

} // namespace
extern "C" int zsign_check_identity(const char *pkcs12, const char *password,
    const char *profile, const char *team, char *error, size_t capacity) {
    std::lock_guard<std::mutex> guard(libraryMutex);
    if (!pkcs12 || !password || !profile || !team || !*team || strlen(team) > 128)
        return fail(error, capacity, "invalid signing identity request");
    QuietLog quiet;
    try {
        ZSignAsset asset;
        if (!asset.InitStandalone(pkcs12, password, profile, team))
            return fail(error, capacity, "signing identity unavailable or does not match host team/profile");
        if (error && capacity) *error = 0;
        ERR_clear_error();
        return 0;
    } catch (...) { return fail(error, capacity, "signing identity unavailable or invalid"); }
}
static int signLibrary(const char *path, const char *pkcs12, const char *password,
    const char *profile, const char *team, const char *identifier,
    const char *infoPlistPath, const char *resourcePath, char *error, size_t capacity) {
    std::lock_guard<std::mutex> guard(libraryMutex);
    if (!path || !pkcs12 || !password || !profile || !team || !*team || strlen(team) > 128 ||
        !identifier || !*identifier || strlen(identifier) > 255)
        return fail(error, capacity, "invalid signing request");
    QuietLog quiet;
    try {
        File file{open(path, O_RDWR | O_NOFOLLOW)};
        uint32_t signatureStart = 0, signatureSize = 0;
        if (file.fd < 0 || !library(file.fd, signatureStart, signatureSize))
            return fail(error, capacity, "expected staged thin arm64 library with signature reservation");
        ZSignAsset asset;
        if (!asset.InitStandalone(pkcs12, password, profile, team))
            return fail(error, capacity, "signing identity unavailable or does not match host team/profile");
        struct stat st;
        if (fstat(file.fd, &st)) return fail(error, capacity, "cannot read staged native image");
        std::vector<unsigned char> bytes(st.st_size);
        if (pread(file.fd, bytes.data(), bytes.size(), 0) != (ssize_t)bytes.size())
            return fail(error, capacity, "cannot read staged native image");
        uint8_t pageSize = 12;
        bool hasInfoSeal = false, hasResourceSeal = false;
        if (!bounded(signatureStart, signatureSize, bytes.size()) ||
            !codePageSize(bytes.data() + signatureStart, signatureSize, signatureStart,
                          pageSize, hasInfoSeal, hasResourceSeal))
            return fail(error, capacity, "invalid or unsupported existing code signature layout");
        ZArchO image;
        if (!image.Init(bytes.data(), bytes.size())) return fail(error, capacity, "cannot parse staged native image");
        const bool hasResourcePath = resourcePath && *resourcePath;
        if ((!infoPlistPath && hasInfoSeal && image.m_strInfoPlist.empty()) ||
            (hasResourceSeal && !hasResourcePath))
            return fail(error, capacity, "existing signature requires external framework metadata/resources");
        std::string infoData = image.m_strInfoPlist, resources;
        if (infoPlistPath) {
            std::vector<unsigned char> infoBytes, resourceBytes;
            if (!readFile(infoPlistPath, infoBytes, 1024 * 1024) ||
                (hasResourcePath && !readFile(resourcePath, resourceBytes)))
                return fail(error, capacity, "cannot read bounded staged framework metadata/resources");
            infoData.assign((const char*)infoBytes.data(), infoBytes.size());
            if (hasResourcePath) resources.assign((const char*)resourceBytes.data(), resourceBytes.size());
        }
        std::string sha1(20, 0), sha256(32, 0);
        if (!infoData.empty()) ZSHA::SHA(infoData, sha1, sha256);
        if (!image.Sign(&asset, true, identifier, sha1, sha256, resources, pageSize))
            return fail(error, capacity, "native signing failed (signature reservation may be too small)");
        // Only the signature reservation changes. Partial I/O requires discarding the private stage.
        size_t offset = image.m_uCodeLength;
        while (offset < bytes.size()) {
            ssize_t written = pwrite(file.fd, bytes.data() + offset, bytes.size() - offset, offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return fail(error, capacity, "cannot write staged native signature");
            offset += written;
        }
        if (fsync(file.fd)) return fail(error, capacity, "cannot flush staged native signature");
        if (error && capacity) *error = 0;
        ERR_clear_error();
        return 0;
    } catch (...) { return fail(error, capacity, "native signing failed"); }
}

extern "C" int zsign_sign_library(const char *path, const char *pkcs12, const char *password,
    const char *profile, const char *team, const char *identifier, char *error, size_t capacity) {
    return signLibrary(path, pkcs12, password, profile, team, identifier, nullptr, nullptr, error, capacity);
}

extern "C" int zsign_sign_library_with_resources(const char *path, const char *pkcs12, const char *password,
    const char *profile, const char *team, const char *identifier,
    const char *info_plist, const char *code_resources, char *error, size_t capacity) {
    if (!info_plist || !*info_plist)
        return fail(error, capacity, "staged framework Info.plist is required");
    return signLibrary(path, pkcs12, password, profile, team, identifier,
                       info_plist, code_resources, error, capacity);
}
