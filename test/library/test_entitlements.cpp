// Synthetic ad-hoc signatures only. Check library omission and executable parity.
#include "common.h"
#include "archo.h"

static void check(bool value, const char* message) {
    if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static uint32_t be32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
static uint64_t be64(const uint8_t* p) { return uint64_t(be32(p)) << 32 | be32(p + 4); }
template<class T> static void append(vector<uint8_t>& bytes, size_t& offset, const T& value) {
    memcpy(bytes.data() + offset, &value, sizeof value); offset += sizeof value;
}
static vector<uint8_t> image(uint32_t type) {
    vector<uint8_t> bytes(4096 + 32768, 0);
    mach_header_64 header = {};
    header.magic = MH_MAGIC_64; header.cputype = CPU_TYPE_ARM64;
    header.filetype = type; header.ncmds = 3; header.sizeofcmds = 160;
    segment_command_64 text = {}, link = {};
    text.cmd = link.cmd = LC_SEGMENT_64; text.cmdsize = link.cmdsize = 72;
    strcpy(text.segname, "__TEXT"); text.vmsize = text.filesize = 4096;
    text.maxprot = text.initprot = 5;
    strcpy(link.segname, "__LINKEDIT"); link.vmaddr = link.fileoff = 4096;
    link.vmsize = link.filesize = 32768; link.maxprot = link.initprot = 1;
    codesignature_command signature = {};
    signature.cmd = LC_CODE_SIGNATURE; signature.cmdsize = 16;
    signature.dataoff = 4096; signature.datasize = 32768;
    size_t offset = 0;
    append(bytes, offset, header); append(bytes, offset, text);
    append(bytes, offset, link); append(bytes, offset, signature);
    return bytes;
}
static void run(uint32_t type, const string& entitlements, bool debug, bool sha256Only) {
    auto bytes = image(type);
    ZArchO arch; check(arch.Init(bytes.data(), bytes.size()), "parse fixture");
    ZSignAsset asset; asset.m_bAdhoc = true; asset.m_bSHA256Only = sha256Only;
    asset.m_strEntitleData = entitlements;
    check(arch.Sign(&asset, true, "org.test", string(20, 0), string(32, 0), ""), "sign fixture");
    const uint8_t* super = bytes.data() + 4096;
    check(be32(super) == CSMAGIC_EMBEDDED_SIGNATURE, "superblob magic");
    map<uint32_t, const uint8_t*> slots;
    for (uint32_t i = 0; i < be32(super + 8); ++i)
        slots[be32(super + 12 + 8 * i)] = super + be32(super + 16 + 8 * i);
    const bool expected = type == MH_EXECUTE && !entitlements.empty();
    check(bool(slots.count(CSSLOT_ENTITLEMENTS)) == expected, "XML entitlement presence");
    check(bool(slots.count(CSSLOT_DER_ENTITLEMENTS)) == expected, "DER entitlement presence");
    check(slots.count(CSSLOT_SIGNATURESLOT) == 0, "ad-hoc fixture must not contain CMS");
    for (const auto& item : slots) {
        if (item.first != CSSLOT_CODEDIRECTORY && item.first != CSSLOT_ALTERNATE_CODEDIRECTORIES) continue;
        const uint8_t* cd = item.second;
        const uint32_t special = be32(cd + 24), hashOffset = be32(cd + 16);
        check(special == (expected ? 7u : 2u), "unexpected special-slot count");
        uint64_t flags = type == MH_EXECUTE ? CS_EXECSEG_MAIN_BINARY : 0;
        if (type == MH_EXECUTE && debug) flags |= CS_EXECSEG_ALLOW_UNSIGNED;
        check(be64(cd + 80) == flags, "executable signing flags changed");
        if (expected) {
            for (uint32_t slot : {uint32_t(CSSLOT_ENTITLEMENTS), uint32_t(CSSLOT_DER_ENTITLEMENTS)}) {
                const uint8_t* blob = slots[slot];
                check(be32(blob) == (slot == CSSLOT_ENTITLEMENTS ? CSMAGIC_EMBEDDED_ENTITLEMENTS : CSMAGIC_EMBEDDED_DER_ENTITLEMENTS), "entitlement blob magic");
                string digest;
                if (cd[37] == 1) ZSHA::SHA1(const_cast<uint8_t*>(blob), be32(blob + 4), digest);
                else ZSHA::SHA256(const_cast<uint8_t*>(blob), be32(blob + 4), digest);
                check(digest.size() == cd[36] && !memcmp(cd + hashOffset - slot * cd[36], digest.data(), digest.size()), "entitlement slot hash");
            }
            const uint8_t* xml = slots[CSSLOT_ENTITLEMENTS];
            check(string((const char*)xml + 8, be32(xml + 4) - 8) == entitlements, "executable XML changed");
        }
    }
}
int main() {
    const string prefix = "<?xml version=\"1.0\"?><plist version=\"1.0\">";
    const vector<string> entitlements = {"", prefix + "<dict/></plist>",
        prefix + "<dict><key>get-task-allow</key><false/></dict></plist>",
        prefix + "<dict><key>get-task-allow</key><true/></dict></plist>"};
    for (uint32_t type : {uint32_t(MH_DYLIB), uint32_t(MH_BUNDLE), uint32_t(MH_EXECUTE)})
        for (size_t i = 0; i < entitlements.size(); ++i)
            for (bool sha256Only : {false, true}) run(type, entitlements[i], i == 3, sha256Only);
    puts("PASS: dylib/bundle entitlement omission; executable XML/DER hashes and flags unchanged");
}
