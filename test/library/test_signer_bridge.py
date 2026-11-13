#!/usr/bin/env python3
"""Linux bridge smoke test. Synthetic identity only, never Apple credentials.
Usage: test_signer_bridge.py /tmp/lib-shell-signing.so
Does not establish kernel trust or iOS loadability.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile


def openssl(root, *args):
    return subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)


def image(code_length=4096, reservation=32768, page_power=None):
    text = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0, code_length, 0, code_length, 5, 5, 0, 0)
    link = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", code_length, reservation, code_length, reservation, 1, 1, 0, 0)
    signature = struct.pack("<IIII", 0x1d, 16, code_length, reservation)
    header = struct.pack("<8I", 0xfeedfacf, 0x0100000c, 0, 6, 3, 160, 0, 0)
    existing = b""
    if page_power is not None:
        slots = (code_length >> page_power) + bool(code_length % (1 << page_power))
        identifier = b"org.test\0"
        hash_offset = 88 + len(identifier)
        cd = bytearray(hash_offset + slots * 32)
        struct.pack_into(">9I4B", cd, 0, 0xfade0c02, len(cd), 0x20400, 2,
                         hash_offset, 88, 0, slots, code_length, 32, 2, 0, page_power)
        cd[88:hash_offset] = identifier
        # Deliberately stale input digests must not be reused by the forced signer.
        cd[hash_offset:] = b"\xa5" * (slots * 32)
        existing = struct.pack(">5I", 0xfade0cc0, 20 + len(cd), 1, 0, 20) + cd
        assert len(existing) <= reservation
    return (header + text + link + signature).ljust(code_length, b"\x5a") + existing.ljust(reservation, b"\0")


def verify_signature(root, signed, code_length, reservation, page_power, info=None, resources=None):
    data = signed[code_length:]
    magic, length, count = struct.unpack_from(">III", data)
    assert magic == 0xfade0cc0 and length <= reservation and len(data) == reservation
    slots = {}
    for i in range(count):
        kind, offset = struct.unpack_from(">II", data, 12 + 8 * i)
        size = struct.unpack_from(">I", data, offset + 4)[0]
        slots[kind] = data[offset:offset + size]
    cd = slots[0]
    hash_offset = struct.unpack_from(">I", cd, 16)[0]
    page_count, code_limit = struct.unpack_from(">II", cd, 28)
    hash_size, hash_type, _, actual_power = cd[36:40]
    assert code_limit == code_length and hash_type == 2 and hash_size == 32
    assert actual_power == page_power
    special_count = struct.unpack_from(">I", cd, 24)[0]
    assert 5 not in slots and 7 not in slots # Frameworks/libraries have no entitlement blobs.
    assert special_count == (3 if resources is not None else 2)
    for slot, content in [(1, info), (3, resources)]:
        digest = cd[hash_offset - slot * 32:hash_offset - (slot - 1) * 32] if special_count >= slot else bytes(32)
        assert digest == (hashlib.sha256(content).digest() if content is not None else bytes(32)), slot
    assert page_count == code_length // (1 << page_power) + bool(code_length % (1 << page_power))
    for page in range(page_count):
        chunk = signed[page * (1 << page_power):min(code_length, (page + 1) * (1 << page_power))]
        assert cd[hash_offset + page * 32:hash_offset + (page + 1) * 32] == hashlib.sha256(chunk).digest()
    team_offset = struct.unpack_from(">I", cd, 48)[0]
    assert cd[team_offset:].split(b"\0", 1)[0] == b"TESTTEAM01"
    (root / "cd").write_bytes(cd)
    (root / "cms").write_bytes(slots[0x10000][8:])
    openssl(root, "cms", "-verify", "-binary", "-inform", "DER", "-in", "cms", "-content", "cd", "-noverify", "-out", "verified")
    assert (root / "verified").read_bytes() == cd
    return length


def load(path):
    library = ctypes.CDLL(str(Path(path).resolve()))
    library.zsign_sign_library.argtypes = [ctypes.c_char_p] * 7 + [ctypes.c_size_t]
    library.zsign_sign_library_with_resources.argtypes = [ctypes.c_char_p] * 9 + [ctypes.c_size_t]
    return library


def main():
    enabled = load(sys.argv[1])
    message = ctypes.create_string_buffer(1024)
    with tempfile.TemporaryDirectory(prefix="shell-synthetic-signing-") as temporary:
        root = Path(temporary)
        openssl(root, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Shell Synthetic Test CA", "-days", "1", "-keyout", "ca.key", "-out", "ca.pem")
        openssl(root, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Shell Synthetic Test Leaf/OU=TESTTEAM01", "-keyout", "leaf.key", "-out", "leaf.csr")
        openssl(root, "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-out", "leaf.pem")
        openssl(root, "pkcs12", "-export", "-inkey", "leaf.key", "-in", "leaf.pem", "-certfile", "ca.pem", "-passout", "pass:test-only", "-out", "identity.p12")
        certificate = openssl(root, "x509", "-in", "leaf.pem", "-outform", "DER").stdout
        (root / "profile.plist").write_bytes(plistlib.dumps({"TeamIdentifier": ["TESTTEAM01"], "DeveloperCertificates": [certificate], "Entitlements": {"application-identifier": "TESTTEAM01.org.test"}}))
        openssl(root, "cms", "-sign", "-binary", "-nodetach", "-in", "profile.plist", "-signer", "leaf.pem", "-inkey", "leaf.key", "-outform", "DER", "-out", "profile.cms")
        native = root / "native"

        def sign(team=b"TESTTEAM01", password=b"test-only", p12="identity.p12"):
            return enabled.zsign_sign_library(str(native).encode(), str(root / p12).encode(), password,
                str(root / "profile.cms").encode(), team, b"org.test", message, 1024)

        def sign_resources(info_path="Info.plist", resource_path="CodeResources"):
            return enabled.zsign_sign_library_with_resources(str(native).encode(),
                str(root / "identity.p12").encode(), b"test-only", str(root / "profile.cms").encode(),
                b"TESTTEAM01", b"org.test",
                None if info_path is None else str(root / info_path).encode(),
                None if resource_path is None else (str(root / resource_path).encode() if resource_path else b""),
                message, 1024)

        info = plistlib.dumps({"CFBundleIdentifier": "org.test", "CFBundleExecutable": "native"},
                             fmt=plistlib.FMT_BINARY)
        resources = plistlib.dumps({"files": {}, "files2": {}, "rules": {}, "rules2": {}})
        (root / "Info.plist").write_bytes(info)
        (root / "CodeResources").write_bytes(resources)
        original = image(page_power=14)
        native.write_bytes(original)
        assert sign_resources() == 0, message.value
        signed = native.read_bytes()
        assert signed[:4096] == original[:4096] and len(signed) == len(original)
        verify_signature(root, signed, 4096, 32768, 14, info, resources)
        assert sign() != 0 and native.read_bytes() == signed # Never silently strip external seals.
        for absent in (None, ""):
            assert sign_resources(resource_path=absent) != 0 and native.read_bytes() == signed
        assert sign_resources() == 0, message.value
        verify_signature(root, native.read_bytes(), 4096, 32768, 14, info, resources)

        # Seal supplied bytes afresh, including binary Info.plist, not cached digests.
        info = plistlib.dumps({"CFBundleIdentifier": "org.test", "CFBundleExecutable": "native", "changed": True})
        resources = plistlib.dumps({"files": {}, "rules": {"^.*": True}})
        (root / "Info.plist").write_bytes(info)
        (root / "CodeResources").write_bytes(resources)
        assert sign_resources() == 0, message.value
        signed = native.read_bytes()
        verify_signature(root, signed, 4096, 32768, 14, info, resources)
        (root / "info-link").symlink_to(root / "Info.plist")
        (root / "resources-link").symlink_to(root / "CodeResources")
        os.mkfifo(root / "info-pipe")
        os.mkfifo(root / "resources-pipe")
        (root / "oversize-info").write_bytes(bytes(1024 * 1024 + 1))
        (root / "oversize-resources").write_bytes(bytes(16 * 1024 * 1024 + 1))
        for info_path, resource_path in [(None, "CodeResources"), ("missing", "CodeResources"),
                ("info-link", "CodeResources"), ("Info.plist", "resources-link"),
                ("info-pipe", "CodeResources"), ("Info.plist", "resources-pipe"),
                ("oversize-info", "CodeResources"), ("Info.plist", "oversize-resources"),
                ("Info.plist", "missing")]:
            assert sign_resources(info_path, resource_path) != 0 and native.read_bytes() == signed

        # Info-only sealing is allowed when no resource manifest/seal exists.
        for absent in (None, ""):
            native.write_bytes(original)
            assert sign_resources(resource_path=absent) == 0, message.value
            verify_signature(root, native.read_bytes(), 4096, 32768, 14, info, None)
            signed_info = native.read_bytes()
            assert sign() != 0 and native.read_bytes() == signed_info

        # Same team is insufficient when the certificate is absent from the profile.
        openssl(root, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Other/OU=TESTTEAM01", "-days", "1", "-keyout", "other.key", "-out", "other.pem")
        openssl(root, "pkcs12", "-export", "-inkey", "other.key", "-in", "other.pem", "-passout", "pass:test-only", "-out", "other.p12")
        native.write_bytes(image())
        assert sign(p12="other.p12") != 0
        assert native.read_bytes() == image()
        native.write_bytes(image())
        assert sign(b"OTHERTEAM1") != 0 and b"host team" in message.value
        assert native.read_bytes() == image()
        assert sign(password=b"wrong") != 0
        assert native.read_bytes() == image()
        for offset, value in [(16, 0xffffffff), (20, 0xffffffff), (36, 0), (104, 1), (188, 0xffffffff), (4, 19)]:
            malformed = bytearray(image())
            struct.pack_into("<I", malformed, offset, value)
            native.write_bytes(malformed)
            assert sign() != 0, (offset, message.value)
            assert native.read_bytes() == malformed
        tiny = bytearray(image()[:4108])
        struct.pack_into("<I", tiny, 188, 12)
        struct.pack_into("<Q", tiny, 152, 12) # __LINKEDIT filesize
        native.write_bytes(tiny)
        assert sign() != 0 # No automatic resizing when CMS exceeds reservation.
        assert native.read_bytes() == tiny
        # Valid full-width section names must not be rejected as unterminated.
        full = bytearray(image())
        section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_capture", b"__TEXT", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        full[104:264] = section + full[104:184]
        full[264:280] = image()[184:200]
        struct.pack_into("<I", full, 20, 240)
        struct.pack_into("<I", full, 36, 152)
        struct.pack_into("<I", full, 96, 1)
        native.write_bytes(full)
        assert sign() == 0, message.value
        native.write_bytes(image())
        assert sign() == 0, message.value
        verify_signature(root, native.read_bytes(), 4096, 32768, 12)
        assert sign() == 0, message.value # Re-sign existing CMS without resizing.

        # Same-size reservation as a large arm64 image; contains no game data.
        # 4 KB needs 422720 hash bytes, while 16 KB needs only 105696.
        for code_length, reservation, page_power in [(4096, 32768, 12), (4096, 32768, 14),
                                                     (16384, 32768, 14),
                                                     (54108160, 124176, 14)]:
            original = image(code_length, reservation, page_power)
            native.write_bytes(original)
            assert sign() == 0, (code_length, page_power, message.value)
            signed = native.read_bytes()
            assert signed[:code_length] == original[:code_length] and len(signed) == len(original)
            size = verify_signature(root, signed, code_length, reservation, page_power)
            assert sign() == 0, message.value
            verify_signature(root, native.read_bytes(), code_length, reservation, page_power)
            if code_length > 16384:
                print(f"PASS: synthetic 16 KB signature {size} bytes fits {reservation}-byte reservation")

        # Preserving 4 KB is intentional: do not increase pages solely to make an image fit.
        original = image(54108160, 124176)
        native.write_bytes(original)
        assert sign() != 0 and native.read_bytes() == original

        # Malformed/ambiguous existing geometry is rejected before modifying the file.
        original = image(page_power=14)
        for offset, value in [(4, 0xffffffff), (8, 0xffffffff), (16, 12), (16, 0xffffffff),
                              (20 + 4, 43), (20 + 4, 0xffffffff), (20 + 8, 0x20700),
                              (20 + 16, 0xffffffff), (20 + 20, 0xffffffff),
                              (20 + 24, 0xffffffff), (20 + 28, 0xffffffff),
                              (20 + 32, 4095), (20 + 44, 48), (20 + 56, 1)]:
            malformed = bytearray(original)
            struct.pack_into(">I", malformed, 4096 + offset, value)
            native.write_bytes(malformed)
            assert sign() != 0 and native.read_bytes() == malformed, offset
        for offset, values in [(39, [0, 13, 31, 32, 255]), (36, [0, 20, 255]), (37, [0, 1, 255])]:
            for value in values:
                malformed = bytearray(original)
                malformed[4096 + 20 + offset] = value
                native.write_bytes(malformed)
                assert sign() != 0 and native.read_bytes() == malformed, (offset, value)
        # Two individually valid directories must agree, even if the primary is last.
        for types, powers in [([0, 0x1000], [14, 12]), ([0x1000, 0], [12, 14]),
                              ([0, 0], [14, 14]), ([0, 0x1000], [14, 14]), ([0x1000, 0], [14, 14])]:
            cds = []
            for power in powers:
                fixture = image(page_power=power)[4096:]
                cd_length = struct.unpack_from(">I", fixture, 24)[0]
                cds.append(fixture[20:20 + cd_length])
            entries = struct.pack(">4I", types[0], 28, types[1], 28 + len(cds[0]))
            blob = struct.pack(">3I", 0xfade0cc0, 28 + sum(map(len, cds)), 2) + entries + b"".join(cds)
            malformed = original[:4096] + blob.ljust(32768, b"\0")
            native.write_bytes(malformed)
            if types[0] != types[1] and powers[0] == powers[1]:
                assert sign() == 0, message.value
                verify_signature(root, native.read_bytes(), 4096, 32768, 14)
            else:
                assert sign() != 0 and native.read_bytes() == malformed
        # Existing CD fits, but a full CMS cannot: still no resizing or partial write.
        original = image(4096, 256, 14)
        native.write_bytes(original)
        assert sign() != 0 and native.read_bytes() == original
    print("PASS: identity rejection, external framework seals, bounds, 4/16 KB geometry, independent hashes/CMS, no-resize failures, re-signing")



if __name__ == "__main__":
    main()
