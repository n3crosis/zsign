"""Portable import checks with disposable certificates, never real credentials."""
import ctypes
import datetime
import os
import plistlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

@unittest.skipUnless(shutil.which("openssl") and os.environ.get("ZSIGN_LIBRARY"),
                     "requires openssl and ZSIGN_LIBRARY pointing to the built library")
class ImportedIdentityValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nx-disposable-identity-")
        cls.directory = Path(cls.temp.name)
        def run(*args):
            subprocess.run(args, cwd=cls.directory, check=True, capture_output=True)
        (cls.directory / "content").write_bytes(b"disposable synthetic code directory")
        for name in ("host", "other"):
            run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1" if name == "host" else "2",
                "-subj", "/CN=" + name + "/OU=TESTTEAM01", "-keyout", name + ".key",
                "-out", name + ".pem")
            run("openssl", "pkcs12", "-export", "-inkey", name + ".key", "-in", name + ".pem",
                "-passout", "pass:disposable", "-out", name + ".p12")
        run("openssl", "pkcs12", "-export", "-legacy", "-inkey", "host.key", "-in", "host.pem",
            "-passout", "pass:disposable", "-out", "legacy.p12")
        run("openssl", "cms", "-sign", "-binary", "-in", "content", "-signer", "host.pem",
            "-inkey", "host.key", "-outform", "DER", "-out", "host.cms")
        run("openssl", "cms", "-sign", "-binary", "-in", "content", "-signer", "other.pem",
            "-inkey", "other.key", "-certfile", "host.pem", "-outform", "DER", "-out", "extra.cms")
        run("openssl", "cms", "-sign", "-binary", "-in", "content", "-signer", "host.pem",
            "-inkey", "host.key", "-signer", "other.pem", "-inkey", "other.key",
            "-outform", "DER", "-out", "multiple.cms")
        run("openssl", "cms", "-sign", "-binary", "-nocerts", "-in", "content", "-signer", "host.pem",
            "-inkey", "host.key", "-outform", "DER", "-out", "missing.cms")
        run("openssl", "x509", "-in", "host.pem", "-signkey", "host.key", "-days", "3", "-out", "ambiguous.pem")
        run("openssl", "cms", "-sign", "-binary", "-in", "content", "-signer", "host.pem",
            "-inkey", "host.key", "-certfile", "ambiguous.pem", "-outform", "DER", "-out", "ambiguous.cms")
        cls.certificate_expirations = {}
        for name in ("host", "other"):
            text = subprocess.check_output(["openssl", "x509", "-in", name + ".pem", "-noout", "-enddate"],
                                           cwd=cls.directory, text=True).strip().split("=", 1)[1]
            date = datetime.datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            cls.certificate_expirations[name] = int(date.timestamp())
        cls.profile_expiration = datetime.datetime(2099, 1, 2, 3, 4, 5)
        cls.profile_content = plistlib.dumps({"TeamIdentifier": ["TESTTEAM01"],
                                           "ExpirationDate": cls.profile_expiration})
        (cls.directory / "profile.plist").write_bytes(cls.profile_content)
        run("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", "profile.plist",
            "-signer", "host.pem", "-inkey", "host.key", "-outform", "DER", "-out", "profile.cms")
        binary = plistlib.dumps({"TeamIdentifier": ["TESTTEAM01"],
                                 "ExpirationDate": cls.profile_expiration}, fmt=plistlib.FMT_BINARY)
        (cls.directory / "binary.plist").write_bytes(binary)
        run("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", "binary.plist",
            "-signer", "host.pem", "-inkey", "host.key", "-outform", "DER", "-out", "binary.cms")
        run("openssl", "x509", "-in", "host.pem", "-outform", "DER", "-out", "host.der")
        run("openssl", "pkcs12", "-export", "-nokeys", "-in", "host.pem",
            "-passout", "pass:disposable", "-out", "keyless.p12")
        cls.library = ctypes.CDLL(str(Path(os.environ["ZSIGN_LIBRARY"]).resolve()))
        cls.validate = cls.library.zsign_validate_imported_identity
        cls.validate.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        cls.validate.restype = ctypes.c_int
        cls.copy_content = cls.library.zsign_copy_profile_content
        cls.copy_content.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        cls.copy_content.restype = ctypes.c_int
        cls.copy_expiration = cls.library.zsign_copy_signer_expiration
        cls.copy_expiration.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int64)]
        cls.copy_expiration.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self, name="host", password=b"disposable", cms=None):
        p12 = (self.directory / (name + ".p12")).read_bytes()
        if cms is None:
            cms = (self.directory / "host.cms").read_bytes()
        output = ctypes.create_string_buffer(65536)
        length = ctypes.c_size_t()
        result = self.validate(p12, len(p12), password, cms, len(cms), output,
                               len(output), ctypes.byref(length))
        return result, output.raw[:length.value]

    def test_matching_host_returns_exact_certificate(self):
        self.assertEqual(self.check(), (0, (self.directory / "host.der").read_bytes()))

    def test_legacy_encrypted_identity_matches_host(self):
        self.assertEqual(self.check("legacy"), (0, (self.directory / "host.der").read_bytes()))

    def test_same_team_different_certificate_is_rejected(self):
        self.assertEqual(self.check("other"), (3, b""))

    def test_wrong_password_and_missing_private_key_are_rejected(self):
        self.assertEqual(self.check(password=b"wrong"), (1, b""))
        self.assertEqual(self.check("keyless"), (1, b""))

    def test_missing_malformed_and_trailing_cms_are_rejected(self):
        for cms in (b"", b"not cms", (self.directory / "host.cms").read_bytes() + b"extra"):
            with self.subTest(cms_length=len(cms)):
                self.assertEqual(self.check(cms=cms), (2, b""))

    def extract(self, profile, capacity=4 * 1024 * 1024):
        output = ctypes.create_string_buffer(capacity)
        length = ctypes.c_size_t()
        result = self.copy_content(profile, len(profile), output, capacity, ctypes.byref(length))
        return result, output.raw[:length.value]

    def test_extracts_only_actual_embedded_cms_profile_content(self):
        profile = (self.directory / "profile.cms").read_bytes()
        self.assertEqual(self.extract(profile), (0, self.profile_content))
        self.assertEqual(self.extract(profile, capacity=1), (1, b""))

    def test_rejects_plain_truncated_trailing_and_detached_profiles(self):
        profile = (self.directory / "profile.cms").read_bytes()
        for data in (b"", self.profile_content, plistlib.dumps({}, fmt=plistlib.FMT_BINARY),
                     b"junk" + self.profile_content, profile[:-1], profile + b"extra",
                     (self.directory / "host.cms").read_bytes()):
            with self.subTest(size=len(data)):
                self.assertEqual(self.extract(data), (1, b""))

    def test_expiration_comes_from_xml_or_binary_cms_payload(self):
        for name in ("profile.cms", "binary.cms"):
            with self.subTest(name=name):
                status, content = self.extract((self.directory / name).read_bytes())
                self.assertEqual(status, 0)
                self.assertEqual(plistlib.loads(content)["ExpirationDate"], self.profile_expiration)

    def expiration(self, cms):
        result = ctypes.c_int64(123)
        status = self.copy_expiration(cms, len(cms), ctypes.byref(result))
        return status, result.value

    def test_actual_signer_certificate_expiration(self):
        self.assertEqual(self.expiration((self.directory / "host.cms").read_bytes()),
                         (0, self.certificate_expirations["host"]))
        self.assertEqual(self.expiration((self.directory / "extra.cms").read_bytes()),
                         (0, self.certificate_expirations["other"]))
        self.assertNotEqual(self.certificate_expirations["host"], self.certificate_expirations["other"])

    def test_expiration_rejects_multiple_or_missing_signer_certificates(self):
        for name in ("multiple.cms", "missing.cms", "ambiguous.cms"):
            with self.subTest(name=name):
                self.assertEqual(self.expiration((self.directory / name).read_bytes()), (1, 0))

    def test_expiration_rejects_malformed_and_out_of_bounds_input(self):
        cms = (self.directory / "host.cms").read_bytes()
        for data in (b"", b"invalid", cms[:-1], cms + b"extra", self.profile_content):
            with self.subTest(size=len(data)):
                self.assertEqual(self.expiration(data), (1, 0))
        result = ctypes.c_int64(123)
        self.assertEqual(self.copy_expiration(cms, 16 * 1024 * 1024 + 1, ctypes.byref(result)), 1)
        self.assertEqual(result.value, 0)
        self.assertEqual(self.copy_expiration(cms, len(cms), None), 1)

    def test_expiration_rejects_invalid_certificate_date(self):
        cms = (self.directory / "host.cms").read_bytes()
        expiration = datetime.datetime.fromtimestamp(self.certificate_expirations["host"], datetime.timezone.utc)
        original = expiration.strftime("%y%m%d%H%M%SZ").encode()
        self.assertIn(original, cms)
        malformed = original[:2] + b"13" + original[4:] # Invalid month, same DER length.
        self.assertEqual(self.expiration(cms.replace(original, malformed)), (1, 0))
