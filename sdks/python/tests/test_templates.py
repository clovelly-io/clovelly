"""Templates: the SDK's ciphertext is crates/common's byte for byte, uploads stream it to
the control plane under a key from the customer's verifier, and sandboxes name a
template and a volume."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import grpc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import clovelly
from clovelly import _template
from fakes import ENV_ID, VERIFIER_TOKEN, FakeVerifier, Services

CHUNK = 1 << 20
KEY = bytes(range(32))


def pattern(length: int) -> bytes:
    """Byte i is i % 251, as in the Rust vector and crates/common's own tests."""
    return (bytes(range(251)) * (length // 251 + 1))[:length]


def decrypt(key: bytes, digest: bytes, ciphertext: bytes) -> bytes:
    """The cell's side of the format (crates/common/src/template.rs ``Decryptor``), for
    checking what was uploaded: every record must open in order with its index and the
    last-chunk flag set on the final record only."""
    aead = AESGCM(key)
    plain, offset, index = [], 0, 0
    while offset < len(ciphertext):
        length = int.from_bytes(ciphertext[offset : offset + 4], "big")
        record = ciphertext[offset + 4 : offset + 4 + length]
        offset += 4 + length
        last = b"\x01" if offset == len(ciphertext) else b"\x00"
        nonce = bytes(4) + index.to_bytes(8, "big")
        aad = b"clovelly-v1 template chunk" + digest + index.to_bytes(8, "big") + last
        plain.append(aead.decrypt(nonce, record, aad))
        index += 1
    return b"".join(plain)


class TempFiles(unittest.TestCase):
    def file(self, data: bytes) -> Path:
        tmp = tempfile.TemporaryDirectory(prefix="clovelly-sdk-template-")
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "template.tar.gz"
        path.write_bytes(data)
        return path


class Vector(TempFiles):
    # From crates/common/src/template.rs: a throwaway Rust binary (outside the repo,
    # depending on `common` by path) called common::template::encrypt with key bytes
    # 0..31 on these plaintexts and printed the SHA-256 of each ciphertext. The
    # TypeScript SDK's test checks the same constants.
    DIGEST = "b5c324a19845fd0e5fd3bb9471d9ced2215154672c50aca851fc0ca780f761da"  # of 1 MiB + 5
    VECTORS = {
        CHUNK + 5: (1_048_621, "a6540cd98420766b207786d85e28d0741e36185899a154414c2e1d64ff891572"),
        CHUNK: (1_048_596, "df0ee53b9d7a5914524b1f9502c11ddf3416de7f14e696773dd6bb44b9143412"),
        0: (20, "8bb1a4e9df0fcbab4478cef0213e48978b5996978fe6fd2167bde585a541d1fb"),
    }

    def test_ciphertext_is_byte_for_byte_the_rust_encryptors(self) -> None:
        for length, (ct_bytes, ct_sha256) in self.VECTORS.items():
            with self.subTest(length=length):
                path = self.file(pattern(length))
                digest, size = _template.file_digest(path)
                self.assertEqual(size, length)
                if length == CHUNK + 5:
                    self.assertEqual(digest.hex(), self.DIGEST)
                ct = b"".join(_template.ciphertext(path, KEY, digest, size))
                self.assertEqual((len(ct), hashlib.sha256(ct).hexdigest()), (ct_bytes, ct_sha256))
                self.assertEqual(decrypt(KEY, digest, ct), pattern(length))

    def test_a_file_that_changes_after_its_digest_is_refused_before_its_last_chunk(self) -> None:
        path = self.file(pattern(2 * CHUNK))
        digest, size = _template.file_digest(path)
        path.write_bytes(pattern(2 * CHUNK - 1) + b"!")
        with self.assertRaisesRegex(ValueError, "changed while it was being uploaded"):
            list(_template.ciphertext(path, KEY, digest, size))


class Upload(Services, TempFiles):
    def test_upload_streams_the_header_then_ciphertext_that_opens(self) -> None:
        plain = pattern(9 * CHUNK + 3)  # three data messages
        path = self.file(plain)
        digest = hashlib.sha256(plain).digest()

        tpl = self.env.upload_template("a", "analyst-v3", path)

        seal = self.verifier.requests[0]
        self.assertEqual(self.verifier.calls, ["SealTemplateKey"])
        self.assertEqual((seal.env_id, seal.subenv_id, seal.digest), (ENV_ID, "a", digest.hex()))
        self.assertEqual(self.verifier.tokens, {f"Bearer {VERIFIER_TOKEN}"})
        (upload,) = self.control.uploads
        header = upload.header
        self.assertEqual(
            (header.env_id, header.subenv_id, header.name, header.digest, header.sealed_key, header.plaintext_bytes),
            (ENV_ID, "a", "analyst-v3", digest.hex(), b"sealed:" + digest.hex().encode(), len(plain)),
        )
        self.assertEqual([len(d) for d in upload.data[:-1]], [_template.DATA_BYTES] * 2)
        self.assertLessEqual(len(upload.data[-1]), _template.DATA_BYTES)
        ct = b"".join(upload.data)
        self.assertEqual(len(ct), len(plain) + 10 * 20, "a 20-byte length and tag per 1 MiB chunk")
        self.assertNotIn(plain[:64], ct, "the control plane receives no plaintext")
        self.assertEqual(decrypt(FakeVerifier.KEY, digest, ct), plain)
        self.assertEqual(tpl, clovelly.Template("analyst-v3", digest.hex(), len(ct), len(plain), 1))
        self.assertEqual(self.env.template("a", "analyst-v3"), tpl)

    def test_a_file_changed_mid_upload_cancels_it(self) -> None:
        path = self.file(pattern(CHUNK + 1))
        stale = (hashlib.sha256(b"before").digest(), CHUNK + 1)
        with mock.patch.object(_template, "file_digest", return_value=stale):
            with self.assertRaisesRegex(ValueError, "changed while it was being uploaded"):
                self.env.upload_template("a", "analyst-v3", path)
        self.assertEqual(self.control.templates, {}, "a cancelled stream stores nothing")

    def test_template_names_are_checked_and_lookups_typed(self) -> None:
        path = self.file(b"x")
        for bad in ("Analyst", "a b", "x" * 65, ""):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                self.env.upload_template("a", bad, path)
        with self.assertRaises(clovelly.NoSuchTemplate):
            self.env.template("a", "missing")
        self.assertEqual(self.verifier.calls, [])


class SandboxFromTemplate(Services, TempFiles):
    def test_create_carries_the_template_digest_and_volume(self) -> None:
        tpl = self.env.upload_template("a", "analyst-v3", self.file(b"a root"))
        bare = self.env.sandbox("a")
        by_value = self.env.sandbox("a", template=tpl, volume="work", volume_gib=5)
        by_digest = self.env.sandbox("a", template=tpl.digest, volume="work")
        lookups = self.control.calls.count("GetTemplate")
        by_name = self.env.sandbox("a", template="analyst-v3")

        created = {sb.id: self.cell.sandboxes[sb.id].request for sb in (bare, by_value, by_digest, by_name)}
        self.assertEqual(
            [(r.template_digest, r.volume, r.volume_gib) for r in created.values()],
            [("", "", 0), (tpl.digest, "work", 5), (tpl.digest, "work", 0), (tpl.digest, "", 0)],
        )
        self.assertEqual(lookups, 0, "a Template or digest needs no lookup")
        self.assertEqual(self.control.calls.count("GetTemplate"), 1, "a name is resolved once")
        self.assertEqual(by_value.close().doc["sandbox"]["template_digest"], tpl.digest)

    def test_unknown_template_name_is_refused_before_placing(self) -> None:
        with self.assertRaises(clovelly.NoSuchTemplate):
            self.env.sandbox("a", template="missing")
        self.assertEqual(self.control.places, [])

    def test_volume_refusals_are_typed_and_not_placed_again(self) -> None:
        self.cell.refuse_create = (grpc.StatusCode.FAILED_PRECONDITION, "VOLUME_BUSY")
        with self.assertRaises(clovelly.VolumeBusy) as caught:
            self.env.sandbox("a", volume="work")
        self.assertEqual(caught.exception.reason, "VOLUME_BUSY")
        self.assertEqual(len(self.control.places), 1)
        self.assertEqual(len(self.control.released), 1)


if __name__ == "__main__":
    unittest.main()
