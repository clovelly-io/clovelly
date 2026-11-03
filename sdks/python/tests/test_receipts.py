"""Receipts: the signed pieces a cell returns, the customer's receipt log at their
verifier, and the egress log checked against its hash and a receipt's."""

from __future__ import annotations

import hashlib
import json
import unittest

import clovelly
from clovelly.verifier.v1 import verifier_pb2
from fakes import ENV_ID, SIGNATURE, Services, environment, pki

LINES = (
    '{"host":"api.openai.com","port":443,"kind":"substituted"}',
    '{"host":"example.com","port":443,"kind":"wildcard"}',
)
LINES_SHA256 = hashlib.sha256("".join(line + "\n" for line in LINES).encode()).hexdigest()


def logged(sandbox_id: str, *, subenv: str = "a", egress_log_hash: object = LINES_SHA256) -> verifier_pb2.LoggedReceipt:
    doc = {"v": 1, "env": ENV_ID, "subenv": subenv, "sandbox": {"id": sandbox_id}, "egress_log_hash": egress_log_hash}
    return verifier_pb2.LoggedReceipt(
        receipt=json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(),
        signature=SIGNATURE,
        cell_cert=pki().der("cell_a"),
        final=True,
        received_unix_ms=1_761_000_000_000,
        records=4,
        finals=1,
    )


class CellReceipts(Services):
    def test_receipts_carry_the_signed_bytes_certificate_and_final_flag(self) -> None:
        sb = self.env.sandbox("a")
        interim = sb.receipt()
        self.assertEqual((interim.exit_kind, interim.final), ("running", False))

        final = sb.close()
        self.assertEqual((final.exit_kind, final.final), ("killed", True))
        self.assertEqual(final.signature, SIGNATURE)
        self.assertEqual(final.cell_cert, pki().der("cell_a"))
        self.assertEqual(json.loads(final.json), final.doc)
        self.assertEqual(final.doc["sandbox"]["id"], sb.id)
        self.assertNotIn(final.json.decode(), repr(final), "the raw bytes stay out of repr")


class ReceiptLog(Services):
    def test_receipts_lists_the_log_as_asked(self) -> None:
        ids = ["1" * 32, "2" * 32, "3" * 32]
        self.verifier.log = [logged(ids[0]), logged(ids[1]), logged(ids[2], subenv="b")]

        everything = self.env.receipts()
        mine = self.env.receipts("a", sandbox_ids=[ids[1]])

        self.assertEqual([r.doc["sandbox"]["id"] for r in everything], ids)
        (record,) = mine
        request = self.verifier.requests[-1]
        self.assertEqual((request.env_id, request.subenv_id, list(request.sandbox_ids)), (ENV_ID, "a", [ids[1]]))
        self.assertEqual(
            (record.final, record.received_unix_ms, record.records, record.finals, record.signature),
            (True, 1_761_000_000_000, 4, 1, SIGNATURE),
        )
        self.assertEqual(record.cell_cert, pki().der("cell_a"))
        self.assertEqual(json.loads(record.json), record.doc)
        with self.assertRaises(ValueError):
            self.env.receipts(sandbox_ids=["not-an-id"])

    def test_egress_log_is_checked_against_its_hash_and_the_receipt(self) -> None:
        sid, other = "1" * 32, "2" * 32
        self.verifier.egress[sid] = verifier_pb2.GetEgressLogResponse(lines=LINES, sha256=LINES_SHA256)
        self.verifier.log = [logged(sid), logged(other), logged("3" * 32, egress_log_hash="0" * 64)]

        log = self.env.egress_log(sid)
        receipts = {r.doc["sandbox"]["id"]: r for r in self.env.receipts()}

        self.assertEqual((log.sandbox_id, log.lines, log.sha256), (sid, LINES, LINES_SHA256))
        self.assertEqual(clovelly.egress_log_sha256(LINES), LINES_SHA256)
        self.assertTrue(log.matches(receipts[sid]))
        self.assertFalse(log.matches(receipts[other]), "another sandbox's receipt")
        self.assertFalse(clovelly.EgressLog("3" * 32, LINES, LINES_SHA256).matches(receipts["3" * 32]), "another hash")
        empty = clovelly.EgressLog(sid, (), clovelly.egress_log_sha256(()))
        self.assertTrue(empty.matches(clovelly.LoggedReceipt._from_proto(logged(sid, egress_log_hash=None))))
        self.assertFalse(log.matches(clovelly.LoggedReceipt._from_proto(logged(sid, egress_log_hash=None))))

    def test_a_tampered_egress_log_is_refused(self) -> None:
        sid = "1" * 32
        for lines, sha256 in (
            ((*LINES, '{"host":"exfil.example","port":443}'), LINES_SHA256),  # a line added
            (LINES[:1], LINES_SHA256),  # a line dropped
            (LINES, "0" * 64),  # the hash replaced
        ):
            with self.subTest(lines=len(lines), sha256=sha256[:4]):
                self.verifier.egress[sid] = verifier_pb2.GetEgressLogResponse(lines=lines, sha256=sha256)
                with self.assertRaises(clovelly.EgressLogMismatch):
                    self.env.egress_log(sid)
        with self.assertRaises(clovelly.SandboxNotFound):
            self.env.egress_log("2" * 32)

    def test_the_log_needs_the_sdk_token(self) -> None:
        no_token = environment(self.control)
        self.addCleanup(no_token.close)
        with self.assertRaisesRegex(ValueError, "SDK token"):
            no_token.receipts()
        wrong = clovelly.Environment(
            self.verifier.url, ENV_ID, pki().cert("env"), verifier_token="wrong", verifier_ca=pki().cert("api")
        )
        self.addCleanup(wrong.close)
        with self.assertRaises(clovelly.Unauthenticated):
            wrong.egress_log("1" * 32)


if __name__ == "__main__":
    unittest.main()
