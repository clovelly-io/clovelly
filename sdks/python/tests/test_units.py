"""Argument parsing, the error tables and the handshake classifier, without servers."""

from __future__ import annotations

import unittest

import grpc

import clovelly
from clovelly import _cell, _parse, errors
from clovelly.cell.v1 import cell_pb2
from clovelly.control.v1 import control_pb2
from fakes import environment


class Sizes(unittest.TestCase):
    def test_cpu_is_sent_in_halves(self) -> None:
        self.assertEqual(
            [_parse.cpu_halves(c) for c in (None, 0.5, 1, 1.5, 7)], [0, 1, 2, 3, 14]
        )

    def test_cpu_that_is_not_a_positive_multiple_of_half_is_refused(self) -> None:
        for cpu in (0, -0.5, 0.3, 1.25, True, "1", float("inf"), float("nan")):
            with self.subTest(cpu=cpu), self.assertRaises(ValueError):
                _parse.cpu_halves(cpu)  # type: ignore[arg-type]

    def test_sandbox_rejects_bad_arguments_before_any_call(self) -> None:
        env = environment()  # no control plane: a network call would raise differently
        self.addCleanup(env.close)
        bad = [
            {"cpu": 0.3},
            {"memory": 0},
            {"memory": 1.5},
            {"timeout": 0},
            {"timeout": 86_401},
            {"template": "Analyst v3"},
            {"template": "x" * 65},
            {"template": 3},
            {"policy": "default"},
            {"volume": "a/b"},
            {"volume": "x" * 65},
            {"volume": "v", "volume_gib": 0},
            {"volume": "v", "volume_gib": 21},
            {"volume_gib": 2},
            {"command": []},
            {"env": {"A": 1}},
        ]
        for kwargs in bad:
            with self.subTest(**kwargs), self.assertRaisesRegex(ValueError, r"^(?!the control plane)"):
                env.sandbox("a", **kwargs)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            env.sandbox("Not_A_Label")

    def test_ids_and_addresses_are_parsed(self) -> None:
        self.assertEqual(_parse.sandbox_id("0" * 32), "0" * 32)
        for bad in ("0" * 31, "0" * 33, "A" * 32, "g" * 32):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _parse.sandbox_id(bad)
        self.assertEqual(_parse.cell_address("10.0.0.7:443"), "10.0.0.7:443")
        for bad in ("10.0.0.7", "cell.example:443", "10.0.0.7:0", "10.0.0.7:x", "[::1]:443"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _parse.cell_address(bad)


class ErrorTables(unittest.TestCase):
    def test_every_reason_in_both_protos_has_a_typed_error(self) -> None:
        for enum, table in (
            (cell_pb2.ErrorReason, errors._CELL_REASONS),
            (control_pb2.ErrorReason, errors._CONTROL_REASONS),
        ):
            names = {name for name in enum.keys() if name != "ERROR_REASON_UNSPECIFIED"}
            self.assertEqual(set(table), names)
            for cls in table.values():
                self.assertTrue(issubclass(cls, clovelly.ClovellyError) and cls is not clovelly.ClovellyError)

    def test_unknown_reason_is_a_plain_clovelly_error(self) -> None:
        class Failed:  # the grpc.Call surface the mapper reads
            def code(self) -> grpc.StatusCode:
                return grpc.StatusCode.FAILED_PRECONDITION

            def details(self) -> str:
                return "newer server"

            def trailing_metadata(self) -> tuple[tuple[str, str], ...]:
                return (("clovelly-error", "SOMETHING_NEW"),)

        err = errors._cell_error(Failed())  # type: ignore[arg-type]
        self.assertIs(type(err), clovelly.ClovellyError)
        self.assertEqual((err.reason, err.code), ("SOMETHING_NEW", "FAILED_PRECONDITION"))


class Handshake(unittest.TestCase):
    # As grpcio 1.74 reports them (BoringSSL).
    CASES = [
        (
            "failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:1: "
            "Peer name a.staging.cells.clovelly.internal is not in peer certificate",
            "name_mismatch",
        ),
        (
            "failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:1: Ssl "
            "handshake failed (TSI_PROTOCOL_FAILURE): SSL_ERROR_SSL: error:1000007d:SSL "
            "routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate",
            "untrusted_certificate",
        ),
        (
            "failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:1: Ssl "
            "handshake failed (TSI_PROTOCOL_FAILURE): SSL_ERROR_SSL: error:100000f7:SSL "
            "routines:OPENSSL_internal:WRONG_VERSION_NUMBER: Invalid certificate verification context",
            "handshake",
        ),
        (
            "failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:1: "
            "Failed to connect to remote host: connect: Connection refused (61)",
            None,
        ),
    ]

    def test_classifier(self) -> None:
        for details, kind in self.CASES:
            with self.subTest(kind=kind):
                self.assertEqual(_cell.handshake_kind(details), kind)


class Pem(unittest.TestCase):
    def test_ca_bundle_must_hold_a_certificate(self) -> None:
        with self.assertRaises(ValueError):
            clovelly.Environment("https://v.invalid", "staging", b"not a pem")
        with self.assertRaises(ValueError):
            clovelly.Environment("https://v.invalid", "Bad_Env", b"-----BEGIN CERTIFICATE-----")


if __name__ == "__main__":
    unittest.main()


class Credentials(unittest.TestCase):
    def test_placeholders_name_the_credential(self) -> None:
        self.assertEqual(clovelly.placeholder("openai"), "clovelly://cred/openai")
        for bad in ("", "Open AI", "a/b", "x" * 65):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                clovelly.placeholder(bad)

    def test_put_credential_checks_its_arguments_before_any_call(self) -> None:
        env = environment()
        self.addCleanup(env.close)
        good = {"adapter": "bearer", "destination": "api.example.com"}
        for name, secret, kw in (
            ("Bad Name", "s", good),
            ("ok", "", good),
            ("ok", "s", {"adapter": "sigv4", "destination": "api.example.com"}),
            ("ok", "s", {"adapter": "bearer", "destination": "*.example.com"}),
            ("ok", "s", {"adapter": "bearer", "destination": "a b"}),
        ):
            with self.subTest(name=name, kw=kw), self.assertRaises(ValueError):
                env.put_credential("a", name, secret, **kw)
        with self.assertRaisesRegex(ValueError, "SDK token"):
            env.put_credential("a", "ok", "s", **good)

    def test_policy_and_credential_refusals_are_typed(self) -> None:
        self.assertIs(errors._CELL_REASONS["POLICY_REFUSED"], clovelly.PolicyRefused)
        self.assertIs(errors._CELL_REASONS["CREDENTIAL_UNAVAILABLE"], clovelly.CredentialUnavailable)
        self.assertIs(errors._CONTROL_REASONS["STORAGE"], clovelly.StorageUnavailable)

    def test_template_and_volume_refusals_are_typed(self) -> None:
        self.assertIs(errors._CELL_REASONS["TEMPLATE_UNAVAILABLE"], clovelly.TemplateUnavailable)
        self.assertIs(errors._CELL_REASONS["VOLUME_UNREADABLE"], clovelly.VolumeUnreadable)
        self.assertIs(errors._CELL_REASONS["VOLUME_UNAVAILABLE"], clovelly.VolumeUnavailable)
        self.assertIs(errors._CONTROL_REASONS["NO_SUCH_TEMPLATE"], clovelly.NoSuchTemplate)
        for table in (errors._CELL_REASONS, errors._CONTROL_REASONS):
            self.assertIs(table["VOLUME_BUSY"], clovelly.VolumeBusy)
