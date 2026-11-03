"""The SDK refuses a cell that is not verified for its environment and sub-environment,
and sends it nothing (SPEC.md phase 2 criterion 2)."""

from __future__ import annotations

import socket
import threading
import time
import unittest
from unittest import mock

import clovelly
from fakes import FakeCell, FakeControl, environment

# (certificate the cell presents, the refusal kind the SDK must raise)
REFUSALS = [
    ("self_signed", "untrusted_certificate"),
    ("other_ca", "untrusted_certificate"),
    ("cell_b", "name_mismatch"),
]


class RefusedCells(unittest.TestCase):
    def test_sandbox_refuses_each_unverified_cell_and_sends_nothing(self) -> None:
        for cert, kind in REFUSALS:
            with self.subTest(cert=cert):
                cell = FakeCell(cert)
                self.addCleanup(cell.stop)
                control = FakeControl([cell])
                self.addCleanup(control.stop)
                env = environment(control)
                self.addCleanup(env.close)

                with self.assertRaises(clovelly.CellVerificationError) as caught:
                    env.sandbox("a")

                self.assertEqual(caught.exception.kind, kind)
                self.assertEqual(caught.exception.address, cell.address)
                self.assertEqual(cell.calls, [], "no RPC, not even the probe, may reach a refused cell")
                self.assertEqual(control.released, list(control.placed), "the abandoned placement is released")

    def test_low_level_verify_refuses_and_drops_the_connection(self) -> None:
        cell = FakeCell("cell_b")
        self.addCleanup(cell.stop)
        env = environment()
        self.addCleanup(env.close)

        conn = env.cell(cell.address, "a")
        with self.assertRaises(clovelly.CellVerificationError) as caught:
            conn.verify()
        self.assertEqual(caught.exception.kind, "name_mismatch")
        self.assertTrue(conn.closed)
        # A refused connection stays refused and sends nothing.
        with self.assertRaises(clovelly.CellVerificationError):
            conn.create_sandbox("0" * 32, b"k" * 32, 2, 2, 60)
        self.assertEqual(cell.calls, [])
        # The cache hands out a fresh connection, not the refused one.
        self.assertIsNot(env.cell(cell.address, "a"), conn)

    def test_the_right_sub_environment_verifies_with_one_probe(self) -> None:
        cell = FakeCell("cell_b")
        self.addCleanup(cell.stop)
        env = environment()
        self.addCleanup(env.close)

        conn = env.cell(cell.address, "b")
        conn.verify()
        conn.verify()
        self.assertTrue(conn.verified)
        self.assertEqual(cell.calls, ["Check"])

    def test_unreachable_cell_is_unavailable_not_refused(self) -> None:
        env = environment()
        self.addCleanup(env.close)
        conn = env.cell("127.0.0.1:1", "a")
        started = time.monotonic()
        with mock.patch.object(clovelly._cell, "CONNECT_WAIT_SECS", 1.0), self.assertRaises(clovelly.CellUnavailable):
            conn.verify()
        # Waited for the cell to become reachable, then gave up; the connection stays usable.
        self.assertGreaterEqual(time.monotonic() - started, 1.0)
        self.assertFalse(conn.closed)

    def test_a_cell_that_never_answers_the_handshake_is_given_up_after_the_connect_wait(self) -> None:
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        accepted: list[socket.socket] = []
        threading.Thread(target=lambda: accepted.append(listener.accept()[0]), daemon=True).start()
        self.addCleanup(lambda: [s.close() for s in accepted])
        env = environment()
        self.addCleanup(env.close)

        with mock.patch.object(clovelly._cell, "PROBE_TIMEOUT_SECS", 0.2), mock.patch.object(clovelly._cell, "CONNECT_WAIT_SECS", 1.0):
            started = time.monotonic()
            with self.assertRaises(clovelly.CellUnavailable) as caught:
                env.cell(f"127.0.0.1:{listener.getsockname()[1]}", "a").verify()
        self.assertEqual(caught.exception.code, "DEADLINE_EXCEEDED")
        self.assertGreaterEqual(time.monotonic() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
