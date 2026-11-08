"""The SDK refuses a cell that is not verified for its environment, sub-environment and
own name, and sends it nothing (SPEC.md phase 2 criterion 2, phase 12 criterion 9)."""

from __future__ import annotations

import socket
import threading
import time
import unittest
from unittest import mock

import clovelly
from fakes import CELL_1, CELL_2, CELL_B, FakeCell, FakeControl, environment

# (certificate the cell presents when dialled as CELL_1, the refusal kind the SDK must raise)
REFUSALS = [
    ("self_signed", "untrusted_certificate"),
    ("other_ca", "untrusted_certificate"),
    ("cell_b", "name_mismatch"),
    # Through the relay: a second cell of the same sub-environment, behind a relay that
    # routed the connection to the wrong cell.
    ("cell_a2", "name_mismatch"),
    # A cell whose certificate names only the sub-environment, as before phase 12.
    ("old_a", "name_mismatch"),
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
                self.assertIn(CELL_1, caught.exception.details)
                self.assertEqual(cell.calls, [], "no RPC, not even the probe, may reach a refused cell")
                self.assertEqual(control.released, list(control.placed), "the abandoned placement is released")

    def test_a_placement_naming_another_sub_environments_cell_is_refused_before_dialling(self) -> None:
        for name in (CELL_B, "a.staging.cells.clovelly.internal", f"x.{CELL_1}", "", CELL_1.upper()):
            with self.subTest(name=name):
                cell = FakeCell("cell_b", name=CELL_B)
                self.addCleanup(cell.stop)
                control = FakeControl([cell])
                self.addCleanup(control.stop)
                control.name_override = name
                env = environment(control)
                self.addCleanup(env.close)

                with self.assertRaises(clovelly.ProtocolError) as caught:
                    env.sandbox("a")
                self.assertIn("cell name", caught.exception.details)
                self.assertEqual(cell.calls, [], "nothing is dialled")
                self.assertEqual(control.released, list(control.placed))

    def test_low_level_verify_refuses_and_drops_the_connection(self) -> None:
        cell = FakeCell("cell_a2", name=CELL_2)
        self.addCleanup(cell.stop)
        env = environment()
        self.addCleanup(env.close)

        conn = env.cell(cell.address, CELL_1, "a")
        with self.assertRaises(clovelly.CellVerificationError) as caught:
            conn.verify()
        self.assertEqual(caught.exception.kind, "name_mismatch")
        self.assertTrue(conn.closed)
        # A refused connection stays refused and sends nothing.
        with self.assertRaises(clovelly.CellVerificationError):
            conn.create_sandbox("0" * 32, b"k" * 32, 2, 2, 60)
        self.assertEqual(cell.calls, [])
        # The cache hands out a fresh connection, not the refused one.
        self.assertIsNot(env.cell(cell.address, CELL_1, "a"), conn)

    def test_the_right_name_verifies_with_one_probe_and_each_name_has_its_own_connection(self) -> None:
        cell = FakeCell("cell_a2", name=CELL_2)
        self.addCleanup(cell.stop)
        env = environment()
        self.addCleanup(env.close)

        conn = env.cell(cell.address, CELL_2, "a")
        conn.verify()
        conn.verify()
        self.assertTrue(conn.verified)
        self.assertEqual(cell.calls, ["Check"])
        self.assertIs(env.cell(cell.address, CELL_2, "a"), conn, "one connection per cell")
        # Every cell of a region shares the relay's address: the name is part of the key.
        self.assertIsNot(env.cell(cell.address, CELL_1, "a"), conn)

    def test_a_name_outside_the_sub_environment_is_refused(self) -> None:
        env = environment()
        self.addCleanup(env.close)
        with self.assertRaises(ValueError):
            env.cell("127.0.0.1:1", CELL_B, "a")

    def test_unreachable_cell_is_unavailable_not_refused(self) -> None:
        env = environment()
        self.addCleanup(env.close)
        conn = env.cell("127.0.0.1:1", CELL_1, "a")
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
                env.cell(f"127.0.0.1:{listener.getsockname()[1]}", CELL_1, "a").verify()
        self.assertEqual(caught.exception.code, "DEADLINE_EXCEEDED")
        self.assertGreaterEqual(time.monotonic() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
