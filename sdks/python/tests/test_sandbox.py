"""Sandboxes end to end against a fake control plane and fake cells over TLS."""

from __future__ import annotations

import threading
import unittest
from concurrent import futures

import grpc

import clovelly
from clovelly.cell.v1 import cell_pb2
from fakes import ENV_ID, TOKEN, FakeCell, FakeControl, environment


class Fixture(unittest.TestCase):
    """One control plane over the cells ``self.cell_ids`` names, and an Environment."""

    cell_ids = ["cell-1"]

    def setUp(self) -> None:
        self.cells = [FakeCell("cell_a", cell_id) for cell_id in self.cell_ids]
        for cell in self.cells:
            self.addCleanup(cell.stop)
        self.cell = self.cells[0]
        self.control = FakeControl(self.cells)
        self.addCleanup(self.control.stop)
        self.env = environment(self.control)
        self.addCleanup(self.env.close)


class HappyPath(Fixture):
    def test_create_exec_files_close(self) -> None:
        sb = self.env.sandbox("a", cpu=1.5, memory=3, timeout=600, command="sleep 600", env={"A": "1"})

        place = self.control.places[0]
        self.assertEqual((place.env_id, place.subenv_id), (ENV_ID, "a"))
        self.assertEqual((place.size.cpu_halves, place.size.memory_gib, place.timeout_secs), (3, 3, 600))
        self.assertEqual(self.control.tokens, {f"Bearer {TOKEN}"})
        self.assertEqual(self.cell.calls, ["Check", "CreateSandbox"], "the probe comes first")
        create = self.cell.sandboxes[sb.id].request
        self.assertEqual(len(create.access_key), 32)
        self.assertEqual(create.access_key.hex(), sb.key)
        self.assertEqual((create.cpu_halves, create.memory_gib, create.timeout_secs), (3, 3, 600))
        self.assertEqual(list(create.command), ["/bin/sh", "-c", "sleep 600"])
        self.assertEqual(dict(create.env), {"A": "1"})
        self.assertEqual((sb.cell_id, sb.subenv, sb.cold), ("cell-1", "a", False))
        self.assertEqual((sb.cpu, sb.memory, sb.timeout), (1.5, 3, 600))
        self.assertEqual(set(sb.timings), {"place_ms", "connect_ms", "create_ms", "runsc_ms"})
        self.assertEqual(sb.timings["runsc_ms"], 7.0)
        self.assertNotIn(sb.key, repr(sb), "the access key is a secret")

        r = sb.exec("python3 -c 'print(6*7)'")
        self.assertEqual((r.exit_code, r.stdout, r.stderr), (0, b"42\n", b"err"))
        self.assertEqual(r.first_exec_ms, 123)
        self.assertIsInstance(r.first_stdout_at, float)
        self.assertIsNone(r.sandbox_ended)
        self.assertIsNone(sb.exec(["exit", "3"]).first_exec_ms, "first_exec_ms is for the first exec only")
        self.assertEqual(sb.exec(["exit", "3"]).exit_code, 3)

        big = bytes(range(256)) * 1000  # several 64 KiB chunks each way
        self.assertEqual(sb.exec(["cat"], stdin=big).stdout, big)
        self.assertEqual(sb.files.write("/tmp/in.bin", big), len(big))
        self.assertEqual(sb.files.read("/tmp/in.bin"), big)
        with self.assertRaises(clovelly.FileNotFound) as caught:
            sb.files.read("/missing")
        self.assertEqual((caught.exception.reason, caught.exception.code), ("NO_SUCH_FILE", "NOT_FOUND"))

        receipt = sb.close()
        self.assertEqual(receipt.exit_kind, "killed")
        self.assertEqual(receipt.doc["sandbox"]["id"], sb.id)
        self.assertIs(receipt.data, receipt.doc, "data is the phase 2 name of doc")
        self.assertEqual(self.control.released, [sb.id])

    def test_second_sandbox_reuses_the_verified_connection(self) -> None:
        first = self.env.sandbox("a")
        second = self.env.sandbox("a")
        self.assertEqual(second.timings["connect_ms"], 0.0)
        self.assertEqual(self.cell.calls.count("Check"), 1)
        self.assertEqual((second.cpu, second.memory, second.timeout), (1.0, 2, 900), "defaults filled in")
        first.exec("true")
        second.exec("true")
        self.assertEqual(len(self.cell.peers), 1, "one TLS connection for both sandboxes")

    def test_close_after_the_sandbox_ended_returns_its_receipt(self) -> None:
        sb = self.env.sandbox("a", command=["true"])
        self.cell.sandboxes[sb.id].ended = cell_pb2.EXIT_KIND_EXITED
        self.assertEqual(sb.close().exit_kind, "exited")
        self.assertEqual(self.control.released, [sb.id])


class Errors(Fixture):
    cell_ids = ["cell-1", "cell-2", "cell-3"]

    def test_control_plane_refusal_is_typed(self) -> None:
        self.control.refuse_place = (grpc.StatusCode.INVALID_ARGUMENT, "ABOVE_POLICY_MAXIMUM")
        with self.assertRaises(clovelly.AbovePolicyMaximum) as caught:
            self.env.sandbox("a", cpu=64)
        self.assertEqual(caught.exception.reason, "ABOVE_POLICY_MAXIMUM")
        self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(self.cell.calls, [])

    def test_quota_refusal_is_typed_and_not_placed_again(self) -> None:
        self.control.refuse_place = (grpc.StatusCode.RESOURCE_EXHAUSTED, "QUOTA_EXCEEDED")
        with self.assertRaises(clovelly.QuotaExceeded) as caught:
            self.env.sandbox("a")
        self.assertEqual(caught.exception.reason, "QUOTA_EXCEEDED")
        self.assertEqual(len(self.control.places), 1, "a quota is not a capacity problem: no retry")

    def test_capacity_refusal_places_again_avoiding_that_cell(self) -> None:
        self.cells[0].refuse_create = (grpc.StatusCode.RESOURCE_EXHAUSTED, "CAPACITY")
        sb = self.env.sandbox("a")
        self.assertEqual(sb.cell_id, "cell-2")
        self.assertEqual([list(p.avoid_cells) for p in self.control.places], [[], ["cell-1"]])
        refused = next(sid for sid, cell in self.control.placed.items() if cell is self.cells[0])
        self.assertEqual(self.control.released, [refused])
        self.assertEqual(sb.exec("true").exit_code, 0)

    def test_three_refusing_cells_raise_the_last_refusal(self) -> None:
        for cell in self.cells:
            cell.refuse_create = (grpc.StatusCode.UNAVAILABLE, "DRAINING")
        with self.assertRaises(clovelly.CellDraining):
            self.env.sandbox("a")
        self.assertEqual(len(self.control.places), 3)
        self.assertEqual(len(self.control.released), 3)

    def test_wrong_token_is_unauthenticated(self) -> None:
        env = clovelly.Environment(
            "https://verifier.invalid", ENV_ID, self.env._ca,
            api_url=self.control.address, api_token="wrong", api_ca=self.env._api_ca,
        )
        self.addCleanup(env.close)
        with self.assertRaises(clovelly.Unauthenticated):
            env.sandbox("a")


class Reconnect(Fixture):
    def test_a_fresh_environment_reaches_the_same_sandbox(self) -> None:
        sb = self.env.sandbox("a")
        sb.files.write("/tmp/state", b"from the first process")

        other = environment(self.control)
        self.addCleanup(other.close)
        again = other.reconnect(sb.id, sb.key)

        self.assertEqual((again.id, again.cell_id, again.key), (sb.id, sb.cell_id, sb.key))
        self.assertEqual(again.files.read("/tmp/state"), b"from the first process")
        self.assertEqual(len(self.cell.peers), 2, "the new Environment has its own connection")
        self.assertEqual(set(again.timings), {"locate_ms", "connect_ms", "receipt_ms"})

    def test_reconnect_with_the_wrong_key_is_refused_by_the_cell(self) -> None:
        sb = self.env.sandbox("a")
        other = environment(self.control)
        self.addCleanup(other.close)
        with self.assertRaises(clovelly.PermissionDenied):
            other.reconnect(sb.id, "00" * 32)


class Concurrency(Fixture):
    STREAMS = 50

    def test_fifty_sandboxes_share_one_connection_with_streams_open_at_once(self) -> None:
        with futures.ThreadPoolExecutor(self.STREAMS) as pool:
            sandboxes = list(pool.map(lambda _: self.env.sandbox("a"), range(self.STREAMS)))
            # Every exec blocks in the cell until all fifty streams are open together.
            self.cell.barrier = threading.Barrier(self.STREAMS, timeout=20)
            results = list(pool.map(lambda sb: sb.exec(["wait-for-all"]), sandboxes))

        self.assertEqual([r.stdout.decode() for r in results], [sb.id for sb in sandboxes])
        self.assertEqual(self.cell.calls.count("Check"), 1, "verified once")
        self.assertEqual(len(self.cell.peers), 1, "one TLS connection for every stream")


if __name__ == "__main__":
    unittest.main()
