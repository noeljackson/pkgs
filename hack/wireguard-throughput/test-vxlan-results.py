#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject incomplete or falsely successful nested-tunnel receipts."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("run-vm.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def transcript(batched):
    parts = []
    for wire in (4, 6):
        for vxlan, checksums in [(4, ("udpcsum", "noudpcsum")), (6, ("default6",))]:
            for checksum in checksums:
                for inner in (4, 6):
                    for direction in ("forward", "reverse"):
                        case = f"wg{wire}-vx{vxlan}-{checksum}-tcp{inner}-{direction}"
                        for when, packets, count in [("before", 10, 1000), ("after", 12 if batched else 30, 29040)]:
                            value = [dict(ifname="wg0", stats64=dict(tx=dict(packets=packets, bytes=count)))]
                            parts += [f"BEGIN_LINK {case} {when}", json.dumps(value), "END_LINK"]
                        value = dict(end=dict(sum_received=dict(bytes=1000, seconds=5, bits_per_second=1600)))
                        parts += [f"BEGIN_VXLAN {case} duration=5", json.dumps(value), "END_VXLAN"]
    return "\n".join(parts + ["VXLAN_FIXTURE_COMPLETE"])


class Results(unittest.TestCase):
    def test_complete_candidate_matrix(self):
        self.assertEqual(len(runner.parse_vxlan_results(transcript(True), "enabled")), 24)

    def test_complete_baseline_matrix(self):
        self.assertEqual(len(runner.parse_vxlan_results(transcript(False), "disabled")), 24)

    def test_previous_behavior_fails_candidate_acceptance(self):
        with self.assertRaisesRegex(ValueError, "batching missing"):
            runner.parse_vxlan_results(transcript(False), "enabled")

    def test_baseline_cannot_silently_contain_candidate(self):
        with self.assertRaisesRegex(ValueError, "already batches"):
            runner.parse_vxlan_results(transcript(True), "disabled")

    def test_missing_transfer(self):
        text = transcript(True)
        start = text.index("BEGIN_VXLAN ")
        end = text.index("END_VXLAN", start) + len("END_VXLAN")
        with self.assertRaisesRegex(ValueError, "incomplete VXLAN matrix"):
            runner.parse_vxlan_results(text[:start] + text[end:], "enabled")

    def test_duplicate_transfer(self):
        text = transcript(True)
        chunk = text[text.index("BEGIN_VXLAN "):text.index("END_VXLAN")]
        with self.assertRaisesRegex(ValueError, "duplicate VXLAN transfer"):
            runner.parse_vxlan_results(text + "\n" + chunk, "enabled")

    def test_counter_regression(self):
        text = transcript(True).replace('"packets": 12', '"packets": 9', 1)
        with self.assertRaisesRegex(ValueError, "non-progressing"):
            runner.parse_vxlan_results(text, "enabled")

    def test_wrong_counter_interface(self):
        with self.assertRaisesRegex(ValueError, "wrong VXLAN counter interface"):
            runner.parse_vxlan_results(transcript(True).replace('"wg0"', '"vx0"', 1), "enabled")

    def test_short_transfer(self):
        with self.assertRaisesRegex(ValueError, "incomplete VXLAN transfer"):
            runner.parse_vxlan_results(transcript(True).replace('"seconds": 5', '"seconds": 1', 1), "enabled")

    def test_guest_failure(self):
        with self.assertRaisesRegex(ValueError, "did not finish"):
            runner.parse_vxlan_results(transcript(True).replace("VXLAN_FIXTURE_COMPLETE", ""), "enabled")


if __name__ == "__main__":
    unittest.main()
