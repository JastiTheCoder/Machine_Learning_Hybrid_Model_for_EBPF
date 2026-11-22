import json
import tempfile
import unittest
from pathlib import Path

import build_corpus_manifest


class CorpusManifestSafetyTests(unittest.TestCase):
    def test_categories_are_loaded_from_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packages.txt"
            path.write_text(
                "# --- Credential stealers ---\n"
                "example-stealer # steals credentials\n"
                "# --- Another category ---\n"
                "example-backdoor\n",
                encoding="utf-8",
            )
            categories = build_corpus_manifest.read_malware_categories(path)

        self.assertEqual(categories["example-stealer"], "credential stealers")
        self.assertEqual(categories["example-backdoor"], "another category")

    def test_suspicious_findings_set_behavior_flag(self):
        session = {
            "verdict": {
                "level": "suspicious",
                "findings": [{"rule_id": "PROC-001"}],
            },
            "process_tree": "npm(1)->bash(2)",
            "tcp": {"remote_ips": 1},
            "sensitive": {},
            "syscalls": {"process_ops": 2},
        }
        flags = build_corpus_manifest.behavior_flags(session)
        self.assertEqual(flags["shell_observed"], 1)
        self.assertEqual(flags["network_observed"], 1)
        self.assertEqual(flags["suspicious_or_worse"], 1)

    def test_npmrc_alone_is_not_sensitive_file_evidence(self):
        session = {
            "verdict": {"level": "benign", "findings": []},
            "process_tree": "",
            "tcp": {},
            "sensitive": {"npmrc_read": 1},
            "syscalls": {},
        }
        flags = build_corpus_manifest.behavior_flags(session)
        self.assertEqual(flags["sensitive_file_observed"], 0)

    def test_load_sessions_never_executes_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            path.write_text(json.dumps({
                "session_id": "npm-test",
                "package_name": "controlled-fixture",
                "label": 1,
                "verdict": {"level": "suspicious", "findings": []},
                "process_tree": "",
            }), encoding="utf-8")

            rows = build_corpus_manifest.load_sessions(Path(directory), 1)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["package_name"], "controlled-fixture")


if __name__ == "__main__":
    unittest.main()
