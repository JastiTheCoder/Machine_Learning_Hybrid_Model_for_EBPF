import unittest

import pandas as pd

import train_native


class NativeTrainerSafetyTests(unittest.TestCase):
    def test_family_group_keeps_scoped_package_versions_together(self):
        self.assertEqual(
            train_native.family_group_key("@scope/example@1.2.3"),
            "@scope/example",
        )
        self.assertEqual(
            train_native.family_group_key("lodash@4.17.21"),
            "lodash",
        )

    def test_family_group_keeps_unversioned_name(self):
        self.assertEqual(
            train_native.family_group_key("controlled-fixture"),
            "controlled-fixture",
        )

    def test_leakage_audit_rejects_verdict_feature(self):
        df = pd.DataFrame({
            "verdict_score": [10, 20],
            "feature_a": [1, 2],
        })
        with self.assertRaisesRegex(RuntimeError, "Leakage audit failed"):
            train_native.audit_features(df, ["verdict_score", "feature_a"])

    def test_leakage_audit_accepts_numeric_feature_only(self):
        df = pd.DataFrame({
            "feature_a": [1, 2],
            "feature_b": [3, 4],
        })
        train_native.audit_features(df, ["feature_a", "feature_b"])


if __name__ == "__main__":
    unittest.main()
