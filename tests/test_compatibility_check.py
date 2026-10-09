import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check_compatibility.py"


class CompatibilityCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("compatibility_check", SCRIPT)
        cls.check = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.check)

    def test_registry_version_cannot_inject_commands_or_paths(self):
        for value in ["1.2.3", "0.153.0"]:
            self.assertEqual(self.check.stable_version(value), value)
        for value in ["1.2.3-beta", "$(id)", "../../bad", "01.2.3", "1.2"]:
            with self.assertRaises(ValueError):
                self.check.stable_version(value)

    def test_schema_comparison_ignores_documentation_but_detects_wire_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            baseline, candidate = root / "baseline", root / "candidate"
            baseline.mkdir()
            candidate.mkdir()
            (baseline / "Initialize.json").write_text('{"type":"object","description":"old"}')
            (candidate / "Initialize.json").write_text('{"type":"object","description":"new"}')
            self.assertEqual(self.check.schema_changes(baseline, candidate), [])
            (candidate / "Initialize.json").write_text('{"type":"array"}')
            self.assertEqual(self.check.schema_changes(baseline, candidate), ["changed: Initialize.json"])
            (candidate / "Added.json").write_text('{}')
            self.assertIn("added: Added.json", self.check.schema_changes(baseline, candidate))
            (candidate / "Initialize.json").unlink()
            self.assertIn("removed: Initialize.json", self.check.schema_changes(baseline, candidate))

    def test_empty_schema_bundle_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                self.check.schema_changes(pathlib.Path(temporary), pathlib.Path(temporary))

    def test_wire_fields_named_title_or_description_and_literal_defaults_are_preserved(self):
        original = {"description": "prose", "properties": {
            "title": {"type": "string", "description": "more prose"},
            "description": {"type": "integer"}},
            "default": {"description": "wire value"}}
        self.assertEqual(self.check.normalized(original), {
            "properties": {"title": {"type": "string"}, "description": {"type": "integer"}},
            "default": {"description": "wire value"}})

    def test_generated_manifest_matches_binary_and_version_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            binary = root / "rcodex-0.2.0-aarch64-apple-darwin"
            binary.write_bytes(b"example binary")
            manifest = self.check.release_manifest("0.2.0", "0.153.0", root)
            self.assertEqual(manifest["codex_versions"], ["0.153.0"])
            self.assertEqual(manifest["assets"][0]["size"], 14)
            self.assertEqual(len(manifest["assets"][0]["sha256"]), 64)
            with self.assertRaises(ValueError):
                self.check.release_manifest("0.3.0", "0.153.0", root)


if __name__ == "__main__":
    unittest.main()
