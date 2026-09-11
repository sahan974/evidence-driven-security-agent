"""Exercise the real variant harness with passing and deliberately broken repairs."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HARNESS = Path(__file__).resolve().parents[1] / 'src' / 'python_patch_variants.py'
REPLAY = 'getattr(importlib.import_module("app"), "read_file")(candidate)'
SAFE = '''from pathlib import Path
def read_file(value):
    root = Path(__file__).resolve().parent
    target = (root / value).resolve()
    if not target.is_relative_to(root):
        raise ValueError('outside')
    return target.read_text()
'''


class VariantHarnessTests(unittest.TestCase):
    def execute_case(self, source, index):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'app.py').write_text(source, encoding='utf-8')
            return subprocess.run(
                [sys.executable, str(HARNESS), REPLAY, str(index)],
                cwd=directory, capture_output=True, text=True, timeout=15,
            )

    def test_containment_passes_all_distinct_variants(self):
        results = [self.execute_case(SAFE, index) for index in range(8)]
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('EDSA_VARIANT_BLOCKED', result.stdout)
        self.assertEqual(len({r.stdout.splitlines()[0] for r in results}), 8)

    def test_string_prefix_repair_fails_sibling_variant(self):
        broken = SAFE.replace('target.is_relative_to(root)', 'str(target).startswith(str(root))')
        self.assertNotEqual(self.execute_case(broken, 0).returncode, 0)

    def test_unrelated_crash_is_not_a_pass(self):
        broken = 'def read_file(value):\n    raise RuntimeError("broken")\n'
        self.assertNotEqual(self.execute_case(broken, 0).returncode, 0)

    def test_missing_file_is_not_a_pass(self):
        broken = 'def read_file(value):\n    raise FileNotFoundError(value)\n'
        self.assertNotEqual(self.execute_case(broken, 0).returncode, 0)


if __name__ == '__main__':
    unittest.main()
