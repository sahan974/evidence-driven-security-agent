"""Run the actual Node and Go verifiers against complete and incomplete repairs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'src'
NODE_REPLAY = '''const payload=control?'safe.txt':'../../etc/passwd';
const mod=await import("./app.mjs"); await mod["readUserFile"](payload);'''
GO_REPLAY = ['go', 'test', './...', '-run=^TestBoundary$', '-count=1', '-v']
GO_TEST = '''package fixture
import "testing"
func TestBoundary(t *testing.T) {
 path := "../../etc/passwd"
 content, err := ReadUserFile(path)
 _ = content; _ = err
}
'''
NODE_SAFE = '''import fs from 'node:fs/promises';
import path from 'node:path';
export async function readUserFile(value) {
 const root = process.cwd();
 let target = path.resolve(root, value);
 const inside = p => p === root || p.startsWith(root + path.sep);
 if (!inside(target)) throw new Error('outside');
 target = await fs.realpath(target);
 if (!inside(target)) throw new Error('outside');
 return fs.readFile(target, 'utf8');
}
'''
GO_SAFE = '''package fixture
import ("os"; "path/filepath"; "strings"; "fmt")
func ReadUserFile(value string) ([]byte, error) {
 root, err := os.Getwd(); if err != nil { return nil, err }
 target, err := filepath.Abs(value); if err != nil { return nil, err }
 inside := func(p string) bool { return p == root || strings.HasPrefix(p, root + string(filepath.Separator)) }
 if !inside(target) { return nil, fmt.Errorf("outside") }
 target, err = filepath.EvalSymlinks(target); if err != nil { return nil, err }
 if !inside(target) { return nil, fmt.Errorf("outside") }
 return os.ReadFile(target)
}
'''


class PolyglotPatchGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.go_helper = str(Path(cls.directory.name, 'gate'))
        subprocess.run(['go', 'build', '-o', cls.go_helper, str(SOURCE / 'go_patch_gate.go')],
                       check=True, timeout=180)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_gate(self, language, source, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if language.startswith('node'):
                filename = 'app.mts' if language == 'node-typescript' else 'app.mjs'
                if filename.endswith('.mts'):
                    source = source.replace('readUserFile(value)', 'readUserFile(value: string)')
                (root / filename).write_text(source)
                command = ['node', '--experimental-strip-types', '--input-type=module', '--eval',
                           (SOURCE / 'node_patch_gate.mjs').read_text(),
                           NODE_REPLAY.replace('app.mjs', filename), str(mode)]
            else:
                (root / 'go.mod').write_text('module fixture\n\ngo 1.24\n')
                (root / 'fixture.go').write_text(source)
                (root / 'fixture_test.go').write_text(GO_TEST)
                command = [self.go_helper, json.dumps(GO_REPLAY), str(mode),
                           json.dumps({'fixture_test.go': GO_TEST})]
            return subprocess.run(command, cwd=root, capture_output=True, text=True,
                                  timeout=180, env=os.environ.copy())

    def test_complete_repairs_pass_proof_and_all_eight_variants(self):
        for language, source in [('node', NODE_SAFE), ('node-typescript', NODE_SAFE), ('go', GO_SAFE)]:
            for mode in ['proof', *range(8)]:
                with self.subTest(language=language, mode=mode):
                    result = self.run_gate(language, source, mode)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    marker = 'EDSA_PATCH_BLOCKED' if mode == 'proof' else 'EDSA_VARIANT_BLOCKED'
                    self.assertIn(marker, result.stdout)

    def test_prefix_only_repair_fails(self):
        node = NODE_SAFE.replace('root + path.sep', 'root')
        go = GO_SAFE.replace('root + string(filepath.Separator)', 'root')
        for language, source in [('node', node), ('go', go)]:
            with self.subTest(language=language):
                self.assertNotEqual(self.run_gate(language, source, 0).returncode, 0)

    def test_rejecting_every_read_fails(self):
        node = "export function readUserFile() { throw new Error('outside'); }"
        go = 'package fixture\nimport "fmt"\nfunc ReadUserFile(s string)([]byte,error){return nil,fmt.Errorf("outside")}'
        for language, source in [('node', node), ('go', go)]:
            with self.subTest(language=language):
                self.assertNotEqual(self.run_gate(language, source, 0).returncode, 0)

    def test_missing_files_and_crashes_fail(self):
        node = NODE_SAFE.replace("throw new Error('outside')", "throw new TypeError('crash')")
        go = GO_SAFE.replace('fmt.Errorf("outside")', 'fmt.Errorf("%w", &os.PathError{Op:"open",Path:value,Err:os.ErrNotExist})')
        for language, source in [('node', node), ('go', go)]:
            with self.subTest(language=language):
                self.assertNotEqual(self.run_gate(language, source, 0).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
