"""Trusted patch gate, executed only in the existing Docker boundary."""
import ast
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


def target_from_replay(source):
    tree = ast.parse(source)
    targets = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != 'getattr' or len(node.args) != 2:
            continue
        module, function = node.args
        if (isinstance(module, ast.Call) and isinstance(module.func, ast.Attribute)
                and isinstance(module.func.value, ast.Name)
                and module.func.value.id == 'importlib'
                and module.func.attr == 'import_module' and len(module.args) == 1
                and isinstance(module.args[0], ast.Constant)
                and isinstance(function, ast.Constant)):
            targets.append((module.args[0].value, function.value))
    if len(targets) != 1 or not all(isinstance(x, str) for x in targets[0]):
        raise ValueError('Unsupported replay target: variant gate cannot run')
    return targets[0]


def main():
    module, function = target_from_replay(sys.argv[1])
    index = int(sys.argv[2])
    with tempfile.TemporaryDirectory(prefix='edsa-variants-') as temporary:
        parent = Path(temporary)
        root = parent / 'application'
        shutil.copytree(Path.cwd(), root, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        sibling = parent / 'application-sibling'
        sibling.mkdir()
        marker = 'EDSA_OUTSIDE_' + os.urandom(16).hex()
        outside = sibling / 'outside.txt'
        outside.write_text(marker, encoding='utf-8')
        (root / 'inside').mkdir(exist_ok=True)
        (root / 'outside-link').symlink_to(outside)
        (root / 'directory-link').symlink_to(sibling, target_is_directory=True)
        candidates = [
            '../application-sibling/outside.txt',
            str(outside),
            './../application-sibling/outside.txt',
            'inside/../../application-sibling/outside.txt',
            '../application-sibling/./outside.txt',
            '../application-sibling//outside.txt',
            'outside-link',
            'directory-link/outside.txt',
        ]
        if not 0 <= index < len(candidates):
            raise ValueError('Unsupported variant index')
        candidate = candidates[index]
        # Each probe must point to a real outside file before calling the target.
        assert (root / candidate).resolve() == outside
        assert outside.read_text(encoding='utf-8') == marker
        os.chdir(root)
        sys.path.insert(0, str(root))
        reader = getattr(importlib.import_module(module), function)
        try:
            result = reader(candidate)
        except (ValueError, PermissionError) as error:
            print(json.dumps({'index': index, 'candidate': candidate, 'blocked_by': type(error).__name__}))
            print('EDSA_VARIANT_BLOCKED')
            return
        # Missing files, import errors, and arbitrary crashes are failures.
        raise AssertionError(f'Variant {index} returned instead of rejecting: {result!r}')


if __name__ == '__main__':
    main()
