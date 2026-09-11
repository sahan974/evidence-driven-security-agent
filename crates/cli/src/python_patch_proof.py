"""Run the admitted proof while distinguishing rejection from broken execution."""
import ast
import sys

tree = ast.parse(sys.argv[1])
handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
if len(handlers) != 1 or handlers[0].name != 'error':
    raise ValueError('Unsupported proof exception contract')
handlers[0].body = ast.parse('''
if isinstance(error, (ValueError, PermissionError)):
    print('EDSA_PATCH_BLOCKED')
else:
    raise
''').body
ast.fix_missing_locations(tree)
exec(compile(tree, '<admitted-proof>', 'exec'))
