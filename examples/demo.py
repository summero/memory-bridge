"""Disposable synthetic demo. No Hermes imports, launcher, network, or live profiles."""
from __future__ import annotations

import argparse
import importlib.util
import json
from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace


@contextmanager
def quiet_demo_logs(logger):
    """Suppress only this demo's logger and restore it even if a call fails."""
    previous = logger.disabled
    logger.disabled = True
    try:
        yield
    finally:
        logger.disabled = previous


def main():
    if sys.version_info < (3, 11):
        raise SystemExit('Python 3.11+ is required')
    if sys.platform != 'darwin':
        raise SystemExit('This demo is supported on macOS only')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interactive', action='store_true', help='pause between recording beats')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('memory_bridge_demo', repo / '__init__.py',
                                                submodule_search_locations=[str(repo)])
    plugin = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = plugin
    spec.loader.exec_module(plugin)
    # Fixed system-temp parent; no caller-selected destination or existing profile is accepted.
    with tempfile.TemporaryDirectory(prefix='memory-bridge-demo-', dir='/private/tmp') as scratch:
        base = Path(scratch)
        root = base / 'memory'
        root.mkdir(mode=0o700)
        for rel in ('projects/garden.md', 'decisions/watering.md', 'workflows/visit.md',
                    'private/plans.md', 'drafts/layout.md', 'profile-b/observatory.md'):
            target = root / rel
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_text((repo / 'examples/memory' / rel).read_text(encoding='utf-8'), encoding='utf-8')
            target.chmod(0o600)
        profiles = {}
        for label, allow in (('A', ['projects/**', 'decisions/**', 'workflows/**']),
                             ('B', ['profile-b/**'])):
            home = base / ('profile-' + label.lower())
            path = home / 'plugin-data/memory-bridge/policy.json'
            path.parent.mkdir(mode=0o700, parents=True)
            data = json.loads((repo / 'examples/policy.example.json').read_text())
            data.update(root=str(root), allow=allow)
            path.write_text(json.dumps(data), encoding='utf-8')
            path.chmod(0o600)
            profiles[label] = plugin.runtime.Probes(
                home_override=lambda h=home: str(h), secret_scope_home=lambda h=home: str(h),
                is_multiplexed=lambda: True, hermes_home=lambda h=home: h,
                is_delegated_child=lambda: False, cron_session_flag=lambda: '')
        ctx = SimpleNamespace(current_cron_execution=lambda: None)
        def show(label, profile, operation, arguments):
            if args.interactive:
                input('\nPress Enter for ' + label + ': ')
            with quiet_demo_logs(plugin.logger):
                result = json.loads(operation(arguments, ctx, profiles[profile]))
            print(label + ' — synthetic profile ' + profile)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return result
        print('Synthetic handler demonstration — no live Hermes session. Temporary fixtures only.')
        a = show('Allowed search', 'A', plugin.handle_search, {'query': 'garden'})
        assert a['ok'] and a['results']
        result = show('Read returned ID', 'A', plugin.handle_read, {'id': a['results'][0]['id']})
        assert result['ok']
        denied = show('Denied memory', 'A', plugin.handle_read, {'id': 'private/plans.md'})
        missing = show('Missing memory', 'A', plugin.handle_read, {'id': 'projects/missing.md'})
        assert denied == missing and denied['error'] == 'not_found_or_denied'
        b = show('Different profile policy', 'B', plugin.handle_search, {'query': 'observatory'})
        assert b['ok'] and len(b['results']) == 1
        isolated = show('Profile A cannot retrieve B memory', 'A', plugin.handle_read,
                        {'id': b['results'][0]['id']})
        assert isolated['error'] == 'not_found_or_denied'
    print('Demo verified; disposable fixtures removed.')


if __name__ == '__main__':
    main()
