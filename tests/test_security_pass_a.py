"""Adversarial fixtures for Security Pass A; no live profiles or mounts."""
import dataclasses
import os
import stat
import unittest
from unittest import mock

from _support import FakeCtx, Sandbox, errors, policy, runtime, safe_fs


class SecurityPassATests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write('a.md', 'inside')
        self.box.write_policy()

    def test_root_ancestor_swapped_after_validation(self):
        parent = self.box.base / 'approved'
        parent.mkdir()
        root = parent / 'memory'
        root.mkdir()
        (root / 'a.md').write_text('inside')
        (self.box.outside / 'memory').mkdir()
        (self.box.outside / 'memory' / 'a.md').write_text('outside')
        parsed = policy.parse_policy(self.box.policy_data(root=str(root)))
        parent.rename(self.box.base / 'moved')
        parent.symlink_to(self.box.outside, target_is_directory=True)
        with self.assertRaises(errors.MemoryBridgeError):
            safe_fs.read_document(parsed.root, ('a.md',), 4096)

    def test_opened_root_ancestor_cannot_redirect_remaining_walk(self):
        parent = self.box.base / 'approved'
        parent.mkdir()
        root = parent / 'memory'
        root.mkdir()
        (root / 'a.md').write_text('inside')
        (self.box.outside / 'memory').mkdir()
        (self.box.outside / 'memory' / 'a.md').write_text('outside')
        original = os.open
        def swap(path, flags, *args, **kwargs):
            fd = original(path, flags, *args, **kwargs)
            if path == 'approved':
                parent.rename(self.box.base / 'moved')
                parent.symlink_to(self.box.outside, target_is_directory=True)
            return fd
        with mock.patch.object(safe_fs.os, 'open', side_effect=swap):
            self.assertEqual(safe_fs.read_document(str(root), ('a.md',), 4096), 'inside')
        self.assertTrue(parent.is_symlink())

    def test_policy_symlinked_parent_cannot_select_other_profile(self):
        other = Sandbox()
        self.addCleanup(other.cleanup)
        other.write_policy()
        parent = self.box.policy_file.parent
        parent.rename(parent.with_name('saved'))
        parent.symlink_to(other.policy_file.parent, target_is_directory=True)
        with self.assertRaises(errors.MemoryBridgeError):
            policy.load_policy(self.box.policy_file)

    def test_policy_opened_parent_substitution_stays_pinned(self):
        other = Sandbox()
        self.addCleanup(other.cleanup)
        other.write_policy()
        parent = self.box.policy_file.parent
        original = os.open
        def swap(path, flags, *args, **kwargs):
            fd = original(path, flags, *args, **kwargs)
            if path == 'memory-bridge':
                parent.rename(parent.with_name('saved'))
                parent.symlink_to(other.policy_file.parent, target_is_directory=True)
            return fd
        with mock.patch.object(policy.os, 'open', side_effect=swap):
            self.assertEqual(policy.load_policy(self.box.policy_file).root, str(self.box.root))
        self.assertTrue(parent.is_symlink())

    def test_policy_writable_ancestors_rejected(self):
        for parent in (self.box.base, self.box.home, self.box.policy_file.parent.parent, self.box.policy_file.parent):
            for mode in ((0o777, 0o770, 0o1777) if os.getuid() != 0 else (0o777, 0o770)):
                with self.subTest(parent=parent.name, mode=mode):
                    os.chmod(parent, mode)
                    try:
                        with self.assertRaises(errors.MemoryBridgeError):
                            policy.load_policy(self.box.policy_file)
                    finally:
                        os.chmod(parent, 0o700)

    def test_policy_wrong_owner_ancestor_rejected(self):
        original = os.fstat
        target = os.stat(self.box.home).st_ino
        def wrong_owner(fd):
            info = original(fd)
            if info.st_ino == target:
                values = list(info)
                values[4] = os.getuid() + 12345
                return os.stat_result(values)
            return info
        with mock.patch.object(policy.os, 'fstat', side_effect=wrong_owner):
            with self.assertRaises(errors.MemoryBridgeError):
                policy.load_policy(self.box.policy_file)

    def test_matching_profile_signals(self):
        caller = runtime.resolve_caller(FakeCtx(), self.box.probes(scope_home=str(self.box.home)))
        self.assertEqual(caller.home, self.box.home)

    def test_conflicting_profile_signals(self):
        for multiplexed in (False, True):
            with self.subTest(multiplexed=multiplexed):
                with self.assertRaises(errors.MemoryBridgeError):
                    runtime.resolve_caller(FakeCtx(), self.box.probes(
                        scope_home=str(self.box.outside), multiplexed=multiplexed))

    def test_override_must_agree_with_resolved_home(self):
        probes = dataclasses.replace(self.box.probes(), home_override=lambda: str(self.box.outside))
        with self.assertRaises(errors.MemoryBridgeError):
            runtime.resolve_caller(FakeCtx(), probes)

    def test_relative_scope_signal_rejected_even_with_override(self):
        with self.assertRaises(errors.MemoryBridgeError):
            runtime.resolve_caller(FakeCtx(), self.box.probes(scope_home='relative'))

    def test_missing_profile_signals(self):
        for override, scope, multiplexed, accepted in (
            (False, None, False, True), (False, None, True, False),
            (True, None, True, True), (False, str(self.box.home), True, True),
        ):
            with self.subTest(override=override, scope=scope, multiplexed=multiplexed):
                probes = self.box.probes(override=override, scope_home=scope, multiplexed=multiplexed)
                if accepted:
                    self.assertEqual(runtime.resolve_caller(FakeCtx(), probes).home, self.box.home)
                else:
                    with self.assertRaises(errors.MemoryBridgeError):
                        runtime.resolve_caller(FakeCtx(), probes)

    def test_empty_profile_signal_is_not_silently_ignored(self):
        for field in ('home_override', 'secret_scope_home'):
            probes = dataclasses.replace(self.box.probes(), **{field: lambda: ''})
            with self.subTest(field=field), self.assertRaises(errors.MemoryBridgeError):
                runtime.resolve_caller(FakeCtx(), probes)

    def test_override_expansion_agrees_with_hermes(self):
        probes = dataclasses.replace(self.box.probes(scope_home=str(self.box.home)),
                                     home_override=lambda: '$MB_TEST_PROFILE')
        with mock.patch.dict(os.environ, {'MB_TEST_PROFILE': str(self.box.home)}):
            self.assertEqual(runtime.resolve_caller(FakeCtx(), probes).home, self.box.home)

    def test_final_file_device_mismatch_rejected_before_read(self):
        original = os.fstat
        def different_device(fd):
            info = original(fd)
            if stat.S_ISREG(info.st_mode):
                values = list(info)
                values[2] += 1
                return os.stat_result(values)
            return info
        with mock.patch.object(safe_fs.os, 'fstat', side_effect=different_device):
            with mock.patch.object(safe_fs, 'read_bounded', side_effect=AssertionError('must not read')):
                self.assertIsNone(safe_fs.read_document(str(self.box.root), ('a.md',), 4096))
                stats = safe_fs.ScanStats()
                self.assertEqual(list(safe_fs.iter_documents(str(self.box.root), lambda p: True,
                    lambda p: True, max_file_bytes=4096, max_entries=10, max_depth=8, stats=stats)), [])
