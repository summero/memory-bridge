"""Read-only guarantees: a search changes nothing on disk, and the plugin source has no write paths."""

import hashlib
import io
import os
import re
import tokenize
import unittest

from _support import REPO, Sandbox


def snapshot(base):
    state = {}
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            info = os.lstat(path)
            digest = None
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            state[os.path.relpath(path, base)] = (info.st_mode, info.st_size, info.st_mtime_ns, digest)
    return state


def code_lines(source):
    """Source lines with comments and string literals blanked, so prose cannot trip the scan."""
    lines = [list(line) for line in source.splitlines()]
    blank = {tokenize.COMMENT, tokenize.STRING}
    blank |= {getattr(tokenize, name) for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END")
              if hasattr(tokenize, name)}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type not in blank:
            continue
        (start_row, start_col), (end_row, end_col) = token.start, token.end
        for row in range(start_row, end_row + 1):
            line = lines[row - 1]
            first = start_col if row == start_row else 0
            last = end_col if row == end_row else len(line)
            for col in range(first, last):
                line[col] = " "
    return ["".join(line) for line in lines]


class ReadOnlyTests(unittest.TestCase):
    def test_tools_leave_memory_and_profile_unchanged(self):
        box = Sandbox()
        self.addCleanup(box.cleanup)
        box.write("projects/a.md", "# A\nalpha beta")
        box.write("projects/private/b.md", "alpha secret")
        box.write("inbox/c.md", "alpha inbox")
        box.write_policy(allow=["projects/**"], deny=["**/private/**"])
        before = snapshot(box.base)
        for query in ("alpha", "beta", "secret", "missing words"):
            box.search({"query": query})
        box.search({"query": "alpha"}, cron_flag="1")
        box.search({"query": "alpha", "agent": "x"})
        for doc_id in ("projects/a.md", "projects/private/b.md", "inbox/c.md", "projects/none.md", "../x.md"):
            box.read({"id": doc_id})
        box.read({"id": "projects/a.md"}, subagent=True)
        self.assertEqual(snapshot(box.base), before)

    def test_missing_policy_does_not_create_anything(self):
        box = Sandbox()
        self.addCleanup(box.cleanup)
        before = snapshot(box.base)
        box.search({"query": "alpha"})
        box.read({"id": "projects/a.md"})
        self.assertEqual(snapshot(box.base), before)

    def test_plugin_source_has_no_write_shell_or_eval_paths(self):
        forbidden = re.compile(
            r"subprocess|os\.system|os\.popen|os\.exec|os\.spawn|O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC"
            r"|\.write\(|\.write_text|\.write_bytes|unlink|rmdir|remove\(|rename|mkdir|makedirs|shutil"
            r"|chmod|chown|utime|truncate\(|ftruncate|os\.symlink|os\.link|plugin_data_dir|\beval\(|\bexec\(|socket|urllib"
            r"|(?<![\w.])open\(")
        sources = [p for p in REPO.glob("*.py")]
        self.assertTrue(sources)
        for path in sources:
            for number, line in enumerate(code_lines(path.read_text()), 1):
                self.assertIsNone(forbidden.search(line), f"{path.name}:{number}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
