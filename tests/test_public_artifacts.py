"""Public artifact hygiene: no personal paths, local usernames, or credential-shaped strings."""

import re
import unittest

from _support import REPO

# Stable project-specific identity guard: independent of a CI account named root,
# runner, or another ordinary word used in documentation. Keep path/secret guards too.
PRIVATE_IDENTIFIERS = ("sum" + "mer",)
SKIP_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache"}
PERSONAL_PATHS = [
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "C:" + "\\Users",
    "~" + "/Projects",
    "Projects" + "/memory",
]
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]


def public_files():
    for path in sorted(REPO.rglob("*")):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.relative_to(REPO).parts):
            yield path


class PublicArtifactTests(unittest.TestCase):
    def test_no_personal_paths_usernames_or_secrets(self):
        checked = 0
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            checked += 1
            rel = path.relative_to(REPO)
            for marker in PERSONAL_PATHS:
                self.assertNotIn(marker, text, f"{rel} contains a personal path marker")
            for user in PRIVATE_IDENTIFIERS:
                # Copyright attribution is intentionally public; all other text is checked.
                identity_text = (re.sub(r"(?m)^Copyright \(c\) \d{4} [^\n]+$", "", text)
                                 if rel.as_posix() == "LICENSE" else text)
                self.assertNotIn(user.lower(), identity_text.lower(), f"{rel} contains the local username")
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(pattern.search(text), f"{rel} matches {pattern.pattern}")
        self.assertGreater(checked, 5)


if __name__ == "__main__":
    unittest.main()
