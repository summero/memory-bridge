"""Public artifact hygiene: no personal paths, local usernames, emails, or credential-shaped strings."""

import re
import unittest

from _support import REPO

# Stable project-specific identity guard: independent of a CI account named root,
# runner, or another ordinary word used in documentation. Keep path/secret guards too.
PRIVATE_IDENTIFIERS = ("sum" + "mer",)
# The public GitHub owner contains the local username. Only the exact approved
# repository URL, optionally in its `.git` clone form, is exempt from the username
# check; any other occurrence of the owner name still fails.
GITHUB_OWNER = "sum" + "mer" + "o"
APPROVED_REPO_URL = "https://github.com/" + GITHUB_OWNER + "/memory-bridge"
APPROVED_REPO_URL_RE = re.compile(re.escape(APPROVED_REPO_URL) + r"(?:\.git)?(?![\w/-])")
COPYRIGHT_LINE_RE = re.compile(r"(?m)^Copyright \(c\) \d{4} [^\n]+$")
# Public files need no contact address, and a GitHub noreply address still identifies
# an account, so any address-shaped string in public file contents is rejected.
# Commit metadata is not file content and is verified separately before publishing.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
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


def privacy_findings(rel, text):
    """Return finding labels (never matched content) for one public file's text."""
    findings = []
    for marker in PERSONAL_PATHS:
        if marker in text:
            findings.append("personal path marker")
    # Copyright attribution is intentionally public; all other text is checked.
    identity_text = COPYRIGHT_LINE_RE.sub("", text) if rel == "LICENSE" else text
    identity_text = APPROVED_REPO_URL_RE.sub("", identity_text)
    for user in PRIVATE_IDENTIFIERS:
        if user.lower() in identity_text.lower():
            findings.append("local username")
    if EMAIL_RE.search(text):
        findings.append("email address")
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"matches {pattern.pattern}")
    return findings


class PublicArtifactTests(unittest.TestCase):
    def test_no_personal_paths_usernames_or_secrets(self):
        checked = 0
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            checked += 1
            rel = path.relative_to(REPO).as_posix()
            self.assertEqual(privacy_findings(rel, text), [], f"{rel} failed public artifact hygiene")
        self.assertGreater(checked, 5)


class PrivacyCheckRegressionTests(unittest.TestCase):
    def assertClean(self, text):
        self.assertEqual(privacy_findings("README.md", text), [], text)

    def assertFinding(self, text, label):
        self.assertIn(label, privacy_findings("README.md", text), text)

    def test_approved_repository_url_forms_pass(self):
        url = APPROVED_REPO_URL
        for text in (
            f"**Status:** v0.1.0. Public source: {url}. Not listed in the catalog.",
            f"- **GitHub:** The source is public at {url}. Clone it.",
            f"git clone {url}.git\ncd memory-bridge\n",
            f"See [the repository]({url}).",
            f"<{url}>",
        ):
            self.assertClean(text)

    def test_unexpected_username_occurrences_fail(self):
        user = PRIVATE_IDENTIFIERS[0]
        owner = GITHUB_OWNER
        for text in (
            f"Maintained by {owner}.",
            f"Ask {user} for access.",
            f"https://github.com/{owner}/other-repo",
            f"https://github.com/{owner}/memory-bridge-fork",
            f"{APPROVED_REPO_URL}/tree/main",
            f"http://github.com/{owner}/memory-bridge",
            "https://github.com/" + owner.capitalize() + "/memory-bridge",
            f"{APPROVED_REPO_URL} and also {owner}",
        ):
            self.assertFinding(text, "local username")

    def test_personal_paths_fail_even_with_approved_url(self):
        for marker in PERSONAL_PATHS:
            self.assertFinding(f"Clone {APPROVED_REPO_URL} into {marker}notes", "personal path marker")

    def test_email_addresses_fail_even_with_approved_url(self):
        for address in (
            "someone" + "@" + "me.com",
            "first.last" + "@" + "mail.example.org",
            "123+" + GITHUB_OWNER + "@" + "users.noreply.github.com",
        ):
            self.assertFinding(f"Source: {APPROVED_REPO_URL}. Contact {address}.", "email address")

    def test_secrets_fail_even_with_approved_url(self):
        token = "gh" + "p_" + "A" * 36
        findings = privacy_findings("README.md", f"{APPROVED_REPO_URL}.git {token}")
        self.assertTrue(any(label.startswith("matches") for label in findings))

    def test_license_copyright_exemption_is_limited_to_license(self):
        line = "Copyright (c) 2026 " + PRIVATE_IDENTIFIERS[0].capitalize() + " Example"
        self.assertEqual(privacy_findings("LICENSE", line), [])
        self.assertIn("local username", privacy_findings("README.md", line))


if __name__ == "__main__":
    unittest.main()
