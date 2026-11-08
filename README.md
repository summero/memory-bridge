# Memory Bridge

Memory Bridge is a Hermes Agent plugin for read-only, permission-aware search and reading over a folder of Markdown notes, such as a team's shared agent memory. An operator decides which files each Hermes profile may search and read. The model can only ask questions; it cannot widen what it sees.

**Status:** v0.1.0. Public source: https://github.com/summero/memory-bridge. Not listed in the Hermes plugin catalog and not installable by catalog name. Two tools, `memory_bridge_search` and `memory_bridge_read`. Tested against synthetic fixtures only. See [Availability](#availability) and [Validation status](#validation-status).

## Availability

- **GitHub:** The source is public at https://github.com/summero/memory-bridge. Clone it and record the commit you install.
- **Hermes plugin catalog:** Not accepted or listed. Catalog listing is a separate maintainer review of a pinned commit. Until a catalog entry is confirmed, install from source using the steps below.

## Compatibility and dependencies

macOS-first, Python 3.11+; the unit suite has passed on Python 3.13.5.
Linux is experimental
and unsupported pending validation on a real Linux filesystem. Other platforms
are unsupported. The plugin uses the Python standard library and the operating
system ACL API; no third-party Python dependencies are required by the plugin.
Hermes itself has its own dependencies.

Previously verified Hermes: **v0.22.7**, commit
`b200f5bc60e31588ba2cb60e288029c4a54ba5fa`.
Latest registry-level validation target: **v0.23.0**, tag commit
`2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`; this
is not a full re-verification of the v0.22.7 record.
The manifest minimum is `>=0.22.7`; this is not a guarantee of compatibility
with every later release. Re-run isolated checks after upgrades.

## Validation status

Completed:

- Unit suite on Python 3.13.5: 170 tests passed. The suite blocks every Hermes import, so it tests the plugin alone and does not show Hermes compatibility.
- Official `hermes plugins doctor . --ci` exited 0 (2 tools, 0 hooks registered, no warnings). The separate `validate_plugin_dir` check reports one warning, for the flagged internal dependency at `runtime.py:46` described below.
- Registry-level integration test: with a temporary `HERMES_HOME` and synthetic memory only, tool calls through Hermes's real tool registry gave correct results for authorized search/read, denied and missing paths, traversal, absolute paths, symlink escape, and a second home with no policy.

Simulated only:

- Cron and delegated-subagent refusal were checked by setting the cron session flag and the delegated-child environment marker by hand. This shows the plugin refuses when those signals are present. It does not show that Hermes's real scheduler or `delegate_task` sets them. Real scheduler and delegation execution remain **unverified**.

Not tested:

- No model-driven session has been run; the registry-level test is not an end-to-end session.
- Memory Bridge has not been installed into a real Hermes profile, and behavior with a running gateway is unknown.
- The temporary `HERMES_HOME` did not give complete write isolation: Hermes still wrote small files (such as bytecode and lease files) in the real installation. Do not treat the test as proof of zero side effects.

Hermes public plugin interfaces include `ctx.register_tool` and
`ctx.current_cron_execution`. The tested admission checker also recognizes
`hermes_constants`, `agent.secret_scope`, and `gateway.session_context` as public
import surfaces. This classification is not a promise that every helper's runtime
semantics will remain unchanged. The exact dependencies are:

- `hermes_constants.get_hermes_home` and `get_hermes_home_override`: profile identity.
- `agent.secret_scope.current_secret_scope_home` and `is_multiplex_active`: routed profile context.
- **Flagged internal dependency:** `agent.delegation_context.is_delegated_child_process_context` supplies subagent detection and generates the catalog-rule-9 warning.
- `gateway.session_context.get_session_env`: cron session flag.
- `PluginContext.current_cron_execution`: additional cron detection.

Missing helpers or conflicting identity signals fail closed. Semantic changes
in Hermes still require compatibility review; import success alone is insufficient.
Only the two tools are registered through `ctx.register_tool`. This is a standalone
tool plugin, not a replacement for Hermes's memory provider.

## How it decides access

Each call goes through the same steps, and any failure stops the call with a generic error.

1. **Who is calling.** Memory Bridge reads the calling profile from the runtime context Hermes binds for each turn. Tool arguments never identify the caller. On a gateway serving several profiles, a call that does not name its profile is refused.
2. **What the operator allows.** The policy is read fresh from `<profile home>/plugin-data/memory-bridge/policy.json` on every call, so edits and revocations apply immediately. A missing, unreadable, malformed, group/world-writable, or ACL-writable policy denies everything.
3. **What kind of run it is.** Cron jobs and delegated subagents are refused unless the policy opts in with `allow_cron` or `allow_subagents`.
4. **Which files.** Only `.md` files whose root-relative path matches an `allow` pattern and no `deny` pattern are opened. Deny always wins.

## Policy

```json
{
  "version": 1,
  "root": "/absolute/canonical/path/to/shared-memory",
  "allow": ["projects/**", "decisions/**"],
  "deny": ["**/private/**"],
  "allow_cron": false,
  "allow_subagents": false,
  "limits": {"max_results": 10, "snippet_chars": 300}
}
```

- `root` must be an absolute path with no symlinks anywhere in it (`realpath(root) == root`).
- Patterns are root-relative and match path segments without regard to case. `*` matches within one segment and `**` matches any number of segments. Patterns may not be absolute or contain `..`.
- `limits` defaults are: `max_results` 10, `default_results` 5, `snippet_chars` 300, `total_chars` 4000, `max_file_bytes` 262144, `max_entries` 2000, `max_depth` 8, `read_chars` 8000.
- Hard ceilings above the defaults: `max_file_bytes` 1048576, `max_entries` 10000, `max_depth` 16. Other ceilings equal the defaults listed above. `default_results` must not exceed `max_results`; `total_chars` must be at least `snippet_chars`.
- Unknown keys are an error. The file must be owned by the user running Hermes and must not be group- or world-writable.

A full example is in [examples/policy.example.json](examples/policy.example.json).

## Tools

`memory_bridge_search(query, limit)` returns up to `limit` results (default 5, at most 10), each with a document `id` (root-relative path), an optional `title` from the first heading, and a short `snippet`.

With the bundled synthetic notes in `examples/memory` and the example policy, a search for `garden` returns:

```json
{"ok": true, "results": [
  {"id": "decisions/watering.md", "title": "Watering decision", "snippet": "# Watering decision Synthetic memory: water the garden at dawn using collected rainwater."},
  {"id": "projects/garden.md", "title": "Lantern Garden", "snippet": "# Lantern Garden Synthetic memory: plant blue asters beside the east gate. Opening day is April 12."},
  {"id": "workflows/visit.md", "title": "Garden visit", "snippet": "# Garden visit Synthetic memory: bring a notebook and count the blue asters."}
], "truncated": false}
```

`memory_bridge_read(id)` returns one document by the `id` that search returned. Content is capped at `read_chars` characters (8000 at most). A capped document ends with a visible truncation note and has `"truncated": true`.

```json
{"ok": true, "id": "projects/garden.md", "content": "# Lantern Garden\n\nSynthetic memory: plant blue asters beside the east gate. Opening day is April 12.\n", "truncated": false}
```

Read applies the same policy, depth, and filesystem trust rules as search; subsequent changes can revoke access. A document that is denied, outside the allow list, deeper than `max_depth`, a symlink, a hard link, oversized, binary, or simply missing all produce the same `not_found_or_denied` response.

Errors use three codes with fixed messages: `invalid_request` (bad arguments, with a hint about the argument), `unavailable` (no trustworthy context, no valid policy, a refused run kind, an unreadable root, or a scan that hit the hard ceiling), and `not_found_or_denied` (read only). Errors never include paths or system error text.

For **search**, the single `truncated` flag combines different limits:

- Result-count and total-response-character limits omit query-matching documents
  already read and accepted during this scan. Per-snippet clipping alone does not
  set the flag.
- Scan entry/byte limits stop at policy-matching candidate filenames before proving
  they are trusted, readable documents or query matches.
- Depth look-ahead finds policy-matching candidate names below the depth boundary
  through trusted directories. It does not read or validate the final file's
  contents or trustworthiness, or establish a query match.

Thus `truncated=true` does not always promise another readable matching result.
For **read**, the flag specifically means the returned text was shortened.

## Filesystem safety

- Root and policy paths are traversed from an open filesystem-root descriptor, one component at a time, with `O_DIRECTORY | O_NOFOLLOW` on macOS and Linux. The `realpath` policy check is only an early validation; subsequent opens do not depend on it for safety.
- **One trust rule for every path Memory Bridge uses.** Every component from `/` down to the policy directory, from `/` down to the memory root *including the root itself*, and every directory traversed below the root must be a directory owned by root or the Hermes user, not group- or world-writable, and without an ACL that grants write-class access to anyone but that user or root. The policy file gets the same ACL check. Every Markdown file must pass the owner, mode, and ACL checks on its open descriptor before any content is read. A writable ancestor could otherwise be used to swap in attacker-controlled content, so an untrusted root path is refused with `unavailable`; an untrusted directory or file below the root is skipped, like a symlink, and read treats it as not found.
- **System temporary directories.** The only exception to the writable rule is a root-owned sticky directory that is exactly `/private/tmp`, `/private/var/tmp`, `/tmp`, or `/var/tmp`, **and only as an intermediate ancestor**. The system temp directory itself is refused as a memory root or policy directory; a directory you own beneath it is fine. Sticky stops other users replacing the *next* entry, and that entry is owner-checked in turn, so synthetic fixtures under those directories work. Any other sticky or writable directory, whoever owns it, is refused.
- **ACLs.** The ACL is read from the open descriptor (no path race). On macOS it comes from `acl_get_fd_np`; on Linux from the `system.posix_acl_access` attribute, whose structure is validated (version, tags, permission bits, required and ordered entries) before it is trusted. Only a missing attribute means "no ACL"; `ENOTSUP`/`EOPNOTSUPP` mean the filesystem cannot answer and the path is refused. Any `allow` entry with a write-class permission (write, append, add_file, add_subdirectory, delete, delete_child, writeattr, writeextattr, writesecurity, chown) for anyone but the running user or root is refused; `deny` entries never excuse an allow. If the ACL cannot be read or parsed, or the platform has no inspector, the path is refused rather than trusted by mode bits.
- Symlinked profile homes, policy parents, and memory roots are rejected.
- Independently supplied profile override and secret-scope home signals must agree. Relative, empty, or conflicting identities fail closed; model arguments never supply identity.
- Every directory and file is opened relative to an already-open parent with `O_NOFOLLOW`, and checked with `fstat` on the open descriptor. A symlink or special file swapped in after listing is refused at open time.
- Symlinks, hidden names, names outside `[A-Za-z0-9._-]`, non-Markdown files, FIFOs and devices, hard-linked files, other filesystems, oversized files, binary files, and invalid UTF-8 are skipped.
- Both descendant directories and final files must have the approved root descriptor’s `st_dev`; a mismatched file is rejected before content is read.
- Denied files and fully denied directories are filtered by name and never opened.
- The plugin only reads. It never writes, creates directories, runs shell commands, or opens network connections.

## Install and configure (operator steps)

1. Install Hermes v0.22.7 or newer with Python 3.11+. Clone the source and
   review the commit you use. Installing by catalog name is not available.

   ```sh
   git clone https://github.com/summero/memory-bridge.git
   cd memory-bridge
   git rev-parse HEAD
   ```
2. Copy the plugin into the selected Hermes installation's user plugin directory
   as `plugins/memory-bridge/` (normally `~/.hermes/plugins/memory-bridge/`). Keep
   `plugin.yaml`, `__init__.py`, `acl.py`, `errors.py`, `policy.py`, `reader.py`,
   `runtime.py`, `safe_fs.py`, and `search.py` together. Include LICENSE and README.
   Leave out `tests/` and `examples/`; they are for review and the synthetic demo,
   and the plugin does not use them at runtime.
3. In **each calling profile's home**, create
   `plugin-data/memory-bridge/policy.json` from
   [the example](examples/policy.example.json). Replace `root` with the canonical
   absolute path of a dedicated directory you own. Start with synthetic notes.
   Do not place policy in the memory directory or supply it through tool arguments.
4. Make the policy file owner-readable/writable only (`chmod 600`), and use
   owner-only directories (`chmod 700`) for new policy and memory directories.
   All ancestors and descendants must meet the trust rules below. Inspect ACLs
   with `ls -lde`; chmod alone does not remove ACL grants. Do not recursively
   change permissions on unrelated directories to make a policy load.
5. In the selected Hermes profile, run `hermes plugins enable memory-bridge`,
   then restart the relevant Hermes session using its normal operator workflow.
   Confirm both tools appear. Search for `garden`, then read a returned id.
6. Verify an explicitly denied path returns `not_found_or_denied`. To revoke
   access, remove the policy or narrow its allow list; it is reloaded each call.

These are installation instructions for the operator, not actions performed by
the demo. Keep cron and subagent access disabled unless deliberately approved.
A generic `unavailable` means context, policy, or root trust could not be established;
operator logs contain short reason codes, never document paths or contents.

## Synthetic demo

From this directory, with a Python 3.11+ interpreter:

```sh
# Set this to an existing interpreter; this conventional Hermes venv was verified.
PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
"$PYTHON" -I -B -c 'import sys; print(sys.version); assert sys.version_info >= (3, 11)'
"$PYTHON" -I -B examples/demo.py
"$PYTHON" -I -B examples/demo.py --interactive
```

The setup/runner creates fresh owner-controlled fixtures and two synthetic profile
policies beneath `/private/tmp`, exercises the real plugin handlers, and removes
its temporary tree on normal exit or interruption. It accepts no destination path,
reads only the bundled synthetic examples, and never imports or launches Hermes,
reads live profiles, or changes live configuration. Abrupt process termination may
leave its uniquely named temporary directory for manual cleanup.

[The 75-second narration](examples/DEMO.md) labels the simulated runtime context
explicitly. This demonstrates handler policy isolation, not a live gateway session.

## Threat model and disclosure

The operator, root, and processes running as the operator are trusted. The plugin
protects its own returned data against model-supplied path/identity tricks,
untrusted filesystem writers, unsafe links, and ambiguous runtime context.
It does not sandbox the host agent or authenticate note contents against the owner.
Treat retrieved text as untrusted context, not instructions to execute.

**Filesystem disclosure:** reads its profile policy and operator-approved Markdown
outside the plugin data directory, plus filesystem metadata/ACLs and bounded
candidate directory listings. No network calls, credentials, telemetry, shell
commands, background workers, or writes occur in tool handlers. The demo setup
writes only its disposable synthetic tree. Other Hermes tools and plugins retain
their own authority; returned text may enter histories, hooks, or downstream memory.

## Limits of the protection

- **Mount and operator trust.** Device checks do not detect same-filesystem bind mounts or other mounts preserving `st_dev`. Privileged mount changes and malicious processes running as the Hermes user are outside this boundary.
- **Shared, group-writable roots are refused (v0.1).** A memory root that teammates write through group permissions fails the trust rule. Make the root owner-writable only, or wait for an explicit operator opt-in if that is wanted.
- **ACL support.** macOS ACLs are exercised by tests against synthetic paths. The Linux POSIX-ACL parser is unit-tested on synthetic data and has not been run on a real Linux filesystem; filesystems without ACL support (for example some network or FAT mounts) are refused. Other platforms are refused. Named-user or group write entries are refused even if a mask would neutralize them. Mounts below the root that keep the same device id are not detected.

- **Memory Bridge controls what it returns, not what the agent can reach.** It does not sandbox Hermes. Other tools such as file reading or the terminal can still read the same files if the profile allows them.
- **Returned text can be copied elsewhere.** Search results land in the Hermes session history and are visible to other plugins' tool hooks. A memory provider that retains assistant replies may store anything the assistant quotes. Point Memory Bridge only at content you are comfortable seeing in those places.
- **Profile detection depends on Hermes context semantics.** If a Hermes release moves them, Memory Bridge refuses every call until it is updated.
- **Scan limits count policy-matching candidates.** `max_entries` and the scan byte budget apply to policy-matching Markdown candidates in sorted order, so denied files cannot change results or the `truncated` flag. A separate hard ceiling of 50,000 raw directory entries refuses the whole search with `unavailable`. A very large denied area can therefore cause a refusal, though the refusal reveals nothing about what it contains.
- **Every byte read is charged.** The 16 MiB scan budget counts bytes read from allowed-name files even when the content is then rejected as binary or invalid UTF-8. Files refused by metadata (size, link count, device) are never read and cost nothing. Bytes are charged chunk by chunk, so a read that fails part-way still counts what it consumed. The budget is checked before each file, so the last file read may overshoot it by up to `max_file_bytes`.
- **Depth truncation is name-based.** At the depth limit, `truncated` is set only if an allowed Markdown name exists below it; denied or filtered names cannot change it. The look-ahead lists names only, charges the entry ceiling, enters only trusted directories, and follows the read tool's id limits (16 segments, 512 characters), so deep denied, empty, or unreadable-id trees never raise the flag.
- **Search ids have valid read syntax.** Search skips documents whose id exceeds 512 characters or 16 segments, so every returned id passes read request validation. Later policy changes, file changes, or trust failures can still refuse a read.
- **Refusal logs and timing.** Read logs one reason for every refusal, so operator logs do not distinguish missing from denied. A policy-denied id returns before any filesystem access, so a caller with a precise clock could still see a small timing difference; Memory Bridge does not try to hide it.
- **Profile identity.** A secret-scope home with no home override is accepted only if it equals the home Hermes resolves for the call (`get_hermes_home()`). Ordinary CLI calls, routed gateway turns, and delegated profile scopes bind compatibly (checked against Hermes's own context helpers in an isolated process); a foreign owner scope bound alone is refused.

## Development

Tests use only the Python standard library and build synthetic fixtures in temporary directories:

```bash
# Use Python 3.11 or newer, matching Hermes. macOS's /usr/bin/python3 is 3.9 and is too old:
# the suite refuses to run on it.
PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
"$PYTHON" -I -B -c 'import sys; print(sys.version); assert sys.version_info >= (3, 11)' 
"$PYTHON" -I -B -m unittest discover -s tests -t tests
```

## Package and catalog preparation

MIT licensed; see [LICENSE](LICENSE). The GitHub repository makes the source public. A Hermes catalog listing is a separate step that needs maintainer acceptance of a pinned commit, and it has not been confirmed. See [Availability](#availability).

## Hermes upgrade checklist

The items below are requirements for future upgrades, not a record of completed tests. See [Validation status](#validation-status) for what has been run so far.

Before enabling Memory Bridge on an upgraded Hermes:

1. Record the new Hermes release/commit and actual Python version.
2. Run the complete synthetic suite, Plugin Doctor, and non-installing validation
   in an isolated environment; inspect all warnings.
3. **Renew subagent-refusal testing against the upgraded Hermes runtime helpers.**
   Confirm default refusal for delegated child contexts, explicit opt-in behavior,
   and fail-closed handling of missing helpers. Unit-test mocks alone are insufficient.
4. Recheck ordinary CLI and two-profile routed identity binding and cron refusal
   using synthetic contexts. Re-run the demo without real memory.
5. Review changes to the flagged delegation-context API and public context helpers.
   Keep the plugin disabled if identity or run-kind semantics cannot be verified.
