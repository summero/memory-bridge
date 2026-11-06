# Narrated screen recording: 75 seconds

Use a clean terminal with a neutral prompt; hide personal directory names,
notifications, history and unrelated tabs. Before recording, from the repository:

```sh
PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python"
"$PYTHON" -I -B -c 'import sys; print(sys.version); assert sys.version_info >= (3, 11)'
"$PYTHON" -I -B examples/demo.py --interactive
```

This existing interpreter was verified as 3.13.5; if your installation differs,
select an existing Python 3.11+ interpreter and verify its version first. Record
only the output area. The demo prints no absolute paths. It simulates runtime
contexts; no live Hermes agent or gateway runs. Expected refusal logs are suppressed
only around demo handler calls; production logging is unchanged.

| Time | Screen action | Narration |
| --- | --- | --- |
| 0–10 s | Show the synthetic-context banner. | “Memory Bridge gives a Hermes profile read-only access to selected Markdown notes. Everything here is invented. This demo simulates two runtime contexts; no live agent is running.” |
| 10–25 s | Enter: allowed search, then read returned ID. | “Profile A can search the Lantern Garden notes. Search returns a short snippet and a document ID. Reading that ID returns the permitted note.” |
| 25–40 s | Enter twice: denied and missing reads. | “The private folder is denied. A private note and a missing note get the same response. The tool does not reveal whether denied memory exists.” |
| 40–60 s | Enter: profile B search, then profile A read refusal. | “Profile B has a different policy: it can see the Paper Observatory. Profile A cannot retrieve that note even with its exact ID. Identity comes from the runtime context, never the tool arguments.” |
| 60–75 s | Show the cleanup message; narrate compatibility. | “These temporary profiles are now removed. Version 0.1 targets macOS with Python 3.11 or newer. Linux remains unsupported. This controls these two tools; it does not sandbox other Hermes tools.” |

Pause briefly on JSON; target 75 seconds, cap at 90. Do not imply this simulation
proves live routed gateway integration. No video is produced by the setup script.
