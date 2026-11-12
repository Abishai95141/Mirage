# Technique rules

Layer 1 of the tagger (phase 2 spec, 2.4). Each rule maps an input, or a session's shape, to
an ATT&CK v20.1 technique. The engine (`mirage_intel.techniques`) compiles and applies them;
the policy service uses the same compiled rules to compute its last-tactic context feature.

`00-discovery.yaml` holds benign discovery reads as the starter and the format reference. The
offensive rules are produced separately — see `docs/handoffs/phase-2-technique-rules.md`.

Validate after editing: `uv run python -m mirage_intel.tagger lint`.
