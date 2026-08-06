# Source map
- `src/opencode-policy.js`: plugin hooks; prompt-message rewriting and tool preflight enforcement.
- `src/opencode-policy-rules.js`: JSON loading, regex matching, scoped path/command matchers, prompt injection matcher.
- `src/policies/unsafe-tool-patterns.json`: unsafe rule corpus; optional `scope` limits rules to `path` or `command` while unscoped rules apply to commands.
- `src/policies/prompt-injection-patterns.json`: prompt injection corpus.
- `test/unsafe-tool-patterns.test.js`: unsafe matcher and plugin regressions.
- `test/prompt-injections.test.js`: prompt matcher and message-transform regressions.

# Invariants
- Tool file paths are checked with `protectPath`; shell commands are checked with `protectCommand`.
- Tool text, prompt, and query arguments are checked for prompt injection only, not unsafe shell patterns.
- User chat messages containing injection patterns are rewritten to the policy refusal text rather than rejected.
- Matching events are appended to `opencode-policy.log` beside the package root.
- Policy changes must preserve the rule-id fixture parity test and add regressions for false positives.