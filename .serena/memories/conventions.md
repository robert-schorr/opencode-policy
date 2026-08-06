# Code style
- ESM imports/exports with explicit `.js` extensions.
- Keep policy definitions in JSON; each unsafe rule has `id`, regex `pattern`, and `reason`; optional `flags` and `scope`.
- Rule order is significant: generic matcher returns the first matching rule.
- Use scoped matchers for input-type boundaries: `protectPath` for file paths, `protectCommand` for shell commands; prompt/query/text fields are injection-only.
- Tests keep a rule-id-to-fixture map and assert fixture IDs stay synchronized with the JSON rule set.
- Prefer focused regression tests for false positives alongside corpus coverage.
