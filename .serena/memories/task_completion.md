# Completion checks
- Run `npm test`; all Node test cases must pass.
- Validate edited policy JSON parses successfully.
- Run `git diff --check`.
- Inspect `git status --short` and the complete intended diff.
- For policy edits, confirm no unintended rule-id fixture drift and add/verify regression coverage for safe commands and metadata.
