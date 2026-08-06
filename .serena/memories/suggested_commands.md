# Commands
- Run all tests: `npm test`.
- Run one test file: `node --test test/unsafe-tool-patterns.test.js` or `node --test test/prompt-injections.test.js`.
- Validate policy JSON: `node -e 'JSON.parse(require("fs").readFileSync("src/policies/unsafe-tool-patterns.json", "utf8")); console.log("valid json")'`.
- Check whitespace errors: `git diff --check`.
- Review worktree: `git status --short` and `git diff`.
- Avoid shell inspection of environment variables, secrets, tokens, private keys, or `.env` files; use repository-aware tools instead.
