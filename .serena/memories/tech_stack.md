# Runtime and package
- Node.js ESM package; `package.json` sets `type: module`.
- No runtime dependencies.
- Entry point/export: `src/opencode-policy.js`.
- Built-in Node APIs only in implementation (`node:fs`).
- Test runner: Node built-in `node:test` via `npm test`.
