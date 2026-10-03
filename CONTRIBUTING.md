# Contributing to ipScout

Thanks for helping improve ipScout! Bug reports, suggestions for new sources and pull requests are all welcome.

- **Found a bug?** [Open a bug report](https://github.com/Velidoran/ipscout-extension/issues/new?template=bug_report.yml). Please leave API keys out of issues and screenshots.
- **Know a good free IP research API?** [Suggest it as a new source](https://github.com/Velidoran/ipscout-extension/issues/new?template=feature_request.yml).
- **Found a security problem?** Please report it privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Development setup

You need Node.js 22 or newer and Chrome (or Chromium).

```sh
git clone https://github.com/Velidoran/ipscout-extension.git
cd ipscout-extension
npm install
npx playwright install chromium   # only needed for the end-to-end tests
```

Load the `extension/` folder in Chrome: open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and choose the folder. After changing code, click the reload icon on the ipScout card and reopen the popup.

There's no build step: the extension is plain JavaScript modules, and it has no runtime dependencies.

## Tests

```sh
npm test            # unit tests (Node's built-in test runner)
npm run test:e2e    # the real extension in Chromium via Playwright
```

Neither suite calls the real APIs. Responses come from `tests/fixtures/responses.js`, which follows each API's documented format but contains made-up data. CI runs both suites, plus a formatting check, on every pull request.

## Code style

- Formatting is handled by Prettier: run `npm run format` before committing (CI runs `npm run format:check`).
- Build the UI with the `h()` helper and `textContent`. Text from APIs is untrusted, so it must never be inserted with `innerHTML`.
- Never log, cache or export API keys, and send each key only to its own service.
- Keep the extension dependency-free and the permissions minimal. A new permission needs a clear reason in the pull request.

## Adding a data source

New sources should have a free tier that works from a browser extension.

1. Create `extension/lib/providers/<name>.js` exporting an object with `id`, `name`, `category` (`reputation`, `exposure` or `network`), `description`, `homepage`, `webUrl(ip)`, `key` (or `null`), `freeTier`, `ipv6` and `async lookup(ip, ctx)`. `lookup` calls `ctx.fetchJson(url, options)` and returns `{ verdict, summary, fields, tags, lists, flags, facts }`. The comment at the top of `providers/index.js` describes the full shape.
2. Register it in `extension/lib/providers/index.js`.
3. Add the API host to `host_permissions` in `extension/manifest.json`. A unit test fails if you forget.
4. Add a mock response to `tests/fixtures/responses.js` and tests to `tests/unit/providers.test.js`.
5. Add the source to the README's sources table, and to the API key table if it takes a key.

## Pull requests

- Keep each pull request focused on one change, and describe how you tested it. The pull request template has a short checklist.
- Make sure `npm test`, `npm run test:e2e` and `npm run format:check` pass.

## Releasing (maintainers)

1. Update `version` in `extension/manifest.json` and `package.json`, and move the changelog's Unreleased entries under the new version.
2. Merge to `main`, then tag and push: `git tag v1.2.3 && git push origin v1.2.3`.
3. The release workflow checks that the tag matches the manifest version, builds the zip and publishes a GitHub release with it attached.
