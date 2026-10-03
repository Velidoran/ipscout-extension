# Security policy

ipScout handles API keys and runs in your browser, so security reports are taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Instead, report them privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** ([direct link](https://github.com/Velidoran/ipscout-extension/security/advisories/new)).
3. Describe the problem, how to reproduce it, and its impact.

The maintainer will acknowledge your report, keep you updated while a fix is prepared, and credit you in the release notes if you'd like.

## Scope

In scope:

- Leaks of API keys, browsing data or page content.
- Script injection through data returned by the APIs (for example HTML in an API response being rendered).
- Permissions or behaviour broader than the README describes.

Out of scope:

- Vulnerabilities in the third-party services ipScout queries. Please report those to the service.
- Inaccurate data from a source. Please open a regular issue instead.

## Supported versions

Security fixes go into the latest release.
