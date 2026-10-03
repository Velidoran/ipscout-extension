# Changelog

Notable changes to ipScout are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-03

The first public release.

### Added

- Checks an IP against 11 free sources in parallel: AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX, ThreatFox, Shodan InternetDB, IPinfo, ipapi.is, WHOIS (RDAP), reverse DNS and the Tor Project's relay list.
- One overall verdict, plus key facts (location, network owner, hostname, abuse contact) and traits such as Tor exit, VPN or hosting.
- Toolbar popup that checks a highlighted IP or lists the IPs found on the page, a right-click menu, the `ip` address-bar keyword, the <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd> shortcut and a bookmarkable full-page report.
- Accepts IPv4 and IPv6, URLs, hostnames, log lines and defanged IOCs. Private and reserved addresses are never sent anywhere.
- Per-source caching to save free-tier quota, copyable text and JSON reports, and links to sites without a free API.
- Settings page for API keys, per-source toggles and behaviour, with the version and a link to this repository.

### Security

- Extension storage, which holds the API keys, is restricted to ipScout's own pages, so scripts running on websites can't read it ([#2](https://github.com/Velidoran/ipscout-extension/pull/2)).

[Unreleased]: https://github.com/Velidoran/ipscout-extension/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Velidoran/ipscout-extension/releases/tag/v1.0.0
