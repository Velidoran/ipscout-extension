// Registry of data sources, in display order.
//
// Provider interface:
//   id, name, category ('reputation' | 'exposure' | 'network'), description,
//   homepage, webUrl(ip) -> page for this IP (or null),
//   key: null | { required, url, hint },  freeTier, ipv6 (boolean),
//   lookup(ip, ctx) -> Promise<Result>
//
// ctx: { info, apiKey, settings, fetchJson(url, opts) }
//
// Result:
//   verdict: 'malicious' | 'suspicious' | 'clean' | 'info' | 'none'
//   summary: one-line string
//   fields:  [{ label, value, href?, mono? }]
//   tags, lists: [{ title, items: [{ text, href?, sub? }], more? }]
//   flags:   canonical traits, e.g. 'tor', 'vpn', 'proxy', 'hosting', 'anycast'
//   facts:   { countryCode, city, region, asn, org, hostname, network, ... }
//   link?:   provider-supplied page for this IP (overrides webUrl)
//   raw?:    original API response (kept in memory only, never cached)

import abuseipdb from './abuseipdb.js';
import virustotal from './virustotal.js';
import greynoise from './greynoise.js';
import otx from './otx.js';
import threatfox from './threatfox.js';
import shodan from './shodan.js';
import ipinfo from './ipinfo.js';
import ipapi from './ipapi.js';
import rdap from './rdap.js';
import rdns from './rdns.js';
import tor from './tor.js';

export const PROVIDERS = [abuseipdb, virustotal, greynoise, otx, threatfox, shodan, ipinfo, ipapi, rdap, rdns, tor];

export const CATEGORY_LABELS = {
  reputation: 'Threat reputation',
  exposure: 'Exposure',
  network: 'Network & ownership',
};

export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id) || null;
}
