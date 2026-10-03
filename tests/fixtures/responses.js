// Mock API responses used by the unit and end-to-end tests.
//
// They follow each provider's documented response format, but the values are
// SYNTHETIC. 8.8.8.8 (Google Public DNS) is modelled as benign; 1.2.3.4, the
// classic placeholder address, is given invented "malicious" data purely to
// exercise the warning paths. None of this is real threat intelligence.

export const BENIGN_IP = '8.8.8.8';
export const FLAGGED_IP = '1.2.3.4';

const json = (body, status = 200) => ({ status, body });

const abuseipdbCheck = {
  [BENIGN_IP]: {
    data: {
      ipAddress: BENIGN_IP,
      isPublic: true,
      ipVersion: 4,
      isWhitelisted: true,
      abuseConfidenceScore: 0,
      countryCode: 'US',
      usageType: 'Content Delivery Network',
      isp: 'Google LLC',
      domain: 'google.com',
      hostnames: ['dns.google'],
      isTor: false,
      totalReports: 0,
      numDistinctUsers: 0,
      lastReportedAt: null,
    },
  },
  [FLAGGED_IP]: {
    data: {
      ipAddress: FLAGGED_IP,
      isPublic: true,
      ipVersion: 4,
      isWhitelisted: false,
      abuseConfidenceScore: 100,
      countryCode: 'AU',
      usageType: 'Data Center/Web Hosting/Transit',
      isp: 'Example Hosting Pty Ltd',
      domain: 'example.net',
      hostnames: [],
      isTor: true,
      totalReports: 1532,
      numDistinctUsers: 312,
      lastReportedAt: '2026-10-02T21:14:09+00:00',
    },
  },
};

const abuseipdbReports = {
  [FLAGGED_IP]: {
    data: {
      total: 1532,
      page: 1,
      count: 4,
      perPage: 25,
      lastPage: 62,
      results: [
        {
          reportedAt: '2026-10-02T21:14:09+00:00',
          comment: 'SSH brute force: 240 failed logins for root in 10 minutes',
          categories: [18, 22],
          reporterId: 1,
          reporterCountryCode: 'DE',
        },
        {
          reportedAt: '2026-10-02T19:01:44+00:00',
          comment: 'Port scan on TCP 22, 23, 2323, 8080',
          categories: [14],
          reporterId: 2,
          reporterCountryCode: 'US',
        },
        { reportedAt: '2026-10-02T11:30:00+00:00', comment: '', categories: [18, 22], reporterId: 3, reporterCountryCode: 'NL' },
        {
          reportedAt: '2026-10-01T08:12:51+00:00',
          comment: 'Probing for /wp-login.php and /.env',
          categories: [21, 19],
          reporterId: 4,
          reporterCountryCode: 'GB',
        },
      ],
    },
  },
};

const virustotal = {
  [BENIGN_IP]: {
    data: {
      id: BENIGN_IP,
      type: 'ip_address',
      attributes: {
        as_owner: 'GOOGLE',
        asn: 15169,
        country: 'US',
        network: '8.8.8.0/24',
        regional_internet_registry: 'ARIN',
        reputation: 541,
        tags: [],
        total_votes: { harmless: 198, malicious: 37 },
        last_analysis_date: 1790899200,
        last_analysis_stats: { harmless: 62, malicious: 0, suspicious: 0, undetected: 32, timeout: 0 },
        last_analysis_results: {
          'Engine A': { category: 'harmless', engine_name: 'Engine A', method: 'blacklist', result: 'clean' },
        },
      },
    },
  },
  [FLAGGED_IP]: {
    data: {
      id: FLAGGED_IP,
      type: 'ip_address',
      attributes: {
        as_owner: 'Example Hosting Pty Ltd',
        asn: 64500,
        country: 'AU',
        network: '1.2.3.0/24',
        regional_internet_registry: 'APNIC',
        reputation: -42,
        tags: ['suspicious-udp'],
        total_votes: { harmless: 1, malicious: 23 },
        last_analysis_date: 1790889200,
        last_analysis_stats: { harmless: 55, malicious: 9, suspicious: 2, undetected: 28, timeout: 0 },
        last_analysis_results: {
          'Engine A': { category: 'malicious', engine_name: 'Engine A', method: 'blacklist', result: 'malware' },
          'Engine B': { category: 'malicious', engine_name: 'Engine B', method: 'blacklist', result: 'phishing' },
          'Engine C': { category: 'suspicious', engine_name: 'Engine C', method: 'blacklist', result: 'suspicious' },
          'Engine D': { category: 'harmless', engine_name: 'Engine D', method: 'blacklist', result: 'clean' },
        },
      },
    },
  },
};

const greynoise = {
  [BENIGN_IP]: json({
    ip: BENIGN_IP,
    noise: false,
    riot: true,
    classification: 'benign',
    name: 'Google Public DNS',
    link: `https://viz.greynoise.io/riot/${BENIGN_IP}`,
    last_seen: '2026-10-02',
    message: 'Success',
  }),
  [FLAGGED_IP]: json({
    ip: FLAGGED_IP,
    noise: true,
    riot: false,
    classification: 'malicious',
    name: 'unknown',
    link: `https://viz.greynoise.io/ip/${FLAGGED_IP}`,
    last_seen: '2026-10-02',
    message: 'Success',
  }),
};

const otx = {
  [BENIGN_IP]: {
    indicator: BENIGN_IP,
    type: 'IPv4',
    reputation: 0,
    asn: 'AS15169 google llc',
    country_code: 'US',
    country_name: 'United States of America',
    city: null,
    validation: [{ source: 'whitelist', message: 'Whitelisted IP', name: 'Whitelisted IP' }],
    pulse_info: {
      count: 50,
      pulses: [
        {
          id: 'aaa111',
          name: 'Public DNS resolvers seen in sandbox runs',
          modified: '2026-09-01T10:00:00.000',
          tags: ['dns'],
          author: { username: 'analyst1' },
          malware_families: [],
        },
      ],
      related: { alienvault: { adversary: [], malware_families: [] }, other: { adversary: [], malware_families: [] } },
    },
  },
  [FLAGGED_IP]: {
    indicator: FLAGGED_IP,
    type: 'IPv4',
    reputation: 0,
    asn: 'AS64500 example hosting pty ltd',
    country_code: 'AU',
    country_name: 'Australia',
    city: 'Brisbane',
    region: 'Queensland',
    validation: [],
    pulse_info: {
      count: 4,
      pulses: [
        {
          id: 'bbb222',
          name: 'Brute-force infrastructure (synthetic)',
          modified: '2026-09-28T08:00:00.000',
          tags: ['ssh', 'bruteforce'],
          author: { username: 'analyst2' },
          malware_families: [{ id: 'Mirai', display_name: 'Mirai' }],
          adversary: '',
        },
        {
          id: 'ccc333',
          name: 'Cobalt Strike C2 sweep (synthetic)',
          modified: '2026-09-30T08:00:00.000',
          tags: ['c2'],
          author: { username: 'analyst3' },
          malware_families: [],
          adversary: '',
        },
      ],
      related: { alienvault: { adversary: [], malware_families: ['Cobalt Strike'] }, other: { adversary: [], malware_families: [] } },
    },
  },
};

const threatfox = {
  [BENIGN_IP]: { query_status: 'no_result', data: 'Your search did not yield any results' },
  [FLAGGED_IP]: {
    query_status: 'ok',
    data: [
      {
        id: '1234567',
        ioc: `${FLAGGED_IP}:443`,
        threat_type: 'botnet_cc',
        threat_type_desc: 'Botnet C&C',
        ioc_type: 'ip:port',
        malware: 'win.cobalt_strike',
        malware_printable: 'Cobalt Strike',
        confidence_level: 90,
        first_seen: '2026-09-29 12:00:00 UTC',
        last_seen: null,
        reporter: 'example',
        tags: ['CobaltStrike'],
      },
      {
        // Prefix match that must be filtered out (1.2.3.45 is a different IP).
        id: '7654321',
        ioc: '1.2.3.45:80',
        threat_type: 'payload_delivery',
        threat_type_desc: 'Payload delivery',
        ioc_type: 'ip:port',
        malware: 'elf.mirai',
        malware_printable: 'Mirai',
        confidence_level: 50,
        first_seen: '2026-09-01 12:00:00 UTC',
      },
    ],
  },
};

const internetdb = {
  [BENIGN_IP]: json({ ip: BENIGN_IP, ports: [53, 443], hostnames: ['dns.google'], tags: [], cpes: [], vulns: [] }),
  [FLAGGED_IP]: json({
    ip: FLAGGED_IP,
    ports: [8080, 22, 80, 443],
    hostnames: [],
    tags: ['self-signed', 'cloud'],
    cpes: ['cpe:/a:openbsd:openssh:8.2', 'cpe:/a:f5:nginx'],
    vulns: ['CVE-2021-41617', 'CVE-2023-38408'],
  }),
};

const ipinfo = {
  [BENIGN_IP]: {
    ip: BENIGN_IP,
    hostname: 'dns.google',
    city: 'Mountain View',
    region: 'California',
    country: 'US',
    loc: '37.4056,-122.0775',
    org: 'AS15169 Google LLC',
    postal: '94043',
    timezone: 'America/Los_Angeles',
    anycast: true,
  },
  [FLAGGED_IP]: {
    ip: FLAGGED_IP,
    city: 'Brisbane',
    region: 'Queensland',
    country: 'AU',
    loc: '-27.4679,153.0281',
    org: 'AS64500 Example Hosting Pty Ltd',
    postal: '4000',
    timezone: 'Australia/Brisbane',
  },
};

const ipapi = {
  [BENIGN_IP]: {
    ip: BENIGN_IP,
    rir: 'ARIN',
    is_bogon: false,
    is_mobile: false,
    is_crawler: false,
    is_datacenter: true,
    is_tor: false,
    is_proxy: false,
    is_vpn: false,
    is_abuser: false,
    company: { name: 'Google LLC', abuser_score: '0 (Very Low)', domain: 'google.com', type: 'hosting', network: '8.8.8.0 - 8.8.8.255' },
    abuse: { name: 'Google LLC', email: 'network-abuse@google.com' },
    asn: {
      asn: 15169,
      abuser_score: '0.0001 (Very Low)',
      route: '8.8.8.0/24',
      descr: 'GOOGLE, US',
      country: 'us',
      org: 'Google LLC',
      domain: 'google.com',
      type: 'hosting',
    },
    location: { country: 'United States', country_code: 'US', state: 'California', city: 'Mountain View' },
  },
  [FLAGGED_IP]: {
    ip: FLAGGED_IP,
    rir: 'APNIC',
    is_bogon: false,
    is_mobile: false,
    is_crawler: false,
    is_datacenter: true,
    is_tor: true,
    is_proxy: false,
    is_vpn: true,
    is_abuser: true,
    vpn: { service: 'ExampleVPN', type: 'exit' },
    datacenter: { datacenter: 'Example Hosting', network: '1.2.3.0 - 1.2.3.255' },
    company: { name: 'Example Hosting Pty Ltd', abuser_score: '0.31 (High)', type: 'hosting' },
    abuse: { name: 'Example Hosting abuse desk', email: 'abuse@example.net' },
    asn: { asn: 64500, route: '1.2.3.0/24', org: 'Example Hosting Pty Ltd', type: 'hosting' },
    location: { country: 'Australia', country_code: 'AU', state: 'Queensland', city: 'Brisbane' },
  },
};

const rdap = {
  [BENIGN_IP]: {
    url: 'https://rdap.arin.net/registry/ip/8.8.8.8',
    body: {
      objectClassName: 'ip network',
      handle: 'NET-8-8-8-0-2',
      startAddress: '8.8.8.0',
      endAddress: '8.8.8.255',
      ipVersion: 'v4',
      name: 'GOGL',
      type: 'DIRECT ALLOCATION',
      parentHandle: 'NET-8-0-0-0-0',
      port43: 'whois.arin.net',
      cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }],
      arin_originas0_originautnums: [15169],
      events: [
        { eventAction: 'last changed', eventDate: '2023-12-28T17:24:56-05:00' },
        { eventAction: 'registration', eventDate: '2023-12-28T17:24:33-05:00' },
      ],
      entities: [
        {
          handle: 'GOGL',
          roles: ['registrant'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', 'Google LLC'],
              ['kind', {}, 'text', 'org'],
            ],
          ],
          entities: [
            {
              handle: 'ABUSE5250-ARIN',
              roles: ['abuse'],
              vcardArray: [
                'vcard',
                [
                  ['version', {}, 'text', '4.0'],
                  ['fn', {}, 'text', 'Abuse'],
                  ['email', {}, 'text', 'network-abuse@google.com'],
                  ['tel', { type: ['work', 'voice'] }, 'uri', 'tel:+1-650-253-0000'],
                ],
              ],
            },
          ],
        },
      ],
    },
  },
  [FLAGGED_IP]: {
    url: 'https://rdap.apnic.net/ip/1.2.3.4',
    body: {
      objectClassName: 'ip network',
      handle: '1.2.3.0 - 1.2.3.255',
      startAddress: '1.2.3.0',
      endAddress: '1.2.3.255',
      ipVersion: 'v4',
      name: 'EXAMPLE-NET',
      type: 'ASSIGNED PORTABLE',
      country: 'AU',
      port43: 'whois.apnic.net',
      cidr0_cidrs: [{ v4prefix: '1.2.3.0', length: 24 }],
      remarks: [{ title: 'description', description: ['Example hosting network (synthetic test data)'] }],
      entities: [
        {
          handle: 'EX1-AP',
          roles: ['registrant'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', 'Example Hosting Pty Ltd'],
              ['kind', {}, 'text', 'org'],
            ],
          ],
        },
        {
          handle: 'IRT-EX-AU',
          roles: ['abuse'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', 'IRT-EX-AU'],
              ['email', {}, 'text', 'abuse@example.net'],
            ],
          ],
        },
      ],
      events: [{ eventAction: 'registration', eventDate: '2019-05-01T00:00:00Z' }],
    },
  },
};

const onionoo = {
  [BENIGN_IP]: { version: '8.0', relays_published: '2026-10-03 03:00:00', relays: [], bridges: [] },
  [FLAGGED_IP]: {
    version: '8.0',
    relays_published: '2026-10-03 03:00:00',
    relays: [
      {
        nickname: 'ExampleExit1',
        fingerprint: 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
        or_addresses: ['1.2.3.4:9001'],
        exit_addresses: ['1.2.3.4'],
        running: true,
        flags: ['Exit', 'Fast', 'Running', 'Valid'],
        first_seen: '2025-01-10 00:00:00',
        last_seen: '2026-10-03 02:00:00',
        as: 'AS64500',
        as_name: 'Example Hosting Pty Ltd',
      },
      {
        // Search is a prefix match: 1.2.3.40 must not count as 1.2.3.4.
        nickname: 'SomeoneElse',
        fingerprint: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        or_addresses: ['1.2.3.40:443'],
        exit_addresses: [],
        running: true,
        flags: ['Fast', 'Running', 'Valid'],
      },
    ],
    bridges: [],
  },
};

const dnsPtr = {
  '8.8.8.8.in-addr.arpa': { Status: 0, Answer: [{ name: '8.8.8.8.in-addr.arpa.', type: 12, TTL: 21600, data: 'dns.google.' }] },
  '4.3.2.1.in-addr.arpa': { Status: 3, Authority: [] },
};
const dnsA = {
  'dns.google': {
    Status: 0,
    Answer: [
      { name: 'dns.google.', type: 1, TTL: 300, data: '8.8.8.8' },
      { name: 'dns.google.', type: 1, TTL: 300, data: '8.8.4.4' },
    ],
  },
  'example.org': { Status: 0, Answer: [{ name: 'example.org.', type: 1, TTL: 300, data: '1.2.3.4' }] },
};
const dnsAAAA = {
  'dns.google': { Status: 0, Answer: [{ name: 'dns.google.', type: 28, TTL: 300, data: '2001:4860:4860::8888' }] },
  'example.org': { Status: 0, Answer: [] },
};

/**
 * Resolve a request to a mock response.
 * Returns { status, body, url? } or null when the request isn't covered.
 */
export function mockResponse(urlString, { method = 'GET', body } = {}) {
  const url = new URL(urlString);
  const host = url.hostname;
  const lastSegment = decodeURIComponent(url.pathname.split('/').filter(Boolean).pop() || '');
  const pick = (table, key) => (key in table ? json(table[key]) : json({ error: 'not in fixtures' }, 404));

  switch (host) {
    case 'api.abuseipdb.com': {
      const ip = url.searchParams.get('ipAddress');
      if (url.pathname.endsWith('/reports')) return pick(abuseipdbReports, ip);
      return pick(abuseipdbCheck, ip);
    }
    case 'www.virustotal.com':
      return pick(virustotal, lastSegment);
    case 'api.greynoise.io':
      return (
        greynoise[lastSegment] ||
        json(
          { ip: lastSegment, noise: false, riot: false, message: 'IP not observed scanning the internet or contained in RIOT data set.' },
          404,
        )
      );
    case 'otx.alienvault.com':
      return pick(otx, url.pathname.split('/')[5]);
    case 'threatfox-api.abuse.ch': {
      const term = JSON.parse(body || '{}').search_term;
      return threatfox[term] ? json(threatfox[term]) : json({ query_status: 'no_result', data: 'Your search did not yield any results' });
    }
    case 'internetdb.shodan.io':
      return internetdb[lastSegment] || json({ detail: 'No information available' }, 404);
    case 'ipinfo.io':
      if (url.pathname === '/json') return json({ ip: BENIGN_IP });
      return pick(ipinfo, url.pathname.split('/')[1]);
    case 'api.ipapi.is':
      return pick(ipapi, url.searchParams.get('q'));
    case 'rdap.org': {
      const entry = rdap[lastSegment];
      return entry ? { status: 200, body: entry.body, url: entry.url } : json({ errorCode: 404 }, 404);
    }
    case 'dns.google':
    case 'cloudflare-dns.com': {
      const name = url.searchParams.get('name');
      const type = url.searchParams.get('type');
      const table = type === 'PTR' ? dnsPtr : type === 'A' ? dnsA : dnsAAAA;
      return json(table[name] || { Status: 3 });
    }
    case 'onionoo.torproject.org':
      return pick(onionoo, url.searchParams.get('search'));
    default:
      return null;
  }
}

/** A fetch() replacement backed by mockResponse, for unit tests. */
export function createMockFetch({ override } = {}) {
  const calls = [];
  const mockFetch = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, init });
    const custom = override?.(url, init);
    const res = custom || mockResponse(url, { method: init.method, body: init.body });
    if (!res) throw new TypeError(`Failed to fetch ${url}`);
    const response = new Response(JSON.stringify(res.body), { status: res.status, headers: { 'content-type': 'application/json' } });
    if (res.url) Object.defineProperty(response, 'url', { value: res.url });
    return response;
  };
  mockFetch.calls = calls;
  return mockFetch;
}
