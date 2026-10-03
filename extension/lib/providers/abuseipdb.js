import { LookupError } from '../http.js';
import { countryName, formatDate, plural, timeAgo, truncate } from '../format.js';

// https://www.abuseipdb.com/categories
export const ABUSEIPDB_CATEGORIES = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
};

const API = 'https://api.abuseipdb.com/api/v2';

export function parseAbuseIpdb(d, reports, maxAgeDays) {
  if (!d || typeof d !== 'object') throw new LookupError('parse', 'Unexpected response from AbuseIPDB');
  const score = Number(d.abuseConfidenceScore) || 0;
  const total = Number(d.totalReports) || 0;
  const users = Number(d.numDistinctUsers) || 0;

  let verdict = 'clean';
  if (!d.isWhitelisted) {
    if (score >= 75) verdict = 'malicious';
    else if (score >= 25) verdict = 'suspicious';
  }

  const summary = total
    ? `Abuse confidence ${score}% · ${plural(total, 'report')} from ${plural(users, 'user')} (last ${maxAgeDays} days)`
    : `Abuse confidence ${score}% · no reports in the last ${maxAgeDays} days`;

  const hostnames = Array.isArray(d.hostnames) ? d.hostnames : [];
  const fields = [
    { label: 'Confidence', value: `${score}%` },
    { label: 'Reports', value: total ? `${plural(total, 'report')} · ${plural(users, 'distinct user')}` : 'None' },
    d.lastReportedAt && { label: 'Last reported', value: `${formatDate(d.lastReportedAt)} (${timeAgo(d.lastReportedAt)})` },
    d.isp && { label: 'ISP', value: d.isp },
    d.usageType && { label: 'Usage type', value: d.usageType },
    d.domain && { label: 'Domain', value: d.domain, mono: true },
    hostnames.length && { label: 'Hostnames', value: hostnames.join(', '), mono: true },
    d.countryCode && { label: 'Country', value: countryName(d.countryCode) },
    d.isWhitelisted && { label: 'Allowlisted', value: 'Yes — AbuseIPDB marks this IP as trusted' },
  ].filter(Boolean);

  const flags = [];
  if (d.isTor) flags.push('tor');
  if (/data center|hosting/i.test(d.usageType || '')) flags.push('hosting');

  const tags = [];
  if (d.isTor) tags.push('Tor exit');
  if (d.isWhitelisted) tags.push('Allowlisted');

  const lists = [];
  if (Array.isArray(reports) && reports.length) {
    const counts = new Map();
    for (const r of reports) {
      for (const c of r.categories || []) counts.set(c, (counts.get(c) || 0) + 1);
    }
    const topCategories = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (topCategories.length) {
      lists.push({
        title: `Report categories (latest ${plural(reports.length, 'report')})`,
        inline: true,
        items: topCategories.map(([id, n]) => ({ text: ABUSEIPDB_CATEGORIES[id] || `Category ${id}`, count: n })),
      });
    }
    const comments = reports.filter((r) => r.comment && r.comment.trim()).slice(0, 4);
    if (comments.length) {
      lists.push({
        title: 'Recent report comments',
        items: comments.map((r) => ({
          text: truncate(r.comment, 180),
          sub: [formatDate(r.reportedAt), r.reporterCountryCode && countryName(r.reporterCountryCode)].filter(Boolean).join(' · '),
        })),
      });
    }
  }

  return {
    verdict,
    summary,
    score: { value: score, max: 100 },
    fields,
    tags,
    lists,
    flags,
    facts: { countryCode: d.countryCode || null, org: d.isp || null, hostname: hostnames[0] || null },
  };
}

export default {
  id: 'abuseipdb',
  name: 'AbuseIPDB',
  category: 'reputation',
  description: 'Crowd-sourced abuse reports with an abuse confidence score.',
  homepage: 'https://www.abuseipdb.com',
  webUrl: (ip) => `https://www.abuseipdb.com/check/${ip}`,
  key: {
    required: true,
    url: 'https://www.abuseipdb.com/account/api',
    hint: 'Free account → API → Create Key',
  },
  freeTier: '1,000 checks/day',
  ipv6: true,

  async lookup(ip, ctx) {
    const maxAge = Math.min(365, Math.max(1, Number(ctx.settings.abuseipdbMaxAgeDays) || 90));
    const headers = { Key: ctx.apiKey, Accept: 'application/json' };
    const q = `ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${maxAge}`;
    const { data } = await ctx.fetchJson(`${API}/check?${q}`, { headers });
    const d = data?.data;

    // The reports endpoint has its own, smaller daily quota, so a failure
    // there must never hide the main result.
    let reports = null;
    if (ctx.settings.abuseipdbFetchReports && Number(d?.totalReports) > 0) {
      try {
        const r = await ctx.fetchJson(`${API}/reports?${q}&page=1&perPage=25`, { headers });
        reports = Array.isArray(r.data?.data?.results) ? r.data.data.results : null;
      } catch (err) {
        if (err?.kind === 'aborted') throw err;
      }
    }

    const result = parseAbuseIpdb(d, reports, maxAge);
    result.raw = reports ? { check: data, reports } : data;
    return result;
  },
};
