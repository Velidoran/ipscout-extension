import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyIp,
  defang,
  extractIps,
  formatIPv6,
  normalizeIp,
  parseHostname,
  parseIPv6,
  parseQuery,
  refang,
  reversePointerName,
} from '../../extension/lib/ip.js';

test('normalizeIp accepts IPv4 and rejects malformed input', () => {
  assert.deepEqual(normalizeIp('8.8.8.8'), { ip: '8.8.8.8', version: 4, parts: [8, 8, 8, 8] });
  assert.equal(normalizeIp('  1.2.3.4  ').ip, '1.2.3.4');
  assert.equal(normalizeIp('1.2.3.4:8080').ip, '1.2.3.4');
  for (const bad of ['1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1.2.3.-1', 'a.b.c.d', '', ' ', null, undefined, 42]) {
    assert.equal(normalizeIp(bad), null, `expected ${JSON.stringify(bad)} to be rejected`);
  }
});

test('normalizeIp canonicalises IPv6 per RFC 5952', () => {
  assert.equal(normalizeIp('2001:4860:4860:0:0:0:0:8888').ip, '2001:4860:4860::8888');
  assert.equal(normalizeIp('2001:0DB8:0000:0000:0001:0000:0000:0001').ip, '2001:db8::1:0:0:1'); // first of equal runs
  assert.equal(normalizeIp('1:0:0:1:0:0:0:1').ip, '1:0:0:1::1'); // longest run wins
  assert.equal(normalizeIp('2001:db8:0:1:1:1:1:1').ip, '2001:db8:0:1:1:1:1:1'); // single zero group is not compressed
  assert.equal(normalizeIp('[2606:4700::1111]:443').ip, '2606:4700::1111');
  assert.equal(normalizeIp('fe80::1%eth0').ip, 'fe80::1');
  assert.equal(normalizeIp('::').ip, '::');
  assert.equal(normalizeIp('::1').ip, '::1');
  assert.equal(normalizeIp('1::').ip, '1::');
});

test('IPv4-mapped IPv6 addresses become IPv4', () => {
  assert.deepEqual(normalizeIp('::ffff:192.0.2.1'), { ip: '192.0.2.1', version: 4, parts: [192, 0, 2, 1] });
  assert.equal(normalizeIp('::ffff:c000:0201').ip, '192.0.2.1');
});

test('parseIPv6 rejects invalid forms', () => {
  for (const bad of [
    '1::2::3',
    ':1::',
    '1:::2',
    '12345::',
    '1:2:3:4:5:6:7:8:9',
    '1:2:3:4:5:6:7',
    'g::1',
    '::ffff:1.2.3',
    '1.2.3.4::',
    '1:2:3:4:5:6:7:1.2.3.4',
  ]) {
    assert.equal(parseIPv6(bad), null, `expected ${bad} to be rejected`);
  }
  assert.deepEqual(parseIPv6('1:2:3:4:5:6:1.2.3.4'), [1, 2, 3, 4, 5, 6, 0x0102, 0x0304]);
});

test('formatIPv6 round-trips', () => {
  for (const s of ['2001:db8::1', '::', '::1', 'fe80::1:2', '2001:db8:85a3::8a2e:370:7334']) {
    assert.equal(formatIPv6(parseIPv6(s)), s);
  }
});

test('classifyIp recognises special-purpose ranges', () => {
  const cls = (s) => classifyIp(normalizeIp(s));
  assert.equal(cls('8.8.8.8').isPublic, true);
  assert.equal(cls('2001:4860:4860::8888').isPublic, true);

  const expectations = {
    '10.1.2.3': 'Private network',
    '172.31.255.255': 'Private network',
    '192.168.0.1': 'Private network',
    '100.64.0.1': 'Shared address space (carrier-grade NAT)',
    '127.0.0.1': 'Loopback',
    '169.254.1.1': 'Link-local',
    '192.0.2.10': 'Documentation (TEST-NET-1)',
    '198.51.100.10': 'Documentation (TEST-NET-2)',
    '203.0.113.10': 'Documentation (TEST-NET-3)',
    '198.18.0.1': 'Benchmarking',
    '224.0.0.251': 'Multicast',
    '240.0.0.1': 'Reserved for future use',
    '255.255.255.255': 'Limited broadcast',
    '0.0.0.0': 'This network',
    '::1': 'Loopback',
    '::': 'Unspecified address',
    'fe80::1': 'Link-local',
    'fd12:3456::1': 'Unique local address (private)',
    'ff02::1': 'Multicast',
    '2001:db8::1': 'Documentation',
    '3fff::1': 'Documentation',
    '64:ff9b::808:808': 'NAT64 translation prefix',
    '4000::1': 'Reserved (outside global unicast space)',
  };
  for (const [ip, label] of Object.entries(expectations)) {
    const c = cls(ip);
    assert.equal(c.isPublic, false, `${ip} should not be public`);
    assert.equal(c.label, label, `${ip} label`);
  }
  assert.equal(cls('172.15.0.1').isPublic, true); // just outside 172.16.0.0/12
  assert.equal(cls('172.32.0.1').isPublic, true);
  assert.equal(cls('100.63.255.255').isPublic, true);
  assert.equal(cls('10.0.0.1').isPrivate, true);
  assert.equal(cls('127.0.0.1').isPrivate, false);
});

test('refang and defang', () => {
  assert.equal(refang('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(refang('1.2.3(.)4 and 5[dot]6[dot]7[dot]8'), '1.2.3.4 and 5.6.7.8');
  assert.equal(refang('2001:db8[:]:1'), '2001:db8::1');
  assert.equal(defang('1.2.3.4'), '1[.]2[.]3[.]4');
  assert.equal(defang('2001:db8::1'), '2001[:]db8[:][:]1');
  assert.equal(normalizeIp(refang(defang('9.9.9.9'))).ip, '9.9.9.9');
});

test('extractIps finds addresses in free text, in order, without duplicates', () => {
  const text = `
    Oct 3 sshd[1]: Failed password for root from 185.220.101[.]1 port 52144
    Oct 3 sshd[2]: Failed password for root from 185.220.101.1 port 52145
    upstream [2a03:2880:f12f:83:face:b00c::25de]:443 and 10.0.0.5:22
    version 1.2.3.4.5 build, time 12:30:45, mac aa:bb:cc:dd:ee:ff, std::vector, see 8.8.8.8.
  `;
  assert.deepEqual(extractIps(text), ['185.220.101.1', '2a03:2880:f12f:83:face:b00c:0:25de', '10.0.0.5', '8.8.8.8']);
  assert.deepEqual(extractIps(text, { publicOnly: true }), ['185.220.101.1', '2a03:2880:f12f:83:face:b00c:0:25de', '8.8.8.8']);
  assert.deepEqual(extractIps(text, { limit: 2 }), ['185.220.101.1', '2a03:2880:f12f:83:face:b00c:0:25de']);
  assert.deepEqual(extractIps('no addresses here, 999.1.1.1 or 1.2.3'), []);
  assert.deepEqual(extractIps(''), []);
});

test('reversePointerName builds in-addr.arpa and ip6.arpa names', () => {
  assert.equal(reversePointerName(normalizeIp('8.8.4.4')), '4.4.8.8.in-addr.arpa');
  assert.equal(
    reversePointerName(normalizeIp('2001:db8::567:89ab')),
    'b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
  );
});

test('parseHostname handles URLs, defanged hosts and ports', () => {
  assert.equal(parseHostname('example.com'), 'example.com');
  assert.equal(parseHostname('Sub.Example.CO.uk.'), 'sub.example.co.uk');
  assert.equal(parseHostname('https://example.com:8443/a?b#c'), 'example.com');
  assert.equal(parseHostname('hxxps://evil[.]example[.]net/login'), 'evil.example.net');
  assert.equal(parseHostname('example.com:8080/path'), 'example.com');
  assert.equal(parseHostname('xn--fiqs8s.xn--fiqs8s'), 'xn--fiqs8s.xn--fiqs8s');
  for (const bad of ['localhost', '1.2.3.4', '-bad.com', 'bad-.com', 'two words.com', '']) {
    assert.equal(parseHostname(bad), null, `expected ${bad} to be rejected`);
  }
});

test('parseQuery interprets IPs, URLs, hostnames and log lines', () => {
  assert.deepEqual((({ type, info, others }) => ({ type, ip: info.ip, others }))(parseQuery('8.8.8.8')), {
    type: 'ip',
    ip: '8.8.8.8',
    others: [],
  });
  assert.equal(parseQuery('http://1.2.3.4:8080/x').info.ip, '1.2.3.4');
  assert.equal(parseQuery('https://[2606:4700::1111]/').info.ip, '2606:4700::1111');
  assert.equal(parseQuery('hxxp://5[.]6[.]7[.]8/payload').info.ip, '5.6.7.8');
  assert.deepEqual(parseQuery('example.org'), { type: 'host', host: 'example.org' });
  assert.deepEqual(parseQuery('https://www.example.org/login'), { type: 'host', host: 'www.example.org' });
  const log = parseQuery('DROP IN=eth0 SRC=203.0.113.9 DST=198.51.100.7 then 9.9.9.9');
  assert.equal(log.type, 'ip');
  assert.equal(log.info.ip, '203.0.113.9');
  assert.deepEqual(log.others, ['198.51.100.7', '9.9.9.9']);
  assert.equal(parseQuery('nothing useful'), null);
  assert.equal(parseQuery(''), null);
  assert.equal(parseQuery(undefined), null);
});
