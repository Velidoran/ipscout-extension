// Small fetch wrapper: timeouts, JSON parsing and friendly error mapping.

export class LookupError extends Error {
  /**
   * @param {'auth'|'rate-limit'|'not-found'|'timeout'|'network'|'server'|'http'|'parse'|'aborted'} kind
   */
  constructor(kind, message, { status, detail } = {}) {
    super(message);
    this.name = 'LookupError';
    this.kind = kind;
    this.status = status;
    this.detail = detail;
  }
}

const DEFAULT_TIMEOUT_MS = 15000;

/** Pull a human readable message out of the error bodies the providers use. */
export function extractApiMessage(data) {
  if (!data || typeof data !== 'object') return '';
  const candidates = [
    data.errors?.[0]?.detail, // AbuseIPDB
    data.error?.message, // VirusTotal
    typeof data.error === 'string' ? data.error : null, // ipapi.is
    data.message, // GreyNoise, IPinfo
    data.detail, // Shodan InternetDB
    data.title,
    data.description,
  ];
  const msg = candidates.find((c) => typeof c === 'string' && c.trim());
  return msg ? msg.trim().slice(0, 240) : '';
}

export function errorForStatus(status, data) {
  const detail = extractApiMessage(data);
  if (status === 401 || status === 403) {
    return new LookupError('auth', 'API key missing or rejected', { status, detail });
  }
  if (status === 429) {
    return new LookupError('rate-limit', 'Free-tier rate limit reached — try again later', { status, detail });
  }
  if (status === 404) return new LookupError('not-found', 'Not found', { status, detail });
  if (status >= 500) return new LookupError('server', `Service unavailable (HTTP ${status})`, { status, detail });
  return new LookupError('http', `Unexpected response (HTTP ${status})`, { status, detail });
}

/**
 * Fetch a URL and parse the JSON body.
 * Statuses listed in `allowStatus` are returned instead of thrown, so
 * providers can treat e.g. 404 as "no data" rather than an error.
 * Resolves to { status, data, url }.
 */
export async function fetchJson(url, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal,
    allowStatus = [],
    fetchImpl = globalThis.fetch,
  } = options;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const forwardAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', forwardAbort, { once: true });
  }

  try {
    let res;
    let text;
    try {
      res = await fetchImpl(url, {
        method,
        headers,
        body,
        signal: controller.signal,
        credentials: 'omit', // never send the user's cookies for these sites
        referrerPolicy: 'no-referrer',
      });
      text = await res.text();
    } catch (err) {
      if (timedOut) throw new LookupError('timeout', 'Request timed out');
      if (signal?.aborted) throw new LookupError('aborted', 'Lookup cancelled');
      throw new LookupError('network', 'Could not reach the service', { detail: err?.message });
    }

    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }

    if (res.ok || allowStatus.includes(res.status)) {
      if (data === null && text && res.ok) {
        throw new LookupError('parse', 'Unexpected (non-JSON) response', { status: res.status });
      }
      return { status: res.status, data, url: res.url || url };
    }
    throw errorForStatus(res.status, data);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', forwardAbort);
  }
}

/** Serialisable description of an error for the UI and cache. */
export function describeError(err) {
  if (err instanceof LookupError) {
    return { kind: err.kind, message: err.message, detail: err.detail || '', status: err.status ?? null };
  }
  return { kind: 'unknown', message: 'Something went wrong', detail: String(err?.message || err || ''), status: null };
}
