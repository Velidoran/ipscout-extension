// Rendering of lookup results. Shared by the popup and the full-page view.

import { append, clear, extLink, h, icon } from './dom.js';
import { CATEGORY_LABELS } from '../lib/providers/index.js';
import { FLAG_LABELS, FLAG_TONES, summarize, verdictHeadline } from '../lib/lookup.js';
import { QUICK_LINKS } from '../lib/quicklinks.js';
import { countryFlag, countryName, joinParts, timeAgo } from '../lib/format.js';

export const VERDICT_LABEL = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'Clean',
  info: 'Info',
  none: 'No data',
  error: 'Error',
  loading: 'Loading',
};

const VERDICT_ICON = { malicious: 'shield-alert', suspicious: 'alert', clean: 'shield-check', info: 'info', none: 'minus' };

const ERROR_HINTS = {
  auth: 'Check the API key for this source in Options.',
  'rate-limit': 'The free allowance is used up for now. Cached results don’t count against it.',
  timeout: 'The service took too long to respond.',
  network: 'The service could not be reached. Check your connection.',
  server: 'The service is having problems. Try again later.',
  parse: 'The service returned something unexpected.',
};

/* ------------------------------------------------------------------ */

export function renderSourceCard(provider, state, { ip, open = false, compact = false, onRetry, onOpenOptions } = {}) {
  const status = state?.status || 'loading';
  const result = status === 'done' ? state.result : null;
  const verdict = result ? result.verdict : status;

  const card = h('details', { class: `source v-${verdict}`, dataset: { provider: provider.id } });

  let indicator;
  let summaryText;
  const meta = h('span', { class: 'source-meta' });
  if (status === 'loading') {
    indicator = h('span', { class: 'spinner', role: 'presentation' });
    summaryText = 'Checking…';
  } else if (status === 'error') {
    indicator = h('span', { class: 'dot' });
    summaryText = state.error.message;
  } else {
    indicator = h('span', { class: 'dot', title: VERDICT_LABEL[verdict] });
    summaryText = result.summary;
    if (state.cachedAt) {
      const label = `Cached ${timeAgo(state.cachedAt)}`;
      meta.title = `${label} — use Refresh for fresh data`;
      if (compact) meta.append(icon('clock', { size: 12, label }));
      else meta.textContent = label.toLowerCase();
    }
  }

  const summary = h(
    'summary',
    {},
    indicator,
    h('span', { class: 'source-name', text: provider.name }),
    h(
      'span',
      { class: 'source-summary', title: summaryText },
      h('span', { class: 'visually-hidden', text: `${VERDICT_LABEL[verdict]}: ` }),
      summaryText,
    ),
    meta,
    h('span', { class: 'chev' }, icon('chevron', { size: 14 })),
  );
  card.append(summary);

  if (status === 'loading') {
    card.classList.add('is-static');
    summary.addEventListener('click', (e) => e.preventDefault());
    return card;
  }

  const body = h('div', { class: 'source-body' });
  const actions = h('div', { class: 'source-actions' });

  if (status === 'error') {
    const hint = ERROR_HINTS[state.error.kind] || '';
    body.append(h('p', { class: 'error-detail' }, hint, state.error.detail ? [' ', h('code', { text: state.error.detail })] : null));
    if (onRetry)
      actions.append(
        h('button', { class: 'btn btn-sm', type: 'button', onclick: () => onRetry(provider.id) }, icon('refresh', { size: 13 }), 'Retry'),
      );
    if (state.error.kind === 'auth' && onOpenOptions) {
      actions.append(h('button', { class: 'btn btn-sm', type: 'button', onclick: onOpenOptions }, icon('key', { size: 13 }), 'API keys'));
    }
  } else {
    if (result.fields?.length) {
      body.append(
        h(
          'dl',
          { class: 'fields' },
          result.fields.map((f) => [
            h('dt', { text: f.label }),
            h(
              'dd',
              { class: f.mono ? 'mono' : '' },
              f.href ? (f.href.startsWith('mailto:') ? h('a', { href: f.href, text: f.value }) : extLink(f.href, f.value)) : f.value,
            ),
          ]),
        ),
      );
    }
    if (result.tags?.length) {
      body.append(
        h(
          'div',
          { class: 'tags' },
          result.tags.map((t) => h('span', { class: 'tag', text: t })),
        ),
      );
    }
    for (const list of result.lists || []) {
      if (!list.items?.length) continue;
      if (list.inline) {
        body.append(
          h(
            'div',
            { class: 'list-block' },
            h('h4', { text: list.title }),
            h(
              'div',
              { class: 'tags' },
              list.items.map((item) =>
                h('span', { class: 'tag' }, item.text, item.count ? h('span', { class: 'count', text: String(item.count) }) : null),
              ),
            ),
          ),
        );
        continue;
      }
      body.append(
        h(
          'div',
          { class: 'list-block' },
          h('h4', { text: list.title }),
          h(
            'ul',
            {},
            list.items.map((item) =>
              h(
                'li',
                {},
                item.href ? extLink(item.href, item.text) : item.text,
                item.sub ? h('span', { class: 'sub', text: item.sub }) : null,
              ),
            ),
            list.more ? h('li', { class: 'more', text: `+ ${list.more} more` }) : null,
          ),
        ),
      );
    }
    if (!result.fields?.length && !result.tags?.length && !result.lists?.length) {
      body.append(h('p', { class: 'source-desc', text: provider.description }));
    }
  }

  const link = result?.link || (provider.webUrl ? provider.webUrl(ip) : null);
  if (link) {
    actions.append(extLink(link, provider.webLabel || `Open on ${provider.name}`, ' ', icon('external', { size: 12 })));
  }

  if (result?.raw !== undefined && result?.raw !== null) {
    const pre = h('pre', { class: 'raw-json', hidden: true });
    const toggle = h(
      'button',
      {
        class: 'btn btn-sm',
        type: 'button',
        'aria-expanded': 'false',
        onclick: () => {
          if (!pre.textContent) pre.textContent = JSON.stringify(result.raw, null, 2).slice(0, 300000);
          pre.hidden = !pre.hidden;
          toggle.setAttribute('aria-expanded', String(!pre.hidden));
        },
      },
      icon('braces', { size: 13 }),
      'Raw response',
    );
    actions.append(toggle);
    body.append(actions, pre);
  } else if (actions.childNodes.length) {
    body.append(actions);
  }

  card.append(body);
  card.open = open;
  return card;
}

/* ------------------------------------------------------------------ */

export function renderOverview(summary) {
  const head = verdictHeadline(summary);
  const busy = summary.verdict === 'none' && summary.loading > 0;
  const banner = h(
    'div',
    { class: `verdict-banner v-${busy ? 'loading' : summary.verdict}`, role: 'status', 'aria-live': 'polite' },
    busy ? h('span', { class: 'spinner', style: 'margin-top:4px' }) : icon(VERDICT_ICON[summary.verdict] || 'minus', { size: 18 }),
    h('div', {}, h('div', { class: 'verdict-title', text: head.title }), h('div', { class: 'verdict-detail', text: head.detail })),
  );

  const f = summary.facts;
  const facts = [];
  const place = joinParts([f.city, f.region, countryName(f.countryCode)]);
  if (place) facts.push(fact('pin', [place, f.countryCode ? ` ${countryFlag(f.countryCode)}` : '']));
  const asLine = joinParts([f.asn, f.org], ' · ');
  if (asLine || f.network) {
    facts.push(
      fact('server', [
        asLine,
        f.network ? h('span', { class: asLine ? 'fact-sub mono' : 'mono', text: `${asLine ? ' · ' : ''}${f.network}` }) : null,
      ]),
    );
  }
  if (f.hostname) {
    facts.push(
      fact('globe', [
        h('span', { class: 'mono', text: f.hostname }),
        f.fcrdns ? h('span', { class: 'ok', title: 'Forward-confirmed reverse DNS', text: ' ✓' }) : null,
      ]),
    );
  }
  if (f.abuseEmail) {
    facts.push(
      fact('mail', [
        h('a', { href: `mailto:${f.abuseEmail}`, class: 'mono', text: f.abuseEmail }),
        h('span', { class: 'fact-sub', text: ' · abuse contact' }),
      ]),
    );
  }

  const traits = Object.entries(summary.flags).map(([flag, sources]) =>
    h('span', { class: `trait ${FLAG_TONES[flag] || ''}`, title: `Reported by ${sources.join(', ')}`, text: FLAG_LABELS[flag] || flag }),
  );

  return h(
    'section',
    { class: 'overview', 'aria-label': 'Overview' },
    h('div', {}, banner, traits.length ? h('div', { class: 'traits' }, traits) : null),
    facts.length ? h('ul', { class: 'facts' }, facts) : null,
  );
}

function fact(iconName, content) {
  return h('li', {}, icon(iconName, { size: 15 }), h('span', { class: 'fact-text' }, content));
}

export function renderNotices(states, providers, { onOpenOptions } = {}) {
  const needsKey = providers.filter((p) => states[p.id]?.status === 'needs-key');
  const unsupported = providers.filter((p) => states[p.id]?.status === 'unsupported');
  const notices = [];
  if (needsKey.length) {
    notices.push(
      h(
        'div',
        { class: 'notice' },
        icon('key'),
        h('span', { text: `${joinParts(needsKey.map((p) => p.name))} ${needsKey.length === 1 ? 'needs' : 'need'} a free API key.` }),
        onOpenOptions ? h('button', { class: 'btn btn-sm', type: 'button', onclick: onOpenOptions, text: 'Add keys' }) : null,
      ),
    );
  }
  if (unsupported.length) {
    notices.push(
      h(
        'div',
        { class: 'notice' },
        icon('info'),
        h('span', { text: `${joinParts(unsupported.map((p) => p.name))} only ${unsupported.length === 1 ? 'supports' : 'support'} IPv4.` }),
      ),
    );
  }
  return notices;
}

export function renderQuickLinks(ip) {
  return h(
    'nav',
    { class: 'quicklinks', 'aria-label': 'Look up on other sites' },
    h('span', { text: 'More lookups:' }),
    QUICK_LINKS.map((q) => extLink(q.url(ip), q.name)),
  );
}

export function renderScopeNote(info, scope) {
  return h(
    'div',
    { class: 'scope-note' },
    h('strong', { text: scope.label }),
    ` — ${[scope.rfc, scope.cidr].filter(Boolean).join(', ')}`,
    h('p', {
      style: 'margin:6px 0 0',
      text: scope.isPrivate
        ? 'This address is only meaningful inside a private network, so public sources have nothing on it and no lookups were sent. Check internal logs, DHCP leases or NAT tables instead.'
        : 'This is a special-purpose address that isn’t routable on the public internet, so no lookups were sent.',
    }),
  );
}

export function ipChip(ip, onClick, { verdict, current = false } = {}) {
  return h(
    'button',
    {
      class: 'chip',
      type: 'button',
      title: current ? 'Currently shown' : `Look up ${ip}`,
      'aria-current': current ? 'true' : null,
      onclick: () => onClick(ip),
    },
    verdict ? h('span', { class: `dot v-${verdict}`, title: VERDICT_LABEL[verdict] || '' }) : null,
    ip,
  );
}

/* ------------------------------------------------------------------ */

/**
 * Owns the results area for one IP and updates it as sources report back.
 * Cards are replaced in place so the rest of the page (and which cards the
 * user has expanded) is left alone.
 */
export class ResultView {
  constructor(root, { mode, info, scope, providers, others = [], resolvedFrom = null, handlers = {} }) {
    this.root = root;
    this.mode = mode;
    this.info = info;
    this.scope = scope;
    this.providers = providers;
    this.others = others;
    this.resolvedFrom = resolvedFrom;
    this.handlers = handlers;
    this.states = {};
    this.cards = new Map();
    this.userOpen = new Map();
    this.sections = new Map();
    this.summaryQueued = false;
  }

  render() {
    clear(this.root);
    const { info, scope, handlers } = this;
    const wrap = h('div', { class: 'results' });

    const tools = h('div', { class: 'result-tools' });
    if (scope.isPublic && handlers.onRefresh) {
      tools.append(this.toolButton('refresh', 'Refresh', 'Refresh (skip cache)', () => handlers.onRefresh()));
    }
    if (scope.isPublic && handlers.onCopyReport) {
      tools.append(this.toolButton('copy', 'Copy summary', 'Copy a text summary', (btn) => handlers.onCopyReport(btn)));
    }
    if (scope.isPublic && handlers.onCopyJson) {
      tools.append(this.toolButton('braces', 'Copy JSON', 'Copy all results as JSON', (btn) => handlers.onCopyJson(btn)));
    }
    if (handlers.onOpenTab) {
      tools.append(this.toolButton('external', 'Open in tab', 'Open full report in a tab', () => handlers.onOpenTab()));
    }

    wrap.append(
      h(
        'div',
        { class: 'result-head' },
        h('h1', { class: 'result-ip', style: 'margin:0', text: info.ip }),
        h('span', { class: 'badge', text: `IPv${info.version}` }),
        h(
          'button',
          {
            class: 'icon-btn',
            type: 'button',
            title: 'Copy IP',
            'aria-label': 'Copy IP address',
            onclick: (e) => handlers.onCopyIp?.(e.currentTarget),
          },
          icon('copy', { size: 14 }),
        ),
        tools,
      ),
    );

    if (this.resolvedFrom) {
      const { host, ips } = this.resolvedFrom;
      wrap.append(
        h(
          'div',
          { class: 'resolved-from' },
          h('span', {}, h('span', { class: 'mono', text: host }), ` resolves to ${ips.length} address${ips.length === 1 ? '' : 'es'}:`),
          h(
            'div',
            {},
            ips.map((ip) => ipChip(ip, (x) => handlers.onPick?.(x, this.resolvedFrom), { current: ip === info.ip })),
          ),
        ),
      );
    }
    if (this.others.length) {
      wrap.append(
        h(
          'div',
          { class: 'resolved-from' },
          h('span', { text: 'Also found in the text: ' }),
          h(
            'div',
            {},
            this.others.slice(0, 12).map((ip) => ipChip(ip, (x) => handlers.onPick?.(x))),
          ),
        ),
      );
    }

    if (!scope.isPublic) {
      wrap.append(renderScopeNote(info, scope));
      this.root.append(wrap);
      return;
    }

    this.overviewSlot = h('div', { class: 'overview-slot', style: 'margin-top:2px' });
    wrap.append(this.overviewSlot);

    // Key/IPv6 notices sit under the reputation sources, which they mostly concern.
    this.noticeSlot = h('div', {});
    for (const [category, label] of Object.entries(CATEGORY_LABELS)) {
      const cols = this.mode === 'page' ? [h('div', { class: 'col' }), h('div', { class: 'col' })] : null;
      const list = h('div', { class: 'sources' }, cols);
      const section = h(
        'section',
        { class: 'source-section', hidden: true },
        h('h2', { class: 'section-title', text: label }),
        list,
        category === 'reputation' ? this.noticeSlot : null,
      );
      this.sections.set(category, { section, list, cols, count: 0 });
      wrap.append(section);
    }

    wrap.append(renderQuickLinks(info.ip));
    this.root.append(wrap);
    this.flushSummary();
  }

  toolButton(iconName, label, title, onClick) {
    const showLabel = this.mode === 'page';
    return h(
      'button',
      {
        class: showLabel ? 'btn btn-sm' : 'icon-btn',
        type: 'button',
        title,
        'aria-label': title,
        onclick: (e) => onClick(e.currentTarget),
      },
      icon(iconName, { size: showLabel ? 13 : 16 }),
      showLabel ? h('span', { class: 'btn-label', text: label }) : null,
    );
  }

  defaultOpen(state) {
    return this.mode === 'page' && (state.status === 'done' || state.status === 'error');
  }

  hasCards(category) {
    return this.providers.some((p) => p.category === category && this.cards.has(p.id));
  }

  update(id, states) {
    this.states = states;
    const provider = this.providers.find((p) => p.id === id);
    const state = states[id];
    if (!provider || !state || !this.sections.size) return;
    const entry = this.sections.get(provider.category);
    const existing = this.cards.get(id);

    if (state.status === 'needs-key' || state.status === 'unsupported') {
      existing?.remove();
      this.cards.delete(id);
    } else {
      const open = this.userOpen.has(id) ? this.userOpen.get(id) : this.defaultOpen(state);
      const card = renderSourceCard(provider, state, {
        ip: this.info.ip,
        open,
        compact: this.mode === 'popup',
        onRetry: this.handlers.onRetry,
        onOpenOptions: this.handlers.onOpenOptions,
      });
      card.addEventListener('toggle', () => {
        if (state.status !== 'loading') this.userOpen.set(id, card.open);
      });
      if (existing) {
        card.style.order = existing.style.order;
        existing.replaceWith(card);
      } else {
        // runLookup reports every source's first state synchronously and in
        // display order, so appending preserves order. On the full page,
        // cards alternate between two columns that stack independently.
        const n = entry.count++;
        card.style.order = String(n);
        (entry.cols ? entry.cols[n % 2] : entry.list).append(card);
      }
      this.cards.set(id, card);
    }
    entry.section.hidden = !this.hasCards(provider.category);
    this.queueSummary();
  }

  queueSummary() {
    if (this.summaryQueued) return;
    this.summaryQueued = true;
    queueMicrotask(() => {
      this.summaryQueued = false;
      this.flushSummary();
    });
  }

  flushSummary() {
    if (!this.overviewSlot) return;
    const summary = summarize(this.states, this.providers);
    this.overviewSlot.replaceChildren(renderOverview(summary));
    const notices = renderNotices(this.states, this.providers, { onOpenOptions: this.handlers.onOpenOptions });
    this.noticeSlot.replaceChildren(...notices);
    const reputation = this.sections.get('reputation');
    if (reputation) reputation.section.hidden = !this.hasCards('reputation') && notices.length === 0;
  }
}

/* ------------------------------------------------------------------ */

export function renderHome(root, { history, pageIps, onPick, onMyIp, onClearHistory, mode }) {
  clear(root);
  const wrap = h('div', { class: 'home' });

  if (pageIps?.length) {
    wrap.append(
      h('h2', {}, icon('page', { size: 12 }), ' On this page'),
      h(
        'div',
        { class: 'chip-row' },
        pageIps.slice(0, 18).map((ip) => ipChip(ip, onPick)),
        pageIps.length > 18 ? h('span', { class: 'chip-row-label', text: `+${pageIps.length - 18} more` }) : null,
      ),
    );
  }

  if (history?.length) {
    wrap.append(
      h(
        'h2',
        { style: 'display:flex;align-items:center;gap:6px' },
        icon('history', { size: 12 }),
        ' Recent',
        onClearHistory
          ? h('button', {
              class: 'btn btn-sm',
              type: 'button',
              style: 'margin-left:auto;height:20px;font-size:11px',
              onclick: onClearHistory,
              text: 'Clear',
            })
          : null,
      ),
      h(
        'div',
        { class: 'chip-row' },
        history.slice(0, mode === 'popup' ? 12 : 25).map((e) => ipChip(e.ip, onPick, { verdict: e.verdict || 'none' })),
      ),
    );
  }

  const tip = h(
    'div',
    { class: 'tip' },
    h('strong', { text: 'Tips' }),
    h(
      'ul',
      { style: 'margin:4px 0 0;padding-left:18px' },
      h(
        'li',
        {},
        'Paste an IP, a hostname, a URL or a whole log line. Defanged IOCs like ',
        h('span', { class: 'mono', text: '1.2.3[.]4' }),
        ' work too.',
      ),
      h('li', {}, 'Select an IP on any page, right-click and choose ', h('em', { text: 'Scout with ipScout' }), '.'),
      h('li', {}, 'In the address bar, type ', h('span', { class: 'kbd', text: 'ip' }), ', a space, then the address.'),
    ),
    onMyIp
      ? h(
          'div',
          { style: 'margin-top:8px' },
          h(
            'button',
            { class: 'btn btn-sm', type: 'button', onclick: (e) => onMyIp(e.currentTarget) },
            icon('locate', { size: 13 }),
            'Look up my public IP',
          ),
        )
      : null,
  );
  wrap.append(tip);
  root.append(wrap);
}

export function renderMessage(root, { title, detail, busy = false }) {
  clear(root);
  root.append(
    h(
      'div',
      { class: 'results' },
      h(
        'div',
        { class: 'scope-note', style: 'display:flex;gap:10px;align-items:flex-start' },
        busy ? h('span', { class: 'spinner', style: 'margin-top:4px' }) : icon('info'),
        h('div', {}, h('strong', { text: title }), detail ? h('div', { text: detail }) : null),
      ),
    ),
  );
}

export { append };
