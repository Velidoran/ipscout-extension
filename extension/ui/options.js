import { extLink, h, icon } from './dom.js';
import { CATEGORY_LABELS, PROVIDERS } from '../lib/providers/index.js';
import { clearHistory, createCache, getSettings, saveSettings } from '../lib/storage.js';

const $ = (id) => document.getElementById(id);
let settings = await getSettings();

for (const el of document.querySelectorAll('[data-icon]')) el.prepend(icon(el.dataset.icon, { size: Number(el.dataset.iconSize) || 16 }));

/* --------------------------------------------------------------- save */

let toastTimer;
function toast(message) {
  const el = $('toast');
  el.replaceChildren(icon('check', { size: 14 }), message);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
}

let saveTimer;
function save({ debounce = 0 } = {}) {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    settings = await saveSettings(settings);
    toast('Saved');
  }, debounce);
}

/* ---------------------------------------------------------- providers */

const keyless = PROVIDERS.filter((p) => !p.key?.required);
$('sources-lede').textContent =
  `${keyless.length} of ${PROVIDERS.length} sources work without any setup. ` +
  'The rest need a free API key, which takes a minute to create. Every source can be switched off.';

if (new URLSearchParams(location.search).has('welcome')) {
  const needKeys = PROVIDERS.filter((p) => p.key?.required).map((p) => p.name);
  $('welcome-text').textContent = ` ${keyless.length} sources are ready to go. Add free API keys below to unlock ${needKeys.join(', ')}.`;
  $('welcome').hidden = false;
}

function keyBadge(provider) {
  const hasKey = Boolean(String(settings.keys[provider.id] || '').trim());
  if (!provider.key) return h('span', { class: 'badge ok', text: 'No key needed' });
  if (hasKey) return h('span', { class: 'badge ok', text: 'Key added' });
  if (provider.key.required) return h('span', { class: 'badge req', text: 'Needs free key' });
  return h('span', { class: 'badge opt', text: 'Key optional' });
}

function providerRow(provider) {
  const enabled = settings.enabled[provider.id] !== false;
  const badgeSlot = h('span', {}, keyBadge(provider));
  const row = h('div', { class: `provider-row${enabled ? '' : ' is-disabled'}`, dataset: { provider: provider.id } });

  const toggle = h('input', {
    type: 'checkbox',
    checked: enabled,
    'aria-label': `Use ${provider.name}`,
    onchange: () => {
      if (toggle.checked) delete settings.enabled[provider.id];
      else settings.enabled[provider.id] = false;
      row.classList.toggle('is-disabled', !toggle.checked);
      save();
    },
  });

  const main = h(
    'div',
    { class: 'provider-main' },
    h(
      'div',
      { class: 'provider-title' },
      h('strong', { text: provider.name }),
      badgeSlot,
      h('span', { class: 'badge', text: CATEGORY_LABELS[provider.category] }),
      provider.ipv6 ? null : h('span', { class: 'badge', text: 'IPv4 only' }),
    ),
    h('p', { class: 'provider-desc', text: provider.description }),
    h(
      'div',
      { class: 'provider-tier' },
      `Free tier: ${provider.freeTier} · `,
      extLink(provider.homepage, new URL(provider.homepage).hostname),
    ),
  );

  if (provider.key) {
    const input = h('input', {
      type: 'password',
      value: settings.keys[provider.id] || '',
      placeholder: provider.key.required ? 'Paste your API key' : 'Optional API key',
      autocomplete: 'off',
      spellcheck: 'false',
      'aria-label': `${provider.name} API key`,
      oninput: () => {
        const value = input.value.trim();
        if (value) settings.keys[provider.id] = value;
        else delete settings.keys[provider.id];
        badgeSlot.replaceChildren(keyBadge(provider));
        save({ debounce: 500 });
      },
    });
    const reveal = h(
      'button',
      {
        class: 'icon-btn',
        type: 'button',
        title: 'Show or hide key',
        'aria-label': `Show or hide ${provider.name} key`,
        onclick: () => {
          input.type = input.type === 'password' ? 'text' : 'password';
        },
      },
      icon('eye', { size: 15 }),
    );
    main.append(
      h(
        'div',
        { class: 'key-row' },
        h('div', { class: 'key-input' }, input, reveal),
        h(
          'a',
          { class: 'btn btn-sm', href: provider.key.url, target: '_blank', rel: 'noopener noreferrer' },
          icon('key', { size: 13 }),
          provider.key.required ? 'Get a free key' : 'Get a key',
        ),
        provider.key.hint ? h('div', { class: 'key-hint', text: provider.key.hint }) : null,
      ),
    );
  }

  row.append(h('label', { class: 'switch' }, toggle, h('span', { class: 'track' })), main);
  return row;
}

$('providers').replaceChildren(...PROVIDERS.map(providerRow));

/* ------------------------------------------------------------ general */

for (const id of ['cacheTtlMinutes', 'abuseipdbMaxAgeDays']) {
  const select = $(id);
  select.value = String(settings[id]);
  select.addEventListener('change', () => {
    settings[id] = Number(select.value);
    save();
  });
}

for (const id of ['abuseipdbFetchReports', 'autoLookupSelection', 'scanPage', 'defangOnCopy']) {
  const box = $(id);
  box.checked = Boolean(settings[id]);
  box.addEventListener('change', () => {
    settings[id] = box.checked;
    save();
  });
}

/* -------------------------------------------------------------- about */

const { version, homepage_url: homepage } = chrome.runtime.getManifest();
$('about').append(`ipScout ${version} · `, extLink(homepage, 'Source code and issue tracker on GitHub'), ' · MIT License');

/* --------------------------------------------------------------- data */

$('clear-cache').addEventListener('click', async () => {
  const removed = await createCache({ ttlMs: 1 }).clear();
  $('data-status').textContent = removed ? `Removed ${removed} cached result${removed === 1 ? '' : 's'}.` : 'Cache was already empty.';
});

$('clear-history').addEventListener('click', async () => {
  await clearHistory();
  $('data-status').textContent = 'Lookup history cleared.';
});
