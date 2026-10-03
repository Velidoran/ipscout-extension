// Service worker: context menus, omnibox keyword and first-run onboarding.

import { parseQuery } from './lib/ip.js';
import { restrictStorageToExtension } from './lib/storage.js';

// Keep stored API keys out of reach of content scripts. Chrome remembers the
// setting, so applying it whenever the worker starts covers installs and updates.
restrictStorageToExtension();

const MENU_SELECTION = 'ipscout-selection';
const MENU_LINK = 'ipscout-link';

function resultsUrl(query) {
  return chrome.runtime.getURL(`results.html?q=${encodeURIComponent(String(query).slice(0, 4000))}`);
}

function openResults(query, tab) {
  const props = { url: resultsUrl(query) };
  if (tab?.id >= 0) {
    props.index = tab.index + 1;
    props.openerTabId = tab.id;
    props.windowId = tab.windowId;
  }
  chrome.tabs.create(props);
}

chrome.runtime.onInstalled.addListener(({ reason }) => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_SELECTION, title: 'Scout “%s” with ipScout', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU_LINK, title: 'Scout this link’s host with ipScout', contexts: ['link'] });
  });
  if (reason === chrome.runtime.OnInstalledReason.INSTALL) {
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html?welcome=1') });
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_SELECTION && info.selectionText) openResults(info.selectionText, tab);
  else if (info.menuItemId === MENU_LINK && info.linkUrl) openResults(info.linkUrl, tab);
});

/* ------------------------------------------------- address bar: "ip …" */

const escapeXml = (s) => s.replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]);
const DEFAULT_SUGGESTION = 'Scout an IP address, hostname or URL with ipScout';

chrome.omnibox.setDefaultSuggestion({ description: DEFAULT_SUGGESTION });

chrome.omnibox.onInputChanged.addListener((text) => {
  const parsed = parseQuery(text);
  let description = DEFAULT_SUGGESTION;
  if (parsed?.type === 'ip') description = `Scout <match>${escapeXml(parsed.info.ip)}</match> with ipScout`;
  else if (parsed?.type === 'host') description = `Resolve <match>${escapeXml(parsed.host)}</match> and scout its IP`;
  chrome.omnibox.setDefaultSuggestion({ description });
});

chrome.omnibox.onInputEntered.addListener((text, disposition) => {
  const url = resultsUrl(text.trim());
  if (disposition === 'currentTab') chrome.tabs.update({ url });
  else chrome.tabs.create({ url, active: disposition !== 'newBackgroundTab' });
});
