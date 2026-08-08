// A smoke test for the browser interface, run under Node with a stub DOM.
//
// It exists because two functions were lost to careless block edits and neither
// static syntax checking nor eyeballing caught them: `node --check` proves the
// file parses, not that calling anything in it works, and the browser reports
// only the first missing name before the page goes blank. This loads the real
// app.js, answers its requests with canned data, and drives every screen —
// which is the cheapest way to find a reference that no longer resolves.
//
//   node web/smoke.mjs
//
// Exit status is non-zero when anything threw, so it can gate a release.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, 'app.js'), 'utf8');
const html = readFileSync(join(here, 'index.html'), 'utf8');

// Every id the markup actually has, so a lookup for one that does not exist
// returns null exactly as the browser would.
const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
const classes = new Set(
  [...html.matchAll(/class="([^"]+)"/g)].flatMap((m) => m[1].split(/\s+/)).filter(Boolean));

const problems = [];

function element(name) {
  const el = {
    _name: name,
    dataset: {},
    style: {},
    classList: {
      add() {}, remove() {}, toggle() {}, contains: () => false,
    },
    value: 'day',
    checked: false,
    textContent: '',
    innerHTML: '',
    disabled: false,
    setAttribute() {},
    getAttribute: () => null,
    addEventListener() {},
    removeEventListener() {},
    querySelector: () => element(name + ' >'),
    querySelectorAll: () => [],
    closest: () => null,
    focus() {}, click() {}, remove() {}, appendChild() {},
  };
  return el;
}

const document = {
  querySelector(sel) {
    if (sel.startsWith('#')) {
      const id = sel.slice(1).split(/[ .[]/)[0];
      if (!ids.has(id)) {
        problems.push(`querySelector('${sel}') — no such id in index.html`);
        return null;
      }
    }
    return element(sel);
  },
  querySelectorAll(sel) {
    const first = sel.replace(/^[^.#]*/, '');
    if (first.startsWith('.')) {
      const cls = first.slice(1).split(/[ .[:]/)[0];
      if (cls && !classes.has(cls)) problems.push(`querySelectorAll('${sel}') — no element carries .${cls}`);
    }
    return [element(sel), element(sel)];
  },
  addEventListener() {},
  createElement: () => element('created'),
  body: element('body'),
};

// Canned answers shaped like the real ones, including the awkward cases: an
// empty history, a node with no latency, a subscription that carries no rules.
const responses = {
  '/api/status': {
    connected: true, mode: 'tun', uptime_seconds: 3600, cores: [{ name: 'sing-box', state: 'running', restarts: 0 }],
    node_count: 5, usable_count: 5, core_breakdown: { 'sing-box': 2, xray: 3 },
    rule_count: 3, provider_rule_count: 119, split: 'proxy-list', subscription_count: 1,
    selected_node: 'node-a', selected_name: 'RU-11', zapret: true, version: '0.2.0',
  },
  '/api/host': { os: 'OpenWrt 24.10.4', uptime_seconds: 90000 },
  '/api/traffic': {
    available: true, up: 1200, down: 34000, upload_total: 5e5, download_total: 9e6, connections: 12,
    history: Array.from({ length: 40 }, (_, i) => ({ at: new Date(Date.now() - i * 1000).toISOString(), up: i * 7, down: i * 900 })),
  },
  '/api/history?period=day': {
    available: true, up_total: 1e8, down_total: 9e8, size_bytes: 16384,
    points: Array.from({ length: 24 }, (_, i) => ({ at: new Date(Date.now() - i * 3.6e6).toISOString(), up: i * 1e5, down: i * 1e6 })),
  },
  '/api/connections': {
    total: 3, proxied: 2, direct: 1,
    devices: [{ ip: '192.168.1.31', name: 'PC', connections: 2, up: 10, down: 900 }, { ip: '172.19.0.1', name: 'this router', connections: 1, up: 1, down: 1 }],
    destinations: [{ host: 'meduza.io', connections: 2, up: 5, down: 800, proxied: 2 }],
  },
  '/api/health': {
    internet_ok: true, tunnel_ok: true,
    internet: [{ host: 'yandex.ru', ok: true, status: 302, ms: 150 }],
    tunnel: [{ host: 'rutracker.net', ok: false, error: 'timed out' }],
  },
  '/api/settings': {
    mode: 'tun', split: 'proxy-list', proxy_group: 'proxy',
    dns: { proxy: 'https://1.1.1.1/dns-query', direct: 'udp://1.1.1.1', fake_ip: false, listen: 24053 },
    firewall: { manage: true, zapret: 'share', kill_switch: false, block_quic: false },
  },
  '/api/rules': {
    rules: [{ id: 'a', value: 'meduza.io', kind: 'domain-suffix', action: 'proxy', enabled: true }],
    provider: [{ id: 'p', value: 'sberbank.ru', kind: 'domain-suffix', action: 'direct', enabled: true, origin: 'Stasis' }],
    conflicts: [], summary: { enabled: 1 },
  },
  '/api/nodes': [{
    id: 'n', tag: 'node-a', name: 'RU-11', protocol: 'trojan', transport: 'ws', security: 'tls',
    server: 'a.example.com', port: 443, source_id: 's', core: 'sing-box', usable: true, measured: true, delay: 120, active: true,
  }],
  '/api/subscriptions': [{ id: 's', name: 'Stasis', url: 'https://example.com/sub', enabled: true, import_rules: true, format: 'xray', rule_count: 119 }],
  '/api/user-agents': [{ name: 'Obelisk', value: 'Obelisk/0.1' }],
  '/api/cores': [{ kind: 'sing-box', installed: '1.13.16', available: '1.13.16', managed: true }],
  '/api/logs?name=&n=200': [],
  '/api/nodes/stats': {},
};

function answer(path) {
  if (path in responses) return responses[path];
  const base = path.split('?')[0];
  if (base in responses) return responses[base];
  if (base.startsWith('/api/history')) return responses['/api/history?period=day'];
  if (base.startsWith('/api/logs')) return [];
  return {};
}

const context = {
  document,
  console,
  localStorage: { getItem: () => 'token', setItem() {}, removeItem() {} },
  location: { hash: '', reload() {} },
  setTimeout: () => 0,
  clearTimeout() {},
  setInterval: () => 0,
  clearInterval() {},
  EventSource: class { constructor() { this.onmessage = null; } close() {} addEventListener() {} },
  fetch: async (url) => ({
    ok: true, status: 200,
    text: async () => JSON.stringify(answer(url.replace(/^https?:\/\/[^/]+/, ''))),
  }),
  structuredClone: (v) => JSON.parse(JSON.stringify(v)),
};
context.window = context;
context.globalThis = context;

vm.createContext(context);
try {
  // The file ends with a DOMContentLoaded hookup; running it defines everything.
  vm.runInContext(source, context, { filename: 'app.js' });
} catch (e) {
  console.error('app.js threw while loading:', e.message);
  process.exit(1);
}

// Drive every screen the user can reach, and the actions on the dashboard.
const screens = ['loadDashboard', 'loadConnections', 'loadHealth', 'loadHistory', 'loadTraffic',
  'loadRouting', 'loadNodes', 'loadCores', 'loadSettings', 'loadLogs', 'loadHost'];

for (const name of screens) {
  const fn = context[name];
  if (typeof fn !== 'function') {
    problems.push(`${name} is not defined — the interface calls it`);
    continue;
  }
  try {
    await fn();
  } catch (e) {
    problems.push(`${name}() threw: ${e.message}`);
  }
}

// bind() is where a missing handler shows up as a blank page.
try {
  if (typeof context.bind !== 'function') problems.push('bind is not defined');
  else context.bind();
} catch (e) {
  problems.push(`bind() threw: ${e.message}`);
}

for (const name of ['togglePower', 'setSplit', 'switchView', 'quick', 'firewallToggle', 'drawSparkline']) {
  if (typeof context[name] !== 'function') problems.push(`${name} is not defined`);
}

if (problems.length) {
  console.error('\nweb interface smoke test FAILED:');
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log('web interface smoke test passed: every screen rendered and every handler resolved');
