// Obelisk — browser interface.
//
// Plain ES modules against the JSON API, no framework and no build step. The
// whole thing is embedded in the Go binary, so every kilobyte here is a kilobyte
// a router has to hold in flash and hand to a phone over Wi-Fi.

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const STORE_KEY = 'obelisk.token';
let token = localStorage.getItem(STORE_KEY) || '';
let events = null;
let USER_AGENTS = [];

/* ── transport ─────────────────────────────────────────────────────────── */

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (res.status === 401) {
    showLogin();
    throw new Error('authentication required');
  }

  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || `request failed (${res.status})`);
  return data;
}

/* ── chrome ────────────────────────────────────────────────────────────── */

function toast(message, kind = '') {
  const el = $('#toast');
  el.textContent = message;
  el.className = `toast ${kind}`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.add('hidden'), 4200);
}

function showLogin() {
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  if (events) { events.close(); events = null; }
}

function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
}

const escape = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

const rate = (n) => `${bytes(n)}/s`;

function duration(seconds) {
  if (!seconds || seconds < 1) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

/* ── views ─────────────────────────────────────────────────────────────── */

const loaders = {
  dashboard: loadDashboard,
  routing: loadRouting,
  nodes: loadNodes,
  cores: loadCores,
  settings: loadSettings,
  logs: loadLogs,
};

function switchView(name) {
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  location.hash = name;
  loaders[name]?.().catch((e) => toast(e.message, 'bad'));
}

/* ── overview ──────────────────────────────────────────────────────────── */

async function loadDashboard() {
  const s = await api('/status');

  const btn = $('#power-btn');
  btn.classList.toggle('on', s.connected);
  // A tick when it is carrying traffic, a power symbol when it is not. The
  // state has to survive being read by someone who cannot separate the colours.
  btn.querySelector('.power-ico').innerHTML = s.connected
    ? '<path d="M20 6L9 17l-5-5"/>'
    : '<path d="M12 4v8"/><path d="M17.7 7.3a8 8 0 11-11.4 0"/>';
  $('#power-state').textContent = s.connected ? 'Connected' : 'Disconnected';
  $('#power-detail').textContent = s.connected
    ? 'VPN is active and carrying your network'
    : 'Not routing any traffic';
  $('#s-mode-pill').textContent = `${s.mode} mode`;

  $('#version').textContent = s.version;
  $('#s-nodes').textContent = s.node_count;
  $('#s-nodes-sub').textContent = s.usable_count === s.node_count
    ? 'all usable'
    : `${s.node_count - s.usable_count} unusable`;

  $('#s-rules').textContent = s.rule_count + (s.provider_rule_count || 0);
  $('#s-rules-sub').textContent = {
    'proxy-list':  'only these go through the VPN',
    'bypass-list': 'these bypass the VPN, rest goes in',
    'off':         'ignored — everything goes in',
  }[s.split] || '';
  $('#s-mode').textContent = s.mode;
  $('#s-mode-sub').textContent = { tun: 'full L3 capture', tproxy: 'nftables', redirect: 'TCP only', proxy: 'opt-in' }[s.mode] || '';
  $('#s-uptime').textContent = duration(s.uptime_seconds);
  $('#s-server').textContent = s.selected_name || (s.selected_node ? s.selected_node : 'Automatic');
  $('#s-server-sub').textContent = s.selected_node ? 'chosen by you' : 'fastest by latency';

  // The cores tile says which are up rather than listing them twice: the names
  // matter far less than whether anything is running.
  const cores = s.cores || [];
  const up = cores.filter((c) => c.state === 'running');
  $('#s-cores').textContent = up.length ? up.map((c) => c.name).join(' & ') : 'stopped';
  $('#s-cores-sub').textContent = up.length
    ? (cores.some((c) => c.restarts) ? `${cores.reduce((n, c) => n + (c.restarts || 0), 0)} restarts` : 'running')
    : 'not started';
  $('#s-cores-dot').className = `ico-dot ${up.length ? 'on' : ''}`;

  $('#q-autoconnect').checked = !!s.auto_connect;

  $('#error-card').classList.toggle('hidden', !s.last_error);
  $('#error-text').textContent = s.last_error || '';

  // A DPI bypass and a tunnel are individually fine and ruin each other in
  // combination, so the accommodation is stated rather than made silently.
  const zap = $('#zapret-card');
  if (zap) zap.classList.toggle('hidden', !(s.connected && s.zapret));

  await loadTraffic();
  await loadHistory();
  loadConnections().catch(() => {});
  loadHealth().catch(() => {});
}

// What this is running on. Read once at start: a router's name does not change,
// and its uptime is a headline, not a stopwatch.
async function loadHost() {
  let h;
  try { h = await api('/host'); } catch { return; }
  $('#host-os').textContent = h.os || '';
  $('#host-uptime').textContent = h.uptime_seconds ? `Uptime: ${duration(h.uptime_seconds)}` : '';
}

// The big button. Which way it goes is read from the daemon rather than from
// the class on the button: the state can change from the command line, from a
// second browser tab, or because a core died, and acting on a stale idea of it
// would disconnect a tunnel the user was trying to bring up.
async function togglePower() {
  const btn = $('#power-btn');
  if (btn.classList.contains('busy')) return;

  let connected = false;
  try { connected = (await api('/status')).connected; } catch { /* asked below anyway */ }

  btn.classList.add('busy');
  try {
    await api(connected ? '/disconnect' : '/connect', { method: 'POST' });
    toast(connected ? 'Disconnected' : 'Connected', connected ? '' : 'good');
  } catch (e) {
    toast(e.message, 'bad');
  } finally {
    btn.classList.remove('busy');
    await loadDashboard().catch(() => {});
  }
}

// Who on the network is responsible for what is going through right now.
async function loadConnections() {
  let live;
  try { live = await api('/connections'); } catch { return; }

  $('#c-total').textContent = live.total || 0;
  $('#c-split').innerHTML = live.total
    ? `<span class="key key-tunnel"></span>${live.proxied} through the tunnel`
      + ` <span class="key key-direct"></span>${live.direct} direct`
    : 'Nothing open.';

  const bar = (name, sub, value, peak, ratio) => `
    <div class="bar-row">
      <div class="bar-top">
        <span class="bar-name">${escape(name)}${sub ? `<span class="ip">${escape(sub)}</span>` : ''}</span>
        <span class="bar-val">${value}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill ${ratio === undefined ? '' : 'mixed'}"
             style="width:${peak ? Math.max(3, Math.round(peak * 100)) : 3}%${
               ratio === undefined ? '' : `;--split:${Math.round(ratio * 100)}%`}"></div>
      </div>
    </div>`;

  const devices = (live.devices || []).slice(0, 6);
  const devPeak = Math.max(1, ...devices.map((d) => d.down + d.up));
  $('#c-devices').innerHTML = devices.length
    ? devices.map((d) => bar(
        d.name || d.ip, d.name ? d.ip : '',
        `${bytes(d.down + d.up)} · ${d.connections}`,
        (d.down + d.up) / devPeak)).join('')
    : '<div class="bar-empty">No device is using it yet.</div>';

  const dests = (live.destinations || []).slice(0, 6);
  const dstPeak = Math.max(1, ...dests.map((d) => d.down + d.up));
  // The filled part of each bar is the share that went through the tunnel, so
  // one glance says both how busy a destination is and which way it went.
  $('#c-dests').innerHTML = dests.length
    ? dests.map((d) => bar(
        d.host, '',
        `${bytes(d.down + d.up)} · ${d.connections}`,
        (d.down + d.up) / dstPeak,
        d.connections ? d.proxied / d.connections : 0)).join('')
    : '<div class="bar-empty">Nothing open.</div>';
}

async function loadHistory() {
  const period = $('#history-period').value;
  let h;
  try { h = await api(`/history?period=${period}`); } catch { return; }

  const bars = $('#hist-bars');
  const setEmpty = (msg) => {
    bars.innerHTML = ''; $('#hist-y').innerHTML = ''; $('#hist-x').innerHTML = '';
    $('#history-summary').textContent = msg;
  };
  if (!h.available) return setEmpty('This build stores no history.');
  if (!h.points.length) return setEmpty('Nothing recorded for this period yet.');

  const W = 600, H = 150;
  const peak = Math.max(1, ...h.points.map((p) => p.down + p.up));
  const width = W / h.points.length;

  // Stacked bars rather than a line: at hour or day resolution each sample is a
  // total for a period, not an instantaneous rate, and a line would imply a
  // continuity the data does not have.
  bars.innerHTML = h.points.map((p, i) => {
    const x = (i * width).toFixed(2);
    const w = Math.max(0.6, width - Math.min(2, width * 0.25)).toFixed(2);
    const dh = (p.down / peak) * (H - 2);
    const uh = (p.up / peak) * (H - 2);
    return `<rect class="hist-bar" x="${x}" y="${(H - dh).toFixed(2)}" width="${w}" height="${dh.toFixed(2)}"/>`
         + `<rect class="hist-bar up" x="${x}" y="${(H - dh - uh).toFixed(2)}" width="${w}" height="${uh.toFixed(2)}"/>`;
  }).join('');

  gridLines('#hist-grid', H);
  $('#hist-y').innerHTML = [peak, peak / 2, 0].map((v) => `<span>${bytes(v)}</span>`).join('');

  const stamp = (p) => {
    const d = new Date(p.at);
    if (isNaN(d)) return '';
    return period === 'month'
      ? `${d.getDate()}.${String(d.getMonth() + 1).padStart(2, '0')}`
      : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  };
  const pts = h.points;
  $('#hist-x').innerHTML = [0, Math.floor(pts.length / 3), Math.floor(pts.length * 2 / 3), pts.length - 1]
    .map((i, n) => `<span>${n === 3 ? 'Now' : stamp(pts[i] || {})}</span>`).join('');

  const label = { hour: 'in the last hour', day: 'in the last 24 hours', month: 'in the last 30 days' }[period];
  $('#history-summary').textContent =
    `${bytes(h.down_total)} down · ${bytes(h.up_total)} up ${label}` +
    (h.size_bytes ? ` · history uses ${bytes(h.size_bytes)}` : '');
}

async function loadTraffic() {
  let t;
  try { t = await api('/traffic'); } catch { return; }

  $('#t-down').textContent = t.available ? rate(t.down) : '—';
  $('#t-up').textContent = t.available ? rate(t.up) : '—';
  $('#t-summary').textContent = t.available
    ? `${bytes(t.download_total)} down · ${bytes(t.upload_total)} up · ${t.connections} connection${t.connections === 1 ? '' : 's'}`
    : (t.error || 'Not connected.');

  drawSparkline(t.history || []);
}

// The traffic chart answers "how much, and by which route" at once: the height
// is the throughput, and the two bands are the split between what left through
// the tunnel and what went round it. That split used to be a line of text under
// the connections panel, where it said nothing about how it changed.
//
// Stacked rather than overlaid: the two are parts of one total, and overlapping
// them would draw a quantity nobody has — the larger of two shares.
function drawSparkline(history) {
  const W = 600, H = 150, PAD = 6;
  const points = history.slice(-120);

  const area = $('#spark-tunnel'), direct = $('#spark-direct'), total = $('#spark-down');
  if (points.length < 2) {
    for (const el of [area, direct, total]) el.setAttribute('points', '');
    $('#spark-y').innerHTML = ''; $('#spark-x').innerHTML = '';
    return;
  }

  // One scale for both bands. The core's own byte counters and the per-connection
  // figures are collected differently, so the stack can come out a little under
  // the measured total; taking the larger keeps the line inside the box.
  const peak = Math.max(1, ...points.map((p) => Math.max(p.up + p.down, (p.tunnel || 0) + (p.direct || 0))));
  const step = W / (points.length - 1);
  const y = (v) => (H - PAD - (v / peak) * (H - PAD * 2)).toFixed(1);
  const x = (i) => (i * step).toFixed(1);

  const band = (lower, upper) => {
    const top = points.map((p, i) => `${x(i)},${y(upper(p))}`);
    const bottom = points.map((p, i) => `${x(i)},${y(lower(p))}`).reverse();
    return top.concat(bottom).join(' ');
  };

  // Tunnel sits on the baseline, direct is stacked above it.
  area.setAttribute('points', band(() => 0, (p) => p.tunnel || 0));
  direct.setAttribute('points', band((p) => p.tunnel || 0, (p) => (p.tunnel || 0) + (p.direct || 0)));
  total.setAttribute('points', points.map((p, i) => `${x(i)},${y(p.up + p.down)}`).join(' '));

  gridLines('#spark-grid', H);
  $('#spark-y').innerHTML = [peak, peak / 2, 0].map((v) => `<span>${rate(v)}</span>`).join('');

  // Time labels come from the samples themselves rather than from a counter, so
  // a gap in sampling shows as a gap instead of being quietly relabelled.
  const at = (i) => (points[i] && points[i].at ? clock(points[i].at) : '');
  $('#spark-x').innerHTML = [0, Math.floor(points.length / 2), points.length - 1]
    .map((i) => `<span>${at(i)}</span>`).join('');

  // The legend carries the current numbers, so the colours never have to be
  // guessed from the picture alone.
  const last = points[points.length - 1] || {};
  $('#t-tunnel').textContent = rate(last.tunnel || 0);
  $('#t-direct').textContent = rate(last.direct || 0);
}

function clock(iso) {
  const d = new Date(iso);
  return isNaN(d) ? '' : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// Horizontal rules at the quarter marks. Drawn under the data so that a line
// crossing one stays readable.
function gridLines(sel, H) {
  const el = $(sel);
  if (!el) return;
  el.innerHTML = [0.25, 0.5, 0.75, 1].map((f) =>
    `<line class="grid-line" x1="0" y1="${(H * f).toFixed(1)}" x2="600" y2="${(H * f).toFixed(1)}"/>`).join('');
}

// Reachability. Deliberately two verdicts rather than one: a dead line and a
// misrouted tunnel look identical from a browser, and the single "connected"
// light every VPN client shows reports that a process is running, not that
// traffic is arriving anywhere.
async function loadHealth() {
  const h = await api('/health');
  const row = (r) => `<div class="health-row ${r.ok ? 'ok' : 'bad'}">
      <span class="h-host">${escape(r.host)}</span>
      <span class="h-res">${r.ok ? `${r.status} · ${r.ms} ms` : escape(r.error || 'no answer')}</span>
    </div>`;
  $('#h-net').innerHTML = (h.internet || []).map(row).join('');
  $('#h-tun').innerHTML = (h.tunnel || []).map(row).join('');
  $('#h-net-dot').className = `dot ${h.internet_ok ? 'ok' : 'bad'}`;
  $('#h-tun-dot').className = `dot ${h.tunnel_ok ? 'ok' : 'bad'}`;
}

/* ── split tunnel ──────────────────────────────────────────────────────── */

let SPLIT = 'proxy-list';

async function loadRouting() {
  const [data, settings] = await Promise.all([api('/rules'), api('/settings')]);
  SPLIT = settings.split || 'proxy-list';
  renderSplitSwitch(data);
  renderRules(data.rules, data.conflicts);
  renderProviderRules(data.provider || [], await api('/subscriptions').catch(() => []));
  $('#rule-count').textContent = data.rules.length ? `· ${data.summary.enabled} active` : '';
}

// The mode decides what the whole list means, so it is drawn above the list and
// the list is drawn to match it.
function renderSplitSwitch(data) {
  for (const opt of $$('#split-switch .split-opt')) {
    opt.setAttribute('aria-checked', String(opt.dataset.split === SPLIT));
  }

  const inert = (data.rules || []).filter((r) => isInert(r.action)).length;
  const provider = (data.provider || []).length;
  const note = [];

  if (SPLIT === 'off') {
    note.push('Every destination goes through the VPN. The rules below are kept but not consulted.');
  } else {
    note.push(`Anything no rule matches goes <b>${SPLIT === 'bypass-list' ? 'through the tunnel' : 'direct'}</b>.`);
  }
  // The commonest way to end up with a VPN that does nothing: a provider's
  // bypass list under a mode that already sends everything direct.
  if (SPLIT === 'proxy-list' && provider) {
    note.push(`Your subscription shipped ${provider} rules saying what should <em>bypass</em> the tunnel.
      Those only mean something in <b>Bypass the list</b> — in this mode nothing is proxied unless you name it.`);
  }
  if (SPLIT !== 'off' && inert) {
    note.push(`${inert} of your rules already agree with the fallback, so they change nothing here.`);
  }
  $('#split-note').innerHTML = note.join('<br>');

  // What a new entry means follows the mode, because the opposite of the
  // fallback is the only thing worth adding.
  const action = $('#rule-action');
  if (action && !action.dataset.touched) {
    action.value = SPLIT === 'bypass-list' ? 'direct' : 'proxy';
  }
  // With split tunnelling off the lists are kept but not consulted, so they are
  // shown greyed rather than hidden: hiding them would suggest they were lost.
  $('#rule-add-card').classList.toggle('dim', SPLIT === 'off');
  $('#rule-list').classList.toggle('dim', SPLIT === 'off');
  $('#provider-rules').classList.toggle('dim', SPLIT === 'off');
}

// An entry whose action is the same as the fallback cannot change any outcome.
function isInert(action) {
  if (SPLIT === 'off') return true;
  return action === (SPLIT === 'bypass-list' ? 'proxy' : 'direct');
}

async function setSplit(mode) {
  if (mode === SPLIT) return;
  const settings = await api('/settings');
  settings.split = mode;
  await api('/settings', { method: 'PUT', body: settings });
  SPLIT = mode;
  await loadRouting();
  await loadDashboard().catch(() => {});
}

// Rules the subscription shipped. They are shown separately and cannot be
// edited here, because they are not the user's to edit: every refresh rebuilds
// them from the provider's list, and a change made here would vanish silently.
// They sit below the user's rules, so anything above wins.
function renderProviderRules(rules, subscriptions = []) {
  const box = $('#provider-rules');

  // Explain an empty list rather than showing nothing. The usual reason is not a
  // failure at all: a subscription that is a list of share links has nowhere to
  // put routing rules, and only sing-box or Clash documents can carry them.
  if (!rules.length) {
    if (!subscriptions.length) { box.innerHTML = ''; return; }
    const linkLists = subscriptions.filter((s) => ['links', 'base64', 'uri'].includes(s.format));
    const off = subscriptions.filter((s) => !s.import_rules);
    box.innerHTML = `
      <div class="card">
        <h3>From your subscriptions <span class="muted">· none</span></h3>
        <p class="muted small">Some providers ship a list of what should bypass the tunnel —
          local banking, government sites, their own CDN — and Obelisk applies it beneath your own rules.
          ${linkLists.length ? `<br><br><b>${escape(linkLists.map((s) => s.name || s.url).join(', '))}</b>
            ${linkLists.length === 1 ? 'is a list of share links' : 'are lists of share links'},
            which cannot carry routing rules. Only sing-box and Clash configurations can.` : ''}
          ${off.length ? `<br><br>Rules from <b>${escape(off.map((s) => s.name || s.url).join(', '))}</b>
            are switched off — turn them on with the ⇄ icon under Servers.` : ''}
        </p>
      </div>`;
    return;
  }

  const bySource = {};
  for (const r of rules) (bySource[r.origin || 'subscription'] ||= []).push(r);

  box.innerHTML = `
    <div class="card">
      <div class="card-head">
        <h3>From your subscriptions <span class="muted">· ${rules.length}</span></h3>
        <span class="muted small">Applied below your own rules — anything above wins</span>
      </div>
      <p class="muted small">Providers ship a list of what should bypass the tunnel — local banking,
        government sites, their own CDN. These are rebuilt on every refresh and disappear with the
        subscription. Your rules are never touched by them. Turn a provider's list off under Subscriptions.</p>
      ${Object.entries(bySource).map(([source, items]) => `
        <div class="rules">
          ${items.slice(0, 40).map((r) => `
            <div class="rule ${isInert(r.action) ? 'rule-inert' : ''}">
              <span class="badge ${escape(r.action)}">${escape(r.action)}</span>
              <span class="val">${escape(r.value)}</span>
              <span class="meta">${escape(kindLabel(r.kind))} · ${escape(source)}</span>
            </div>`).join('')}
          ${items.length > 40 ? `<div class="rule"><span class="muted">…and ${items.length - 40} more from ${escape(source)}</span></div>` : ''}
        </div>`).join('')}
    </div>`;
}

function renderRules(rules, conflicts) {
  const list = $('#rule-list');
  if (!rules.length) {
    list.innerHTML = `<div class="rule"><span class="muted">
      Nothing routed yet. Add a domain or address above to send it through the tunnel.</span></div>`;
  } else {
    list.innerHTML = rules.map((r, i) => `
      <div class="rule ${r.enabled ? '' : 'off'} ${isInert(r.action) ? 'rule-inert' : ''}">
        <span class="idx">${i + 1}</span>
        <span class="badge ${escape(r.action)}">${escape(r.action)}</span>
        ${SPLIT !== 'off' && isInert(r.action)
          ? '<span class="badge inert" title="This is already what unmatched traffic does, so the rule changes nothing">no effect</span>'
          : ''}
        <span class="val">${escape(r.value)}</span>
        <span class="meta">${escape(kindLabel(r.kind))}${
          r.sources?.length ? ` · ${escape(r.sources.join(', '))}` : ''}${
          r.comment ? ` · ${escape(r.comment)}` : ''}</span>
        <span class="acts">
          ${i > 0 ? `<button class="btn btn-sm" data-move="${escape(r.id)}" data-to="${i - 1}" title="Move up">↑</button>` : ''}
          <button class="btn btn-sm" data-toggle="${escape(r.id)}" data-enabled="${!r.enabled}">${r.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-danger" data-del="${escape(r.id)}">Remove</button>
        </span>
      </div>`).join('');
  }

  const box = $('#conflicts');
  if (!conflicts?.length) { box.innerHTML = ''; return; }

  // A shadowed rule is invisible trouble: it sits in the list looking correct
  // while never taking effect. Say which rule buried it and offer the fix.
  const harmful = conflicts.filter((c) => c.harmful);
  box.innerHTML = `
    <div class="notice ${harmful.length ? 'warn' : 'plain'}">
      <b>${conflicts.length} rule${conflicts.length === 1 ? '' : 's'} can never match.</b>
      Rules are evaluated top to bottom and the first match wins, so a specific rule
      has to sit above the general one it carves out of.
      <ul>${conflicts.map((c) => `<li>
        <code>${escape(c.entry.value)}</code> — ${escape(c.reason)}
        ${c.harmful ? `<button class="btn btn-sm" data-move="${escape(c.entry.id)}" data-to="${c.shadowed_by}">Move it above</button>` : ''}
      </li>`).join('')}</ul>
    </div>`;
}

function kindLabel(kind) {
  return {
    'domain-suffix': 'domain + subdomains',
    'domain': 'exact domain',
    'domain-keyword': 'keyword',
    'domain-regex': 'regex',
    'ip-cidr': 'network',
    'rule-set': 'external list',
  }[kind] || kind;
}

async function addRules() {
  const text = $('#rule-input').value.trim();
  if (!text) return;

  const sources = $('#rule-sources').value.split(',').map((s) => s.trim()).filter(Boolean);
  const res = await api('/rules', {
    method: 'POST',
    body: { text, action: $('#rule-action').value, sources },
  });

  // Report exactly how each line was understood. Silently reinterpreting a
  // user's input is how a rule ends up not doing what they believe it does.
  const parts = [];
  if (res.added.length) {
    parts.push(`<div class="notice good"><b>Added ${res.added.length}:</b><ul>${
      res.added.map((e) => `<li><code>${escape(e.value)}</code> — ${escape(kindLabel(e.kind))}${
        e.note ? `<br><span class="muted small">${escape(e.note)}</span>` : ''}</li>`).join('')}</ul></div>`);
  }
  if (res.rejected.length) {
    parts.push(`<div class="notice bad"><b>Could not read ${res.rejected.length}:</b><ul>${
      res.rejected.map((r) => `<li><code>${escape(r.text)}</code> — ${escape(r.error)}</li>`).join('')}</ul></div>`);
  }
  $('#rule-feedback').innerHTML = parts.join('');
  $('#rule-input').value = '';
  await loadRouting();
}

async function testRoute() {
  const destination = $('#test-dest').value.trim();
  if (!destination) return;

  const res = await api('/rules/test', {
    method: 'POST',
    body: { destination, from: $('#test-from').value.trim() },
  });

  const kind = { proxy: 'good', direct: 'plain', block: 'bad' }[res.effective] || 'plain';
  const verb = { proxy: 'goes through the tunnel', direct: 'goes direct', block: 'is blocked' }[res.effective];
  $('#test-result').innerHTML = `
    <div class="notice ${kind}">
      <b>${escape(destination)}</b> ${escape(verb || res.effective)}.<br>
      <span class="muted small">${escape(res.decision.explanation)}${
        res.decision.matched ? ` · rule #${res.decision.index + 1}` : ''}</span>
    </div>`;
}

/* ── servers ───────────────────────────────────────────────────────────── */

async function loadNodes() {
  if (!USER_AGENTS.length) USER_AGENTS = await api('/user-agents').catch(() => []);
  const [nodes, subscriptions] = await Promise.all([api('/nodes'), api('/subscriptions')]);
  $('#nodes-sub').textContent =
    `${nodes.length} server${nodes.length === 1 ? '' : 's'} from ${subscriptions.length} subscription${subscriptions.length === 1 ? '' : 's'}`;

  // Servers live under the subscription they came from. A VPN client has no
  // reason to make someone hold two lists in their head and match them up.
  const groups = subscriptions.map((sub) => ({
    sub,
    nodes: nodes.filter((n) => n.source_id === sub.id),
  }));
  const orphans = nodes.filter((n) => !subscriptions.some((s) => s.id === n.source_id));
  if (orphans.length) groups.push({ sub: null, nodes: orphans });

  const box = $('#node-groups');
  if (!groups.length) {
    box.innerHTML = '<div class="notice plain">No subscriptions yet. Add one above.</div>';
    return;
  }
  box.innerHTML = groups.map(renderGroup).join('');
}

function renderGroup({ sub, nodes }) {
  const id = sub ? escape(sub.id) : '';
  const title = sub ? escape(sub.name || sub.url) : 'Added by hand';

  // The two things anyone wants next to a subscription: fetch it again, and
  // find out whether its servers are alive. Icons, on the heading, where the
  // thing they act on is.
  const actions = sub ? `
    <button class="icon-btn" data-sub-refresh="${id}" title="Fetch this subscription again" aria-label="Refresh subscription">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 3v6h-6"/></svg>
    </button>
    <button class="icon-btn" data-sub-test="${id}" title="Measure latency of these servers" aria-label="Measure latency">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20a8 8 0 108-8"/><path d="M12 12l5-4"/></svg>
    </button>
    <button class="icon-btn" data-sub-rules="${id}" data-enabled="${!sub.import_rules}"
      title="${sub.import_rules ? 'Ignore the routing rules this provider ships' : 'Use the routing rules this provider ships'}" aria-label="Provider rules">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" ${sub.import_rules ? '' : 'opacity="0.4"'}><path d="M4 7h6l4 10h6"/><path d="M17 4l3 3-3 3"/></svg>
    </button>
    <button class="icon-btn danger" data-sub-del="${id}" title="Remove this subscription" aria-label="Remove">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M5 7h14M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>
    </button>` : '';

  return `
    <div class="card group ${sub && !sub.enabled ? 'off' : ''}">
      <div class="group-head">
        <div class="grow">
          <div class="title">${title}</div>
          <div class="sub">${sub ? escape(sub.url) : `${nodes.length} server${nodes.length === 1 ? '' : 's'}`}</div>
          ${sub && sub.last_error ? `<div class="sub error">${escape(sub.last_error)}</div>` : ''}
        </div>
        ${sub ? formatBadge(sub) : ''}
        <span class="badge">${nodes.length} server${nodes.length === 1 ? '' : 's'}</span>
        ${actions}
      </div>
      ${sub ? userAgentPicker(sub) : ''}
      ${nodes.length ? `<div class="server-list">${nodes.map(renderNode).join('')}</div>`
                     : '<p class="muted small">No usable servers from this subscription.</p>'}
    </div>`;
}

// What the panel actually served. It matters because only some formats carry the
// provider's routing, and a panel decides which to send from the name the client
// gives — so seeing "base64" here is the whole explanation for an empty rule list.
function formatBadge(sub) {
  if (!sub.format) return '';
  const rich = ['xray', 'sing-box', 'clash'].includes(sub.format);
  const title = rich
    ? `${sub.format} — carries routing rules${sub.rule_count ? ` (${sub.rule_count} imported)` : ''}`
    : `${sub.format} — a plain server list, which cannot carry routing rules. Try another identity below.`;
  return `<span class="badge ${rich ? 'direct' : ''}" title="${escape(title)}">${escape(sub.format)}</span>`;
}

function userAgentPicker(sub) {
  const current = sub.user_agent || '';
  const options = USER_AGENTS.map((p) =>
    `<option value="${escape(p.value)}" ${p.value === current ? 'selected' : ''}>${escape(p.label)}</option>`).join('');
  const known = USER_AGENTS.some((p) => p.value === current);
  return `
    <div class="ua-row">
      <span class="muted small">Identify as</span>
      <select data-sub-ua="${escape(sub.id)}">
        ${options}
        ${known ? '' : `<option value="${escape(current)}" selected>${escape(current || '(default)')}</option>`}
      </select>
      <span class="muted small">Panels serve different formats to different clients; only some carry routing rules.</span>
    </div>`;
}

function renderNode(n) {
  return `
    <div class="server ${n.active ? 'active' : ''} ${n.usable ? '' : 'dead'}"
         ${n.usable && n.tag ? `data-node-select="${escape(n.tag)}" role="button" tabindex="0"` : ''}
         ${n.usable ? '' : `title="${escape(n.reason)}"`}>
      <span class="pick" aria-hidden="true"></span>
      <div class="grow">
        <div class="title">${escape(n.name)}</div>
        <div class="sub">${escape(n.server)}:${n.port}</div>
      </div>
      ${latencyBadge(n)}
      ${specBadges(n)}
      ${n.usable ? `<span class="badge ${n.core === 'xray' ? 'xray' : 'singbox'}">${escape(n.core || '—')}</span>`
                 : '<span class="badge dead">unsupported</span>'}
    </div>`;
}

// Protocol, transport and TLS — what actually distinguishes one server from
// another once they all say "RU-11". A bare protocol name does not: two trojan
// nodes, one over websocket and one over gRPC with REALITY, behave nothing alike
// on a network that is filtering.
function specBadges(n) {
  const out = [`<span class="badge spec-proto">${escape(n.protocol)}</span>`];

  // "tcp" is the absence of a transport rather than a choice of one, so it adds
  // nothing to a row that is already busy.
  if (n.transport && n.transport !== 'tcp') {
    out.push(`<span class="badge spec-net">${escape(n.transport)}</span>`);
  }
  if (n.security && n.security !== 'none') {
    const reality = n.security === 'reality';
    out.push(`<span class="badge ${reality ? 'spec-reality' : 'spec-tls'}"
      title="${reality ? 'REALITY — borrows a real handshake from a site that is not blocked' : 'TLS'}">${escape(n.security)}</span>`);
  }
  return `<span class="spec">${out.join('')}</span>`;
}

// A node that was measured and came back at zero is unreachable, not instant.
// Rendering it as "0 ms" would sort it to the top as the best server on the list.
function latencyBadge(n) {
  if (!n.measured) return '';
  if (!n.delay) return '<span class="badge lat-dead">unreachable</span>';
  const cls = n.delay < 200 ? 'lat-fast' : n.delay < 500 ? 'lat-ok' : 'lat-slow';
  return `<span class="badge ${cls}">${n.delay} ms</span>`;
}

async function addSubscription() {
  const url = $('#sub-url').value.trim();
  if (!url) return;

  $('#sub-feedback').innerHTML = '<div class="notice plain">Fetching…</div>';
  try {
    await api('/subscriptions', { method: 'POST', body: { name: $('#sub-name').value.trim(), url } });
    $('#sub-url').value = ''; $('#sub-name').value = '';
    $('#sub-feedback').innerHTML = '<div class="notice good">Subscription added.</div>';
  } catch (e) {
    $('#sub-feedback').innerHTML = `<div class="notice bad">${escape(e.message)}</div>`;
  }
  await loadNodes();
}

/* ── cores ─────────────────────────────────────────────────────────────── */

async function loadCores() {
  const list = await api('/cores');
  $('#core-list').innerHTML = list.map((c) => {
    const installed = c.installed;
    return `
    <div class="row-card">
      <div class="grow">
        <div class="title">${escape(c.kind)}</div>
        <div class="sub">${installed ? escape(installed.path) : 'not installed'}</div>
      </div>
      <span class="badge">${installed ? escape(installed.version) : '—'}</span>
      ${c.available ? `<span class="badge ${c.update_available ? 'proxy' : ''}">latest ${escape(c.available.version)}</span>` : ''}
      ${installed && installed.managed
        ? `<span class="badge ${installed.verified ? 'direct' : ''}" title="${
            installed.verified ? 'publisher checksum verified' : 'no publisher checksum is available for this project'}">${
            installed.verified ? 'verified' : 'unverified'}</span>`
        : ''}
      <button class="btn btn-sm ${c.update_available ? 'btn-primary' : ''}" data-core-update="${escape(c.kind)}">
        ${c.update_available ? 'Update' : 'Reinstall'}</button>
    </div>
    ${c.error ? `<div class="notice bad small">${escape(c.error)}</div>` : ''}`;
  }).join('');
}

// quick runs a dashboard action with the button disabled for its duration, so
// a slow reconnect cannot be fired three times by an impatient click.
async function quick(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  try {
    await fn();
    await loadDashboard();
  } catch (e) {
    toast(e.message, 'bad');
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

// settingToggle flips one top-level setting, putting the switch back if the
// daemon refuses rather than leaving it showing a state that is not real.
async function settingToggle(key, input, message) {
  const wanted = input.checked;
  try {
    const settings = await api('/settings');
    settings[key] = wanted;
    await api('/settings', { method: 'PUT', body: settings });
    toast(message, 'good');
  } catch (e) {
    input.checked = !wanted;
    toast(e.message, 'bad');
  }
}

// firewallToggle flips one firewall setting and puts it back if the daemon
// refuses, rather than leaving the switch showing a state that is not real.
async function firewallToggle(key, input) {
  const wanted = input.checked;
  try {
    const settings = await api('/settings');
    settings.firewall = { ...settings.firewall, [key]: wanted };
    await api('/settings', { method: 'PUT', body: settings });
    toast(`${key === 'kill_switch' ? 'Kill switch' : 'QUIC blocking'} ${wanted ? 'on' : 'off'}`, 'good');
  } catch (e) {
    input.checked = !wanted;
    toast(e.message, 'bad');
  }
}

/* ── settings ──────────────────────────────────────────────────────────── */

async function loadSettings() {
  const s = await api('/settings');
  $('#set-mode').value = s.mode;
  $('#set-zapret').value = (s.firewall && s.firewall.zapret) || 'share';
  $('#q-autoconnect').checked = !!s.auto_connect;
  $('#q-killswitch').checked = !!(s.firewall && s.firewall.kill_switch);
  $('#q-quic').checked = !!(s.firewall && s.firewall.block_quic);
  $('#zapret-hint').textContent = {
    share:  'zapret desynchronises the direct path as before; its injected packets are routed past the tunnel so they still reach the provider.',
    exempt: 'Nothing the tunnel carries is desynchronised. Safe, but blocked sites on the direct path stay blocked — put them in the tunnel instead.',
    off:    'No accommodation. Measured result on this router: large transfers stopped after 21 kB.',
  }[$('#set-zapret').value] || '';
  $('#set-dns-proxy').value = s.dns.proxy || '';
  $('#set-dns-direct').value = s.dns.direct || '';
  $('#set-fakeip').checked = !!s.dns.fake_ip;
  $('#set-dns-port').value = s.dns.listen || 0;
  loadSettings._current = s;
}

async function saveSettings() {
  const s = structuredClone(loadSettings._current || {});
  s.mode = $('#set-mode').value;
  s.firewall = { ...s.firewall, zapret: $('#set-zapret').value };
  s.dns = {
    ...s.dns,
    proxy: $('#set-dns-proxy').value.trim(),
    direct: $('#set-dns-direct').value.trim(),
    fake_ip: $('#set-fakeip').checked,
    listen: Number($('#set-dns-port').value) || 0,
  };

  await api('/settings', { method: 'PUT', body: s });
  $('#set-feedback').textContent = 'Saved and applied.';
  setTimeout(() => ($('#set-feedback').textContent = ''), 4000);
}

/* ── logs ──────────────────────────────────────────────────────────────── */

async function loadLogs() {
  const core = $('#log-core').value;
  const lines = await api(`/logs?limit=400${core ? `&core=${core}` : ''}`);
  const out = $('#log-out');
  out.textContent = lines?.length
    ? lines.map((l) => `${new Date(l.time).toLocaleTimeString()}  ${l.core.padEnd(9)} ${l.text}`).join('\n')
    : 'No output yet — the cores are not running.';
  out.scrollTop = out.scrollHeight;
}

/* ── live updates ──────────────────────────────────────────────────────── */

function connectEvents() {
  if (events) events.close();
  events = new EventSource(`/api/events?token=${encodeURIComponent(token)}`);

  // The event says only what changed; the view re-reads the part it cares
  // about. A dropped notification costs nothing because the browser reconnects
  // and the next change repaints anyway.
  const repaint = () => {
    const active = $('.view.active')?.id.replace('view-', '');
    loaders[active]?.().catch(() => {});
    if (active !== 'dashboard') loadDashboard().catch(() => {});
  };
  ['status', 'nodes', 'rules', 'settings', 'cores'].forEach((t) => events.addEventListener(t, repaint));
}

/* ── wiring ────────────────────────────────────────────────────────────── */

function bind() {
  $$('.nav-item').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.view)));
  $('#power-btn').addEventListener('click', togglePower);

  $('#rule-add').addEventListener('click', () => addRules().catch((e) => toast(e.message, 'bad')));
  $('#rule-action').addEventListener('change', (e) => { e.target.dataset.touched = '1'; });
  $('#rule-input').addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') addRules().catch((err) => toast(err.message, 'bad'));
  });
  $('#test-btn').addEventListener('click', () => testRoute().catch((e) => toast(e.message, 'bad')));
  $('#test-dest').addEventListener('keydown', (e) => { if (e.key === 'Enter') testRoute().catch(() => {}); });

  $('#sub-add').addEventListener('click', () => addSubscription().catch((e) => toast(e.message, 'bad')));
  $('#nodes-refresh').addEventListener('click', async () => {
    toast('Refreshing subscriptions…');
    try { await api('/refresh', { method: 'POST' }); await loadNodes(); toast('Refreshed', 'good'); }
    catch (e) { toast(e.message, 'bad'); }
  });
  $('#history-period').addEventListener('change', () => loadHistory().catch(() => {}));
  $('#nodes-test').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Measuring…';
    try {
      const results = await api('/nodes/test', { method: 'POST', body: {} });
      const values = Object.values(results).filter((r) => r.delay > 0).map((r) => r.delay);
      toast(values.length
        ? `Measured ${Object.keys(results).length}, best ${Math.min(...values)} ms`
        : 'No node answered', values.length ? 'good' : 'bad');
      await loadNodes();
    } catch (err) { toast(err.message, 'bad'); }
    finally { btn.disabled = false; btn.textContent = 'Measure latency'; }
  });
  $('#cores-refresh').addEventListener('click', () => loadCores().catch((e) => toast(e.message, 'bad')));
  $('#set-save').addEventListener('click', () => saveSettings().catch((e) => toast(e.message, 'bad')));
  $('#log-refresh').addEventListener('click', () => loadLogs().catch(() => {}));
  $('#q-reconnect').addEventListener('click', (e) => quick(e.currentTarget, async () => {
    await api('/connect', { method: 'POST' });
    toast('Reconnected', 'good');
  }));
  $('#q-refresh').addEventListener('click', (e) => quick(e.currentTarget, async () => {
    await api('/refresh', { method: 'POST' });
    toast('Subscriptions refreshed', 'good');
  }));
  $('#q-disconnect').addEventListener('click', (e) => quick(e.currentTarget, async () => {
    await api('/disconnect', { method: 'POST' });
    toast('Disconnected');
  }));

  // The two switches worth reaching for without opening Settings. They write
  // the same setting the Settings page does, so the two can never disagree.
  $('#q-autoconnect').addEventListener('change', (e) => settingToggle('auto_connect', e.target,
    e.target.checked ? 'Will connect on its own at startup' : 'Will stay down until you connect'));
  $('#q-killswitch').addEventListener('change', (e) => firewallToggle('kill_switch', e.target));
  $('#q-quic').addEventListener('change', (e) => firewallToggle('block_quic', e.target));

  $('#health-run').addEventListener('click', async (e) => {
    e.target.disabled = true; e.target.textContent = 'Checking…';
    try { await loadHealth(); } catch (err) { toast(err.message, 'bad'); }
    finally { e.target.disabled = false; e.target.textContent = 'Check now'; }
  });
  $('#set-zapret').addEventListener('change', () => loadSettings._current && loadSettings().catch(() => {}));
  $('#log-core').addEventListener('change', () => loadLogs().catch(() => {}));

  // One delegated handler for every row action, so re-rendering a list never
  // leaves stale listeners behind.
  document.addEventListener('click', async (e) => {
    const el = e.target.closest('[data-del],[data-toggle],[data-move],[data-sub-del],[data-sub-rules],[data-sub-refresh],[data-sub-test],[data-core-update],[data-node-select],[data-split],[data-goto]');
    if (!el) return;
    try {
      if (el.dataset.goto) { e.preventDefault(); switchView(el.dataset.goto); return; }
      if (el.dataset.split) { await setSplit(el.dataset.split); return; }
      if (el.dataset.nodeSelect) {
        const r = await api('/nodes/select', { method: 'POST', body: { tag: el.dataset.nodeSelect } });
        toast(`Now using ${r.active || el.dataset.nodeSelect}`, 'good');
        await loadNodes();
        return;
      }
      if (el.dataset.del) { await api(`/rules/${el.dataset.del}`, { method: 'DELETE' }); await loadRouting(); }
      else if (el.dataset.toggle) {
        await api(`/rules/${el.dataset.toggle}/enabled`, { method: 'POST', body: { enabled: el.dataset.enabled === 'true' } });
        await loadRouting();
      } else if (el.dataset.move) {
        await api(`/rules/${el.dataset.move}/move`, { method: 'POST', body: { to: Number(el.dataset.to) } });
        await loadRouting();
      } else if (el.dataset.subDel) {
        await api(`/subscriptions/${el.dataset.subDel}`, { method: 'DELETE' });
        await loadNodes();
      } else if (el.dataset.subRefresh) {
        el.classList.add('busy');
        try { await api(`/subscriptions/${el.dataset.subRefresh}/refresh`, { method: 'POST' }); toast('Subscription updated', 'good'); }
        finally { el.classList.remove('busy'); }
        await loadNodes();
      } else if (el.dataset.subTest) {
        // Measure only this subscription's servers, so a slow provider does not
        // hold up finding out whether another one is alive.
        const nodes = await api('/nodes');
        const tags = nodes.filter((n) => n.source_id === el.dataset.subTest && n.usable && n.tag).map((n) => n.tag);
        if (!tags.length) { toast('Nothing to measure here'); return; }
        el.classList.add('busy');
        try {
          const results = await api('/nodes/test', { method: 'POST', body: { tags } });
          const alive = Object.values(results).filter((r) => r.delay > 0).map((r) => r.delay);
          toast(alive.length ? `Best ${Math.min(...alive)} ms of ${tags.length}` : 'No server answered',
                alive.length ? 'good' : 'bad');
        } finally { el.classList.remove('busy'); }
        await loadNodes();
      } else if (el.dataset.coreUpdate) {
        toast(`Updating ${el.dataset.coreUpdate}…`);
        const r = await api(`/cores/${el.dataset.coreUpdate}/update`, { method: 'POST' });
        toast(r.already_latest ? 'Already the latest release' : `Updated to ${r.current.version} — restart to apply`, 'good');
        await loadCores();
      }
    } catch (err) { toast(err.message, 'bad'); }
  });

  document.addEventListener('change', async (e) => {
    const sel = e.target.closest('[data-sub-ua]');
    if (!sel) return;
    sel.disabled = true;
    try {
      await api(`/subscriptions/${sel.dataset.subUa}/user-agent`, { method: 'POST', body: { user_agent: sel.value } });
      toast('Refetched with the new identity', 'good');
      await loadNodes();
    } catch (err) { toast(err.message, 'bad'); }
    finally { sel.disabled = false; }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const row = e.target.closest?.('[data-node-select]');
    if (!row) return;
    e.preventDefault();
    row.click();
  });

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    token = $('#login-token').value.trim();
    try {
      await api('/status');
      localStorage.setItem(STORE_KEY, token);
      $('#login-error').classList.add('hidden');
      start();
    } catch {
      $('#login-error').textContent = 'That token was not accepted.';
      $('#login-error').classList.remove('hidden');
    }
  });
}

async function start() {
  showApp();
  connectEvents();
  switchView(location.hash.slice(1) || 'dashboard');

  // Throughput is sampled once a second by the daemon, so the graph is polled
  // at the same rate while the overview is on screen. Everything else waits for
  // an event; a hidden tab polls nothing at all.
  setInterval(() => {
    if (document.hidden) return;
    if ($('#view-dashboard').classList.contains('active')) loadTraffic().catch(() => {});
  }, 1000);
  setInterval(() => { if (!document.hidden) loadDashboard().catch(() => {}); }, 10000);
}

bind();
if (token) {
  api('/status').then(start).catch(showLogin);
  loadHost().catch(() => {});
} else {
  showLogin();
}
