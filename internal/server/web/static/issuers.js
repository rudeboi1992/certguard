// Issuers & registrars: the inventory grouped by who it depends on.
//
// Every other view is organised by *what* expires. This one is organised by
// *who* you are relying on, which is the axis that matters when a CA changes
// its rules or a registrar has to be moved: the question is not "what expires
// next" but "how much of this is affected, and when does the first one land".

let items = [];

// Certificate issuers are DNs — "CN=R11,O=Let's Encrypt,C=US". The
// organisation is the useful grouping (one CA runs many intermediates, and
// they rotate), so group by O and keep the CN as a sub-line. Registrars are
// already plain names and are used as-is.
function dnPart(dn, key) {
  const m = new RegExp('(?:^|,)\\s*' + key + '=([^,]+)').exec(dn || '');
  return m ? m[1].trim() : '';
}
function issuerGroup(dn) {
  return dnPart(dn, 'O') || dnPart(dn, 'CN') || dn || 'Unknown';
}

function summarise(list, keyFn, subFn) {
  const by = new Map();
  for (const it of list) {
    const k = keyFn(it.cert) || 'Unknown';
    if (!by.has(k)) by.set(k, { key: k, items: [], subs: new Set() });
    const g = by.get(k);
    g.items.push(it);
    const sub = subFn ? subFn(it.cert) : '';
    if (sub && sub !== k) g.subs.add(sub);
  }
  const out = [...by.values()].map((g) => {
    let expired = 0, soon = 0, problems = 0, next = null;
    for (const it of g.items) {
      const d = it.days_remaining;
      if (d < 0) expired++;
      else if (d <= 30) soon++;
      if (it.cert.last_error) problems++;
      if (d >= 0 && (next === null || d < next)) next = d;
    }
    return { ...g, count: g.items.length, expired, soon, problems, next };
  });
  // Biggest dependency first — that is the one a CA change costs most.
  out.sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
  return out;
}

function bar(g, total) {
  const pct = Math.round((g.count / total) * 100);
  return `<span class="iss-bar" title="${pct}% of ${total}"><i style="width:${Math.max(2, pct)}%"></i></span>`;
}

function card(g, total, filterKey) {
  const flags = [];
  if (g.expired) flags.push(`<span class="pill urgent">${g.expired} expired</span>`);
  if (g.soon) flags.push(`<span class="pill notice">${g.soon} within 30d</span>`);
  if (g.problems) flags.push(`<span class="pill untrusted">${g.problems} failing</span>`);
  const subs = [...g.subs].slice(0, 4);
  return `<section class="card iss-card">
    <div class="iss-top">
      <span class="iss-name"><strong>${escapeHtml(g.key)}</strong>
        ${subs.length ? `<span class="muted small">${subs.map(escapeHtml).join(' · ')}${g.subs.size > subs.length ? ' …' : ''}</span>` : ''}
      </span>
      <span class="iss-count">${g.count}</span>
    </div>
    ${bar(g, total)}
    <div class="iss-flags">
      ${flags.join('') || '<span class="pill ok">all healthy</span>'}
      ${g.next !== null ? `<span class="muted small">next in ${escapeHtml(fmtRemaining(g.next))}</span>` : ''}
      <span class="spacer"></span>
      <a class="btn ghost small" href="/inventory?q=${encodeURIComponent(filterKey)}">Show entries</a>
    </div>
  </section>`;
}

function render() {
  // Certificates: anything not a domain registration that has an issuer.
  const certs = items.filter((it) => it.cert.kind !== 'domain' && it.cert.issuer);
  const doms = items.filter((it) => it.cert.kind === 'domain' && it.cert.issuer);

  const cg = summarise(certs, (c) => issuerGroup(c.issuer), (c) => dnPart(c.issuer, 'CN'));
  const dg = summarise(doms, (c) => c.issuer);

  $('issCerts').innerHTML = cg.map((g) => card(g, certs.length, g.key)).join('');
  $('issDomains').innerHTML = dg.map((g) => card(g, doms.length, g.key)).join('');
  $('issCertsEmpty').hidden = cg.length !== 0;
  $('issDomainsEmpty').hidden = dg.length !== 0;

  // Key types and signature algorithms, counted.
  const keys = new Map();
  for (const it of certs) {
    for (const v of [it.cert.key_type, it.cert.signature_algorithm]) {
      if (!v) continue;
      keys.set(v, (keys.get(v) || 0) + 1);
    }
  }
  const chips = [...keys.entries()].sort((a, b) => b[1] - a[1]);
  $('issKeys').innerHTML = chips.length
    ? chips.map(([k, n]) => `<span class="iss-chip">${escapeHtml(k)}<em>${n}</em></span>`).join('')
    : '<span class="muted small">Nothing scanned yet — key details come from a live scan or a parsed file.</span>';
  $('issKeyCard').hidden = false;
}

async function load() {
  const res = await api('GET', '/api/v1/certs');
  items = await res.json();
  render();
}

setVaultRefresh(() => load());

(async () => {
  await loadWhoami();
  syncVaultUi();
  await load();
})().catch((e) => toast(e.message || 'Failed to load issuers', true));
