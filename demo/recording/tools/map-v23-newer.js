<script id="v23">
// v23 (2026-11-07): what the recording's text slides said, now on the map.
//  1. a title block over the setup row: the lab, its size, the four things it proves;
//  2. short labels under each lab station (6-14): counts, definitions, frameworks, flows;
//  3. a third row, "The newer parts", stops 16-20 (the lab guide's numbering): Okta, AD hardening,
//     Microsoft PAM, AD FS, Session Manager + Azure least privilege. Every label is true today
//     (readiness/*.md); things not run are said as not run.
//  4. window.__mapFocus(spec): the recording cockpit's hook (stop or tile, zoom, dim the rest).
(function () {
  const lab = window.__lab; if (!lab) return;
  const NS = 'http://www.w3.org/2000/svg', svg = lab.svg, W = lab.W;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const mk = (t, a, p) => { const e = document.createElementNS(NS, t); for (const q in a) e.setAttribute(q, a[q]); p.appendChild(e); return e; };
  const FONT = 'system-ui, -apple-system, sans-serif';

  // ---- 2. labels under the lab stations
  const NOTES = {
    source: ['HR form: the only hand step', 'The HR system issues the number', 'In AD < 1 min · in Entra ≈ 4 min'],
    directory: ['One account, two directories', 'Cloud Sync: one light agent on DC01', 'It also carries HR’s hires into AD'],
    joiner: ['8.1 checklist · 8.2 groups from HR', '8.3 a bundle per job · 8.4 extras expire', '8.5 blocked pairs (nurse + pharmacy)'],
    apps: ['Trust: accepts Entra’s signed sign-in', 'AWS permission set: read-only', 'ServiceNow: account made by Entra'],
    signin: ['9 rules enforced · newer ones report-only', 'Any block wins · CA001 MFA · CA003 old methods', 'HIPAA 164.312(d) · NIST IA-2(1) · CIS 6.3-6.5'],
    privileged: ['Least privilege + just-in-time', 'NIST AC-6, AC-2(7) · HIPAA 164.308(a)(4) · CIS 6.8', 'Exceptions: build account, 2 emergency, robots'],
    detect: ['Rule file (KQL) → Terraform → Sentinel rule', 'SPL twin → render script → Splunk (5 min)', 'Contain only after a person says yes'],
    leaver: ['HR change: off in AD → Entra → AWS', 'IT leaver step: packages out, sessions ended', 'Robot accounts: 20, each with a named owner'],
    proof: ['7 records, each with a fingerprint', 'Write-once store (lock in trial setting)', 'Reviews · requests · passkeys · emergency'],
  };
  const gA = mk('g', { id: 'g-annot', class: 'annot' }, svg);
  lab.L.st.forEach((s) => {
    const lines = NOTES[s.id]; if (!lines || !s.box) return;
    const fs = 24, lh = 34, w = Math.max(...lines.map((l) => l.length)) * fs * 0.55 + 60, h = lines.length * lh + 36;
    const x = s.x - w / 2, y = s.box.y1 + 40;
    const g = mk('g', { class: 'note', 'data-st': s.id }, gA);
    mk('rect', { x, y, width: w, height: h, rx: 22 }, g);
    s.box.y1 = y + h + 20;
    lines.forEach((l, i) => { const t = mk('text', { x: s.x, y: y + 30 + i * lh + 8, 'text-anchor': 'middle', 'font-size': fs, 'font-weight': i ? 600 : 750, fill: i ? '#3A3936' : '#16161A', 'font-family': FONT }, g); t.textContent = l; });
  });

  // ---- 1. the title block over the setup row
  const kS = (W.x1 - W.x0) / (120 * 2 + 600 * 5);
  const titleG = mk('g', { id: 'g-title' }, svg);
  const sTop = parseFloat(document.getElementById('bhost').style.top) || (W.y0 - 1400);
  const tx = W.x0 + 120 * kS, ty = sTop - 230 * kS;
  const t1 = mk('text', { x: tx, y: ty, 'font-size': 64 * kS, 'font-weight': 800, fill: '#1E1E1C', 'font-family': FONT }, titleG); t1.textContent = 'Contoso Health identity lab';
  const t2 = mk('text', { x: tx, y: ty + 52 * kS, 'font-size': 28 * kS, 'font-weight': 600, fill: '#6B6A66', 'font-family': FONT }, titleG); t2.textContent = 'A made-up hospital of about 5,000 staff. Identity: who you are. Access: what you may open.';
  ['1 Access follows HR', '2 Admin power is borrowed, not kept', '3 Misuse gets caught', '4 An auditor can check all of it'].forEach((p, i) => {
    const x = tx + i * 620 * kS, y = ty + 82 * kS;
    mk('rect', { x, y, width: 600 * kS, height: 56 * kS, rx: 28 * kS, fill: '#16161A' }, titleG);
    const t = mk('text', { x: x + 300 * kS, y: y + 37 * kS, 'text-anchor': 'middle', 'font-size': 26 * kS, 'font-weight': 700, fill: '#FFFFFF', 'font-family': FONT }, titleG); t.textContent = p;
  });

  // ---- 3. the newer row (16-20)
  const T = (name, note, glyph, kind, def) => ({ name, note, glyph, kind, def });
  const ROW = [
    { n: 16, id: 'okta', title: 'Okta to Entra', kicker: 'The clinic the hospital bought', goal: 'Move the clinic’s apps to Entra, rule by rule', status: 'RAN · tenant (estate, before sign-in) · BUILT (cut-over)',
      what: ['Okta is the sign-in service the clinic used before the hospital bought it.', 'A script reads Okta and Entra and builds the tracker; nobody types the status.', 'Lab Results uses OpenID Connect, Billing uses SAML, Scheduling is a bookmark.', 'Clinic staff need two factors and sign in again after eight hours; anyone else is denied.', 'The clinic-staff rule matches every hospital address, so Entra gets an assigned group instead.', 'Before: Okta sends her to Entra for her password and code; 24 seconds.', 'The cut-over and the timed rollback are built, not run yet.'],
      tiles: [T('Tracker', 'Built by a script from Okta + Graph', 'LIST', 'code'), T('3 clinic apps', 'OIDC · SAML · bookmark', 'APPS', 'code'), T('Auth policy', '2 factors, again after 8 h', '2FA', 'code', 'Okta’s rule for how a person proves who they are'), T('Group rules', 'Entra gets an assigned group', 'RULE', 'code', 'Okta puts people into a group by itself, from a fact about them'), T('Before sign-in', 'PASS through Okta, 24 s', '24 s', 'code'), T('Entra side', 'Plan: 5 to add, 0 to change', '+5', 'code'), T('Cut-over', 'Built, not run yet', 'NEXT', 'plan'), T('Rollback', 'One command, built', 'BACK', 'plan')],
      outs: ['<b>3</b> clinic apps', 'Cut-over: built, not run'] },
    { n: 17, id: 'ad-hardening', title: 'Hardening AD', kicker: 'Tiers, Protected Users, LAPS', goal: 'A Tier 0 login never touches a lower tier', status: 'RAN · tenant on DC01',
      what: ['A tier is a trust zone for admin work: Tier 0 controls AD, Tier 1 runs servers, Tier 2 is the help desk and staff PCs.', 'Windows leaves a reusable credential where an admin signs in; tiers keep Tier 0 off lower tiers.', 'One new admin account per tier.', 'The deny-logon Group Policy is ready; those tiers hold no computers yet, so today it denies nothing.', 'The new admins are in Protected Users; three older admins stay out because the remote path still needs NTLM.', 'Windows LAPS rotates DC01’s repair password every 30 days.', 'PingCastle scored 58 before, 50 after; lower is better. 35 checks passed.', 'What is left: move the remote path to Kerberos.'],
      tiles: [T('Tier 0', 'AD and domain controllers', 'T0', 'code', 'A trust zone for admin work'), T('Tier 1', 'Servers', 'T1', 'code'), T('Tier 2', 'Help desk and staff PCs', 'T2', 'code'), T('Deny-logon GPO', 'Ready; denies nothing today', 'GPO', 'code', 'Group Policy: settings AD pushes to computers'), T('Protected Users', 'The new admins only', 'PU', 'code', 'A built-in group that blocks weaker sign-in methods'), T('Windows LAPS', 'DC01 repair password, 30 days', 'LAPS', 'code'), T('PingCastle', '58 before → 50 after', '50', 'code'), T('What is left', 'Remote path to Kerberos', 'NEXT', 'plan')],
      outs: ['<b>35</b> checks passed', 'Normal users still sign in'] },
    { n: 18, id: 'pam-microsoft', title: 'Admin passwords + sessions', kicker: 'PAM, the Microsoft way', goal: 'PIM in the middle, Microsoft products around it', status: 'RAN · tenant (Key Vault, Bastion once) · BUILT (EPM)',
      what: ['PAM: how admin power and admin passwords are guarded.', 'Key Vault holds secrets; an app in Kubernetes reads one with no stored password and is refused the next (403).', 'Terraform’s usual read left a password in three files; the ephemeral read, in none.', 'An admin could not open DC01 until she turned on her role in PIM for one hour; Bastion recorded the session and a second admin replayed it.', 'Bastion recording needs Premium (about $0.45 an hour), so the lab creates it to show it, then deletes it.', 'Windows LAPS rotates DC01’s repair password.', 'Intune EPM: one approved app as admin, for 24 hours; licensed, built as a script, not set up yet.', 'What is lost: no shared password to check out. Each admin has a named account and borrows power through PIM.'],
      tiles: [T('PIM', 'The core: borrowed, timed power', 'PIM', 'code'), T('Key Vault', 'Secrets; the next one refused (403)', 'KV', 'code', 'Microsoft’s locked store for secrets'), T('Ephemeral read', 'Usual: 3 files · ephemeral: 0', '3 → 0', 'code', 'Terraform reads the secret only while it runs'), T('Bastion recording', 'Recorded, replayed; deleted after', 'REC', 'code', 'A gateway into servers from the browser'), T('Windows LAPS', 'Rotates DC01’s repair password', 'LAPS', 'code'), T('Intune EPM', 'Built; 24 h per approval', 'EPM', 'plan', 'One approved app as admin, without being admin'), T('What is lost', 'No shared password check-out', 'NOTE', 'note')],
      outs: ['Bastion: about <b>$0.45</b> an hour', 'EPM: built, waiting'] },
    { n: 19, id: 'adfs', title: 'Moving an app off AD FS', kicker: 'Claims, rule by rule', goal: 'The app moves to Entra with the same claims', status: 'RAN on DC01 (steps 1-6) · BUILT (Entra side, cut-over)',
      what: ['AD FS: a Windows server role that lets staff sign in to web apps with their company password; the app trusts AD FS.', 'Its signing key can forge a sign-in for anyone: Golden SAML.', 'AD FS runs on DC01 for this exercise; production would use a dedicated server, never a DC.', 'Five real sign-ins carried all five claims, each signature valid.', 'A claim is one fact about the person; a claim rule is AD FS’s recipe for one claim.', 'The custom rule cuts the domain off the sign-in name; Entra uses its built-in step (ExtractMailPrefix).', 'The readiness report’s agent is installed, not registered yet, so there is no report.', 'Cut-over and way back: one command each, built, not run. Removal refuses while AD FS still has sign-ins.'],
      tiles: [T('AD FS on DC01', 'This exercise only', 'ADFS', 'code', 'A Windows role that vouches for staff to web apps'), T('Golden SAML', 'The signing key can forge anyone', 'KEY', 'note', 'A stolen signing key signs a sign-in for any person'), T('5 sign-ins', 'All 5 claims, signatures valid', '5', 'code'), T('Claim rule', 'Cuts the domain off the name', 'RULE', 'code', 'AD FS’s recipe for one fact about the person'), T('Entra version', 'ExtractMailPrefix', 'ENTRA', 'code'), T('Readiness report', 'Agent installed, not registered', 'WAIT', 'plan'), T('Cut-over', 'Built, not run', 'NEXT', 'plan'), T('Removal', 'Refuses while sign-ins continue', 'STOP', 'code')],
      outs: ['<b>5</b> real sign-ins', 'Report: not registered yet'] },
    { n: 20, id: 'ssm-least-priv', title: 'Server access + least privilege', kicker: 'AWS Session Manager · Azure roles', goal: 'Narrow, borrowed, logged', status: 'RAN · tenant, torn down (SSM) · RAN (Azure role, PIM, locks) · BUILT (pipeline scope)',
      what: ['Session Manager opens a shell with no SSH key and no open port, only during a PIM activation; every command is in the log under the person’s name.', 'Port forwarding, remote commands, an untagged server and someone else’s session were refused.', 'Gaps: new access stops within about 8 minutes of the activation ending, but an issued token lasts up to an hour and an open shell stays open; the server user can sudo. The server ran for the test and was torn down.', 'In Azure, least privilege is the smallest role that does the job: the operator role starts and stops servers and reads logs, and cannot change the network or run commands. You borrow it in PIM.', 'The key vaults have delete locks the pipeline cannot remove.', 'The pipeline limited to the lab resource group is in code; it goes live after merge.'],
      tiles: [T('Session Manager', 'No SSH key, no open port', 'SSM', 'code', 'A shell over an outbound connection from the server'), T('Refused', 'Forwarding · commands · untagged · others', 'NO', 'code'), T('Gaps', '8 min · 1 h token · open shell · sudo', '!', 'note'), T('VM Operator role', 'Start, stop, logs; via PIM', 'ROLE', 'code', 'The smallest role that does the job'), T('Delete locks', 'Key vaults; pipeline can’t remove', 'LOCK', 'code'), T('Pipeline scope', 'Lab resource group, after merge', 'NEXT', 'plan')],
      outs: ['Server: torn down', 'Pipeline scope: after merge'] },
  ];
  const SP = 600, L0 = 120, WH = 820, n = ROW.length, worldW = L0 * 2 + SP * n;
  const k = (W.x1 - W.x0) / (L0 * 2 + SP * 5);   // the same scale as the setup row
  const labBottom = Math.max(W.y1, (() => { try { const b = gA.getBBox(); return b.y + b.height; } catch (e) { return W.y1; } })());
  const BX = W.x0, BY = labBottom + 200 + 420 * k;
  const layer = document.getElementById('nlayer'), host = document.getElementById('nhost'), world = document.getElementById('n-world');
  world.style.width = worldW + 'px'; host.style.left = BX + 'px'; host.style.top = BY + 'px'; host.style.transform = `scale(${k})`;
  document.getElementById('n-stations').innerHTML = ROW.map((s, i) => `<div class="st done in" id="nst${i}" style="left:${L0 + SP * i}px" data-i="${i}">
      <div class="b-tiles">${s.tiles.map((t, j) => `<div class="tile lbl ${t.kind === 'code' ? 'code' : 'hand'}"><div class="ph">${esc(t.glyph || '')}</div><div class="tag">${t.kind === 'plan' ? 'NOT RUN YET' : t.kind === 'note' ? 'NOTE' : 'DONE'}</div><span class="num">${s.n}.${j + 1}</span><div class="lb">${esc(t.name)}<small>${esc(t.note || '')}</small></div>${t.def ? `<div class="def">${esc(t.def)}</div>` : ''}</div>`).join('')}</div>
      <div class="wire"></div>
      <div class="pill"><div class="n"><span>${s.n}</span></div><div><div class="t">${esc(s.title)}</div><div class="k">${esc(s.kicker)}</div></div></div>
      <div class="nxt">›</div><div class="wire2"></div>
      <div class="below"><div class="outs">${s.outs.map((o) => `<span class="out"><i></i>${o}</span>`).join('')}</div><div class="b-goal">${esc(s.goal)}</div></div></div>`).join('');
  document.querySelector('#n-world .spine').classList.add('in'); document.getElementById('n-fill').style.width = '100%';
  // the row title
  const rt = mk('g', { id: 'g-newer-title' }, svg);
  const rtt = mk('text', { x: BX + 120 * k, y: BY + WH * k + 40 * k, 'font-size': 48 * k, 'font-weight': 800, fill: '#2F6BFF', 'font-family': FONT }, rt); rtt.textContent = 'The newer parts · 16 to 20';
  // one camera for all three rows
  const prevSync = window.__syncBuild, prevAll = window.__allBox;
  window.__syncBuild = (cam, vw, vh) => { if (prevSync) prevSync(cam, vw, vh); layer.style.transform = `translate(${vw / 2 - cam.x * cam.z}px, ${vh / 2 - cam.y * cam.z}px) scale(${cam.z})`; };
  window.__allBox = (W2) => { const b = prevAll ? prevAll(W2) : W2; return { x0: b.x0, y0: Math.min(b.y0, sTop - 560 * kS), x1: b.x1, y1: BY + WH * k + 80 }; };
  const rect = (i) => { const el = document.getElementById('nst' + i), tl = el && el.querySelector('.b-tiles'); const over = tl ? Math.max(0, tl.offsetHeight - 410) : 300; return { x0: BX + k * (L0 + SP * i - 40), x1: BX + k * (L0 + SP * i + 580), y0: BY - k * (over + 20), y1: BY + WH * k }; };
  // chips and panel
  const chips = lab.chips, panel = lab.panel;
  const sep = document.createElement('span'); sep.className = 'chipsep newer'; sep.textContent = 'Newer'; chips.appendChild(sep);
  ROW.forEach((s, i) => { const c = document.createElement('button'); c.type = 'button'; c.className = 'chip'; c.dataset.newer = i; c.textContent = `${s.n} ${s.title}`; c.setAttribute('aria-current', 'false'); chips.appendChild(c); });
  const unpick = () => document.querySelectorAll('#nlayer .st').forEach((x) => { x.classList.remove('pick', 'on'); x.classList.add('done'); x.querySelectorAll('.tile.focus').forEach((t) => t.classList.remove('focus')); });
  function show(i, j) {
    const s = ROW[i]; lab.select({ type: 'overview' }, { fly: false }); unpick();
    const el = document.getElementById('nst' + i); el.classList.add('on'); el.classList.remove('done');
    let tileEl = null;
    if (j != null) { tileEl = el.querySelectorAll('.tile')[j]; el.classList.add('pick'); if (tileEl) tileEl.classList.add('focus'); }
    const t = j != null ? s.tiles[j] : null;
    panel.classList.remove('off', 'ovw');
    panel.innerHTML = `<span class="cnum">Newer · ${t ? `${s.n}.${j + 1}` : `${s.n} of 20`}</span><h2>${esc(t ? t.name : s.title)}</h2><div class="goal">${esc(t ? t.note : s.goal)}</div>` +
      (t && t.def ? `<section class="ctx"><h3>What it means</h3><p>${esc(t.def)}</p></section>` : '') +
      `<section class="ctx"><h3>${t ? 'The stop' : 'What it is'}</h3><ul class="read pts">${s.what.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></section>` +
      `<section class="ctx"><h3>Status</h3><p>${esc(s.status)}</p></section>`;
    chips.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-current', c.dataset.newer == i ? 'true' : 'false'));
    lab.flyTo(window.__adjust ? window.__adjust(lab.fitRect(rect(i), 0.9)) : lab.fitRect(rect(i), 0.9));
  }
  chips.addEventListener('click', (e) => { const c = e.target.closest('[data-newer]'); if (c) show(+c.dataset.newer); });
  layer.addEventListener('click', (e) => { const st = e.target.closest('.st'); if (!st) return; const tile = e.target.closest('.tile'); show(+st.dataset.i, tile ? [...st.querySelectorAll('.tile')].indexOf(tile) : null); });
  const prevSel = window.__onSelect; window.__onSelect = (it) => { unpick(); if (prevSel) prevSel(it); };
  window.__newer = { ROW, show };
  lab.flyTo(lab.fitRect(window.__allBox(W), 0.96), 0);
  setTimeout(() => lab.flyTo(lab.fitRect(window.__allBox(W), 0.96), 0), 500);
})();
</script>
