#!/usr/bin/env python3
# v24-alt, round 2 (owner review 2026-11-07): stop 1 names every platform; the "Also in the lab"
# items fold into Delivery (they are checks on every change); a readable overview board at Fit
# (stops as cards in flow order, lanes named, no bubbles over tiles); a legend that is true.
import json, re, sys
SRC, OUT = sys.argv[1], sys.argv[2]
h = open(SRC, encoding='utf-8').read()

def rep(a, b, n=1):
    global h
    assert a in h, a[:90]
    h = h.replace(a, b, n)

# ---- lab-data: the extras become Delivery steps
i = h.index('id="lab-data">') + len('id="lab-data">'); j = h.index('</script>', i)
D = json.loads(h[i:j])
D['delivery']['steps'] += [
  {"id": "SELFTEST", "name": "Scanner self-test (fail on bad, pass on clean)", "glyph": "magnifier", "status": "RAN · tenant"},
  {"id": "RBACLINT", "name": "Kubernetes role checker (11 risky lines in the bad file)", "glyph": "shield", "status": "RAN · harness"},
  {"id": "OFFCHECK", "name": "Built, switched off (policy, audit trail, 2 alarms)", "glyph": "lock", "status": "BUILT"},
  {"id": "CICDKV", "name": "Pipeline settings from Key Vault, every read logged", "glyph": "key", "status": "RAN · tenant"}]
D['delivery']['purpose'] += ' Four checks keep the code honest: the scanners must fail on a planted unsafe file, a role checker flags risky Kubernetes permissions, a read-only check proves the built-but-off items are off, and the pipeline reads its settings from Key Vault.'
for nd in D['nodes']:
    if nd['id'] == 'WORM':
        nd['name'] = 'Write-once store (trial lock)'
        nd['definition'] = 'The evidence container is set to write-once. In the lab its lock stays in the trial (unlocked) setting so the lab can be torn down; a hospital locks it for good.'
h = h[:i] + json.dumps(D, ensure_ascii=False) + h[j:]

# ---- stop 1: the six head pieces, the smaller tools named inside each (checked against the lab
# 2026-11-07; what is not run is said as not run)
SIX = [
 ("HR system → ServiceNow", "HR hires; everything after is automatic", "HR",
  ["A real HR system is being chosen; today the HR form stands in. HR clicks Hire and everything after is automatic.",
   "ServiceNow is the staff help desk: Entra creates each person's account there (RAN · tenant).",
   "Next, being built: a nurse requests app access in ServiceNow, her manager approves, access is granted, and the IAM queue and its report live there."]),
 ("Microsoft Entra ID", "The master list of people and logins", "entra",
  ["The master list of people and logins that every app trusts.",
   "PIM: admin power on loan, for a few hours, with a reason (RAN · tenant).",
   "Cloud Sync copies each account up from Active Directory on DC01 (RAN · tenant).",
   "AD FS: one app's move to Entra is built and its five sign-ins ran on DC01; the cut-over has not run yet."]),
 ("Azure and Intune", "The cloud and the managed PC", "azure",
  ["Azure runs DC01, the evidence store and Log Analytics.",
   "Key Vault holds the secrets (RAN · tenant).",
   "Bastion recorded an admin session to DC01 and a second admin replayed it; it is created for a capture, then deleted (about $0.45 an hour).",
   "Intune: approved, time-limited admin rights (EPM, 24 hours per approval) and rotating local admin passwords (LAPS) for the PC are built as a script, not set up yet. DC01's own LAPS runs through Group Policy (RAN)."]),
 ("Sentinel, Defender + Splunk", "The alarm system", "ALERT",
  ["My rules raise incidents in Sentinel; Defender shows them (RAN · tenant).",
   "A person approves the lockout in Teams before anything happens (the drill, RAN · tenant).",
   "Splunk runs 22 of the same rules on the same records, fed every five minutes."]),
 ("AWS and Okta", "The outside doors that trust Entra", "aws",
  ["AWS trusts the Entra login through IAM Identity Center; Entra creates each user (RAN · tenant).",
   "Server access goes through Session Manager after a PIM loan: no SSH key, no open port (RAN, then torn down).",
   "Okta is the acquired clinic's login; moving its apps to Entra is built, the cut-over not run yet."]),
 ("GitHub, Terraform + VS Code", "The lab, written as code", "github",
  ["The lab is written as code (Terraform and scripts) and edited in VS Code.",
   "Every change goes through a GitHub pull request: Greptile's review and the security scanners (Checkov, TruffleHog).",
   "I approve it before Actions applies it.",
   "PingCastle scores the directory (58 before, 50 after), and a Kubernetes test shows an app's secret coming from Key Vault."]),
]
imgs = {'entra', 'azure', 'aws', 'github'}
tiles = ', '.join("{ name: %s, note: %s, %s, kind: 'hand' }" % (json.dumps(n), json.dumps(note), ("img: BIMG('%s')" % g) if g in imgs else ("glyph: '%s'" % g)) for n, note, g, _ in SIX)
a = h.index("tiles: [{ name: 'Microsoft Entra'"); b = h.index("outs: ['<b>6</b> accounts'", a); b = h.rindex('],', a, b) + 2
h = h[:a] + 'tiles: [' + tiles + '],\n        ' + h[b:].lstrip()
rep("outs: ['<b>6</b> accounts', '<b>1</b> verified domain',", "outs: ['<b>6</b> head pieces', '<b>1</b> verified domain (contosohealthlab.com)',")
rep(h[h.index('  const NOTES = ['):h.index('];', h.index('  const NOTES = [')) + 2], '  const NOTES = ' + json.dumps([x[1] for x in SIX]) + ';')
m = re.search(r'const TILES = (\{.*?\});', h); dec = json.JSONDecoder(); TIL, end = dec.raw_decode(h, m.start(1))
TIL['0'] = [x[3] for x in SIX]
h = h[:m.start(1)] + json.dumps(TIL, ensure_ascii=False) + h[end:]
m = re.search(r'const LINKS = ', h); LK, end = dec.raw_decode(h, m.end())
o = LK['btile']['0']
LK['btile']['0'] = [o[3] if len(o) > 3 else [], o[0], o[1], [], (o[2] if len(o) > 2 else []) + (o[4] if len(o) > 4 else []), o[5] if len(o) > 5 else []]
h = h[:m.end()] + json.dumps(LK, ensure_ascii=False) + h[end:]

# ---- the setup and newer rows: three tiles per row, so 12 tiles stay 4 rows high
rep('#blayer .st{position:absolute;top:0;width:440px;height:820px;cursor:pointer}', '#blayer .st{position:absolute;top:0;width:540px;height:820px;cursor:pointer}')
rep("#blayer .st .nxt{position:absolute;left:456px;", "#blayer .st .nxt{position:absolute;left:556px;")

# ---- the legend, true today
rep("Other vendors sit one step out. Specialist stand-ins sit two steps out, in dashed boxes, each named with what it replaces.",
    "Other vendors sit beside it. Dashed tiles are stand-ins, each named with what it replaces: the HR form (for an HR system), a ServiceNow developer instance, Okta's free tier, a local Kubernetes cluster (for AKS) and midPoint (for SailPoint).")
h = h.replace("Dashed tiles stand in for a product with no free trial.", "Dashed tiles are stand-ins, each named with what it replaces.")

# ---- no end row any more: the extras live in Delivery
rep("  const ROW = [", "  const ROW_UNUSED = [")
rep("  const SP = 600, L0 = 120, WH = 820, n = ROW.length,", "  const ROW = [];\n  if (!ROW.length) { document.getElementById('nlayer').remove(); const prevAll0 = window.__allBox; window.__allBox = (W2) => { const b = prevAll0 ? prevAll0(W2) : W2; return { x0: b.x0, y0: Math.min(b.y0, titleTop()), x1: b.x1, y1: b.y1 }; }; window.__newer = { ROW, show() {} }; return; }\n  const SP = 600, L0 = 120, WH = 820, n = ROW.length,")
# the title sits above the tallest setup stop, wherever its tiles end
rep("const tx = W.x0 + 120 * kS, ty = sTop - 360 * kS;",
    "const over = Math.max(0, ...[...document.querySelectorAll('#blayer .b-tiles')].map((e) => e.offsetHeight - 410));\n  const titleTop = () => ty - 90 * kS;\n  const tx = W.x0 + 120 * kS, ty = sTop - (over + 190) * kS;")

# ---- the overview board: at Fit, a readable summary in flow order; zoom in for the drawing
BOARD = r"""
<style id="v24board">
#board { position: absolute; inset: 0; z-index: 5; overflow-y: auto; background: rgba(246,245,241,.97); padding: 104px 24px 24px; display: none; }
#board.on { display: block; }
#board .bh { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: baseline; margin: 0 0 6px; }
#board .bh h2 { margin: 0; font-size: clamp(22px, 2.4vw, 34px); font-weight: 800; letter-spacing: -.02em; }
#board .bh p { margin: 0; color: #6B6A66; font-size: 15px; }
#board .proves { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0 18px; }
#board .proves span { background: #16161A; color: #fff; border-radius: 999px; padding: 6px 14px; font-size: 13.5px; font-weight: 700; }
#board h3 { margin: 18px 0 8px; font-size: 12px; letter-spacing: .1em; text-transform: uppercase; color: #6B6A66; }
#board .rowg { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 10px; }
#board .c { position: relative; text-align: left; border: 1.5px solid #DEDCD6; background: #fff; border-radius: 14px; padding: 10px 12px 12px; font: inherit; cursor: pointer; display: grid; gap: 4px; align-content: start; min-height: 112px; }
#board .c:hover { border-color: #E8703A; }
#board .c .n { font-weight: 800; font-size: 13px; color: #6B6A66; }
#board .c .t { font-weight: 750; font-size: 16px; line-height: 1.2; }
#board .c .g { font-size: 13px; color: #3A3936; line-height: 1.3; }
#board .c .lane { justify-self: start; font-size: 10.5px; font-weight: 800; letter-spacing: .08em; color: #fff; border-radius: 999px; padding: 2px 8px; }
#board .c .tl { font-size: 12px; color: #6B6A66; line-height: 1.35; }
#board .leg { margin-top: 18px; font-size: 13px; color: #3A3936; display: grid; gap: 4px; max-width: 980px; }
#board .hint2 { margin-top: 6px; font-size: 12.5px; color: #6B6A66; }
@media (max-width: 620px) { .chips { flex-wrap: nowrap !important; overflow-x: auto !important; max-width: calc(100vw - 72px) !important; } #board { padding: 62px 12px 16px; } #board .rowg { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); } }
</style>
<script id="v24boardjs">
(function () {
  const lab = window.__lab; if (!lab) return;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const wrap = document.querySelector('.mapwrap'), panel = lab.panel, chips = lab.chips;
  const board = document.createElement('div'); board.id = 'board'; wrap.appendChild(board);
  const SETUP = [...document.querySelectorAll('#blayer .st')].map((st, i) => ({ i, t: st.querySelector('.pill .t').textContent, g: (st.querySelector('.b-goal') || {}).textContent || '', tiles: [...st.querySelectorAll('.tile .lb')].map((x) => x.childNodes[0].textContent.trim()) }));
  const LANE = { source: ['HR', '#E8703A'], directory: ['IDENTITY', '#2F6BFF'], joiner: ['IDENTITY', '#2F6BFF'], apps: ['APPS + CLOUD', '#16161A'], signin: ['IDENTITY', '#2F6BFF'], privileged: ['IDENTITY', '#2F6BFF'], detect: ['WATCHERS', '#2E9E5B'], leaver: ['IDENTITY', '#2F6BFF'], proof: ['EVIDENCE', '#6B6A66'] };
  const card = (go, n, t, g, tiles, lane) => `<button type="button" class="c" data-bgo="${esc(go)}">${lane ? `<span class="lane" style="background:${lane[1]}">${esc(lane[0])}</span>` : ''}<span class="n">${esc(n)}</span><span class="t">${esc(t)}</span><span class="g">${esc(g)}</span><span class="tl">${esc(tiles.join(' · '))}</span></button>`;
  const dv = lab.L.steps || [];
  board.innerHTML = `<div class="bh"><h2>Contoso Health identity lab</h2><p>A made-up hospital of about 5,000 staff. Identity: who you are. Access: what you may open.</p></div>
    <div class="proves"><span>1 Access follows HR</span><span>2 Admin power is borrowed, not kept</span><span>3 Misuse gets caught</span><span>4 An auditor can check all of it</span></div>
    <h3>Setup · 1 to 5 · how the lab was built</h3><div class="rowg">${SETUP.map((s) => card('build:' + s.i, s.i + 1, s.t, s.g, s.tiles, null)).join('')}</div>
    <h3>The lab · 6 to 15 · a person's path, left to right</h3><div class="rowg">${lab.L.st.map((s) => card('station:' + s.id, s.i + 6, s.title, s.goal || s.subtitle || '', s.nodes.map((nd) => nd.name), LANE[s.id])).join('')}${card('delivery', 15, 'Delivery', 'Every change is code, checked and reviewed', ['PR checks', 'Reviewer gate', 'OIDC sign-in', 'Terraform apply', 'Scanner self-test', 'Kubernetes role checker', 'Built, switched off', 'Pipeline settings from Key Vault'], ['DELIVERY', '#E8703A'])}</div>
    <div class="leg"><b>How to read it</b><span>Left to right is the order things happen. Lanes name the system: HR, identity, apps and cloud, watchers, evidence.</span><span>Dashed tiles on the map are stand-ins, each named with what it replaces. Status: RAN · tenant ran in the lab tenant; RAN · harness on a test setup; BUILT is written and tested; DESIGNED is on paper.</span></div>
    <p class="hint2">Click a card, or zoom in, for the full map of that stop.</p>`;
  let fitZ = null, on = false;
  const ov = document.getElementById('overlay');
  function set(v) { if (v === on) return; on = v; board.classList.toggle('on', v); ov.style.visibility = v ? 'hidden' : ''; panel.classList.toggle('off', v); }
  const prev = window.__syncBuild;
  window.__syncBuild = (cam, vw, vh) => { if (prev) prev(cam, vw, vh); if (fitZ == null) return; set(cam.z <= fitZ * 1.12); };
  const learnFit = () => { try { fitZ = lab.fitRect(window.__allBox(lab.W), 0.96).z; } catch (e) { fitZ = null; } };
  board.addEventListener('click', (e) => {
    const c = e.target.closest('[data-bgo]'); if (!c) return; const go = c.dataset.bgo; set(false); panel.classList.remove('off');
    if (go.startsWith('build:')) { const b = chips.querySelector(`[data-build="${go.slice(6)}"]`); if (b) b.click(); }
    else if (go === 'delivery') lab.select({ type: 'delivery' }); else lab.select({ type: 'station', id: go.slice(8) });
  });
  document.getElementById('zfit').addEventListener('click', () => setTimeout(() => { learnFit(); set(true); }, 50));
  chips.addEventListener('click', (e) => { const c = e.target.closest('.chip'); if (c && c.dataset.go === 'overview') setTimeout(() => { learnFit(); set(true); }, 50); });
  setTimeout(() => { learnFit(); set(true); }, 700);
  window.addEventListener('resize', () => setTimeout(learnFit, 120));
})();
</script>
"""
k = h.rindex('</body>')
h = h[:k] + BOARD + h[k:]
open(OUT, 'w', encoding='utf-8').write(h)
print('ok')
