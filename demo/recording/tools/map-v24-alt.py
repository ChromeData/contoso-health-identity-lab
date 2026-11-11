#!/usr/bin/env python3
# Map v24-alt (2026-11-07), from v23: the side pieces (16-20 and the tour items) are put where they
# belong in the story instead of an end row. Only true extras stay, in a short "Also in the lab"
# strip. Adds swimlane labels (HR -> identity -> apps and cloud -> watchers -> evidence) under the
# lab spine. Same look as v23; no new decoration.
import json, re, sys

SRC, OUT = sys.argv[1], sys.argv[2]
h = open(SRC, encoding='utf-8').read()
L = h.split('\n')

# ---------------------------------------------------------------- lab-data: new tiles in their stops
i = next(k for k, l in enumerate(L) if 'id="lab-data"' in l)
s = L[i]; head, body = s[:s.index('>') + 1], s[s.index('>') + 1:s.rindex('</script>')]
D = json.loads(body)
def node(id_, st, name, glyph, status, definition, level=1, side='down', kind='product'):
    return {"id": id_, "station": st, "name": name, "level": level, "side": side, "kind": kind, "glyph": glyph, "status": status,
            "standin_for": None, "definition": definition, "analogy": "", "owner": "IAM Eng", "adrs": [], "where": [], "proof": [], "tested": None,
            "going": {"after": status, "days": [], "notes": []}}
NEW = [
  node('SNOWREQ', 'joiner', 'Ask in ServiceNow', 'ticket', 'DESIGNED', 'A nurse asks for an extra in ServiceNow; her manager approves; Entra grants it by itself. Being built by another helper; not run yet.', 2, 'up'),
  node('OKTAMIG', 'apps', 'Okta apps to Entra', 'reception', 'RAN · tenant', "The clinic's three Okta apps, moved to Entra rule by rule. The estate and the before sign-in ran (24 s); the cut-over and rollback are built, not run.", 2, 'up'),
  node('ADFS', 'apps', 'App off AD FS', 'certificate', 'RAN · tenant', 'AD FS on DC01 (this exercise only) gave the test app all five claims in five real sign-ins. Golden SAML is why companies leave it. The Entra side and the cut-over are built; the readiness report is not registered yet.', 2, 'down'),
  node('SSM', 'apps', 'Server shell (Session Manager)', 'lock', 'RAN · tenant', 'A shell on an AWS server with no SSH key and no open port, only during a PIM activation; every command logged. Torn down after the test. Gaps: 8 min, a 1 h token, an open shell, sudo.', 2, 'up'),
  node('AZROLE', 'apps', 'Azure VM operator role', 'gear', 'RAN · tenant', 'Start, stop and read logs on the lab servers; cannot change the network or run commands. Borrowed in PIM. Key vaults have delete locks the pipeline cannot remove.', 2, 'down'),
  node('ADTIER', 'directory', 'Admin tiers + LAPS', 'shield', 'RAN · tenant', 'Tier 0, 1 and 2 on DC01; a deny-logon policy ready for the first server; Protected Users for the new admins; Windows LAPS rotates the repair password. PingCastle 58 before, 50 after.', 2, 'down'),
  node('SNOWQ', 'leaver', 'IAM queue + report', 'binder', 'DESIGNED', 'Leaving and access work lands in an IAM queue in ServiceNow, with a report. Being built by another helper; not run yet.', 2, 'up'),
]
D['nodes'] += NEW
D['edges'] += [{"from": "AP", "to": "SNOWREQ", "kind": "dashed"}, {"from": "OKTA", "to": "OKTAMIG", "kind": "dashed"}, {"from": "SSO", "to": "SSM", "kind": "dashed"},
               {"from": "AD", "to": "ADTIER", "kind": "dashed"}, {"from": "LEAVER", "to": "SNOWQ", "kind": "dashed"}]
for n in D['nodes']:
    if n['id'] == 'GUAC': n['definition'] += ' Recorded on 7 November: an admin could not open DC01 until she turned on PIM for one hour; a second admin replayed the session.'
    if n['id'] == 'KV': n['definition'] = 'Azure Key Vault: the locked store for secrets. An app in Kubernetes reads one with no stored password and is refused the next (403).'
L[i] = head + json.dumps(D, ensure_ascii=False) + '</script>'
h = '\n'.join(L)

def rep(a, b):
    global h
    assert a in h, a[:80]
    h = h.replace(a, b, 1)

# ---------------------------------------------------------------- labels under the lab stations (v23 NOTES)
rep("joiner: ['8.1 checklist · 8.2 groups from HR', '8.3 a bundle per job · 8.4 extras expire', '8.5 blocked pairs (nurse + pharmacy)'],",
    "joiner: ['Checklist · groups from HR · bundle per job', 'Extras expire · blocked pairs (nurse + pharmacy)', 'Next: ask in ServiceNow, manager approves, auto-grant'],")
rep("apps: ['Trust: accepts Entra’s signed sign-in', 'AWS permission set: read-only', 'ServiceNow: account made by Entra'],",
    "apps: ['Trust: accepts Entra’s signed sign-in', 'Okta and AD FS apps move to Entra, rule by rule', 'Cloud doors: SSM shell and Azure roles via PIM'],")
rep("directory: ['One account, two directories', 'Cloud Sync: one light agent on DC01', 'It also carries HR’s hires into AD'],",
    "directory: ['One account, two directories', 'Cloud Sync: one light agent on DC01', 'Hardened: tiers, Protected Users, LAPS (58 → 50)'],")
rep("privileged: ['Least privilege + just-in-time', 'NIST AC-6, AC-2(7) · HIPAA 164.308(a)(4) · CIS 6.8', 'Exceptions: build account, 2 emergency, robots'],",
    "privileged: ['Least privilege + just-in-time (PIM)', 'Key Vault · Bastion recording · LAPS · EPM (built)', 'No shared password to check out'],")
rep("leaver: ['HR change: off in AD → Entra → AWS', 'IT leaver step: packages out, sessions ended', 'Robot accounts: 20, each with a named owner'],",
    "leaver: ['HR change: off in AD → Entra → AWS', 'IT leaver step: packages out, sessions ended', 'Next: IAM queue + report in ServiceNow'],")

# ---------------------------------------------------------------- the end row becomes one short "Also in the lab" strip
a = h.index('  const ROW = ['); b = h.index('  ];', a) + 4
h = h[:a] + """  const ROW = [
    { n: 'A', id: 'also', title: 'Also in the lab', kicker: 'Checks that prove the code is safe', goal: 'True extras: they sit beside the story, not in it', status: 'RAN · harness and RAN · tenant (pipeline) · BUILT, off',
      what: ['A Kubernetes role checker flags seven kinds of risky permission: 11 risky lines in a planted bad file, none in the clean one.', 'On every change, GitHub feeds the two scanners a deliberately unsafe file; both must fail on it and pass a clean one.', 'Built and tested, switched off: Azure Policy rules in audit mode, an AWS audit trail, and two new alarms. A read-only check shows none is on.', 'The pipeline reads its few private settings from Key Vault over a short-lived sign-in.'],
      tiles: [T('Role checker', '11 risky lines · 0 in clean', 'K8S', 'code', 'Kubernetes: runs app containers; roles say who may do what'), T('Scanner self-test', 'Fail on bad, pass on clean', '✓✗', 'code'), T('Built, off', 'Policy · audit trail · 2 alarms', 'OFF', 'note'), T('Pipeline secrets', 'Read from Key Vault, logged', 'KV', 'code')],
      outs: ['<b>4</b> extras', 'Off items said as off'] },
  ];""" + h[b:]
rep("<span class=\"num\">${s.n}.${j + 1}</span>", "<span class=\"num\">${s.n}${j + 1}</span>")
rep("rtt.textContent = 'The newer parts · 16 to 20';", "rtt.textContent = 'Also in the lab';")
rep("sep.className = 'chipsep newer'; sep.textContent = 'Newer';", "sep.className = 'chipsep newer'; sep.textContent = 'Also';")
rep("c.textContent = `${s.n} ${s.title}`;", "c.textContent = s.title;")
rep("<span class=\"cnum\">Newer · ${t ? `${s.n}.${j + 1}` : `${s.n} of 20`}</span>", "<span class=\"cnum\">Also in the lab${t ? ` · ${s.n}${j + 1}` : ''}</span>")
h = h.replace('<b>16 to 20</b> are the newer parts, below.', 'Each newer piece sits in its stop; <b>Also in the lab</b> holds the true extras.')
h = h.replace("1 to 5 built it. 6 to 15 is the lab running. 16 to 20 below.", "1 to 5 built it. 6 to 15 is the lab running.")

# ---------------------------------------------------------------- setup stop 3: AD hardening tiles
rep("tiles: [{ name: 'DC01', note: 'Active Directory: where hospital PCs log in', img: BIMG('dc01'), kind: 'code' },",
    "tiles: [{ name: 'DC01', note: 'Active Directory: where hospital PCs log in', img: BIMG('dc01'), kind: 'code' }, { name: 'Admin tiers', note: 'Tier 0 · 1 · 2, a deny-logon policy', glyph: 'T0 T1 T2', kind: 'code' }, { name: 'Protected Users + LAPS', note: 'New admins; repair password rotates', glyph: 'LAPS', kind: 'code' }, { name: 'PingCastle', note: '58 before → 50 after', glyph: '50', kind: 'code' },")
rep("outs: ['<b>1</b> domain controller', 'One login, both places'] }", "outs: ['<b>1</b> domain controller', 'One login, both places', '<b>35</b> hardening checks passed'] }")
m = re.search(r'const TILES = (\{.*\});', h); TIL = json.loads(m.group(1))
TIL['2'] = TIL['2'][:1] + [["A tier is a trust zone for admin work: Tier 0 controls AD, Tier 1 runs servers, Tier 2 is the help desk and staff PCs.", "A deny-logon policy keeps Tier 0 accounts off lower tiers; those tiers hold no computers yet, so today it denies nothing."],
                          ["The new admins are in Protected Users, which blocks weaker sign-in methods; three older admins stay out because the remote path still needs NTLM.", "Windows LAPS rotates DC01's repair password every 30 days."],
                          ["PingCastle, a free AD health scanner: 58 before, 50 after. Lower is better.", "35 checks passed; normal users still sign in."]] + TIL['2'][1:]
h = h[:m.start(1)] + json.dumps(TIL, ensure_ascii=False) + h[m.end(1):]

# ---------------------------------------------------------------- swimlanes under the lab spine
LANES = """
  // ---- swimlanes: which system each lab stop belongs to (HR -> identity -> apps and cloud -> watchers -> evidence)
  { const LANE = { source: ['HR', '#E8703A'], directory: ['IDENTITY', '#2F6BFF'], joiner: ['IDENTITY', '#2F6BFF'], apps: ['APPS + CLOUD', '#16161A'], signin: ['IDENTITY', '#2F6BFF'], privileged: ['IDENTITY', '#2F6BFF'], detect: ['WATCHERS', '#2E9E5B'], leaver: ['IDENTITY', '#2F6BFF'], proof: ['EVIDENCE', '#6B6A66'] };
    const gL = mk('g', { id: 'g-lanes' }, svg);
    const laneY = Math.min(...lab.L.st.filter((s) => s.box).map((s) => s.box.y0)) - 90;
    lab.L.st.forEach((s) => { const ln = LANE[s.id]; if (!ln || !s.box) return; const w = 300, x = s.x - w / 2, y = laneY;
      mk('rect', { x, y, width: w, height: 44, rx: 22, fill: ln[1] }, gL);
      const t = mk('text', { x: s.x, y: y + 30, 'text-anchor': 'middle', 'font-size': 22, 'font-weight': 800, 'letter-spacing': '0.08em', fill: '#FFFFFF', 'font-family': FONT }, gL); t.textContent = ln[0]; });
  }
"""
rep("  // ---- 1. the title block over the setup row", LANES + "  // ---- 1. the title block over the setup row")
h = h.replace('const tx = W.x0 + 120 * kS, ty = sTop - 230 * kS;', 'const tx = W.x0 + 120 * kS, ty = sTop - 360 * kS;')
h = h.replace("y0: Math.min(b.y0, sTop - 560 * kS)", "y0: Math.min(b.y0, sTop - 690 * kS)")
h = h.replace('<title>Contoso Lab Maps</title>', '<title>Contoso Lab Map Alt</title>')
open(OUT, 'w', encoding='utf-8').write(h)
print('ok')
