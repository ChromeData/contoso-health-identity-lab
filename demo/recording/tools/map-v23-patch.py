#!/usr/bin/env python3
# Presenter map v22 -> v23 (2026-11-07). Carries the 49 cockpit text slides onto the map,
# adds the newer parts as stops 16-20 (lab guide numbering), turns the HR spreadsheet into the
# HR form, and replaces the old PAM stand-ins (Vault, Guacamole, Conjur) with the Microsoft
# products. Facts: readiness/{hr-flow,okta-depth,ad-hardening,pam-microsoft,adfs-migration,
# cloud-least-priv}.md and segments/*/script-v2.md.
import json, re, sys

SRC, OUT = sys.argv[1], sys.argv[2]
txt = open(SRC, encoding='utf-8').read()
L = txt.split('\n')

def jline(n, name):
    s = L[n - 1].strip()
    assert s.startswith('const ' + name + ' = '), (n, s[:40])
    return json.loads(s[len('const ' + name + ' = '):].rstrip(';'))

def put(n, name, obj):
    ind = L[n - 1][:len(L[n - 1]) - len(L[n - 1].lstrip())]
    L[n - 1] = ind + 'const ' + name + ' = ' + json.dumps(obj, ensure_ascii=False) + ';'

# ---------------------------------------------------------------- lab-data (line 150)
s = L[149]; head, body = s[:s.index('>') + 1], s[s.index('>') + 1:s.rindex('</script>')]
D = json.loads(body)
st = {x['id']: x for x in D['stations']}
st['source']['purpose'] = ("Everything starts with HR, the official list of who works here. In the lab a small HR form stands in for an HR system like Workday: HR types a name, picks a department and a job from lists and clicks Hire. The HR system issues the employee number. There is no password field. When HR hires, moves or makes a leaver, the accounts follow. Why this way: if access came from anywhere else, HR and IT would drift apart and leavers would keep access.")
st['privileged']['purpose'] = ("No admin keeps power day to day. Admins borrow it through PIM, say why, get it for a few hours, and it switches off again. AWS admin works the same way. The exceptions are the build account, the two emergency accounts and the robot identities that build and run the lab. Admin passwords and recorded sessions use Microsoft products: Key Vault, Bastion, Windows LAPS and Intune (stop 18). Why: a stolen admin account that holds nothing gets nothing.")
st['privileged']['sources'] = [x for x in st['privileged']['sources'] if 'CyberArk' not in json.dumps(x)] + [
    {"pub": "Microsoft Learn", "title": "Azure Bastion session recording", "why": "Records browser sessions; needs the Premium tier.", "url": "https://learn.microsoft.com/en-us/azure/bastion/session-recording"},
    {"pub": "Microsoft Learn", "title": "What is Windows LAPS?", "why": "A long random local admin password per computer, rotated and stored encrypted.", "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"}]
st['source']['subtitle'] = 'HR owns who works here (the HR form)'
ADR36 = [{"label": "ADR 0036: Microsoft-native PAM (PR #220)", "path": "lab/docs/adr/0036-microsoft-native-pam.md", "url": "https://github.com/ChromeData/contoso-health-identity-lab/pull/220", "pub": False}]
REN = {
  'HR': dict(name='HR form', standin_for='Workday or SAP SuccessFactors', status='RAN · tenant',
             definition='The HR form that plays the HR system: name, department and job from lists, a Hire button, and a Change button per worker. The HR system issues the employee number. No password field anywhere.'),
  'VAULT': dict(name='Windows LAPS', status='RAN · tenant', kind='product', definition="Windows LAPS gives a computer a long random admin password, changes it on a schedule and stores it encrypted. On DC01 it rotates the repair password every 30 days (stop 17).", adrs=ADR36, where=[]),
  'GUAC': dict(name='Recorded sessions (Bastion)', status='RAN · tenant', kind='product', definition='Azure Bastion: a gateway into servers from the browser. With Premium it records each admin session for replay. The lab creates it to show it, then deletes it: about $0.45 an hour.', adrs=ADR36, where=[]),
  'HA': dict(name='Intune EPM', status='BUILT', kind='product', definition='Intune Endpoint Privilege Management: a user runs one approved app as admin, for 24 hours, without being an admin. Licensed in the trial and built as a script, not set up yet.', adrs=ADR36, where=[]),
  'DYN': dict(name='Leak test (ephemeral read)', status='RAN · tenant', kind='product', definition='Terraform read a password from Key Vault two ways. The usual read left it in three of its files; the ephemeral read, used and never kept, in none.', adrs=ADR36, where=[]),
  'CONJUR': dict(name='Pipeline secrets (Key Vault)', status='RAN · tenant', kind='product', definition="The pipeline signs in with a short-lived token and reads its few private settings from Key Vault; every read is logged.", adrs=[], where=[]),
  'K8S': dict(name='Container secrets (Key Vault)', status='RAN · tenant', definition='An app in Kubernetes reads one secret from Key Vault with no stored password, and is refused the secret next to it (403).'),
  'FEED': dict(name='DC logon alarm (rework)', status='DESIGNED', definition='The old alarm used vault check-outs. Its replacement, a DC logon that is not from Bastion or has no PIM activation, is designed only.', where=[]),
}
for n in D['nodes']:
    if n['id'] in REN: n.update(REN[n['id']])
    if n.get('adrs') and any('0007' in a.get('path', '') for a in n['adrs']): n['adrs'] = ADR36
L[149] = head + json.dumps(D, ensure_ascii=False) + '</script>'

# ---------------------------------------------------------------- transcripts, context, tiles, links
TR = jline(1042, 'TR')
TR['build']['3']['text'] = "Four, the people. HR uses a small HR form, a stand-in for an HR system like Workday. Each hire flows in automatically. Nobody creates an account by hand. Why: access follows HR."
TR['build']['4']['text'] = "Five, the watchers. A SIEM collects logs and runs alarm rules on them. Microsoft Sentinel is Microsoft's SIEM, and Splunk watches the same records. I built twenty-four alarm rules; seventeen run in Sentinel today. Why: misuse gets caught, whatever tool the hospital owns."
TR['lab']['source']['text'] = "Six, hiring. HR clicks Hire on the form. Within about four minutes, the account is in Active Directory and in Entra. No ticket."
put(1042, 'TR', TR)
CTX = jline(1043, 'CTX')
CTX['0']['what'] = CTX['0'].get('what', []) + ["How they connect: HR feeds Active Directory, Active Directory feeds Entra, Entra creates the accounts in AWS and ServiceNow, Okta sends its sign-ins to Entra, and GitHub changes all of them through code.", "Trust: each app holds Entra's signing certificate and accepts only a sign-in Entra signed, so one switch in Entra stops new sign-ins everywhere."]
CTX['1']['what'] = CTX['1'].get('what', []) + ["A change, step by step: file, commit, push, pull request, checks, merge, the owner's approval, Terraform builds it, Entra shows it.", "Nothing goes live until the owner approves it in GitHub."]
CTX['3'] = {"what": ["A small HR form stands in for an HR system like Workday.", "HR types a name and picks a department and a job from lists; the manager fills in by itself.", "The HR system issues the employee number: the next free number in the range (400xxx for IT).", "There is no password field. HR never sees one.", "Each save goes to Microsoft's HR front door, into Active Directory, then up to Entra.", "IT staff also get a separate admin account, used only for admin work."], "how": ["Measured: in Active Directory in under a minute, in Entra in about four minutes.", "The apps for the job follow within about half an hour."]}
RULES24 = ["pim-activation: a PIM activation completed", "break-glass-signin: any sign-in by an emergency account", "blocked-country-signin", "failed-signin-spike: guessing", "legacy-auth: old methods with no MFA", "app-credential-added", "app-consent-granted", "ca-policy-changed outside code", "role-assigned-outside-pim", "pim-group-member-added-outside-pim", "auth-method-changed-by-admin", "identity-risk left open", "tier0-logon-without-checkout", "ad-privileged-group-change", "kerberoast-rc4-service-ticket", "dcsync-replication-request", "device-code-signin", "security-info-registered-risky", "dc-logon-outside-operator-allowlist", "vault-privileged-access-anomaly (being re-pointed)", "sod-violation-granted", "pim-activation-without-auth-context", "dormant-privileged-account-reactivation (off)", "keyvault-bulk-secret-read (off)"]
CTX['4'] = {"what": ["A SIEM collects logs and runs alarm rules on them.", "Microsoft Sentinel is Microsoft's SIEM, on an Azure Log Analytics workspace.", "Splunk gets the same sign-in and change records every five minutes and runs the same rules, rewritten.", "24 alarm rules written; 17 run in Sentinel today; the rest wait for their data or are switched off.", "Each rule matches one technique from MITRE ATT&CK, a public catalog of how attackers work."], "how": ["The 24 rules: " + "; ".join(f"{i + 1}. {r}" for i, r in enumerate(RULES24)) + "."]}
put(1043, 'CTX', CTX)
TIL = jline(1044, 'TILES')
TIL['3'][0] = ["The HR form: hire a worker, change a worker, make a leaver.", "Stands in for an HR system like Workday.", "The HR system issues the employee number. No password field."]
TIL['4'] = TIL['4'][:2]
put(1044, 'TILES', TIL)
txt2 = '\n'.join(L)
txt2 = txt2.replace('"HR spreadsheet"', '"HR form"')

# ---------------------------------------------------------------- the setup row (buildMapData)
def rep(a, b, count=1):
    global txt2
    assert a in txt2, a[:70]
    txt2 = txt2.replace(a, b, count)
rep("tiles: [{ name: 'HR spreadsheet', note: '13 fake staff', glyph: 'CSV', kind: 'hand' }", "tiles: [{ name: 'HR form', note: 'Stands in for Workday', glyph: 'FORM', kind: 'hand' }")
rep("text: 'A spreadsheet of thirteen fake staff stands in for HR.", "text: 'A small HR form stands in for an HR system like Workday. HR clicks Hire; the HR system issues the employee number; no password field.")
i = txt2.index("{ title: 'The watchers and the vault'"); j = txt2.index("outs:", i); j = txt2.index("] },", j) + 4
txt2 = txt2[:i] + ("{ title: 'The watchers', kicker: 'Sentinel and Splunk', goal: 'Misuse is seen, whatever tool the hospital owns', text: 'A SIEM collects logs and runs alarm rules on them. Microsoft Sentinel is Microsoft\\'s SIEM. Splunk is another one many companies own; it watches the same records, fed every five minutes. Most hospitals pick one; the rules are built for both.',\n"
  "        bullets: ['Microsoft Sentinel: the alarm system, on an Azure Log Analytics workspace', 'Splunk: a second alarm system on the same sign-in and change records', '24 alarm rules written; 17 run in Sentinel today', 'Each rule matches one MITRE ATT&CK technique'],\n"
  "        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],\n"
  "        tiles: [{ name: 'Microsoft Sentinel', note: 'The alarm system, in Azure', glyph: 'ALERT', kind: 'code' }, { name: 'Splunk', note: 'Watches the same records', img: BIMG('splunk'), kind: 'code' }],\n"
  "        outs: ['<b>24</b> alarm rules written', '<b>17</b> running in Sentinel', 'One MITRE ATT&amp;CK technique each'] },") + txt2[j:]
# stop 1 and 2 outs carry the connection and the change flow
rep("outs: ['<b>6</b> accounts', '<b>1</b> verified domain'] }", "outs: ['<b>6</b> accounts', '<b>1</b> verified domain', 'HR → AD → Entra → AWS + ServiceNow', 'Okta → Entra · GitHub → all', 'Trust: apps accept only Entra\\'s signed sign-in'] }")
rep("outs: ['<b>100+</b> reviewed changes', 'Automatic checks on every change'] }", "outs: ['<b>100+</b> reviewed changes', 'File → commit → push → pull request → checks → merge → approval → build', 'Nothing live until the owner approves'] }")
rep("outs: ['<b>13</b> staff in AD and Entra', '<b>3</b> admin accounts', 'Nurses get their apps by rule'] }", "outs: ['HR form: the only hand step', 'In AD under a minute, in Entra in about 4', '<b>3</b> admin accounts', 'Apps for the job within about 30 minutes'] }")
rep("tiles: [{ name: 'DC01', note: 'Windows Server 2022 in Azure', img: BIMG('dc01'), kind: 'code' }, { name: 'Cloud Sync agent', note: 'Installed on DC01'", "tiles: [{ name: 'DC01', note: 'Active Directory: where hospital PCs log in', img: BIMG('dc01'), kind: 'code' }, { name: 'Cloud Sync agent', note: 'One light agent: copies AD up, and carries HR\\'s hires in'")

# ---------------------------------------------------------------- header: what the lab proves
rep('<p class="lede">', '<p class="lede"><b>About five thousand staff, made up. Identity: who you are. Access: what you may open.</b> ')
rep('<nav class="chips" id="chips"', '<div class="keyrow" id="proves" aria-label="What the lab proves"><span class="sp sp-neutral">1 Access follows HR</span><span class="sp sp-neutral">2 Admin power is borrowed, not kept</span><span class="sp sp-neutral">3 Misuse gets caught</span><span class="sp sp-neutral">4 An auditor can check all of it</span></div>\n  <nav class="chips" id="chips"')

# ---------------------------------------------------------------- the newer row's CSS: the setup row's rules, re-scoped
css = []
for line in txt2.split('\n'):
    if '#blayer' in line and line.lstrip().startswith('#blayer') and '{' in line:
        css.append(line.replace('#blayer', '#nlayer').replace('#bhost', '#nhost').replace('#b-world', '#n-world'))
for line in ['#nlayer { position: absolute; left: 0; top: 0; width: 0; height: 0; overflow: visible; transform-origin: 0 0; pointer-events: none; z-index: 2; }',
             '#nhost { position: absolute; left: 0; top: 0; transform-origin: 0 0; }', '#n-world { position: absolute; left: 0; top: 0; height: 820px; }',
             '#nlayer .tile .def { padding: 0 10px 10px; font-size: 11.5px; color: #3A3936; line-height: 1.25; }',
             '#nlayer .tile.lbl .ph { font-size: 20px; }',
             '.annot rect { fill: #FFFFFF; stroke: #DEDCD6; stroke-width: 2; }',
             '.chipsep.newer { color: #2F6BFF; }']:
    css.append(line)
rep('</style>\n\n<div class="page">', '\n/* v23: the newer row (16-20), the same look as the setup row */\n' + '\n'.join(css) + '\n</style>\n\n<div class="page">')
rep('<div id="blayer">', '<div id="nlayer"><div id="nhost"><div id="n-world"><div class="spine"><div class="fill" id="n-fill"></div><div class="cap"></div></div><div id="n-stations"></div></div></div></div>\n      <div id="blayer">')

open(OUT + '.partial', 'w', encoding='utf-8').write(txt2)
print('patched core')
