import sys,re,base64,json
from pathlib import Path
S=sys.argv[1]
# Resolve repo files relative to this tool so the checkout can live anywhere.
# This file sits at lab/scripts/demo/video/tools/; V is the video dir above it and
# REPO the repo root. The optional 2nd arg overrides the assets dir that holds the
# rendered map and PNGs (default lab/evidence/out/video).
HERE=Path(__file__).resolve().parent
V=HERE.parent
REPO=V.parents[3]
ASSETS=Path(sys.argv[2]) if len(sys.argv)>2 else REPO/'lab'/'evidence'/'out'/'video'
SCRIPT_URL='https://claude.ai/artifact/AVNLqMgHXrsNNttw2PhiGw'
# ---------- setup (build map) world CSS, scoped under #blayer ----------
b=open(f'{V}/pages/build-map.html').read()
style=re.search(r'<style>(.*?)</style>',b,re.S).group(1)
keep=[]
for line in style.splitlines():
    t=line.strip()
    if not t or t.startswith('/*') or t.startswith(':root') or t.startswith('*{') or t.startswith('html,body') or t.startswith('body::before'): continue
    if re.match(r'^(\.chips|\.brand|\.chip|\.zoom|\.legend|#vp|#panel|#sheetbtn|#sheetshow|@media|#world)',t): continue
    keep.append(t)
css='\n'.join(keep)
css=re.sub(r'\.tiles\b','.b-tiles',css); css=re.sub(r'\.goal\b','.b-goal',css)
css=re.sub(r'(?m)^(\S)', r'#blayer \1', css)
out=ASSETS/'build'
imgs={n:'data:image/png;base64,'+base64.b64encode(open(f'{out}/{n}.png','rb').read()).decode() for n in ['entra','azure','aws','servicenow','okta','github','domain','dc01','cloudsync','hrapp','users']}
src=open(f'{V}/scenes.mjs').read(); fn=src[src.index('function buildMapData()'):src.index('const MAP =')]
# transcript lines
lines={x['scene']+'-'+str(x['beat']):x['text'] for x in json.load(open(f'{S}/script.json'))}
scene_names={'03-delivery':'Delivery pipeline','04-hr-feed':'HR feed','05-hr-app':'HR front door','06-ad':'Active Directory','07-directory':'Directory sync','08-joiner':'Joiner','09-signin':'Sign-in rules','10-pim':'Admin tiers (PIM)','11-pim-live':'PIM live','12-detect':'Detect and respond','13-leaver':'Leaver','14-worm':'Evidence vault','15-evidence':'Proof pack'}
build_line={0:'01-built-0',1:'01-built-1',2:'01-built-2',3:'01-built-3'}
lab_ids=['source','directory','joiner','apps','signin','privileged','detect','leaver','proof']
lab_line={sid:f'02-map-{i+1}' for i,sid in enumerate(lab_ids)}; lab_line['delivery']='02-map-10'
walk={'source':['04-hr-feed','05-hr-app'],'directory':['06-ad','07-directory'],'joiner':['08-joiner'],'apps':[],'signin':['09-signin'],'privileged':['10-pim','11-pim-live'],'detect':['12-detect'],'leaver':['13-leaver'],'proof':['14-worm','15-evidence'],'delivery':['03-delivery']}
first_beat={}
for k in lines:
    sc=k.rsplit('-',1)[0]
    if sc not in first_beat: first_beat[sc]=k
TR={'build':{str(i):{'id':l,'text':lines.get(l,'')} for i,l in build_line.items()},
    'lab':{sid:{'id':lab_line[sid],'text':lines.get(lab_line[sid],'')} for sid in lab_line},
    'walk':{k:[{'id':first_beat.get(s,s+'-0'),'name':scene_names.get(s,s)} for s in v] for k,v in walk.items()}}

# ---------- every bubble opens the real thing: the live page and the code ----------
E='https://entra.microsoft.com/#view/'
_ids=json.load(open(ASSETS/'ids.json'))
AZ='https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource'
RG='/subscriptions/de0b2a93-1c62-47b3-aaaf-1bdd1939a274/resourceGroups/rg-identity-lab'
GH='https://github.com/ChromeData/contoso-health-identity-lab'
T=GH+'/tree/main/'; B=GH+'/blob/main/'
U={'entra':'https://entra.microsoft.com/','users':E+'Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers',
   'groups':E+'Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups','apps':E+'Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview',
   'ca':E+'Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies','sync':E+'Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/CloudSync',
   'ap':E+'Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement','lcw':E+'Microsoft_AAD_LifecycleManagement/CommonMenuBlade/~/workflows',
   'pim':E+'Microsoft_Azure_PIMCommon/CommonMenuBlade/~/aadgroup','hrapp':E+f"Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/{_ids['hrAppId']}/objectId/{_ids['hrSpId']}",
   'dana':E+f"Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{_ids['dana']}/hidePreviewBanner~/true",
   'sentinel':f"https://security.microsoft.com/sentinel/analytics?tid={_ids['tenantId']}",'incidents':f"https://security.microsoft.com/incidents?tid={_ids['tenantId']}",
   'rg':AZ+RG+'/overview','vm':AZ+_ids['vmId']+'/overview','worm':AZ+_ids['stId']+'/containersList','kv':AZ+RG+'/providers/Microsoft.KeyVault/vaults/kv-idlab-20f1/overview',
   'awsportal':'https://d-90666212c7.awsapps.com/start','awsidc':'https://us-east-1.console.aws.amazon.com/singlesignon/home?region=us-east-1',
   'snow':'https://dev459905.service-now.com','okta':'https://integrator-8288815-admin.okta.com/admin/dashboard','intune':'https://intune.microsoft.com/',
   'splunk':'http://127.0.0.1:8000','gh':GH,'prs':GH+'/pulls?q=is%3Apr+is%3Amerged','runs':GH+'/actions'}
L_=lambda *xs: [[a, U.get(b, b)] for a, b in xs]
LINKS={'build':{
  '0':L_(('Entra','entra'),('Azure','rg'),('AWS','awsportal'),('ServiceNow','snow'),('Okta','okta'),('GitHub','gh')),
  '1':L_(('The reviewed changes','prs'),('Pipeline runs','runs'),('Code',T+'lab/terraform')),
  '2':L_(('Cloud Sync','sync'),('DC01 server','vm'),('Code',T+'lab/scripts/dc')),
  '3':L_(('People in Entra','users'),('HR front door','hrapp'),('HR spreadsheet',B+'lab/scripts/mock-hr/hr_feed.csv'))},
 'btile':{
  '0':[L_(('Entra','entra')),L_(('Azure','rg')),L_(('AWS sign-in','awsportal'),('AWS login door','awsidc')),L_(('ServiceNow','snow')),L_(('Okta','okta')),L_(('GitHub','gh'))],
  '1':[L_(('The reviewed changes','prs')),L_(('The checks',B+'.github/workflows/terraform-plan.yml')),L_(('The approval gate',B+'.github/workflows/terraform-apply.yml')),L_(('Pipeline runs','runs'))],
  '2':[L_(('DC01 server','vm'),('Build scripts',T+'lab/scripts/dc')),L_(('Cloud Sync','sync'),('Install script',B+'lab/scripts/dc/04-Install-CloudSyncAgent.ps1')),L_(('People in Entra','users'))],
  '3':[L_(('HR spreadsheet',B+'lab/scripts/mock-hr/hr_feed.csv')),L_(('HR front door','hrapp'),('Code',T+'lab/scripts/mock-hr')),L_(('People in Entra','users')),L_(('Admin accounts',B+'lab/iga/admin-accounts.json'))]},
 'lab':{
  'source':L_(('HR front door','hrapp'),('HR spreadsheet',B+'lab/scripts/mock-hr/hr_feed.csv'),('Code',T+'lab/scripts/mock-hr')),
  'directory':L_(('Cloud Sync','sync'),('DC01 server','vm'),('Code',T+'lab/scripts/dc')),
  'joiner':L_(('Access packages','ap'),('First and last day tasks','lcw'),('Code',T+'lab/terraform/modules/entitlement')),
  'apps':L_(('AWS sign-in','awsportal'),('ServiceNow','snow'),('Okta','okta'),('Apps in Entra','apps'),('Code',T+'lab/terraform/modules/apps')),
  'signin':L_(('Sign-in rules','ca'),('Code',T+'lab/terraform/modules/conditional-access')),
  'privileged':L_(('Admin power (PIM)','pim'),('Code',T+'lab/terraform/modules/pim'),('Vault code',T+'lab/pam')),
  'detect':L_(('Sentinel rules','sentinel'),('Incidents','incidents'),('Splunk (this Mac)','splunk'),('Rule code',T+'lab/kql')),
  'leaver':L_(('Dana in Entra','dana'),('Leaver script',B+'lab/scripts/powershell/04-Leaver.ps1')),
  'proof':L_(('Evidence store','worm'),('Evidence log',B+'lab/evidence/capture-log.csv'),('Code',T+'lab/evidence')),
  'delivery':L_(('The reviewed changes','prs'),('Pipeline runs','runs'),('Code',T+'lab/terraform'))},
 'node':{
  'HR':L_(('HR spreadsheet',B+'lab/scripts/mock-hr/hr_feed.csv')),'AGENT':L_(('HR front door','hrapp'),('Code',T+'lab/scripts/mock-hr')),
  'AD':L_(('DC01 server','vm'),('Code',T+'lab/scripts/dc')),'ADCS':L_(('Code',B+'lab/scripts/dc/03-Get-LdapsCaCert.ps1')),
  'SYNC':L_(('Cloud Sync','sync'),('Code',B+'lab/scripts/dc/04-Install-CloudSyncAgent.ps1')),'ENTRA':L_(('People in Entra','users'),('Code',T+'lab/terraform/envs/dev')),
  'LCW':L_(('Workflows','lcw'),('Code',B+'lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1')),'DYNGRP':L_(('Groups','groups'),('Code',T+'lab/terraform/modules/groups')),
  'BIRTH':L_(('Rules',B+'lab/iga/birthright-rules.json')),'AP':L_(('Access packages','ap'),('Code',T+'lab/terraform/modules/entitlement')),'SOD':L_(('Rules',B+'lab/iga/sod-rules.json')),
  'SSO':L_(('AWS sign-in','awsportal'),('AWS login door','awsidc'),('Code',T+'lab/terraform/aws')),'SNOW':L_(('ServiceNow','snow'),('Code',T+'lab/terraform/modules/apps')),
  'OKTA':L_(('Okta','okta'),('Code',T+'lab/terraform/modules/apps')),
  'CABASE':L_(('Sign-in rules','ca'),('Code',T+'lab/terraform/modules/conditional-access')),'CARISK':L_(('Sign-in rules','ca'),('Code',T+'lab/terraform/modules/conditional-access')),
  'CAPR':L_(('Sign-in rules','ca'),('Code',T+'lab/terraform/modules/conditional-access')),'CASESS':L_(('Sign-in rules','ca'),('Code',T+'lab/terraform/modules/conditional-access')),
  'INTUNE':L_(('Intune','intune'),('Code',T+'lab/scripts/intune')),'BG':L_(('Break-glass drill',B+'lab/scripts/powershell/Invoke-BreakGlassDrill.ps1')),
  'PIM':L_(('Admin power (PIM)','pim'),('Code',T+'lab/terraform/modules/pim')),'HDAU':L_(('Code',B+'lab/terraform/modules/pim/helpdesk.tf')),
  'KV':L_(('Key Vault','kv'),('Code',T+'lab/terraform/modules/keyvault')),'VAULT':L_(('Code',T+'lab/pam')),'GUAC':L_(('Code',B+'lab/pam/psm-session.sh')),
  'HA':L_(('Code',T+'lab/pam/ha')),'DYN':L_(('Code',T+'lab/pam/dynamic-db')),'CONJUR':L_(('Code',B+'lab/pam/conjur-demo.sh')),'K8S':L_(('Code',T+'lab/k8s')),
  'LA':L_(('Sentinel rules','sentinel'),('Rule code',T+'lab/kql')),'PB':L_(('Code',B+'lab/monitoring/playbook-notify.json')),'CONTAIN':L_(('Code',B+'lab/monitoring/playbook-contain.json')),
  'FEED':L_(('Code',B+'lab/scripts/monitoring/ingest-vault-audit.sh')),'SPLUNK':L_(('Splunk (this Mac)','splunk'),('Code',T+'lab/splunk')),
  'LEAVER':L_(('Dana in Entra','dana'),('Leaver script',B+'lab/scripts/powershell/04-Leaver.ps1')),'NHI':L_(('Apps in Entra','apps'),('Inventory script',B+'lab/scripts/powershell/06-NHI-Inventory.ps1')),
  'REVIEW':L_(('Access reviews',E+'Microsoft_AAD_ERM/DashboardBlade/~/Controls'),('Code',T+'lab/scripts/powershell/post-apply')),'MID':L_(('Code',T+'lab/pam/midpoint')),'EVID':L_(('Evidence script',B+'lab/scripts/powershell/Export-EvidencePack.ps1')),
  'WORM':L_(('Evidence store','worm'),('Code',T+'lab/terraform/modules/evidence-store')),'KPI':L_(('Code',B+'lab/scripts/powershell/08-Measure-KPIs.ps1')),
  'DRIFT':L_(('Nightly check',B+'.github/workflows/config-drift.yml')),'OPMODEL':L_(('Doc',B+'lab/docs/standards/iam-operating-model.md'))}}
# the clip that shows each stop running (published next to the page under seg/)
WATCH={'build':{'1':[['Watch it run','seg/01-pipeline-delivery.mp4']],'2':[['Watch it run','seg/04-directory-cloud-sync.mp4']],'3':[['Watch it run','seg/03-joiner-hr-feed.mp4']]},
       'lab':{'delivery':[['Watch it run','seg/01-pipeline-delivery.mp4']],'source':[['Watch it run','seg/03-joiner-hr-feed.mp4']],'directory':[['Watch it run','seg/04-directory-cloud-sync.mp4']],
              'joiner':[['Watch it run','seg/05-joiner-access-packages.mp4']],'signin':[['Watch it run','seg/06-conditional-access.mp4']],'privileged':[['Watch it run','seg/07-pim-live-activation.mp4']],
              'detect':[['Sentinel','seg/08-detection-sentinel.mp4'],['Splunk','seg/09-detection-splunk.mp4']],'leaver':[['Watch it run','seg/10-leaver.mp4']],'proof':[['Watch it run','seg/11-evidence-proof.mp4']]}}
# ---------- lab page, patched ----------
m=open(ASSETS/'map-video.html').read()
lab=re.search(r'<body>(.*)</body>',m,re.S).group(1)
# Bubble text: ONE source, pages/map-overrides.json (the video's injectSheet reads it too).
OVR=json.load(open(V/'pages'/'map-overrides.json'))
_re=re.compile(r'(<script type="application/json" id="lab-data">)(.*?)(</script>)',re.S)
_d=json.loads(_re.search(lab).group(2))
def _put(obj,path,val):
    # 'going.days.0.ids' -> obj['going']['days'][0]['ids']. A path that is not in the lab data
    # fails the build, so a moved source map can't be patched in the wrong place silently.
    *ks,last=path.split('.')
    for k_ in ks: obj=obj[int(k_)] if isinstance(obj,list) else obj[k_]
    if isinstance(obj,list): obj[int(last)]=val; return
    if last not in obj: raise KeyError(f'map-overrides.json: {path} is not in the lab data')
    obj[last]=val
for st in _d['stations']:
    if st['id'] in OVR['stations']: st['purpose']=OVR['stations'][st['id']]
    for p_,v_ in OVR.get('stationFields',{}).get(st['id'],{}).items(): _put(st,p_,v_)
for nd in _d['nodes']:
    if nd['id'] in OVR['nodes']: nd['definition'],nd['analogy']=OVR['nodes'][nd['id']]
    if nd['id'] in OVR['names']: nd['name']=OVR['names'][nd['id']]
    if nd['id'] in OVR.get('status',{}): nd['status']=OVR['status'][nd['id']]
    for p_,v_ in OVR.get('fields',{}).get(nd['id'],{}).items(): _put(nd,p_,v_)
for p_,v_ in OVR.get('delivery',{}).items(): _put(_d['delivery'],p_,v_)
lab=_re.sub(lambda m: m.group(1)+json.dumps(_d,ensure_ascii=False).replace('<','\\u003c')+m.group(3), lab, count=1)
# The 'Tested offline' links in the source map name a test record that was never
# committed; point them at the committed one.
lab=lab.replace('offline-tests/20261021T074732Z/','offline-tests/20261020T235044Z/')
# The lab overview's four rules: name every account that still holds standing admin power.
lab=lab.replace("'Nobody keeps admin power when they\\'re not using it. The exceptions are two emergency accounts and the build account, which is flagged and next to go.'",
                "'No admin keeps power when they\\'re not using it. The exceptions are the build account and two locked emergency accounts.'")
lab=lab.replace('<title>Contoso Health Lab Map</title>','').replace('<meta name="claude:viewport-fit-sides" content="cover">','')
def rep(a,b_,n=1):
    # Tolerate already-numbered input: director.mjs numbers the map before saving, so a
    # numbering target may already be gone. Skip rather than assert so a second pass is a no-op.
    global lab
    if a not in lab: return
    lab=lab.replace(a,b_,n)
rep("    svg.setAttribute('viewBox', `${f2(cam.x - w / 2)} ${f2(cam.y - h / 2)} ${f2(w)} ${f2(h)}`);\n",
    "    svg.setAttribute('viewBox', `${f2(cam.x - w / 2)} ${f2(cam.y - h / 2)} ${f2(w)} ${f2(h)}`);\n    if (window.__syncBuild) window.__syncBuild(cam, vw, vh);\n")
i=lab.index('  function overviewView() {'); j=lab.index('  function flyTo(')
lab=lab[:i]+'''  function overviewView() {
    const WB = window.__allBox ? window.__allBox(W) : W;
    const all = fitRect(WB, 0.96);
    if (all.z >= 0.08) return all;
    const z = clamp((vh / (WB.y1 - WB.y0)) * 0.96, ZMIN, ZMAX);
    return { x: WB.x0 + vw / (2 * z), y: (WB.y0 + WB.y1) / 2, z };
  }
  window.__lab = { flyTo, fitRect, select, W, L, NB, get cam() { return cam; }, panel: document.getElementById('panel'), chips: document.getElementById('chips'), svg };
'''+lab[j:]
rep('const MIN_GAP = 780;','const MIN_GAP = 900;')
rep('st[i - 1].ex1 - s.ex0 + 170)','st[i - 1].ex1 - s.ex0 + 260)')
rep('PITCH = 252','PITCH = 290')
rep('pillShape(pin, s.title, s.pillW, PILL_H);','pillShape(pin, (s.i + 5) + " · " + s.title, s.pillW + 46, PILL_H);')
rep('data-go="station:${esc(s.id)}">${esc(s.title)}</button>`))','data-go="station:${esc(s.id)}">${s.i + 5} ${esc(s.title)}</button>`))')
rep('data-go="delivery">Delivery</button>','data-go="delivery">14 Delivery</button>')
rep('    if (fly && target) flyTo(target);','    if (window.__onSelect) window.__onSelect(it);\n    if (fly && target) flyTo(window.__adjust ? window.__adjust(target) : target);')
rep('<div class="overlay" id="overlay"></div>','<div class="overlay" id="overlay"></div>\n      <div id="blayer"><div id="bhost"><div id="b-world"><div class="spine"><div class="fill" id="b-fill"></div><div class="cap"></div></div><div id="b-stations"></div></div></div></div>')
rep('.chips::before { content: "Contoso Health · the lab";','.chips::before { content: "Contoso Health";')
rep('#dotgrid { display: none; }','#dotgrid { display: none; }\n#map rect[fill="#ECEBE7"], #map rect[fill="url(#dotgrid)"] { fill: none !important; display: none; }')
glue_css='''
<style>
#blayer { position: absolute; left: 0; top: 0; width: 0; height: 0; overflow: visible; transform-origin: 0 0; pointer-events: none; z-index: 2; }
#bhost { position: absolute; left: 0; top: 0; transform-origin: 0 0; }
#b-world { position: absolute; left: 0; top: 0; height: 820px; }
#blayer .st { pointer-events: auto; }
#blayer .st.pick .tile { opacity: .35; filter: saturate(.6); }
#blayer .st.pick .tile.focus { opacity: 1; filter: none; box-shadow: 0 0 0 5px rgba(232,112,58,.35), 0 12px 30px rgba(0,0,0,.14); border-color: #E8703A; transform: scale(1.04); }
#blayer .st .nxt { position: absolute; left: 456px; top: 432px; width: 34px; height: 34px; border-radius: 50%; background: #fff; border: 1.5px solid #DEDCD6; display: grid; place-items: center; color: #E8703A; font-weight: 800; font-size: 18px; z-index: 3; }
#blayer .st:last-child .nxt { display: none; }
#blayer .tile .num, #blayer .pill .num { position: absolute; right: 7px; top: 7px; min-width: 24px; height: 22px; padding: 0 7px; border-radius: 999px; background: #16161A; color: #fff; font-size: 11.5px; font-weight: 800; display: grid; place-items: center; letter-spacing: .02em; }
#blayer .pill .num { position: static; margin-left: 6px; background: #F4F3EF; color: #5E5D59; }
.mapwrap .zoom, .mapwrap .hint { z-index: 3; }
.chipsep { font-size: 11px; font-weight: 800; letter-spacing: .08em; color: #8A8984; text-transform: uppercase; margin: 0 2px 0 10px; align-self: center; }
.chip[data-build][aria-current="true"] { background: #E8703A; color: #fff; border-color: #E8703A; }
/* callout: the panel sits next to the piece you clicked */
.panel { transition: left .25s ease, top .25s ease; }
.panel.anch { left: 16px !important; top: var(--ptop, 64px) !important; bottom: auto !important; width: min(400px, calc(100% - 32px)); z-index: 7; max-height: calc(100% - 80px) !important; overflow-y: auto !important; }
.panel.anch::before { display: none; }
.panel .shot { width: 100%; border-radius: 10px; border: 1px solid var(--line); display: block; }
.panel .kind { display: inline-flex; font-size: 11px; font-weight: 800; letter-spacing: .08em; padding: 4px 9px; border-radius: 6px; color: #fff; background: var(--pill); width: max-content; }
.panel .kind.hand { background: #E8703A; } .panel .kind.code { background: #2F6BFF; }
.panel .read li[data-tile] { cursor: pointer; } .panel .read li[data-tile]:hover b { color: #E8703A; }
.panel.anch::before { content: ""; position: absolute; left: -9px; top: 22px; width: 16px; height: 16px; background: var(--card); border-left: 1px solid var(--line); border-bottom: 1px solid var(--line); transform: rotate(45deg); }
.panel.anch.flip::before { left: auto; right: -9px; transform: rotate(-135deg); }
.cnum { display: inline-flex; align-items: center; height: 24px; padding: 0 10px; border-radius: 999px; background: #16161A; color: #fff; font-size: 12px; font-weight: 800; letter-spacing: .04em; width: max-content; }
.cnum.setup { background: #E8703A; }
.ctr { display: grid; gap: 6px; border-top: 1px solid var(--line); padding-top: 8px; }
.ctr h3 { margin: 0 !important; display: block !important; }
.ctr p { font-size: 13px !important; color: var(--grey); line-height: 1.4; display: block !important; }
.ctr .q { font-style: italic; color: var(--ink) !important; }
.ctr a { color: var(--blue); font-weight: 600; text-decoration: none; font-size: 12.5px; }
.ctr .walk { display: flex; flex-wrap: wrap; gap: 6px; }
.ctr .walk a { background: var(--soft); border-radius: 999px; padding: 3px 9px; }
.cnav { display: flex !important; justify-content: space-between; gap: 8px; border-top: 1px solid var(--line); padding-top: 8px; }
.cnav button { border: 0; background: var(--soft); color: var(--ink); font: inherit; font-size: 12.5px; font-weight: 700; border-radius: 9px; padding: 7px 11px; cursor: pointer; max-width: 48%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cnav button.next { background: var(--pill); color: #fff; }
.panel.full .ctr p { display: block !important; }
.panel.anch .ctx h3 { display: block !important; margin: 0 0 3px !important; }
.panel.anch .ctx p { display: block !important; -webkit-line-clamp: unset !important; font-size: 13.5px !important; line-height: 1.45; }
.panel.anch .read li, .panel.anch .rules li { display: list-item !important; }
.panel.anch .duo .card:nth-child(n+2), .panel.anch section:has(.tiles), .panel.anch .tiles, .panel.anch .statusrow, .panel.anch .fine { display: revert !important; }
.panel.anch .tiles { display: flex !important; } .panel.anch .statusrow { display: flex !important; }
.panel.anch .card p { display: block !important; }
.panel.anch .standin { display: block !important; }
.panel .pts { margin: 0; padding-left: 16px !important; display: grid !important; gap: 4px !important; font-size: 13.5px !important; line-height: 1.4; }
.panel .pts li { display: list-item !important; }
.panel .pts li::marker { color: #E8703A; }
.panel.ovw { max-height: calc(100% - 90px) !important; overflow-y: auto !important; width: min(420px, calc(100% - 32px)); }
.panel.ovw .read li:nth-child(n+3) { display: list-item !important; }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin: 0 4px 0 0; vertical-align: -1px; }
.talk { display: grid; gap: 4px; background: #FFF4EC; border: 1px solid #F3C9AE; border-radius: 12px; padding: 10px 12px; }
.talk .lbl { font-size: 11px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: #C2551F; }
.talk p { margin: 0; font-size: 15px !important; line-height: 1.45; color: var(--ink) !important; display: block !important; }
.open { display: flex; flex-wrap: wrap; gap: 6px; }
.open a, .open button { font: inherit; font-size: 12.5px; font-weight: 700; text-decoration: none; border-radius: 999px; padding: 6px 11px; cursor: pointer; border: 1px solid var(--line); background: var(--card); color: var(--ink); }
.open a:hover { border-color: #2F6BFF; color: #2F6BFF; }
.open button.w { background: #16161A; color: #fff; border-color: #16161A; }
details.more { border-top: 1px solid var(--line); padding-top: 8px; }
details.more > summary { cursor: pointer; font-size: 12.5px; font-weight: 700; color: var(--grey); list-style: none; }
details.more > summary::before { content: "▸ "; } details.more[open] > summary::before { content: "▾ "; }
details.more[open] > summary { margin-bottom: 8px; }
#segmodal { position: fixed; inset: 0; z-index: 50; background: rgba(10,10,12,.82); display: none; place-items: center; padding: 24px; }
#segmodal.on { display: grid; }
#segmodal video { width: min(1100px, 100%); max-height: calc(100vh - 90px); border-radius: 12px; background: #000; }
#segmodal button { position: absolute; top: 14px; right: 16px; font: inherit; font-weight: 800; font-size: 14px; border: 0; border-radius: 999px; padding: 8px 14px; cursor: pointer; }
#g-bridge text { font-family: system-ui, -apple-system, "SF Pro Display", "Segoe UI", sans-serif; }
'''+css+'''
</style>
'''
pre_script='''<script>
// numbering for the lab row: stations 5..13 (the setup row is 1..4), used by the lab map while it draws
window.__labNum = (s) => s.i + 5;
</script>
'''
glue_js='''
<script>
(function () {
  const lab = window.__lab; if (!lab) return;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const IMGS = ''' + json.dumps(imgs) + ''';
  const BIMG = (n) => IMGS[n] || '';
  const TR = ''' + json.dumps(TR, ensure_ascii=False) + ''';
  const CTX = {"0": {"what": ["Six accounts, six platforms, one job each.", "Entra: everyone's login, the work badge.", "Azure: runs the lab's servers and storage.", "ServiceNow, AWS, Okta: the outside systems staff sign in to.", "GitHub: the code and every change.", "contosohealthlab.com: the hospital's own web name, verified with one DNS record."], "how": ["Each sign-up: a card, a phone code, a confirmation email.", "Free trials or free developer editions; AWS is pay-as-you-go."]}, "1": {"what": ["Nothing is clicked into the tenant by hand.", "Each change is written as Terraform code and opened as a pull request.", "Automatic checks run, a person types approve, then the pipeline applies it.", "More than 90 changes, each with a trail: who proposed it, what changed, who approved it.", "The pipeline signs in with a token that lasts minutes. No stored password."], "how": ["Day 1: sign-in rules, report-only so nobody gets locked out.", "Day 2: admin tiers in PIM.", "Day 3: access packages and workflows.", "Then 17 live alarm rules, the domain controller, and the outside apps."]}, "2": {"what": ["Most hospitals still run on-site Active Directory, so the lab does too.", "DC01: a Windows Server 2022 VM in Azure, built by Terraform, promoted by script.", "Cloud Sync copies accounts up to Entra on a schedule, passwords included (scrambled).", "One person, one password, both places."], "how": ["The VM shuts down nightly and is started for demos.", "The sync agent is installed by script, because it has to run from inside the server."]}, "3": {"what": ["No real HR system, so a spreadsheet of thirteen fake staff stands in.", "A script pushes each row through Microsoft's HR front door into Active Directory.", "Cloud Sync carries them to Entra.", "Priya arrives marked as a leaver and lands disabled.", "Three IT staff get a second adm- admin account."], "how": ["Run once for joiners, again for a mover (a nurse changing ward) and a leaver.", "The leaver run is the nine-minute HR to AWS clock shown in the lab."]}};
  const TILES = {"0": [["The hospital's login system. Every staff account, group and sign-in rule lives here.", "Sign into anything in the lab and Entra is what checks who you are.", "Why Entra: the hospital runs on Microsoft 365 and Windows, so staff accounts belong here.", "E5 trial unlocks the security features: sign-in rules, timed admin rights, risk alerts."], ["The computer room. Microsoft's cloud, used only for hosting.", "Runs the one Windows server, the locked evidence storage, the secrets vault and the log store.", "Staff never sign into Azure. Only the pipeline and the admin do."], ["Amazon's cloud. Hospitals run their own apps there.", "IAM Identity Center is AWS's own login door, set to trust Entra.", "Staff sign in with their hospital login. No separate AWS password.", "HR marks you a leaver and AWS switches you off on its own: nine minutes, measured."], ["The IT help desk. Staff raise tickets here, IT tracks changes here.", "Developer instance means ServiceNow's free practice copy. Works like the real one.", "Staff sign in with their hospital login; Entra creates their account from HR and switches it off when they leave."], ["Plays a partner clinic the hospital bought, which already has its own login system.", "Integrator org means Okta's free practice account.", "Why: acquired clinics' staff need hospital systems without being re-created one by one.", "Okta trusts Entra, so clinic staff use their own door and still follow hospital rules."], ["The filing cabinet for the code and the diary of every change.", "Every rule, server and account was written as text and saved here.", "Private repo: only invited people can see it.", "Also runs the pipeline: tests, approval, apply."]], "1": [["Every change starts here.", "The change, its plan and an AI review.", "A person approves before it goes live."], ["Automatic checks on every pull request: tests against a fake tenant, security scans and an AI review.", "Broken rules are caught before a human looks."], ["The human gate.", "The pipeline opens an issue with the plan. A person types approve.", "That word is what releases the apply."], ["The APPLY robot runs Terraform and makes the real tenant match the code.", "The plan it used and the result are saved as evidence."]], "2": [["A Windows Server 2022 VM in Azure.", "Created by Terraform, promoted to a domain controller by script.", "The on-site directory most hospitals still have.", "Shuts down nightly to save money."], ["Microsoft's agent, installed on DC01.", "On a schedule, it copies the Workforce and Disabled folders up to Entra.", "Carries a scrambled copy of each password, so one password works in both places."], ["The cloud side of the directory.", "Synced accounts land here and pick up sign-in rules, groups and app access."]], "3": [["Thirteen fake staff: department, title, manager.", "Two are leavers: Priya from day one, Dana after her last day.", "Stands in for the HR system."], ["Microsoft's inbound provisioning app.", "The same door a real HR system like Workday would use.", "A script pushes each spreadsheet row through it into Active Directory."], ["The staff, synced up from Active Directory.", "Each in the right department. In this lab, access by rule covers the nursing jobs."], ["Three IT staff get a second adm- account for admin work.", "Everyday logins never hold admin power."]]};
  const ul = (v) => Array.isArray(v) ? `<ul class="read pts">${v.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : `<p>${esc(v || '')}</p>`;
  const SCRIPT_URL = ''' + json.dumps(SCRIPT_URL) + ''';
  ''' + fn + '''
  const NOTES = ["Where every staff login lives", "Hosts the server and the evidence files", "Amazon's cloud, where hospitals run their own apps", "The IT help desk", "A partner clinic's own login system", "Where the code and the change history live"];
  const D = buildMapData(), SP = 600, L0 = 120, WH = 820, n = D.stations.length, worldW = L0 * 2 + SP * n;
  D.stations[0].tiles.forEach((t, j) => { if (NOTES[j]) t.note = NOTES[j]; });
  const W = lab.W, k = (W.x1 - W.x0) / worldW, gap = 420 * k, BX = W.x0, BY = W.y0 - WH * k - gap;
  const layer = document.getElementById('blayer'), host = document.getElementById('bhost'), world = document.getElementById('b-world');
  world.style.width = worldW + 'px'; host.style.left = BX + 'px'; host.style.top = BY + 'px'; host.style.transform = `scale(${k})`;
  document.getElementById('b-stations').innerHTML = D.stations.map((s, i) => `<div class="st done in" id="bst${i}" style="left:${L0 + SP * i}px" data-i="${i}">
      <div class="b-tiles">${s.tiles.map((t, j) => `<div class="tile ${t.kind || ''}">${t.img ? `<img src="${esc(t.img)}" alt="">` : `<div class="ph">${esc(t.glyph || '')}</div>`}<div class="tag">${esc(t.kind === 'hand' ? 'BY HAND' : t.kind === 'code' ? 'AS CODE' : '')}</div><span class="num">${i + 1}.${j + 1}</span><div class="lb">${esc(t.name)}<small>${esc(t.note || '')}</small></div></div>`).join('')}</div>
      <div class="wire"></div>
      <div class="pill"><div class="n"><span>${i + 1}</span></div><div><div class="t">${esc(s.title)}</div><div class="k">${esc(s.kicker || '')}</div></div></div>
      <div class="nxt">›</div>
      <div class="wire2"></div>
      <div class="below"><div class="outs">${(s.outs || []).map((o) => `<span class="out"><i></i>${o}</span>`).join('')}</div><div class="b-goal">${esc(s.goal || '')}</div></div></div>`).join('');
  document.querySelector('#b-world .spine').classList.add('in'); document.getElementById('b-fill').style.width = '100%';
  // ---- numbering on the lab row: tiles 5.1, 5.2 ... and a badge on the delivery band (14)
  const svg = lab.svg, NSVG = 'http://www.w3.org/2000/svg';
  const mk = (t, a, p) => { const e = document.createElementNS(NSVG, t); for (const q in a) e.setAttribute(q, a[q]); p.appendChild(e); return e; };
  const tileNum = {};
  lab.L.st.forEach((s) => s.nodes.forEach((nd, j) => { tileNum[nd.id] = `${s.i + 5}.${j + 1}`; }));
  svg.querySelectorAll('g.node[data-go^="tile:"]').forEach((g) => {
    const id = g.getAttribute('data-go').slice(5), nd = lab.NB[id]; if (!nd) return;
    const bg = mk('g', { class: 'tnum', transform: `translate(${-nd.size / 2 + 4},${-nd.size / 2 + 4})`, 'pointer-events': 'none' }, g);
    const label = tileNum[id] || '', w = label.length * 11 + 14;
    mk('rect', { x: -w / 2, y: -13, width: w, height: 26, rx: 13, fill: '#16161A', stroke: '#FFFFFF', 'stroke-width': 3 }, bg);
    mk('text', { x: 0, y: 5, 'text-anchor': 'middle', 'font-size': 15, 'font-weight': 800, fill: '#FFFFFF', 'font-family': 'system-ui, -apple-system, sans-serif' }, bg).textContent = label;
  });
  // ---- flow: arrows between lab stations on the spine, and a bridge from the setup row down into the lab
  const stX = lab.L.st.map((s) => s.x);
  const gFlow = mk('g', { id: 'g-bridge' }, svg);
  for (let i = 0; i < stX.length - 1; i++) { const x = (stX[i] + stX[i + 1]) / 2; mk('path', { d: `M${x - 14} -16L${x + 10} 0L${x - 14} 16`, fill: 'none', stroke: '#E8703A', 'stroke-width': 7, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, gFlow); }
  const sx0 = BX + k * (L0 + SP * (n - 1) + 300), sy0 = BY + k * 456, ex = stX[0], ey = -60;
  const x1 = sx0 + 420 * k, gy = (BY + WH * k + W.y0) / 2, r = 90;
  mk('path', { d: `M${sx0} ${sy0}L${x1 - r} ${sy0}Q${x1} ${sy0} ${x1} ${sy0 + r}L${x1} ${gy - r}Q${x1} ${gy} ${x1 - r} ${gy}L${ex + r} ${gy}Q${ex} ${gy} ${ex} ${gy + r}L${ex} ${ey - 10}`, fill: 'none', stroke: '#E8703A', 'stroke-width': 8, 'stroke-dasharray': '26 18', 'stroke-linecap': 'round' }, gFlow);
  mk('path', { d: `M${ex - 26} ${ey - 40}L${ex} ${ey - 6}L${ex + 26} ${ey - 40}`, fill: 'none', stroke: '#E8703A', 'stroke-width': 8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, gFlow);
  const lbx = (x1 + ex) / 2, lby = gy - 70;
  mk('rect', { x: lbx - 330, y: lby - 42, width: 660, height: 84, rx: 42, fill: '#16161A' }, gFlow);
  mk('text', { x: lbx, y: lby + 14, 'text-anchor': 'middle', 'font-size': 40, 'font-weight': 700, fill: '#FFFFFF' }, gFlow).textContent = '1 to 4 built it. 5 to 14 is the lab running.';
  // ---- one camera for both rows
  const panel = lab.panel, wrap = document.querySelector('.mapwrap');
  let anchor = null; // world point the callout points at
  function place(cam, vw, vh) { panel.classList.toggle('anch', !!anchor); if (anchor) { const cb = chips.getBoundingClientRect().bottom - wrap.getBoundingClientRect().top; panel.style.setProperty('--ptop', Math.max(64, cb + 10) + 'px'); } }
  const PW = 432; // panel width plus gutter: the selected piece is framed in the space to its right
  window.__adjust = (t) => { const r = svg.getBoundingClientRect(), vw = Math.max(1, r.width); const z = t.z * Math.max(0.5, (vw - PW) / vw); return { x: t.x - (PW / 2) / z, y: t.y, z }; };
  window.__syncBuild = (cam, vw, vh) => { layer.style.transform = `translate(${vw / 2 - cam.x * cam.z}px, ${vh / 2 - cam.y * cam.z}px) scale(${cam.z})`; place(cam, vw, vh); };
  window.__allBox = (W) => ({ x0: W.x0, y0: BY - 320 * k, x1: W.x1, y1: W.y1 + 120 });
  const rect = (i) => ({ x0: BX + k * (L0 + SP * i - 40), x1: BX + k * (L0 + SP * i + 480), y0: BY, y1: BY + WH * k });
  // ---- one chip bar
  const chips = lab.chips, first = chips.querySelector('.chip');
  const sep1 = document.createElement('span'); sep1.className = 'chipsep'; sep1.textContent = 'Setup';
  const sep2 = document.createElement('span'); sep2.className = 'chipsep'; sep2.textContent = 'Lab';
  first.after(sep1); let a0 = sep1;
  D.stations.forEach((s, i) => { const c = document.createElement('button'); c.type = 'button'; c.className = 'chip'; c.dataset.build = i; c.textContent = `${i + 1} ${s.title}`; c.setAttribute('aria-current', 'false'); a0.after(c); a0 = c; });
  a0.after(sep2);
  // ---- sequence for Prev / Next
  const SEQ = D.stations.map((s, i) => ({ type: 'build', i })).concat(lab.L.st.map((s) => ({ type: 'station', id: s.id }))).concat([{ type: 'delivery' }]);
  const seqName = (it) => it.type === 'build' ? `${it.i + 1} ${D.stations[it.i].title}` : it.type === 'delivery' ? '14 Delivery' : `${lab.L.st.find((s) => s.id === it.id).i + 5} ${lab.L.st.find((s) => s.id === it.id).title}`;
  let cur = -1;
  const goSeq = (idx) => { const it = SEQ[(idx + SEQ.length) % SEQ.length]; if (it.type === 'build') go(it.i); else lab.select(it); };
  function nav(idx) {
    const el = document.createElement('div'); el.className = 'cnav';
    el.innerHTML = `<button type="button" data-nav="${idx - 1}">← ${esc(seqName(SEQ[(idx - 1 + SEQ.length) % SEQ.length]))}</button><button type="button" class="next" data-nav="${idx + 1}">${esc(seqName(SEQ[(idx + 1) % SEQ.length]))} →</button>`;
    el.addEventListener('click', (e) => { const b = e.target.closest('[data-nav]'); if (!b) return; e.stopPropagation(); e.preventDefault(); goSeq(+b.dataset.nav); }, true);
    return el;
  }
  const link = (id) => `${SCRIPT_URL}#${id}`;
  const LINKS = ''' + json.dumps(LINKS, ensure_ascii=False) + ''', WATCH = ''' + json.dumps(WATCH) + ''';
  const modal = document.createElement('div'); modal.id = 'segmodal'; modal.innerHTML = '<video controls playsinline></video><button type="button">Close ✕</button>'; document.body.appendChild(modal);
  const mv = modal.querySelector('video'), closeSeg = () => { mv.pause(); modal.classList.remove('on'); };
  modal.querySelector('button').onclick = closeSeg; modal.addEventListener('click', (e) => { if (e.target === modal) closeSeg(); }); document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSeg(); });
  const presenter = (say, links, watch) => {
    const d = document.createElement('div'); d.className = 'pres'; d.style.cssText = 'display:grid;gap:8px';
    let h = say ? `<div class="talk"><span class="lbl">Say</span><p>${esc(say)}</p></div>` : '';
    const btns = (watch || []).map(([l, u]) => `<button type="button" class="w" data-seg="${esc(u)}">▶ ${esc(l)}</button>`).join('') + (links || []).map(([l, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(l)} ↗</a>`).join('');
    if (btns) h += `<div class="open">${btns}</div>`;
    d.innerHTML = h;
    d.querySelectorAll('[data-seg]').forEach((b) => b.addEventListener('click', (e) => { e.stopPropagation(); mv.src = b.dataset.seg; modal.classList.add('on'); mv.play().catch(() => {}); }));
    return d;
  };
  const fold = (after) => {   // everything below `after` goes under "More detail"
    const rest = []; let el = after.nextElementSibling; while (el) { rest.push(el); el = el.nextElementSibling; }
    if (!rest.length) return; const det = document.createElement('details'); det.className = 'more'; det.innerHTML = '<summary>More detail</summary>';
    rest.forEach((x) => det.appendChild(x)); after.after(det);
  };
  function transcript(kind, key) {
    const t = kind === 'build' ? TR.build[key] : TR.lab[key], w = TR.walk[key] || [];
    if (!t && !w.length) return '';
    let h = '<div class="ctr"><h3>In the video</h3>';
    if (t) h += `<p class="q">“${esc(t.text)}”</p><a href="${link(t.id)}" target="_blank" rel="noopener">Edit this line in the script ↗</a>`;
    else if (kind === 'build') h += '<p>Not narrated in the intro; it is on the map for completeness.</p>';
    if (w.length) h += `<p>Full walkthrough:</p><div class="walk">${w.map((x) => `<a href="${link(x.id)}" target="_blank" rel="noopener">${esc(x.name)}</a>`).join('')}</div>`;
    return h + '</div>';
  }
  const unpick = () => document.querySelectorAll('#blayer .st.pick').forEach((x) => { x.classList.remove('pick'); x.querySelectorAll('.tile.focus').forEach((t) => t.classList.remove('focus')); });
  function go(i) {
    const s = D.stations[i];
    unpick(); lab.select({ type: 'overview' }, { fly: false });
    for (let q = 0; q < n; q++) { const e = document.getElementById('bst' + q); e.classList.toggle('on', q === i); e.classList.toggle('done', q !== i); }
    panel.classList.remove('off');
    const c = CTX[String(i)] || {};
    panel.innerHTML = `<span class="cnum setup">Setup · ${i + 1} of ${n}</span><h2>${esc(s.title)}</h2><div class="goal">${esc(s.goal || '')}</div><section class="ctx"><h3>What it is</h3>${ul(c.what || s.text)}</section><section class="ctx"><h3>How it was set up</h3>${ul(c.how)}</section><section class="ctx"><h3>The pieces</h3><ul class="read">${s.tiles.map((t, j) => `<li data-tile="${j}"><b>${i + 1}.${j + 1}</b> ${esc(t.name)}<span class="fine"> · ${esc(t.note || '')}</span></li>`).join('')}</ul></section>`;
    panel.querySelectorAll('li[data-tile]').forEach((li) => li.addEventListener('click', () => tileGo(i, +li.dataset.tile)));
    { const g = panel.querySelector('.goal'), tr = TR.build[String(i)]; const pr = presenter(tr && tr.text, LINKS.build[String(i)], WATCH.build[String(i)]); g.after(pr); fold(pr); }
    cur = i; panel.appendChild(nav(cur));
    if (window.sheet) window.sheet.full(false);
    chips.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-current', c.dataset.build == i ? 'true' : 'false'));
    anchor = { x: BX + k * (L0 + SP * i + 470), y: BY + k * 120 };
    lab.flyTo(window.__adjust(lab.fitRect(rect(i), 0.9)));
  }
  function worldRect(el) {
    const r = el.getBoundingClientRect(), v = svg.getBoundingClientRect(), cam = lab.cam, vw = v.width, vh = v.height;
    const toW = (sx, sy) => ({ x: (sx - v.left - vw / 2) / cam.z + cam.x, y: (sy - v.top - vh / 2) / cam.z + cam.y });
    const a = toW(r.left, r.top), b2 = toW(r.right, r.bottom); return { x0: a.x, y0: a.y, x1: b2.x, y1: b2.y };
  }
  function tileGo(i, j) {
    const s = D.stations[i], t = s.tiles[j], el = document.querySelectorAll(`#bst${i} .tile`)[j]; if (!t || !el) return;
    lab.select({ type: 'overview' }, { fly: false });
    for (let q = 0; q < n; q++) { const e = document.getElementById('bst' + q); e.classList.toggle('on', q === i); e.classList.toggle('done', q !== i); }
    const desc = (TILES[String(i)] || [])[j] || t.note || '';
    panel.classList.remove('off');
    panel.innerHTML = `<span class="cnum setup">Setup · ${i + 1}.${j + 1}</span><h2>${esc(t.name)}</h2><div class="goal">${esc(t.note || '')}</div>${t.img ? `<img class="shot" src="${esc(t.img)}" alt="">` : ''}<span class="kind ${t.kind || ''}">${t.kind === 'hand' ? 'Signed up by hand' : t.kind === 'code' ? 'Built as code' : 'Piece'}</span><section class="ctx"><h3>What it is</h3>${ul(desc)}</section>`;
    { const g = panel.querySelector('.goal'), pr = presenter(Array.isArray(desc) ? desc.join(' ') : desc, (LINKS.btile[String(i)] || [])[j], null); g.after(pr); fold(pr); }
    const nv = document.createElement('div'); nv.className = 'cnav';
    const prev = j > 0 ? { l: `← ${i + 1}.${j}`, f: () => tileGo(i, j - 1) } : { l: `← ${i + 1} ${s.title}`, f: () => go(i) };
    const next = j < s.tiles.length - 1 ? { l: `${i + 1}.${j + 2} →`, f: () => tileGo(i, j + 1) } : { l: `${seqName(SEQ[(i + 1) % SEQ.length])} →`, f: () => goSeq(i + 1) };
    nv.innerHTML = `<button type="button" data-nav="p">${esc(prev.l)}</button><button type="button" class="next" data-nav="n">${esc(next.l)}</button>`;
    nv.addEventListener('click', (e) => { const b = e.target.closest('[data-nav]'); if (!b) return; e.stopPropagation(); (b.dataset.nav === 'p' ? prev.f : next.f)(); }, true);
    panel.appendChild(nv);
    if (window.sheet) window.sheet.full(false);
    chips.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-current', c.dataset.build == i ? 'true' : 'false'));
    anchor = { x: 0, y: 0 }; cur = i;
    document.querySelectorAll('#blayer .tile.focus').forEach((x) => x.classList.remove('focus')); el.classList.add('focus'); document.getElementById('bst' + i).classList.add('pick');
    lab.flyTo(window.__adjust(lab.fitRect(worldRect(el.parentElement), 0.8)));
  }
  window.__onSelect = (it) => {
    unpick();
    for (let q = 0; q < n; q++) { const el = document.getElementById('bst' + q); el.classList.remove('on'); el.classList.add('done'); }
    if (it.type === 'overview') { anchor = null; cur = -1; panel.classList.add('ovw');
      panel.insertAdjacentHTML('beforeend', `<section class="ctx"><h3>How to read it</h3><ul class="read pts"><li><b>1 to 4</b> is how the lab was built. <b>5 to 14</b> is the lab running.</li><li>Click any bubble: the card shows what to say, links that open the real thing, and the clip of it running.</li><li>Click a number for the overview of that part. Click a sub-number like 1.3 for just that piece.</li><li><span class="sw" style="background:#E8703A"></span>Orange: done by a person. <span class="sw" style="background:#2F6BFF"></span>Blue: written as code.</li><li>Dark tiles are Microsoft products. Dashed tiles stand in for a product with no free trial.</li><li>Orange chevrons point to the next step. Prev and Next on each card walk all fourteen.</li></ul></section>`);
      return; }
    panel.classList.remove('ovw');
    let num = '', key = null;
    if (it.type === 'station') { const s = lab.L.st.find((x) => x.id === it.id); num = `Lab · ${s.i + 5} of 14`; key = s.id; const g = svg.querySelector(`g[data-go="station:${s.id}"] g`); anchor = { x: s.x + (s.pillW || 300) / 2 + 20, y: -30 }; cur = n + s.i; }
    else if (it.type === 'tile') { const nd = lab.NB[it.id]; num = `Lab · ${tileNum[it.id] || ''}`; key = nd.st.id; anchor = { x: nd.x + nd.size / 2 + 10, y: nd.y - nd.size / 2 }; cur = n + nd.st.i; }
    else if (it.type === 'delivery') { num = 'Lab · 14 of 14'; key = 'delivery'; anchor = { x: lab.L.spineX0 + 40, y: W.y0 + 40 }; cur = SEQ.length - 1; }
    panel.querySelectorAll('p:not(.fine):not(.why):not(.path)').forEach((pp) => { if (pp.closest('.cnav, .ctr')) return; if (pp.textContent.length < 60) return; const parts = pp.textContent.split(/(?<=[.!?])\\s+(?=[A-Z])/).filter(Boolean); if (parts.length > 1) { const u = document.createElement('ul'); u.className = 'read pts'; u.innerHTML = parts.map((x) => `<li>${esc(x)}</li>`).join(''); pp.replaceWith(u); } });
    const badge = document.createElement('span'); badge.className = 'cnum'; badge.textContent = num; panel.prepend(badge);
    { const isStop = it.type !== 'tile'; const top = isStop ? (panel.querySelector('.goal') || panel.querySelector('h2')) : panel.querySelector('h2');
      const say = isStop ? (TR.lab[key] ? TR.lab[key].text : '') : (lab.NB[it.id] && lab.NB[it.id].definition) || '';
      const pr = presenter(say, isStop ? LINKS.lab[key] : LINKS.node[it.id], isStop ? WATCH.lab[key] : null);
      if (top) { top.after(pr); fold(pr); } }
    panel.appendChild(nav(cur));
  };
  chips.addEventListener('click', (e) => { const c = e.target.closest('[data-build]'); if (c) go(+c.dataset.build); });
  layer.addEventListener('click', (e) => { const tile = e.target.closest('.tile'); const st = e.target.closest('.st'); if (tile && st) { const j = [...st.querySelectorAll('.tile')].indexOf(tile); tileGo(+st.dataset.i, j); } else if (st) go(+st.dataset.i); });
  lab.select({ type: 'overview' }, { fly: false });
  lab.flyTo(lab.fitRect(window.__allBox(W), 0.96), 0);
  setTimeout(() => lab.flyTo(lab.fitRect(window.__allBox(W), 0.96), 0), 400);
})();
</script>
'''
page='<title>Contoso Lab Maps</title>\n<meta name="claude:viewport-fit-sides" content="cover">\n'+pre_script+lab+glue_css+glue_js
open(f'{S}/contoso-lab-setup-map.html','w').write(page); print(len(page)//1024,'KB')
