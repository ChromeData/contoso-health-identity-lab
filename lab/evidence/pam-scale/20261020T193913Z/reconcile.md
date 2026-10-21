# PAM reconciliation report

Generated 2026-10-20T19:42:40Z from `out/pam-scale/discovery-latest.json` (discovery 2026-10-20T19:39:47Z) and Vault. Lab evidence: account names only, no secrets.

| KPI | Value |
|---|---|
| Privileged accounts discovered | 515 |
| Eligible for vaulting (excl. documented exceptions) | 387 |
| Vaulted | 263 (67% of eligible) |
| Rotated within policy | 263 (100% of vaulted) |
| Verified (vaulted password binds) | not run (--verify) |
| Documented exceptions | 128 |
| Held (unresolved dependencies) | 124 |
| **GAP** (not vaulted, no exception) | **0** |
| ORPHAN (in Vault, not in AD) | 0 |

| Account | Tier | Status | Vault object | Last rotation | Policy | Within | Verified | Exception / note | Next action |
|---|---|---|---|---|---|---|---|---|---|
| a0-achebe167 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 140d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-ahmed121 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-ahmed155 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 361d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-bello111 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-carter108 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-cohen130 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:34Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-dubois120 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-fischer125 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-fischer159 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 837d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-garcia105 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-garcia139 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 321d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-haddad114 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-ivanova126 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-jensen116 | tier0 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a0-jensen116 on app13.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a0-jensen116 |
| a0-kim112 | tier0 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a0-kim112 on app32.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a0-kim112 |
| a0-kowalski122 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-lopez124 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-mensah123 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-moreau101 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-moreau135 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 493d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-murphy119 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-mwangi106 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-nair110 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-nguyen104 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-novak115 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-obi127 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-okafor102 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-osei107 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-patel103 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-reyes109 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-reyes143 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 543d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-rossi117 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-rossi151 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 154d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-santos128 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-silva113 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-silva147 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 299d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-tanaka118 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a0-walsh129 | tier0 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a0-walsh129 on app26.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a0-walsh129 |
| a0-walsh163 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 268d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a0-yilmaz131 | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 262d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| Administrator | tier0 | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: RID-500 built-in: break-glass, held offline under dual control, rotated by the break-glass drill | owner review (see exception) |
| svc-agent-001 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-002 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-003 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-004 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-005 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-006 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-007 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-008 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-009 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-agent-010 | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-legacy-da | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-vault-rotator | tier0 | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: Vault's own bind (reconcile) account: rotated by ldap/rotate-root, never a static role | owner review (see exception) |
| t0-never-admin | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 200d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| t0-stale-admin | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 400d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| tier0-admin-01 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:22Z | on check-in; idle <= 30d | yes | skipped | - | - |
| tier0-admin-02 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T19:39:22Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-achebe031 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-achebe065 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-achebe099 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-achebe133 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 649d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-achebe235 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-ahmed019 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-ahmed053 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-ahmed087 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-ahmed189 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 272d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-bello009 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-bello043 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-bello077 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-bello145 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 307d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-bello179 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 323d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-brennan030 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for a1-brennan030 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only a1-brennan030 |
| a1-brennan064 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-brennan098 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-brennan098 on app02.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-brennan098 |
| a1-brennan132 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 174d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-brennan166 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 450d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-brennan234 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-carter006 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-carter040 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-carter074 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-carter142 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 801d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-carter176 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 80d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-cohen028 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-cohen028 on app15.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-cohen028 |
| a1-cohen062 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-cohen096 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-cohen164 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 564d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-cohen232 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-dubois018 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-dubois052 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-dubois052 on app12.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-dubois052 |
| a1-dubois086 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-dubois154 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 651d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-dubois188 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 240d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-fischer023 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-fischer057 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-fischer091 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-fischer193 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 238d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-fischer227 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-garcia003 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-garcia037 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-garcia071 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for a1-garcia071 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only a1-garcia071 |
| a1-garcia173 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 185d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-haddad012 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-haddad046 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-haddad080 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-haddad148 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 622d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-haddad182 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 174d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-ivanova024 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-ivanova024 on app07.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-ivanova024 |
| a1-ivanova058 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-ivanova092 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-ivanova160 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 864d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-ivanova194 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 171d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-ivanova228 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-jensen014 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-jensen014 on app24.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-jensen014 |
| a1-jensen048 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-jensen082 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-jensen082 on app12.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-jensen082 |
| a1-jensen150 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 503d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-jensen184 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 290d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-kim010 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kim044 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kim078 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kim146 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 618d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-kim180 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 98d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-kowalski020 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kowalski054 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kowalski088 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-kowalski156 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 800d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-kowalski190 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 192d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-lindqvist032 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lindqvist066 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lindqvist100 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lindqvist134 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 140d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-lindqvist168 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 822d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-lindqvist236 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-lopez022 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lopez056 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lopez090 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-lopez158 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 862d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-lopez192 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 80d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-lopez226 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-mensah021 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for a1-mensah021 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only a1-mensah021 |
| a1-mensah055 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-mensah089 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-mensah157 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 579d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-mensah191 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 121d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-moreau033 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-moreau033 on app23.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-moreau033 |
| a1-moreau067 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-moreau169 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 527d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-moreau237 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-murphy017 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-murphy051 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-murphy085 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-murphy153 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 556d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-murphy187 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 247d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-mwangi004 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-mwangi038 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-mwangi072 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-mwangi140 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 279d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-mwangi174 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 113d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-nair008 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-nair042 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-nair076 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-nair144 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 790d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-nair178 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 384d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-nguyen002 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-nguyen036 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-nguyen036 on app31.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-nguyen036 |
| a1-nguyen070 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-nguyen138 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 286d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-nguyen172 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 80d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-nguyen240 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-novak013 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-novak047 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-novak081 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-novak149 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 431d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-novak183 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 231d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-obi025 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-obi059 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-obi093 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-obi161 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 324d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-obi195 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 375d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-obi229 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-okafor034 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-okafor068 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-okafor136 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 511d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-okafor170 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 157d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-okafor238 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-osei005 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-osei039 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-osei073 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-osei141 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 425d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-osei175 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 344d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-patel001 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-patel001 on app32.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-patel001 |
| a1-patel035 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for a1-patel035 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only a1-patel035 |
| a1-patel069 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-patel137 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 748d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-patel171 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 58d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-patel239 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-reyes007 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-reyes041 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-reyes075 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-reyes177 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 164d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-rossi015 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-rossi049 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-rossi083 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-rossi185 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 271d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-santos026 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\RunAs-a1-santos026 on app32.corp.test.local (owner: app-team) | resolve dependencies, then ./onboard.sh --only a1-santos026 |
| a1-santos060 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-santos094 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-santos162 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 868d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-santos230 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-silva011 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-silva045 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-silva079 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-silva181 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 300d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-tanaka016 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:30Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-tanaka050 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-tanaka084 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-tanaka152 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 485d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-tanaka186 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 286d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| a1-walsh027 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-walsh061 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-walsh095 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for a1-walsh095 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only a1-walsh095 |
| a1-walsh231 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| a1-yilmaz029 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:31Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-yilmaz063 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:32Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-yilmaz097 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:33Z | on check-in; idle <= 30d | yes | skipped | - | - |
| a1-yilmaz165 | tier1 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 196d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| a1-yilmaz233 | tier1 | EXCEPTION | - | - | - | n/a | n/a | disabled account: remove privileged rights or delete, do not vault | owner review (see exception) |
| svc-mgmt-001 | tier1 | VAULTED | static:tier1/svc-mgmt-001 | 2026-10-20T19:40:29.796387865Z | every 72h | yes | skipped | - | - |
| svc-mgmt-002 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service MGMTSvc on mgmt002.corp.test.local (owner: mgmt-team) | resolve dependencies, then ./onboard.sh --only svc-mgmt-002 |
| svc-mgmt-003 | tier1 | VAULTED | static:tier1/svc-mgmt-003 | 2026-10-20T19:40:29.950490786Z | every 72h | yes | skipped | - | - |
| svc-mgmt-004 | tier1 | VAULTED | static:tier1/svc-mgmt-004 | 2026-10-20T19:40:30.088976714Z | every 72h | yes | skipped | - | - |
| svc-mgmt-005 | tier1 | VAULTED | static:tier1/svc-mgmt-005 | 2026-10-20T19:40:30.23639652Z | every 72h | yes | skipped | - | - |
| svc-mgmt-006 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service MGMTSvc on mgmt006.corp.test.local (owner: mgmt-team) | resolve dependencies, then ./onboard.sh --only svc-mgmt-006 |
| svc-mgmt-007 | tier1 | VAULTED | static:tier1/svc-mgmt-007 | 2026-10-20T19:40:30.407881152Z | every 72h | yes | skipped | - | - |
| svc-mgmt-008 | tier1 | VAULTED | static:tier1/svc-mgmt-008 | 2026-10-20T19:41:35.773960765Z | every 72h | yes | skipped | - | - |
| svc-mgmt-009 | tier1 | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service MGMTSvc on mgmt009.corp.test.local (owner: mgmt-team) | resolve dependencies, then ./onboard.sh --only svc-mgmt-009 |
| svc-mgmt-010 | tier1 | VAULTED | static:tier1/svc-mgmt-010 | 2026-10-20T19:40:30.703052307Z | every 72h | yes | skipped | - | - |
| t1-srvadmin-01 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:18Z | on check-in; idle <= 30d | yes | skipped | - | - |
| t1-srvadmin-02 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T19:39:18Z | on check-in; idle <= 30d | yes | skipped | - | - |
| krbtgt | svc | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: KDC account: reset twice with the krbtgt reset procedure (runbook), never vaulted | owner review (see exception) |
| svc-backup | svc | VAULTED | static:svc-backup | 2026-10-20T19:39:22.655357197Z | every 24h | yes | skipped | - | - |
| svc-bi-001 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service BISvc on bi001.corp.test.local (owner: bi-team) | resolve dependencies, then ./onboard.sh --only svc-bi-001 |
| svc-bi-002 | svc | VAULTED | static:svc/svc-bi-002 | 2026-10-20T19:41:29.369471527Z | every 720h | yes | skipped | - | - |
| svc-bi-003 | svc | VAULTED | static:svc/svc-bi-003 | 2026-10-20T19:40:31.321311964Z | every 720h | yes | skipped | - | - |
| svc-bi-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\BiNightly on bi004.corp.test.local (owner: bi-team) | resolve dependencies, then ./onboard.sh --only svc-bi-004 |
| svc-bi-005 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-bi-005 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-bi-005 |
| svc-bi-006 | svc | VAULTED | static:svc/svc-bi-006 | 2026-10-20T19:40:31.497385495Z | every 720h | yes | skipped | - | - |
| svc-bi-007 | svc | VAULTED | static:svc/svc-bi-007 | 2026-10-20T19:40:31.649477533Z | every 720h | yes | skipped | - | - |
| svc-bi-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\BiNightly on bi008.corp.test.local (owner: bi-team) | resolve dependencies, then ./onboard.sh --only svc-bi-008 |
| svc-bi-009 | svc | VAULTED | static:svc/svc-bi-009 | 2026-10-20T19:40:31.823795305Z | every 720h | yes | skipped | - | - |
| svc-bi-010 | svc | VAULTED | static:svc/svc-bi-010 | 2026-10-20T19:41:29.876473119Z | every 720h | yes | skipped | - | - |
| svc-bi-011 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\BiNightly on bi011.corp.test.local (owner: bi-team) | resolve dependencies, then ./onboard.sh --only svc-bi-011 |
| svc-bi-012 | svc | VAULTED | static:svc/svc-bi-012 | 2026-10-20T19:40:32.132280403Z | every 720h | yes | skipped | - | - |
| svc-bi-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-bi-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-bi-013 |
| svc-bi-014 | svc | VAULTED | static:svc/svc-bi-014 | 2026-10-20T19:40:32.298204301Z | every 720h | yes | skipped | - | - |
| svc-bi-015 | svc | VAULTED | static:svc/svc-bi-015 | 2026-10-20T19:40:32.439172119Z | every 720h | yes | skipped | - | - |
| svc-bkp-001 | svc | VAULTED | static:svc/svc-bkp-001 | 2026-10-20T19:40:32.582769825Z | every 720h | yes | skipped | - | - |
| svc-bkp-002 | svc | VAULTED | static:svc/svc-bkp-002 | 2026-10-20T19:40:32.720835337Z | every 720h | yes | skipped | - | - |
| svc-bkp-003 | svc | VAULTED | static:svc/svc-bkp-003 | 2026-10-20T19:41:30.381697786Z | every 720h | yes | skipped | - | - |
| svc-bkp-004 | svc | VAULTED | static:svc/svc-bkp-004 | 2026-10-20T19:40:32.998947328Z | every 720h | yes | skipped | - | - |
| svc-bkp-005 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\BkpNightly on bkp005.corp.test.local (owner: bkp-team) | resolve dependencies, then ./onboard.sh --only svc-bkp-005 |
| svc-bkp-006 | svc | VAULTED | static:svc/svc-bkp-006 | 2026-10-20T19:40:33.158388904Z | every 720h | yes | skipped | - | - |
| svc-bkp-007 | svc | VAULTED | static:svc/svc-bkp-007 | 2026-10-20T19:40:33.323757385Z | every 720h | yes | skipped | - | - |
| svc-bkp-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service BKPSvc on bkp008.corp.test.local (owner: bkp-team) | resolve dependencies, then ./onboard.sh --only svc-bkp-008 |
| svc-bkp-009 | svc | VAULTED | static:svc/svc-bkp-009 | 2026-10-20T19:40:33.54327659Z | every 720h | yes | skipped | - | - |
| svc-bkp-010 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-bkp-010 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-bkp-010 |
| svc-bkp-011 | svc | VAULTED | static:svc/svc-bkp-011 | 2026-10-20T19:40:33.714329348Z | every 720h | yes | skipped | - | - |
| svc-bkp-012 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service BKPSvc on bkp012.corp.test.local (owner: bkp-team) | resolve dependencies, then ./onboard.sh --only svc-bkp-012 |
| svc-bkp-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-bkp-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-bkp-013 |
| svc-bkp-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-bkp-014 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-bkp-014 |
| svc-bkp-015 | svc | VAULTED | static:svc/svc-bkp-015 | 2026-10-20T19:40:33.922041871Z | every 720h | yes | skipped | - | - |
| svc-fax-001 | svc | VAULTED | static:svc/svc-fax-001 | 2026-10-20T19:41:30.874229846Z | every 720h | yes | skipped | - | - |
| svc-fax-002 | svc | VAULTED | static:svc/svc-fax-002 | 2026-10-20T19:40:34.216377154Z | every 720h | yes | skipped | - | - |
| svc-fax-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service FAXSvc on fax003.corp.test.local (owner: fax-team) | resolve dependencies, then ./onboard.sh --only svc-fax-003 |
| svc-fax-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service FAXSvc on fax004.corp.test.local (owner: fax-team) | resolve dependencies, then ./onboard.sh --only svc-fax-004 |
| svc-fax-005 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-fax-005 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-fax-005 |
| svc-fax-006 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service FAXSvc on fax006.corp.test.local (owner: fax-team) | resolve dependencies, then ./onboard.sh --only svc-fax-006 |
| svc-fax-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service FAXSvc on fax007.corp.test.local (owner: fax-team) | resolve dependencies, then ./onboard.sh --only svc-fax-007 |
| svc-fax-008 | svc | VAULTED | static:svc/svc-fax-008 | 2026-10-20T19:40:34.482155172Z | every 720h | yes | skipped | - | - |
| svc-fax-009 | svc | VAULTED | static:svc/svc-fax-009 | 2026-10-20T19:40:34.650790044Z | every 720h | yes | skipped | - | - |
| svc-fax-010 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service FAXSvc on fax010.corp.test.local (owner: fax-team) | resolve dependencies, then ./onboard.sh --only svc-fax-010 |
| svc-fax-011 | svc | VAULTED | static:svc/svc-fax-011 | 2026-10-20T19:40:34.838323135Z | every 720h | yes | skipped | - | - |
| svc-fax-012 | svc | VAULTED | static:svc/svc-fax-012 | 2026-10-20T19:41:31.357402733Z | every 720h | yes | skipped | - | - |
| svc-fax-013 | svc | VAULTED | static:svc/svc-fax-013 | 2026-10-20T19:40:35.155789075Z | every 720h | yes | skipped | - | - |
| svc-fax-014 | svc | VAULTED | static:svc/svc-fax-014 | 2026-10-20T19:40:35.322153938Z | every 720h | yes | skipped | - | - |
| svc-fax-015 | svc | VAULTED | static:svc/svc-fax-015 | 2026-10-20T19:40:35.4801093Z | every 720h | yes | skipped | - | - |
| svc-hl7-001 | svc | VAULTED | static:svc/svc-hl7-001 | 2026-10-20T19:40:35.658586181Z | every 720h | yes | skipped | - | - |
| svc-hl7-002 | svc | VAULTED | static:svc/svc-hl7-002 | 2026-10-20T19:40:35.81745259Z | every 720h | yes | skipped | - | - |
| svc-hl7-003 | svc | VAULTED | static:svc/svc-hl7-003 | 2026-10-20T19:40:35.966275574Z | every 720h | yes | skipped | - | - |
| svc-hl7-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service HL7Svc on hl7004.corp.test.local (owner: hl7-team) | resolve dependencies, then ./onboard.sh --only svc-hl7-004 |
| svc-hl7-005 | svc | VAULTED | static:svc/svc-hl7-005 | 2026-10-20T19:41:31.839172114Z | every 720h | yes | skipped | - | - |
| svc-hl7-006 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service HL7Svc on hl7006.corp.test.local (owner: hl7-team) | resolve dependencies, then ./onboard.sh --only svc-hl7-006 |
| svc-hl7-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-hl7-007 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-hl7-007 |
| svc-hl7-008 | svc | VAULTED | static:svc/svc-hl7-008 | 2026-10-20T19:40:36.312280283Z | every 720h | yes | skipped | - | - |
| svc-hl7-009 | svc | VAULTED | static:svc/svc-hl7-009 | 2026-10-20T19:40:36.453494856Z | every 720h | yes | skipped | - | - |
| svc-hl7-010 | svc | VAULTED | static:svc/svc-hl7-010 | 2026-10-20T19:40:36.592583918Z | every 720h | yes | skipped | - | - |
| svc-hl7-011 | svc | VAULTED | static:svc/svc-hl7-011 | 2026-10-20T19:40:36.731899773Z | every 720h | yes | skipped | - | - |
| svc-hl7-012 | svc | VAULTED | static:svc/svc-hl7-012 | 2026-10-20T19:40:36.869210826Z | every 720h | yes | skipped | - | - |
| svc-hl7-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service HL7Svc on hl7013.corp.test.local (owner: hl7-team) | resolve dependencies, then ./onboard.sh --only svc-hl7-013 |
| svc-hl7-014 | svc | VAULTED | static:svc/svc-hl7-014 | 2026-10-20T19:40:37.024589553Z | every 720h | yes | skipped | - | - |
| svc-hl7-015 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service HL7Svc on hl7015.corp.test.local (owner: hl7-team) | resolve dependencies, then ./onboard.sh --only svc-hl7-015 |
| svc-iis-app | svc | VAULTED | static:svc/svc-iis-app | 2026-10-20T19:40:37.182233416Z | every 720h | yes | skipped | - | - |
| svc-job-001 | svc | VAULTED | static:svc/svc-job-001 | 2026-10-20T19:41:32.324897684Z | every 720h | yes | skipped | - | - |
| svc-job-002 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch03.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-002 |
| svc-job-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-003 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-003 |
| svc-job-004 | svc | VAULTED | static:svc/svc-job-004 | 2026-10-20T19:40:37.497486559Z | every 720h | yes | skipped | - | - |
| svc-job-005 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch01.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-005 |
| svc-job-006 | svc | VAULTED | static:svc/svc-job-006 | 2026-10-20T19:40:37.655628466Z | every 720h | yes | skipped | - | - |
| svc-job-007 | svc | VAULTED | static:svc/svc-job-007 | 2026-10-20T19:40:37.793579274Z | every 720h | yes | skipped | - | - |
| svc-job-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch19.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-008 |
| svc-job-009 | svc | VAULTED | static:svc/svc-job-009 | 2026-10-20T19:40:37.94916121Z | every 720h | yes | skipped | - | - |
| svc-job-010 | svc | VAULTED | static:svc/svc-job-010 | 2026-10-20T19:41:32.811683053Z | every 720h | yes | skipped | - | - |
| svc-job-011 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch19.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-011 |
| svc-job-012 | svc | VAULTED | static:svc/svc-job-012 | 2026-10-20T19:40:38.242766498Z | every 720h | yes | skipped | - | - |
| svc-job-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-013 |
| svc-job-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-014 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-014 |
| svc-job-015 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-015 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-015 |
| svc-job-016 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch05.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-016 |
| svc-job-017 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch03.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-017 |
| svc-job-018 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch13.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-018 |
| svc-job-019 | svc | VAULTED | static:svc/svc-job-019 | 2026-10-20T19:40:38.482031725Z | every 720h | yes | skipped | - | - |
| svc-job-020 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-020 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-020 |
| svc-job-021 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch12.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-021 |
| svc-job-022 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-022 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-022 |
| svc-job-023 | svc | VAULTED | static:svc/svc-job-023 | 2026-10-20T19:40:38.676274312Z | every 720h | yes | skipped | - | - |
| svc-job-024 | svc | VAULTED | static:svc/svc-job-024 | 2026-10-20T19:40:38.815650169Z | every 720h | yes | skipped | - | - |
| svc-job-025 | svc | VAULTED | static:svc/svc-job-025 | 2026-10-20T19:40:38.954691608Z | every 720h | yes | skipped | - | - |
| svc-job-026 | svc | VAULTED | static:svc/svc-job-026 | 2026-10-20T19:41:33.285529188Z | every 720h | yes | skipped | - | - |
| svc-job-027 | svc | VAULTED | static:svc/svc-job-027 | 2026-10-20T19:40:39.237931179Z | every 720h | yes | skipped | - | - |
| svc-job-028 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch10.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-028 |
| svc-job-029 | svc | VAULTED | static:svc/svc-job-029 | 2026-10-20T19:40:39.394879708Z | every 720h | yes | skipped | - | - |
| svc-job-030 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-030 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-030 |
| svc-job-031 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-031 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-031 |
| svc-job-032 | svc | VAULTED | static:svc/svc-job-032 | 2026-10-20T19:40:39.572562797Z | every 720h | yes | skipped | - | - |
| svc-job-033 | svc | VAULTED | static:svc/svc-job-033 | 2026-10-20T19:40:39.71545859Z | every 720h | yes | skipped | - | - |
| svc-job-034 | svc | VAULTED | static:svc/svc-job-034 | 2026-10-20T19:41:33.771846473Z | every 720h | yes | skipped | - | - |
| svc-job-035 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch08.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-035 |
| svc-job-036 | svc | VAULTED | static:svc/svc-job-036 | 2026-10-20T19:40:40.015988622Z | every 720h | yes | skipped | - | - |
| svc-job-037 | svc | VAULTED | static:svc/svc-job-037 | 2026-10-20T19:40:40.15705449Z | every 720h | yes | skipped | - | - |
| svc-job-038 | svc | VAULTED | static:svc/svc-job-038 | 2026-10-20T19:40:40.303563759Z | every 720h | yes | skipped | - | - |
| svc-job-039 | svc | VAULTED | static:svc/svc-job-039 | 2026-10-20T19:40:40.440644273Z | every 720h | yes | skipped | - | - |
| svc-job-040 | svc | VAULTED | static:svc/svc-job-040 | 2026-10-20T19:40:40.585398242Z | every 720h | yes | skipped | - | - |
| svc-job-041 | svc | VAULTED | static:svc/svc-job-041 | 2026-10-20T19:41:34.248877794Z | every 720h | yes | skipped | - | - |
| svc-job-042 | svc | VAULTED | static:svc/svc-job-042 | 2026-10-20T19:40:40.872266001Z | every 720h | yes | skipped | - | - |
| svc-job-043 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-043 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-043 |
| svc-job-044 | svc | VAULTED | static:svc/svc-job-044 | 2026-10-20T19:40:41.031119415Z | every 720h | yes | skipped | - | - |
| svc-job-045 | svc | VAULTED | static:svc/svc-job-045 | 2026-10-20T19:40:41.173181121Z | every 720h | yes | skipped | - | - |
| svc-job-046 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-046 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-046 |
| svc-job-047 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch09.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-047 |
| svc-job-048 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-048 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-048 |
| svc-job-049 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch17.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-049 |
| svc-job-050 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch12.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-050 |
| svc-job-051 | svc | VAULTED | static:svc/svc-job-051 | 2026-10-20T19:40:41.410847595Z | every 720h | yes | skipped | - | - |
| svc-job-052 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch12.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-052 |
| svc-job-053 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-job-053 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-job-053 |
| svc-job-054 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch15.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-054 |
| svc-job-055 | svc | VAULTED | static:svc/svc-job-055 | 2026-10-20T19:41:34.726524578Z | every 720h | yes | skipped | - | - |
| svc-job-056 | svc | VAULTED | static:svc/svc-job-056 | 2026-10-20T19:40:41.745779344Z | every 720h | yes | skipped | - | - |
| svc-job-057 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch10.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-057 |
| svc-job-058 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch06.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-058 |
| svc-job-059 | svc | VAULTED | static:svc/svc-job-059 | 2026-10-20T19:40:41.924716109Z | every 720h | yes | skipped | - | - |
| svc-job-060 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\JobNightly on batch14.corp.test.local (owner: job-team) | resolve dependencies, then ./onboard.sh --only svc-job-060 |
| svc-lis-001 | svc | VAULTED | static:svc/svc-lis-001 | 2026-10-20T19:40:42.083579442Z | every 720h | yes | skipped | - | - |
| svc-lis-002 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-lis-002 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-lis-002 |
| svc-lis-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: connection-string lis.config (ConnectionStrings) on lis003.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-003 |
| svc-lis-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: connection-string lis.config (ConnectionStrings) on lis004.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-004 |
| svc-lis-005 | svc | VAULTED | static:svc/svc-lis-005 | 2026-10-20T19:40:42.274284808Z | every 720h | yes | skipped | - | - |
| svc-lis-006 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-lis-006 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-lis-006 |
| svc-lis-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-lis-007 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-lis-007 |
| svc-lis-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: connection-string lis.config (ConnectionStrings) on lis008.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-008 |
| svc-lis-009 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service LISSvc on lis009.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-009 |
| svc-lis-010 | svc | VAULTED | static:svc/svc-lis-010 | 2026-10-20T19:41:35.22293888Z | every 720h | yes | skipped | - | - |
| svc-lis-011 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service LISSvc on lis011.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-011 |
| svc-lis-012 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service LISSvc on lis012.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-012 |
| svc-lis-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service LISSvc on lis013.corp.test.local (owner: lis-team) | resolve dependencies, then ./onboard.sh --only svc-lis-013 |
| svc-lis-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-lis-014 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-lis-014 |
| svc-lis-015 | svc | VAULTED | static:svc/svc-lis-015 | 2026-10-20T19:40:42.692293848Z | every 720h | yes | skipped | - | - |
| svc-pacs-001 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PACSSvc on pacs001.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-001 |
| svc-pacs-002 | svc | VAULTED | static:svc/svc-pacs-002 | 2026-10-20T19:40:42.848552085Z | every 720h | yes | skipped | - | - |
| svc-pacs-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool PacsPool on pacs003.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-003 |
| svc-pacs-004 | svc | VAULTED | static:svc/svc-pacs-004 | 2026-10-20T19:40:43.005016156Z | every 720h | yes | skipped | - | - |
| svc-pacs-005 | svc | VAULTED | static:svc/svc-pacs-005 | 2026-10-20T19:40:43.144914812Z | every 720h | yes | skipped | - | - |
| svc-pacs-006 | svc | VAULTED | static:svc/svc-pacs-006 | 2026-10-20T19:41:36.286237196Z | every 720h | yes | skipped | - | - |
| svc-pacs-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool PacsPool on pacs007.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-007 |
| svc-pacs-008 | svc | VAULTED | static:svc/svc-pacs-008 | 2026-10-20T19:40:43.439842533Z | every 720h | yes | skipped | - | - |
| svc-pacs-009 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-pacs-009 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-pacs-009 |
| svc-pacs-010 | svc | VAULTED | static:svc/svc-pacs-010 | 2026-10-20T19:40:43.597678236Z | every 720h | yes | skipped | - | - |
| svc-pacs-011 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-pacs-011 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-pacs-011 |
| svc-pacs-012 | svc | VAULTED | static:svc/svc-pacs-012 | 2026-10-20T19:40:43.763989441Z | every 720h | yes | skipped | - | - |
| svc-pacs-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PACSSvc on pacs013.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-013 |
| svc-pacs-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool PacsPool on pacs014.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-014 |
| svc-pacs-015 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PACSSvc on pacs015.corp.test.local (owner: pacs-team) | resolve dependencies, then ./onboard.sh --only svc-pacs-015 |
| svc-pam-discovery | svc | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: read-only discovery bind account: credential in Key Vault for discover.sh | owner review (see exception) |
| svc-print-001 | svc | VAULTED | static:svc/svc-print-001 | 2026-10-20T19:40:43.97535187Z | every 720h | yes | skipped | - | - |
| svc-print-002 | svc | VAULTED | static:svc/svc-print-002 | 2026-10-20T19:40:44.113792936Z | every 720h | yes | skipped | - | - |
| svc-print-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PRINTSvc on print003.corp.test.local (owner: print-team) | resolve dependencies, then ./onboard.sh --only svc-print-003 |
| svc-print-004 | svc | VAULTED | static:svc/svc-print-004 | 2026-10-20T19:41:36.776428677Z | every 720h | yes | skipped | - | - |
| svc-print-005 | svc | VAULTED | static:svc/svc-print-005 | 2026-10-20T19:40:44.415777944Z | every 720h | yes | skipped | - | - |
| svc-print-006 | svc | VAULTED | static:svc/svc-print-006 | 2026-10-20T19:40:44.555837518Z | every 720h | yes | skipped | - | - |
| svc-print-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-print-007 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-print-007 |
| svc-print-008 | svc | VAULTED | static:svc/svc-print-008 | 2026-10-20T19:40:44.714878729Z | every 720h | yes | skipped | - | - |
| svc-print-009 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PRINTSvc on print009.corp.test.local (owner: print-team) | resolve dependencies, then ./onboard.sh --only svc-print-009 |
| svc-print-010 | svc | VAULTED | static:svc/svc-print-010 | 2026-10-20T19:40:44.870043587Z | every 720h | yes | skipped | - | - |
| svc-print-011 | svc | VAULTED | static:svc/svc-print-011 | 2026-10-20T19:40:45.008839489Z | every 720h | yes | skipped | - | - |
| svc-print-012 | svc | VAULTED | static:svc/svc-print-012 | 2026-10-20T19:41:37.257274652Z | every 720h | yes | skipped | - | - |
| svc-print-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service PRINTSvc on print013.corp.test.local (owner: print-team) | resolve dependencies, then ./onboard.sh --only svc-print-013 |
| svc-print-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-print-014 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-print-014 |
| svc-print-015 | svc | VAULTED | static:svc/svc-print-015 | 2026-10-20T19:40:45.330156845Z | every 720h | yes | skipped | - | - |
| svc-ris-001 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RisPool on ris001.corp.test.local (owner: ris-team) | resolve dependencies, then ./onboard.sh --only svc-ris-001 |
| svc-ris-002 | svc | VAULTED | static:svc/svc-ris-002 | 2026-10-20T19:40:45.488662263Z | every 720h | yes | skipped | - | - |
| svc-ris-003 | svc | VAULTED | static:svc/svc-ris-003 | 2026-10-20T19:40:45.630790057Z | every 720h | yes | skipped | - | - |
| svc-ris-004 | svc | VAULTED | static:svc/svc-ris-004 | 2026-10-20T19:40:45.768392995Z | every 720h | yes | skipped | - | - |
| svc-ris-005 | svc | VAULTED | static:svc/svc-ris-005 | 2026-10-20T19:41:37.747406428Z | every 720h | yes | skipped | - | - |
| svc-ris-006 | svc | VAULTED | static:svc/svc-ris-006 | 2026-10-20T19:40:46.047265848Z | every 720h | yes | skipped | - | - |
| svc-ris-007 | svc | VAULTED | static:svc/svc-ris-007 | 2026-10-20T19:40:46.190111563Z | every 720h | yes | skipped | - | - |
| svc-ris-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RisPool on ris008.corp.test.local (owner: ris-team) | resolve dependencies, then ./onboard.sh --only svc-ris-008 |
| svc-ris-009 | svc | VAULTED | static:svc/svc-ris-009 | 2026-10-20T19:40:46.348078146Z | every 720h | yes | skipped | - | - |
| svc-ris-010 | svc | VAULTED | static:svc/svc-ris-010 | 2026-10-20T19:40:46.486521714Z | every 720h | yes | skipped | - | - |
| svc-ris-011 | svc | VAULTED | static:svc/svc-ris-011 | 2026-10-20T19:40:46.625186658Z | every 720h | yes | skipped | - | - |
| svc-ris-012 | svc | VAULTED | static:svc/svc-ris-012 | 2026-10-20T19:41:38.249588769Z | every 720h | yes | skipped | - | - |
| svc-ris-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RisPool on ris013.corp.test.local (owner: ris-team) | resolve dependencies, then ./onboard.sh --only svc-ris-013 |
| svc-ris-014 | svc | VAULTED | static:svc/svc-ris-014 | 2026-10-20T19:40:46.924077154Z | every 720h | yes | skipped | - | - |
| svc-ris-015 | svc | VAULTED | static:svc/svc-ris-015 | 2026-10-20T19:40:47.062782724Z | every 720h | yes | skipped | - | - |
| svc-rx-001 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-rx-001 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-rx-001 |
| svc-rx-002 | svc | VAULTED | static:svc/svc-rx-002 | 2026-10-20T19:40:47.217384583Z | every 720h | yes | skipped | - | - |
| svc-rx-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RxPool on rx003.corp.test.local (owner: rx-team) | resolve dependencies, then ./onboard.sh --only svc-rx-003 |
| svc-rx-004 | svc | VAULTED | static:svc/svc-rx-004 | 2026-10-20T19:40:47.376649839Z | every 720h | yes | skipped | - | - |
| svc-rx-005 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RxPool on rx005.corp.test.local (owner: rx-team) | resolve dependencies, then ./onboard.sh --only svc-rx-005 |
| svc-rx-006 | svc | VAULTED | static:svc/svc-rx-006 | 2026-10-20T19:41:38.842419762Z | every 720h | yes | skipped | - | - |
| svc-rx-007 | svc | VAULTED | static:svc/svc-rx-007 | 2026-10-20T19:40:47.675609046Z | every 720h | yes | skipped | - | - |
| svc-rx-008 | svc | VAULTED | static:svc/svc-rx-008 | 2026-10-20T19:40:47.817036714Z | every 720h | yes | skipped | - | - |
| svc-rx-009 | svc | VAULTED | static:svc/svc-rx-009 | 2026-10-20T19:40:47.956936998Z | every 720h | yes | skipped | - | - |
| svc-rx-010 | svc | VAULTED | static:svc/svc-rx-010 | 2026-10-20T19:40:48.096712158Z | every 720h | yes | skipped | - | - |
| svc-rx-011 | svc | VAULTED | static:svc/svc-rx-011 | 2026-10-20T19:40:48.235761523Z | every 720h | yes | skipped | - | - |
| svc-rx-012 | svc | VAULTED | static:svc/svc-rx-012 | 2026-10-20T19:40:48.374370343Z | every 720h | yes | skipped | - | - |
| svc-rx-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-rx-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-rx-013 |
| svc-rx-014 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool RxPool on rx014.corp.test.local (owner: rx-team) | resolve dependencies, then ./onboard.sh --only svc-rx-014 |
| svc-rx-015 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-rx-015 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-rx-015 |
| svc-sccm-001 | svc | VAULTED | static:svc/svc-sccm-001 | 2026-10-20T19:41:39.484871397Z | every 720h | yes | skipped | - | - |
| svc-sccm-002 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\SccmNightly on sccm002.corp.test.local (owner: sccm-team) | resolve dependencies, then ./onboard.sh --only svc-sccm-002 |
| svc-sccm-003 | svc | VAULTED | static:svc/svc-sccm-003 | 2026-10-20T19:40:48.722996093Z | every 720h | yes | skipped | - | - |
| svc-sccm-004 | svc | VAULTED | static:svc/svc-sccm-004 | 2026-10-20T19:40:48.860961119Z | every 720h | yes | skipped | - | - |
| svc-sccm-005 | svc | VAULTED | static:svc/svc-sccm-005 | 2026-10-20T19:40:49.011693793Z | every 720h | yes | skipped | - | - |
| svc-sccm-006 | svc | VAULTED | static:svc/svc-sccm-006 | 2026-10-20T19:40:49.157572984Z | every 720h | yes | skipped | - | - |
| svc-sccm-007 | svc | VAULTED | static:svc/svc-sccm-007 | 2026-10-20T19:41:40.057305201Z | every 720h | yes | skipped | - | - |
| svc-sccm-008 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-sccm-008 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-sccm-008 |
| svc-sccm-009 | svc | VAULTED | static:svc/svc-sccm-009 | 2026-10-20T19:40:49.455374356Z | every 720h | yes | skipped | - | - |
| svc-sccm-010 | svc | VAULTED | static:svc/svc-sccm-010 | 2026-10-20T19:40:49.592534295Z | every 720h | yes | skipped | - | - |
| svc-sccm-011 | svc | VAULTED | static:svc/svc-sccm-011 | 2026-10-20T19:40:49.732547457Z | every 720h | yes | skipped | - | - |
| svc-sccm-012 | svc | VAULTED | static:svc/svc-sccm-012 | 2026-10-20T19:40:49.873902501Z | every 720h | yes | skipped | - | - |
| svc-sccm-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-sccm-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-sccm-013 |
| svc-sccm-014 | svc | VAULTED | static:svc/svc-sccm-014 | 2026-10-20T19:41:40.615145347Z | every 720h | yes | skipped | - | - |
| svc-sccm-015 | svc | VAULTED | static:svc/svc-sccm-015 | 2026-10-20T19:40:50.172271835Z | every 720h | yes | skipped | - | - |
| svc-sql-001 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: connection-string sql.config (ConnectionStrings) on sql001.corp.test.local (owner: sql-team) | resolve dependencies, then ./onboard.sh --only svc-sql-001 |
| svc-sql-002 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-sql-002 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-sql-002 |
| svc-sql-003 | svc | VAULTED | static:svc/svc-sql-003 | 2026-10-20T19:40:50.346605462Z | every 720h | yes | skipped | - | - |
| svc-sql-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-sql-004 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-sql-004 |
| svc-sql-005 | svc | VAULTED | static:svc/svc-sql-005 | 2026-10-20T19:40:50.504839717Z | every 720h | yes | skipped | - | - |
| svc-sql-006 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-sql-006 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-sql-006 |
| svc-sql-007 | svc | VAULTED | static:svc/svc-sql-007 | 2026-10-20T19:40:50.666188446Z | every 720h | yes | skipped | - | - |
| svc-sql-008 | svc | VAULTED | static:svc/svc-sql-008 | 2026-10-20T19:40:50.806362485Z | every 720h | yes | skipped | - | - |
| svc-sql-009 | svc | VAULTED | static:svc/svc-sql-009 | 2026-10-20T19:40:50.947587904Z | every 720h | yes | skipped | - | - |
| svc-sql-010 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service SQLSvc on sql010.corp.test.local (owner: sql-team) | resolve dependencies, then ./onboard.sh --only svc-sql-010 |
| svc-sql-011 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: scheduled-task \Contoso\SqlNightly on sql011.corp.test.local (owner: sql-team) | resolve dependencies, then ./onboard.sh --only svc-sql-011 |
| svc-sql-012 | svc | VAULTED | static:svc/svc-sql-012 | 2026-10-20T19:41:41.196782788Z | every 720h | yes | skipped | - | - |
| svc-sql-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: connection-string sql.config (ConnectionStrings) on sql013.corp.test.local (owner: sql-team) | resolve dependencies, then ./onboard.sh --only svc-sql-013 |
| svc-sql-014 | svc | VAULTED | static:svc/svc-sql-014 | 2026-10-20T19:40:51.282167798Z | every 720h | yes | skipped | - | - |
| svc-sql-015 | svc | VAULTED | static:svc/svc-sql-015 | 2026-10-20T19:40:51.422990341Z | every 720h | yes | skipped | - | - |
| svc-sql01 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: windows-service MSSQLSERVER on sql01.corp.test.local (owner: dba-team);scheduled-task \Contoso\NightlyIndexMaintenance on sql01.corp.test.local (owner: dba-team) | resolve dependencies, then ./onboard.sh --only svc-sql01 |
| svc-web-001 | svc | VAULTED | static:svc/svc-web-001 | 2026-10-20T19:40:51.581456222Z | every 720h | yes | skipped | - | - |
| svc-web-002 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-web-002 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-web-002 |
| svc-web-003 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-web-003 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-web-003 |
| svc-web-004 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-web-004 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-web-004 |
| svc-web-005 | svc | VAULTED | static:svc/svc-web-005 | 2026-10-20T19:40:51.773921026Z | every 720h | yes | skipped | - | - |
| svc-web-006 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool WebPool on web006.corp.test.local (owner: web-team) | resolve dependencies, then ./onboard.sh --only svc-web-006 |
| svc-web-007 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: iis-app-pool WebPool on web007.corp.test.local (owner: web-team) | resolve dependencies, then ./onboard.sh --only svc-web-007 |
| svc-web-008 | svc | VAULTED | static:svc/svc-web-008 | 2026-10-20T19:41:41.726074118Z | every 720h | yes | skipped | - | - |
| svc-web-009 | svc | VAULTED | static:svc/svc-web-009 | 2026-10-20T19:40:52.089142656Z | every 720h | yes | skipped | - | - |
| svc-web-010 | svc | VAULTED | static:svc/svc-web-010 | 2026-10-20T19:40:52.228274316Z | every 720h | yes | skipped | - | - |
| svc-web-011 | svc | VAULTED | static:svc/svc-web-011 | 2026-10-20T19:40:52.36847544Z | every 720h | yes | skipped | - | - |
| svc-web-012 | svc | VAULTED | static:svc/svc-web-012 | 2026-10-20T19:40:52.50649997Z | every 720h | yes | skipped | - | - |
| svc-web-013 | svc | HELD | - | - | - | n/a | n/a | unresolved dependencies: no dependency record for svc-web-013 in out/pam-scale/deps-rescan.json (add one; an empty list [] means 'no consumers') | resolve dependencies, then ./onboard.sh --only svc-web-013 |
| svc-web-014 | svc | VAULTED | static:svc/svc-web-014 | 2026-10-20T19:40:52.663183761Z | every 720h | yes | skipped | - | - |
| svc-web-015 | svc | VAULTED | static:svc/svc-web-015 | 2026-10-20T19:40:52.804964059Z | every 720h | yes | skipped | - | - |
| a0-achebe201 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-ahmed223 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-bello213 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-brennan200 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-carter210 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-cohen198 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-dubois222 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-garcia207 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-haddad216 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-jensen218 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-kim214 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-kowalski224 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-lindqvist202 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-mensah225 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-moreau203 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-murphy221 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-mwangi208 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-nair212 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-nguyen206 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-novak217 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-okafor204 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-osei209 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-patel205 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-reyes211 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-rossi219 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-santos196 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-silva215 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-tanaka220 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-walsh197 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| a0-yilmaz199 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
| former-admin-01 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
