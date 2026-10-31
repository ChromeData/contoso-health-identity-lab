# Glossary: the lab in plain words

Every term the demo video uses, in the order you'd meet it. One line each,
written for someone who is not in IT, then the longer name in brackets.

## The setup

- **Tenant.** Your company's own fenced-off space inside Microsoft's cloud. Users, rules and logs live inside it.
- **Entra ID.** Microsoft's cloud directory: the list of who works here and what they can sign in to. (Formerly Azure Active Directory.)
- **Active Directory (AD).** The older, on-site version of that list, running on a server in the building. Most hospitals still have one.
- **Domain controller (DC).** The server that runs Active Directory. The lab's is called DC01.
- **Virtual machine (VM).** A computer rented in the cloud instead of bought for a server room.
- **E5.** Microsoft's top licence tier. The lab needs it because the sign-in rules, timed admin rights and risk alerts only come with it.
- **SAML and OIDC.** Two standard ways an app accepts a signed note from the login system instead of keeping its own password. SAML is the older one most business apps speak; OIDC is the newer one.
- **SCIM.** The standard for one system telling another "create this account" or "remove it". It is how AWS accounts appear and disappear with HR.
- **PIM (Privileged Identity Management).** Microsoft's feature for admin rights that switch on for a few hours with a reason, instead of being held all day.
- **Fusion.** A Sentinel detection that joins several weak signals into one alert. It counts as a rule in Microsoft's totals, which is why rule counts differ by one.
- **Organizational unit (OU).** A folder inside Active Directory. The lab has one per department, plus a Disabled folder for leavers.
- **Cloud Sync.** Microsoft's bridge: a small agent on the domain controller that copies accounts up to Entra ID every few minutes. (Microsoft Entra Cloud Sync.)
- **Password hash sync.** Part of that bridge. It carries a scrambled form of each password up, so people have one password in both places; the real password never leaves the server.
- **Custom domain.** The company's own name on the internet, here contosohealthlab.com, verified so sign-in names can use it.

## Getting changes made

- **Code, not clicks.** Every setting is written in a text file, reviewed, and applied by a machine. Hand-clicking is the thing auditors flag: nobody can prove who changed what, or put it back.
- **Repository (repo).** The folder, kept on GitHub, that holds all of that code and its history.
- **Pull request (PR).** A proposed change, shown line by line, with a person named to review it.
- **Merge.** Accepting a pull request into the main copy, the one that counts.
- **Branch.** A working copy of the code, made to try a change. A *throwaway branch* is one made only for a test and deleted afterwards.
- **Checks.** Automatic tests that run on every pull request before a person looks at it.
- **Mocked test.** A rehearsal of the change against a fake tenant, so mistakes fail safely.
- **Reviewer gate.** A named person must say "approve" before the change goes live.
- **Pipeline.** The automated path a change takes: checks, reviewer, sign-in, apply.
- **OIDC sign-in.** How the pipeline's robot identity signs in: GitHub vouches for it with a token that lasts minutes. There is no stored password. (OpenID Connect federation.)
- **Terraform.** The tool that reads the code and makes the tenant match it. **Plan** shows what it would change; **apply** does it.
- **Evidence row.** A numbered line that records what was done, when, the file's fingerprint, and where it's kept.

## People and access

- **HR as the source of truth.** The HR list decides who works here. Accounts and access follow it, never the other way round.
- **Inbound provisioning API.** Microsoft's front door for HR data: HR posts a worker, Microsoft creates the account. (API-driven inbound provisioning.)
- **SCIM.** The standard format for sending "here is a person" between systems.
- **Joiner, mover, leaver.** Someone starting, changing job, or leaving. Each has an automatic path.
- **Mass-change guard.** A safety check: a push that would disable or move more than ten people stops, because a broken HR export looks exactly like a layoff.
- **Access package.** A bundle of access for one job (apps and groups), wrapped with rules on who gets it, who approves, and when it expires.
- **Automatic assignment.** An access package given from HR facts alone, with no request. Nurses get the nurse package because HR says they are nurses.
- **Separation of duties (SoD).** Two kinds of access that must never sit on one person. Here: nursing apps and controlled-substance dispensing.
- **Lifecycle workflow.** A checklist that runs on an HR date: first-day tasks for a joiner, a timed lock-out for a leaver (AD in 7 s, Entra under 3 min, AWS in 9 min; E52).
- **Admin account.** A second, separate login (adm-...) for people who do IT work. Admin power never sits on a daily account.

## Sign-in

- **MFA.** Proving it's you with a second thing, not just a password. (Multi-factor authentication.)
- **Phishing-resistant MFA.** A second factor that can't be tricked out of you, such as a security key or a passkey.
- **Conditional Access (CA).** The bouncer at every sign-in. Each policy is one rule: who it applies to and what it demands.
- **Report-only.** A rule that logs what it would have blocked, without blocking yet. The lab turns each rule on only after its report shows no clinician would be locked out.
- **Legacy authentication.** Old sign-in methods that cannot do a second factor. Blocked.
- **Device code flow.** A sign-in trick for screens without keyboards, often abused by attackers. Blocked.
- **Break-glass account.** An emergency login kept in a safe, excluded from every rule, so there is always a way back in.
- **Temporary Access Pass (TAP).** A one-time code an admin issues so someone can sign in once without a password, for example to set up their first security key.

## Admin power

- **Privileged Identity Management (PIM).** Admin power you switch on for a short window, with a reason, and it switches itself off.
- **Eligible vs active.** Eligible means you may switch the power on. Active means it is on, with an end time.
- **Tier 0 / Tier 1.** Tier 0 roles can change security itself (approval, ticket, four hours). Tier 1 is the service desk (no approval, eight hours, everyday accounts only).
- **Administrative unit (AU).** A fence inside the directory. The help desk's power stops at it, so a help-desk admin cannot touch another admin.
- **Justification.** The reason typed when switching power on. It lands in the audit log.

## Watching and proving

- **Microsoft Defender.** The security console where incidents are worked.
- **Microsoft Sentinel.** The alarm system behind it: rules that read the logs and raise incidents.
- **Log Analytics.** The store where every sign-in and settings change is written.
- **Analytics rule.** One alarm: a query that runs on a schedule and raises an incident when it matches.
- **ITDR.** Identity threat detection and response: rules that spot an attacker's moves inside the directory (standing power granted, a back door added to an app).
- **Incident.** One case in Defender, with its alerts, the accounts involved, and the raw log lines.
- **Containment playbook.** An automatic response to a high incident: disable the account, end its sessions, after a human approves.
- **WORM store.** Write once, read many: storage where evidence can be added but never deleted or altered. Six-year retention here, the HIPAA documentation window.
- **Hash.** A fingerprint of a file. Change one byte and the fingerprint changes, so a stored hash proves the file is untouched.
- **KPI baseline.** A before-and-after measurement: standing admins, uncovered accounts, stale accounts.
