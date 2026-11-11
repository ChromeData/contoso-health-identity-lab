# Intro script (part N00)

What Michael reads on camera for the intro, while he walks the lab map. One line per step, in order, grouped by the map stop on screen. Each line shows the map spot in brackets.
Source: the `piece: 0` steps in [`recording/steps.mjs`](recording/steps.mjs). If the two differ, `steps.mjs` wins.

## Opening: the whole map

1. [`overview`] Hi, I'm Michael. I'm an identity and privileged access engineer. I build IAM, PAM and cloud security labs, and this is my biggest one. IAM is identity and access management. PAM is privileged access management: how admin power is guarded.
2. [`overview`] This is my identity lab. It runs the logins and the access for Contoso Health, a made-up hospital of about five thousand staff. Identity means who you are. Access means what you may open.
3. [`overview`] The lab proves four things. Access follows HR. Admin power is borrowed, not kept. Misuse gets caught. And an auditor can check all of it.
4. [`overview`] This map is the whole lab. The top row is how it was built. The bottom row is the lab running, from hire to leaving.

## Setup stop 1: the sign-ups

5. [`setup:1`] Stop one: the sign-ups. Each piece is a real account, on a free trial or a free developer edition. AWS is pay as you go.
6. [`setup:1.2`] The center is Microsoft Entra ID, Microsoft's cloud login. It is the work badge every other app trusts. A nurse signs in once, and the badge opens what she needs.
7. [`setup:1`] Around it: OrangeHRM for HR, ServiceNow for the IT service desk, and Azure, Microsoft's cloud. AWS, Amazon's cloud, and Okta trust the Entra login. GitHub holds the code, and builds the rest.

## Setup stop 2: the pipeline

8. [`setup:2`] Stop two: the pipeline. The lab is written as code, and Terraform makes each real system match it. Every change is a pull request. GitHub runs a dry run and two security scans. Then nothing changes until I approve it.
9. [`setup:2.3`] Why: an auditor sees what changed and who approved it. To be plain, the domain controller scripts, and fourteen applies from branches before merge, ran outside that gate. The change record lists each one.

## Setup stop 3: the directory

10. [`setup:3`] Stop three: the directory. Hospital PCs still sign in to Active Directory, an older on-site login system. Here it runs on DC01, a Windows server in Azure. Cloud Sync copies each account up to Entra, so one person has one login, on old PCs and in cloud apps.

## Setup stop 4: the people

11. [`setup:4`] Stop four: the people. Thirteen staff and three admins, all from HR. Each IT admin also has a separate admin account, only for admin work, so an everyday login never carries admin power.

## Setup stop 5: the watchers

12. [`setup:5`] Stop five: the watchers. A SIEM, a security information and event management system, collects logs and runs alarm rules on them. Microsoft Sentinel is one. I wrote the rules as code. Fifteen run there, plus Microsoft's Fusion rule. Each matches a technique in MITRE ATT&CK, a public catalog of how attackers work.
13. [`setup:5.2`] Splunk is another SIEM. It gets the same logs every five minutes, and twenty-two rules ran there. Why both: the rules move with the hospital, whichever tool it owns.

## Lab: HR

14. [`tile:HR`] Now the lab, in the order a person moves through it. It starts in HR. HR works in OrangeHRM, an open-source HR system that stands in for the hospital's own. HR sets the job, the department and the manager. There is no password field. Why: HR is the source of truth for who works here.

## Lab stop 6: HR feed to Active Directory

15. [`lab:6`] A connector reads one view of eight fields from HR, once each minute, so private HR data stays in HR. It signs in as a robot identity with no stored password. An agent on DC01 creates the account in Active Directory. In the test run, that took about a minute and a half.

## Lab stop 7: one account, two directories

16. [`lab:7`] Cloud Sync carries the account up to Entra. One account, one password, two directories. Disable it in Active Directory, and it is disabled in the cloud too.

## Lab stop 8: access by job

17. [`lab:8`] Access by job. An access package is a bundle of app access for one job, given on day one, with no ticket. Extras need a manager's approval, and they expire. Nurse and pharmacy packages are incompatible, so no one holds both.

## Lab stop 9: the outside systems

18. [`lab:9`] The outside systems: AWS, ServiceNow and Okta. Entra creates the accounts in AWS and ServiceNow. Each app accepts only a sign-in that Entra signed. So one switch in Entra stops new sign-ins everywhere.

## Lab stop 10: sign-in rules

19. [`lab:10`] Sign-in rules. Conditional Access, or CA, checks every sign-in: who, from where, and how it was proven. Nine rules are enforced, so a stolen password alone gets nobody in.
20. [`tile:CAPR`] New rules start report-only: they log what they would block, and block nothing. CA002, a phishing-proof sign-in for admins, and CA021, an extra check when the top admins switch on their power, are still report-only. Two emergency accounts sit outside every rule, so a bad rule can be undone.

## Lab stop 11: admin power

21. [`lab:11`] Admin power. PIM, Privileged Identity Management, lends it for a few hours, with a reason and a second check. When the time ends, it switches off on its own. Why: a stolen admin account that holds nothing gets nothing. In Entra, no IT admin holds an admin role all day. In Active Directory, four Domain Admin accounts are still standing, and PIM cannot reach them.

## Lab stop 12: alarms

22. [`lab:12`] Alarms. My Sentinel rule caught that admin power-up and opened an incident, and the same rule runs in Splunk. Nothing is locked until a person approves it in Teams, because a wrong lockout can stop a nurse at a bedside.

## Lab stop 13: leaving

23. [`lab:13`] Leaving. HR ends the job, and in the test run Active Directory switched the account off within a minute. Entra, ServiceNow and AWS followed, each on its own sync. IT's leaver workflow is live, but its package removal has not passed its test yet.

## Lab stop 14: proof

24. [`lab:14`] Proof. One click runs the evidence workflow. It files each record with a fingerprint, into a write-once store in Azure. In the lab, its lock stays in its unlocked trial mode, so the lab can be torn down. Why: an auditor can check, instead of taking my word.

## Newer pieces: Key Vault and Bastion

25. [`tile:KV`] Now the newer pieces. Key Vault holds the lab's secrets, so no password sits in the code. Azure Bastion recorded an admin session for replay. It is created only to show that, then deleted, because it costs money every hour.

## Newer pieces: hardening Active Directory

26. [`tile:ADTIER`] Hardening Active Directory. A tier is a trust zone for admin work. A policy denies the top admin accounts any sign-in to lower-tier computers. Those tiers hold no computers yet, so today it denies nothing. PingCastle, a free scanner, scored the domain fifty-eight before and fifty after. Lower is better.

## Newer pieces: AD FS

27. [`tile:ADFS`] AD FS, Active Directory Federation Services, is an older sign-in server. Its signing key can forge a sign-in for anyone, which is why companies move off it. One app's move off it, to Entra, is built and tested. The cut-over has not run yet.

## Newer pieces: Okta

28. [`tile:OKTAMIG`] Okta is the login of a clinic the hospital bought. Moving its three apps to Entra is built. The cut-over has not run yet.

## Newer pieces: server access

29. [`tile:SSM`] Server access in AWS goes through Session Manager, only during a PIM loan, with no SSH key and no open port. SSH is the usual way to log in to a server. The test server ran, and was then torn down. In Azure, a narrow operator role can start a server but not change its network. It is borrowed through PIM too.

## Delivery

30. [`delivery`] Last, delivery. A scanner that never fails proves nothing, so on every change, GitHub feeds the scanners a deliberately unsafe file. More than a hundred and thirty changes are merged. Three things are built but switched off: Azure Policy in audit mode, an AWS audit trail, and two new alarms.

## Close

31. [`overview`] I built this with an AI coding assistant, and I own every decision. The rest of this video shows each piece working, with on-screen text. Let's start.
