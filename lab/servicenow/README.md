# ServiceNow: what it is FOR in the hospital, from the IAM seat

**Status: RAN · tenant (2026-11-07, capture-log E170 to E173)** for the
ServiceNow side and every live proof below, using a **throwaway** twin of the
Entra app (deleted after the proof). The durable Entra app is
[`modules/apps/servicenow_fulfilment.tf`](../terraform/modules/apps/servicenow_fulfilment.tf):
**BUILT** until its PR is merged and the owner approves the apply.

ServiceNow is the hospital's **service desk**: the one place staff go when
they need something from IT. A nurse does not know what Entra ID or an access
package is; she knows "the IT portal". So ServiceNow is the front door, and
**Entra ID stays the system that grants access**. ServiceNow never holds a
role in Entra beyond asking for an access package to be assigned.

| # | Use case | What the person does | What really changes |
|---|---|---|---|
| 1 | **Staff self-service** | A nurse signs in to the portal through Entra single sign-on and fills in **Request app access** (app, reason, start and end date). Her manager approves in the portal. | ServiceNow asks Entra ID Governance to assign the access package (`adminAdd`), with the ticket number in Entra's justification. Entra adds her to the app group. The ticket closes itself when Entra says *Delivered*. Access ends on the end date. |
| 1b | **When Entra says no** | A nurse in ICU asks for Pharmacy dispensing; the manager approves. | Entra refuses: Pharmacy is incompatible with the ICU package (separation of duties). Nothing is granted; the ticket lands in the IAM queue with Entra's reason. |
| 2 | **The IAM queue** | The IAM engineer works group **IAM Operations**: requests that need a person, sign-in / MFA tickets, leaver tasks. | A leaver task has a **Remove access in Entra** button (`adminRemove`, task number in the justification). A sign-in ticket's number goes into the PIM activation justification of the service desk's admin badge. Each Entra change carries its ticket. |
| 3 | **Reporting** | One list, *Access requests (IAM)*: every request grouped by status (the group headers carry the counts), with **Duration** = opened to closed, the time to fulfil. | Read-only. |

## How ServiceNow talks to Entra (and why this way)

```
nurse --SSO--> ServiceNow portal --(manager approves)--> ServiceNow
   ServiceNow --signed JWT (its own key)--> Entra token endpoint --> token, no Graph roles
   ServiceNow --POST assignmentRequests (adminAdd, "RITM... approved by ...")--> Entra ID Governance
   Entra --> App-ICU-CriticalCare-Users (+ Entra audit log, Sentinel)
```

- **Identity:** app *ServiceNow - Access Fulfilment*. **No Graph API
  permission.** One entitlement-management role: *Access package assignment
  manager* on the **Clinical** catalog. Microsoft's Graph reference says an
  app-only caller can hold that role *instead of*
  `EntitlementManagement.ReadWrite.All`, and that it is less privileged. It
  can add or remove people on existing packages of one catalog; it cannot
  read the directory, edit a package, or touch a group directly.
- **No client secret.** ServiceNow signs a 5-minute `client_assertion` with
  a key in its own Java key store (`jwt_provider` + `jwt_keystore_aliases`,
  x5t header). Entra holds only the public certificate.
  [`fulfilment-cert.py`](fulfilment-cert.py) mints / rotates it; the private
  key exists only inside the instance.
- **Who approves:** the person's manager **from Entra**. The provisioning
  job now also maps `manager` and `objectId` → `u_entra_object_id`
  ([`provisioning-mapping.py`](provisioning-mapping.py)), so ServiceNow keeps
  no org chart of its own and names people to Graph by their immutable id.
- **Fail closed:** any token or Graph error leaves the ticket open, assigned
  to IAM Operations, with the error in the work notes. Nothing retries
  silently.

Seen live and designed around:

| Finding (dev459905 / tenant, 2026-11-07) | Effect on the design |
|---|---|
| With only a catalog role, `GET assignmentRequests/{id}` and an assignments filter on the person alone return **403**; the same reads filtered by a package of the catalog return 200 | Tickets store `packageId/requestId`; every read names the package |
| A catalog item with no flow falls back to the **DEFAULT delivery plan**, which approved the item automatically and opened two generic tasks | `delivery_plan` is set empty on both items, so the manager approval is the only approval |
| The JWT key alias accepts only a **Java key store** (business rule *validate*), and a certificate record's type cannot be changed after insert | `fulfilment-cert.py` converts PKCS#12 to JKS with `keytool` |
| `sys_script` names are cut at **40 characters** | names kept short; `apply.py` asserts it |
| A `sys_report` bar chart on request items was refused to the IAM engineer (*report_view field ACLs*), although she holds `itil` | reporting is a list view grouped by state; lists follow the read ACLs the queue already uses |
| The PDI demo data reuses ticket numbers (`REQ0010001`, `RITM0010001` twice) | `cleanup.py` never deletes by REQ number, and finds a RITM only through the lab's own catalog items |
| `adminAdd` of Pharmacy for an ICU nurse: **400**, Entra names the conflicting group and package | the refusal is shown as-is in the IAM queue |

## Files

| File | What it does |
|---|---|
| [`apply.py`](apply.py) | Builds everything on the instance through the Table API, idempotent (`--plan` first). Reads access-package and policy ids live from Graph as the lab operator. |
| [`config.json`](config.json) | Names only: catalog item text, app list → access package, queue, reports. |
| [`server/`](server) | The ServiceNow server code, one file per record: script include `ContosoEntraAccess`, business rules, script action, scheduled job, UI action. |
| [`fulfilment-cert.py`](fulfilment-cert.py) | New key in ServiceNow + public PEM for Terraform. |
| [`provisioning-mapping.py`](provisioning-mapping.py) | Adds `manager` and `u_entra_object_id` to the Entra → ServiceNow provisioning schema (tenant-time step; azuread has no schema resource). |
| [`snlib.py`](snlib.py) | Table API client; admin password from the Keychain, never printed. |
| [`demo/portal.mjs`](demo/portal.mjs) | The browser side: nurse requests, manager approves, IAM engineer clicks, screenshots. Sign-in through the lab's sign-in tool. |
| [`demo/pim.mjs`](demo/pim.mjs) | Admin-badge PIM activation with the ticket number as the justification. |
| [`demo/prove.py`](demo/prove.py) | The live proof of every use case, evidence to `lab/evidence/servicenow/<UTC>/`, then cleanup. |
| [`demo/cleanup.py`](demo/cleanup.py) | Deletes test tickets (never PDI demo data). |
| [`tests/`](tests) | Offline unit tests (CI: `lab-tests.yml`). |

## Order (operator Mac)

```bash
/usr/bin/python3 -I lab/servicenow/fulfilment-cert.py            # key into ServiceNow, PEM into the module
# PR -> merge -> owner approves the apply (enable_servicenow_fulfilment = true)
/usr/bin/python3 -I lab/servicenow/provisioning-mapping.py --plan && /usr/bin/python3 -I lab/servicenow/provisioning-mapping.py
/usr/bin/python3 -I lab/servicenow/apply.py --plan && /usr/bin/python3 -I lab/servicenow/apply.py
/usr/bin/python3 -I lab/servicenow/demo/prove.py                 # live proof + cleanup
```

Run Python with `/usr/bin/python3 -I`: the python.org build on the operator
Mac has no CA bundle and refuses the instance's certificate.

## Not done here (plainly)

- **ServiceNow accounts for IT staff** come from `App-ServiceNow-Users`.
  Ava Lin and Raj Patel were added to it **directly** on 2026-11-07 (operator,
  capture-log E170) so the IAM queue has its real owners. The other members
  arrive through access packages; an *IT staff* birthright package is the
  clean follow-up.
- **The help desk issuing a Temporary Access Pass in the portal** is a human
  step on camera; the proof covers the PIM activation and its audit row.
- No IntegrationHub spoke: the Entra spoke needs a client secret and a
  subscription. A scripted REST call with a certificate is free and holds no
  secret.
