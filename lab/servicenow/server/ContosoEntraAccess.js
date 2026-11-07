/*
 * Script Include: ContosoEntraAccess (global, not client-callable)
 * -----------------------------------------------------------------------------
 * ServiceNow -> Microsoft Entra ID Governance, for the "Request app access"
 * catalog item and the leaver access-removal task.
 *
 * WHO SERVICENOW IS, TO ENTRA
 *   App registration "ServiceNow - Access Fulfilment" (Terraform:
 *   lab/terraform/modules/apps/servicenow_fulfilment.tf). It has NO Microsoft
 *   Graph API permission at all. It holds ONE entitlement-management role:
 *   "Access package assignment manager" on the Clinical catalog. Microsoft
 *   Learn (Graph, "Create accessPackageAssignmentRequest", Permissions): "In
 *   app-only scenarios, the calling app can be assigned one of the preceding
 *   supported roles instead of the EntitlementManagement.ReadWrite.All
 *   application permission. The Access package assignment manager role is
 *   less privileged". So ServiceNow can add or remove people on EXISTING
 *   packages in that one catalog, and nothing else: it cannot edit a package,
 *   read the directory, or touch any group directly.
 *
 * HOW IT SIGNS IN (no client secret)
 *   OAuth 2.0 client credentials with a certificate (client_assertion,
 *   RFC 7523; Learn "Microsoft identity platform application authentication
 *   certificate credentials"). ServiceNow signs a 5-minute JWT with the key in
 *   its Java key store (jwt_provider "Contoso - Entra access fulfilment",
 *   x5t header on), Entra checks it against the public certificate on the app
 *   and returns a 1-hour Graph token. Key minted by
 *   lab/servicenow/fulfilment-cert.py; the private key exists only here.
 *
 * WHAT IT CALLS (Graph v1.0, verified on Learn 2026-11-07)
 *   POST /identityGovernance/entitlementManagement/assignmentRequests
 *        requestType adminAdd   {assignment:{targetId,assignmentPolicyId,accessPackageId}, schedule, justification}
 *        requestType adminRemove {assignment:{id}, justification}
 *   GET  .../assignmentRequests?$filter=accessPackage/id eq '{pkg}' and id eq '{req}'
 *   GET  .../assignments?$filter=accessPackage/id eq '{pkg}' and target/objectId eq '{oid}' and state eq 'delivered'
 *   Every read names the access package. Seen live 2026-11-07: with only a
 *   CATALOG role, GET assignmentRequests/{id} and an assignments filter on the
 *   person alone return 403; the same reads filtered by a package in the
 *   catalog return 200. So the ticket stores "packageId/requestId".
 *   The ServiceNow ticket number goes into `justification`, so Entra's own
 *   request history and audit log carry the ticket (the audit link).
 *
 * FAIL CLOSED
 *   Any token or Graph error -> the ticket is NOT closed: it is assigned to the
 *   IAM Operations queue with the error in the work notes. Nothing retries
 *   silently, nothing falls back to another identity.
 *
 * CONFIG (system properties, set by lab/servicenow/apply.py)
 *   contoso.entra.tenant_id, contoso.entra.fulfilment.client_id,
 *   contoso.entra.fulfilment.jwt_provider (name), contoso.entra.fulfilment.packages
 *   (JSON: choice value -> {accessPackageId, assignmentPolicyId, label}),
 *   contoso.entra.iam_queue (assignment group name).
 */
var ContosoEntraAccess = Class.create();
ContosoEntraAccess.GRAPH = 'https://graph.microsoft.com/v1.0';
ContosoEntraAccess.EM = ContosoEntraAccess.GRAPH + '/identityGovernance/entitlementManagement';
ContosoEntraAccess.CORRELATION = 'Entra ID Governance';
ContosoEntraAccess.MAX_DAYS = 180;
// Some removals accepted, some never sent: follow the accepted ones, never close.
ContosoEntraAccess.PARTIAL = ContosoEntraAccess.CORRELATION + ' - partial';

ContosoEntraAccess.prototype = {
    initialize: function () {
        this.tenant = gs.getProperty('contoso.entra.tenant_id', '');
        this.clientId = gs.getProperty('contoso.entra.fulfilment.client_id', '');
        this.providerName = gs.getProperty('contoso.entra.fulfilment.jwt_provider', '');
        this.queueName = gs.getProperty('contoso.entra.iam_queue', 'IAM Operations');
        this._token = null;
    },

    // ---- token ---------------------------------------------------------------
    _b64urlJson: function (part) {
        var s = part.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        return JSON.parse(GlideStringUtil.base64Decode(s));
    },

    getToken: function () {
        if (this._token) return this._token;
        if (!this.tenant || !this.clientId || !this.providerName)
            throw 'Entra fulfilment is not configured (contoso.entra.* properties are empty)';
        var prov = new GlideRecord('jwt_provider');
        if (!prov.get('name', this.providerName)) throw 'JWT provider not found: ' + this.providerName;
        var tokenUrl = 'https://login.microsoftonline.com/' + this.tenant + '/oauth2/v2.0/token';
        var now = Math.floor(new Date().getTime() / 1000);
        // Claims Entra requires in a client assertion: aud = the token
        // endpoint, iss = sub = the client id, a unique jti, nbf/exp (Learn,
        // "certificate credentials", Assertion format). 5 minutes is plenty.
        var assertion = new sn_auth.GlideJWTAPI().generateJWT(prov.getUniqueValue(),
            JSON.stringify({ typ: 'JWT' }),
            JSON.stringify({ aud: tokenUrl, iss: this.clientId, sub: this.clientId,
                jti: gs.generateGUID(), nbf: now - 60, iat: now, exp: now + 300 }));
        var r = new sn_ws.RESTMessageV2();
        r.setEndpoint(tokenUrl);
        r.setHttpMethod('post');
        r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        r.setRequestBody('client_id=' + encodeURIComponent(this.clientId) +
            '&scope=' + encodeURIComponent('https://graph.microsoft.com/.default') +
            '&grant_type=client_credentials' +
            '&client_assertion_type=' + encodeURIComponent('urn:ietf:params:oauth:client-assertion-type:jwt-bearer') +
            '&client_assertion=' + encodeURIComponent(String(assertion)));
        var resp = r.execute();
        var body = {};
        try { body = JSON.parse(resp.getBody()); } catch (e) { /* not JSON */ }
        if (resp.getStatusCode() != 200 || !body.access_token)
            throw 'Entra token request failed (' + resp.getStatusCode() + '): ' + (body.error || '') + ' ' + String(body.error_description || '').split('\r')[0];
        this._token = body.access_token;
        return this._token;
    },

    graph: function (method, url, payload) {
        var r = new sn_ws.RESTMessageV2();
        r.setEndpoint(url);
        r.setHttpMethod(method);
        r.setRequestHeader('Authorization', 'Bearer ' + this.getToken());
        r.setRequestHeader('Accept', 'application/json');
        if (payload) {
            r.setRequestHeader('Content-Type', 'application/json');
            r.setRequestBody(JSON.stringify(payload));
        }
        var resp = r.execute();
        var status = resp.getStatusCode();
        var body = null;
        try { body = JSON.parse(resp.getBody()); } catch (e) { body = null; }
        if (status < 200 || status > 299) {
            var msg = body && body.error ? (body.error.code + ': ' + body.error.message) : String(resp.getBody()).substring(0, 300);
            throw 'Graph ' + method.toUpperCase() + ' ' + url.replace(ContosoEntraAccess.GRAPH, '') + ' -> ' + status + ' ' + msg;
        }
        return body;
    },

    // ---- config --------------------------------------------------------------
    packages: function () {
        return JSON.parse(gs.getProperty('contoso.entra.fulfilment.packages', '{}'));
    },

    queueId: function () {
        var g = new GlideRecord('sys_user_group');
        return g.get('name', this.queueName) ? g.getUniqueValue() : '';
    },

    // ---- fulfil one approved request ------------------------------------------
    // Called by the script action on event contoso.entra.fulfil (after the
    // manager approved). Writes the Entra request id to correlation_id; the
    // poller (checkInFlight) closes the ticket when Entra says Delivered.
    fulfil: function (ritm) {
        // The event was queued when the manager approved. Read the ticket
        // again NOW: a later rejection, a cancel or a close must win, and a
        // ticket already sent to Entra is never sent twice.
        var fresh = new GlideRecord('sc_req_item');
        if (!fresh.get(ritm.getUniqueValue())) return null;
        ritm = fresh;
        // String(...): a GlideElement is an object, so `!ritm.active` would
        // always be false.
        if (String(ritm.approval) != 'approved' || String(ritm.active) != 'true' || !ritm.correlation_id.nil()) {
            ritm.work_notes = 'Not sent to Entra: the request is no longer approved and open (approval ' +
                ritm.approval + ', active ' + ritm.active + ')' + (ritm.correlation_id.nil() ? '.' : ', or it was already sent.');
            ritm.update();
            return null;
        }
        var pkgKey = String(ritm.variables.app_access || '');
        try {
            var pkg = this.packages()[pkgKey];
            if (!pkg) throw 'No Entra access package is mapped for "' + pkgKey + '". IAM decides by hand.';
            var oid = String(ritm.requested_for.u_entra_object_id || '');
            if (!/^[0-9a-f-]{36}$/.test(oid)) throw 'The person has no Entra object id in ServiceNow (provisioning maps objectId -> u_entra_object_id).';
            var approver = this._approverName(ritm);
            var body = {
                requestType: 'adminAdd',
                justification: ritm.getValue('number') + ' (ServiceNow): approved by ' + approver +
                    '. Reason: ' + String(ritm.variables.business_reason || '').substring(0, 200),
                assignment: { targetId: oid, assignmentPolicyId: pkg.assignmentPolicyId, accessPackageId: pkg.accessPackageId }
            };
            var sched = this._schedule(String(ritm.variables.start_date || ''), String(ritm.variables.end_date || ''));
            if (sched) body.schedule = sched;
            var res = this.graph('post', ContosoEntraAccess.EM + '/assignmentRequests', body);
            ritm.correlation_id = pkg.accessPackageId + '/' + res.id;
            ritm.correlation_display = ContosoEntraAccess.CORRELATION;
            ritm.state = 2; // Work in Progress
            ritm.work_notes = 'Sent to Microsoft Entra ID Governance: add ' + ritm.requested_for.getDisplayValue() +
                ' to access package "' + pkg.label + '"' + (sched ? ' from ' + sched.startDateTime + ' to ' + sched.expiration.endDateTime : '') +
                '.\nEntra request id: ' + res.id + ' (state: ' + res.state + '). The ticket number is in the Entra justification.';
            ritm.update();
            return res.id;
        } catch (e) {
            this._toQueue(ritm, 'Automatic fulfilment stopped: ' + e);
            return null;
        }
    },

    // ---- leaver: remove what the person holds in the catalog ---------------------
    removeAll: function (task, personGr) {
        // refs is filled after EACH successful removal request, so a later
        // failure never hides a removal Entra already accepted: the poller
        // still follows it, and the error is shown next to it.
        var removed = [], refs = [], err = null;
        try {
            var oid = String(personGr.u_entra_object_id || '');
            if (!/^[0-9a-f-]{36}$/.test(oid)) throw 'The person has no Entra object id in ServiceNow.';
            var mine = this.packages();
            // Only the REQUESTABLE packages this catalog item hands out. Birthright
            // packages follow HR attributes and are removed by the Leaver
            // lifecycle workflow when HR disables the account.
            for (var k in mine) {
                var pkg = mine[k];
                var list = this.graph('get', ContosoEntraAccess.EM + '/assignments?$filter=' + encodeURIComponent(
                    "accessPackage/id eq '" + pkg.accessPackageId + "' and target/objectId eq '" + oid + "' and state eq 'delivered'"));
                for (var i = 0; i < list.value.length; i++) {
                    var res = this.graph('post', ContosoEntraAccess.EM + '/assignmentRequests', {
                        requestType: 'adminRemove',
                        justification: task.getValue('number') + ' (ServiceNow): leaver access removal',
                        assignment: { id: list.value[i].id }
                    });
                    removed.push(pkg.label);
                    refs.push(pkg.accessPackageId + '/' + res.id);
                }
            }
        } catch (e) {
            err = String(e);
        }
        var lines = [];
        if (removed.length)
            lines.push('Sent to Microsoft Entra ID Governance: remove ' + removed.join(', ') + '.\nEntra request id(s): ' + refs.join(', '));
        if (err)
            lines.push('Entra removal stopped: ' + err + (removed.length ? '\nThe removals above were accepted and are followed.' : ''));
        if (!removed.length && !err)
            lines.push('Entra shows no requestable access package for this person: nothing to remove.');
        task.work_notes = lines.join('\n');
        if (refs.length) {
            task.correlation_id = refs.join(',');
            task.correlation_display = err ? ContosoEntraAccess.PARTIAL : ContosoEntraAccess.CORRELATION;
        }
        if (err) {
            var q = this.queueId();
            if (q) task.assignment_group = q;
        } else if (!refs.length) {
            task.state = 3;
        }
        task.update();
        return err && !refs.length ? null : refs;
    },

    // ---- poller: close tickets Entra has finished -------------------------------
    checkInFlight: function () {
        var tables = ['sc_req_item', 'sc_task'];
        for (var t = 0; t < tables.length; t++) {
            var gr = new GlideRecord(tables[t]);
            gr.addQuery('correlation_display', 'IN', ContosoEntraAccess.CORRELATION + ',' + ContosoEntraAccess.PARTIAL);
            gr.addQuery('active', true);
            gr.query();
            while (gr.next()) this._check(gr);
        }
    },

    _check: function (gr) {
        var ids = String(gr.correlation_id).split(','), states = [], lastErr = '';
        try {
            for (var i = 0; i < ids.length; i++) {
                var ref = ids[i].split('/');
                var found = this.graph('get', ContosoEntraAccess.EM + '/assignmentRequests?$filter=' + encodeURIComponent(
                    "accessPackage/id eq '" + ref[0] + "' and id eq '" + ref[1] + "'")).value;
                if (found.length != 1) throw 'Entra request ' + ref[1] + ' not found in package ' + ref[0];
                var r = found[0];
                states.push(r.state);
                if (r.state == 'deliveryFailed' || r.state == 'denied' || r.state == 'canceled')
                    lastErr = 'Entra request ' + ref[1] + ' ended ' + r.state + (r.status ? ' (' + r.status + ')' : '');
            }
        } catch (e) {
            lastErr = String(e);
        }
        if (lastErr) {
            gr.correlation_display = ContosoEntraAccess.CORRELATION + ' - needs IAM';
            this._toQueue(gr, lastErr);
            return;
        }
        var done = true;
        for (var j = 0; j < states.length; j++) if (states[j] != 'delivered') done = false;
        if (!done) return;
        if (String(gr.correlation_display) == ContosoEntraAccess.PARTIAL) {
            // The accepted part is done; the part that failed was never sent.
            gr.correlation_display = ContosoEntraAccess.CORRELATION + ' - needs IAM';
            this._toQueue(gr, 'Entra delivered the removals that were accepted. The rest failed earlier (see above) and was never sent: a person must finish it. Not closed.');
            return;
        }
        gr.state = 3; // Closed Complete
        gr.correlation_display = ContosoEntraAccess.CORRELATION + ' - delivered';
        gr.work_notes = 'Microsoft Entra ID Governance reports Delivered (request ' + ids.join(', ').replace(/[0-9a-f-]{36}\//g, '') + '). Closed automatically.';
        gr.update();
    },

    // ---- helpers ------------------------------------------------------------------
    _toQueue: function (gr, why) {
        var q = this.queueId();
        if (q) gr.assignment_group = q;
        gr.work_notes = why + '\nAssigned to ' + this.queueName + ' for a person to finish.';
        gr.update();
    },

    _approverName: function (ritm) {
        var a = new GlideRecord('sysapproval_approver');
        a.addQuery('sysapproval', ritm.getUniqueValue());
        a.addQuery('state', 'approved');
        a.orderByDesc('sys_updated_on');
        a.query();
        return a.next() ? a.approver.getDisplayValue() : 'unknown approver';
    },

    // Dates from the form are calendar days. The hospital runs on one clock
    // (the instance time zone), so start = 00:00 and end = 23:59 that day, in
    // UTC as Graph wants. A start in the past or today means "now".
    _schedule: function (start, end) {
        if (!end) return null;
        var s = new GlideDateTime();
        if (start) {
            var gs0 = new GlideDateTime(); gs0.setDisplayValue(start + ' 00:00:00');
            if (gs0.after(s)) s = gs0;
        }
        var e = new GlideDateTime(); e.setDisplayValue(end + ' 23:59:59');
        if (!e.after(s)) throw 'The end date is before the start date.';
        // The form promises 180 days at most (the ICU / Pharmacy request
        // policies' own limit). Checked here too: an admin assignment carries
        // the schedule it is given, so the limit is not left to Entra.
        var max = new GlideDateTime(s); max.addDaysUTC(ContosoEntraAccess.MAX_DAYS);
        if (e.after(max)) throw 'The end date is more than ' + ContosoEntraAccess.MAX_DAYS + ' days after the start. Ask again for a shorter time.';
        return {
            startDateTime: s.getValue().replace(' ', 'T') + 'Z',
            expiration: { type: 'afterDateTime', endDateTime: e.getValue().replace(' ', 'T') + 'Z' }
        };
    },

    type: 'ContosoEntraAccess'
};
