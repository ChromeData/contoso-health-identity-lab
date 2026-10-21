// record-decisions.groovy - record reviewer decisions on an open midPoint
// certification campaign.
//
// run-campaign.sh sends this script to midPoint as administrator over REST:
// POST /midpoint/ws/rest/rpc/executeScript (bulk action "execute", Groovy).
// midPoint 4.10's REST API has no endpoint for certification decisions. Its
// GUI records one by calling AccessCertificationService.recordDecision (see
// CertMiscUtil in admin-gui-4.10.4.jar), and this script makes that same call.
//
// The reviewer recorded on each decision is the reviewer midPoint ASSIGNED to
// the work item, never the administrator. For every decision the script
// switches the security context to that reviewer (SecurityContextManager
// .runAsChecked), so midPoint applies the reviewer's own authorizations (the
// built-in "Reviewer" role grants recordCertificationDecision) and stores the
// reviewer as performerRef. This is a lab driver standing in for the reviewer's
// click. A production reviewer decides in the UI (or through SailPoint/Entra
// in the real estate).
//
// Probes run first. Each one has a user who must NOT be able to decide try to
// decide an item, and the script reports whether midPoint refused. A probe uses
// the same response as the real decision for that item, so a probe midPoint
// wrongly allowed could not change the outcome.
//
// Input: __INPUT_B64__ is replaced by base64(JSON) with
//   {campaignOid, decisions:[{user, role, expectedReviewer, response, comment}],
//    probes:[{actor, user, role, response, why}]}
//   response: accept | revoke | reduce | notDecided | none (leave unanswered)
// Output: one JSON string (the bulk action's data output).

import com.evolveum.midpoint.model.api.AccessCertificationService
import com.evolveum.midpoint.model.api.ModelService
import com.evolveum.midpoint.model.impl.expr.SpringApplicationContextHolder
import com.evolveum.midpoint.prism.PrismContext
import com.evolveum.midpoint.schema.result.OperationResult
import com.evolveum.midpoint.security.api.SecurityContextManager
import com.evolveum.midpoint.task.api.TaskManager
import com.evolveum.midpoint.xml.ns._public.common.common_3.AccessCertificationCaseType
import com.evolveum.midpoint.xml.ns._public.common.common_3.AccessCertificationResponseType
import com.evolveum.midpoint.xml.ns._public.common.common_3.RoleType
import com.evolveum.midpoint.xml.ns._public.common.common_3.UserType
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

def input = new JsonSlurper().parseText(new String(Base64.decoder.decode('__INPUT_B64__'), 'UTF-8'))
def campaignOid = input.campaignOid as String

def ctx = SpringApplicationContextHolder.getApplicationContext()
def certService = ctx.getBean(AccessCertificationService.class)
def modelService = ctx.getBean(ModelService.class)
def securityContextManager = ctx.getBean('securityContextManager', SecurityContextManager.class)
def task = ctx.getBean(TaskManager.class).createTaskInstance('contoso-record-decisions')
def result = new OperationResult('contoso.recordDecisions')

def oidOf = { Class type, String name ->
    def o = midpoint.searchObjectByName(type, name)
    if (o == null) {
        throw new IllegalStateException("no ${type.simpleName} named '${name}'")
    }
    return o.oid
}
def userName = { String oid -> midpoint.getObject(UserType.class, oid).name.orig }

// The one open work item of the (user, role) case in the current stage.
def openItem = { String user, String role ->
    def uOid = oidOf(UserType.class, user)
    def rOid = oidOf(RoleType.class, role)
    def query = PrismContext.get().queryFor(AccessCertificationCaseType.class).ownerId(campaignOid).build()
    def cases = modelService.searchContainers(AccessCertificationCaseType.class, query, null, task, result)
            .findAll { it.objectRef?.oid == uOid && it.targetRef?.oid == rOid }
    if (cases.size() != 1) {
        throw new IllegalStateException("expected 1 case for ${user} / ${role}, found ${cases.size()}")
    }
    def c = cases[0]
    def open = c.workItem.findAll {
        it.closeTimestamp == null && it.stageNumber == c.stageNumber && it.iteration == c.iteration
    }
    if (open.size() != 1) {
        throw new IllegalStateException("expected 1 open work item for ${user} / ${role}, found ${open.size()}")
    }
    def wi = open[0]
    def assignees = wi.assigneeRef*.oid
    if (assignees.size() != 1) {
        throw new IllegalStateException("expected 1 assignee for ${user} / ${role}, found ${assignees.size()}")
    }
    return [caseId: c.id, workItemId: wi.id, assigneeOid: assignees[0]]
}

def decideAs = { String actorOid, Map item, String response, String comment ->
    def actor = modelService.getObject(UserType.class, actorOid, null, task, result)
    securityContextManager.runAsChecked({ OperationResult r ->
        certService.recordDecision(campaignOid, item.caseId as long, item.workItemId as long,
                AccessCertificationResponseType.fromValue(response), comment, task, r)
        return null
    } as SecurityContextManager.ResultAwareCheckedProducer, actor, result)
}

def probes = []
(input.probes ?: []).each { p ->
    def rec = [actor: p.actor, user: p.user, role: p.role, response: p.response, why: p.why]
    try {
        def item = openItem(p.user as String, p.role as String)
        rec.assignedReviewer = userName(item.assigneeOid as String)
        decideAs(oidOf(UserType.class, p.actor as String), item, p.response as String,
                "probe: ${p.actor} is not the assigned reviewer" as String)
        rec.status = 'ALLOWED'
    } catch (Throwable t) {
        rec.status = 'refused'
        rec.error = t.getClass().getSimpleName() + ': ' + t.getMessage()
    }
    probes << rec
}

def decisions = []
(input.decisions ?: []).each { d ->
    def rec = [user: d.user, role: d.role, response: d.response]
    try {
        def item = openItem(d.user as String, d.role as String)
        rec.caseId = item.caseId
        rec.workItemId = item.workItemId
        rec.reviewer = userName(item.assigneeOid as String)
        if (d.expectedReviewer && d.expectedReviewer != rec.reviewer) {
            throw new IllegalStateException("assigned reviewer is ${rec.reviewer}, expected ${d.expectedReviewer}")
        }
        if (d.response == 'none') {
            rec.status = 'left-unanswered'
        } else {
            decideAs(item.assigneeOid as String, item, d.response as String, d.comment as String)
            rec.status = 'recorded'
        }
    } catch (Throwable t) {
        rec.status = 'error'
        rec.error = t.getClass().getSimpleName() + ': ' + t.getMessage()
    }
    decisions << rec
}

return JsonOutput.toJson([campaignOid: campaignOid, probes: probes, decisions: decisions])
