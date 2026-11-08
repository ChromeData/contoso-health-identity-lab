// Business rule: "Contoso - access: route to manager" (sc_req_item, before insert)
// Condition (set by apply.py): current.cat_item.name == 'Request app access'
// WHY: the person's manager approves, the same rule Entra uses on the
// ICU - Float Access policy (requestorManager). The manager comes from Entra:
// the provisioning job maps manager -> sys_user.manager (apply-provisioning-
// mapping.py), so ServiceNow never keeps its own org chart.
(function executeRule(current, previous) {
    var q = new ContosoEntraAccess().queueId();
    if (q) current.assignment_group = q;
    var mgr = current.requested_for.manager;
    if (mgr.nil()) {
        current.approval = 'not requested';
        current.work_notes = 'No manager on ' + current.requested_for.getDisplayValue() +
            "'s record (it comes from Entra). IAM Operations decides who approves.";
        return;
    }
    if (String(mgr) == String(current.opened_by) && String(current.opened_by) != String(current.requested_for)) {
        // A manager asking FOR a report would approve their own request.
        current.approval = 'not requested';
        current.work_notes = 'Raised by the approving manager on behalf of the person: IAM Operations finds a second approver.';
        return;
    }
    current.approval = 'requested';
    current.stage = 'waiting_for_approval';
})(current, previous);
