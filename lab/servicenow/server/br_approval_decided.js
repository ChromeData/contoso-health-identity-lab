// Business rule: "Contoso - access: manager decided" (sysapproval_approver, after update)
// Condition: current.state.changes() && (current.state == 'approved' || current.state == 'rejected')
//            && current.source_table == 'sc_req_item'
// Approved -> event contoso.entra.fulfil (script action calls Entra, async, so
// the manager's click never waits on Graph). Rejected -> closed, reason kept.
(function executeRule(current, previous) {
    var ritm = new GlideRecord('sc_req_item');
    if (!ritm.get(current.sysapproval)) return;
    if (ritm.cat_item.name != 'Request app access') return;
    var who = current.approver.getDisplayValue();
    if (current.state == 'approved') {
        ritm.approval = 'approved';
        ritm.stage = 'fulfillment';
        ritm.state = 2;
        ritm.work_notes = 'Approved by ' + who + ' (manager). Sending to Microsoft Entra ID Governance.';
        ritm.update();
        gs.eventQueue('contoso.entra.fulfil', ritm, String(current.approver), '');
    } else {
        ritm.approval = 'rejected';
        ritm.state = 4;
        ritm.work_notes = 'Rejected by ' + who + ' (manager). ' + (current.comments.getJournalEntry(1) || '');
        ritm.update();
    }
})(current, previous);
