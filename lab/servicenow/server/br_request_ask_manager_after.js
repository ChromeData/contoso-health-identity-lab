// Business rule: "Contoso - access: create approval" (sc_req_item, after insert)
// Condition: current.cat_item.name == 'Request app access' && current.approval == 'requested'
(function executeRule(current, previous) {
    var a = new GlideRecord('sysapproval_approver');
    a.initialize();
    a.approver = current.requested_for.manager;
    a.sysapproval = current.sys_id;
    a.source_table = 'sc_req_item';
    a.document_id = current.sys_id;
    a.state = 'requested';
    a.insert();
})(current, previous);
