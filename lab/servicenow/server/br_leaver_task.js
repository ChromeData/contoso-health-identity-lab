// Business rule: "Contoso - leaver: create the IAM task" (sc_req_item, after insert)
// Condition: current.cat_item.name == 'Report a leaver: remove app access'
(function executeRule(current, previous) {
    var person = current.variables.leaving_person.getDisplayValue();
    var t = new GlideRecord('sc_task');
    t.initialize();
    t.request_item = current.sys_id;
    t.request = current.request;
    t.assignment_group = new ContosoEntraAccess().queueId();
    t.short_description = 'Leaver: remove requested app access for ' + person + ' (last day ' + current.variables.last_day + ')';
    t.description = 'HR disables the account on the last day; the Entra Leaver workflow then removes birthright access.\n' +
        'This task removes the REQUESTED extras (access packages granted through ServiceNow) and is the audit link: ' +
        'the task number goes into each Entra removal request.';
    t.insert();
})(current, previous);
