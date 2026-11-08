// UI action "Remove access in Entra" (sc_task form button)
// Condition: current.active && gs.hasRole('itil') && current.request_item.cat_item.name == 'Report a leaver: remove app access'
// The person who clicks owns the task from now on (the queue shows who acted).
if (current.assigned_to.nil()) current.assigned_to = gs.getUserID();
var person = new GlideRecord('sys_user');
if (person.get(current.request_item.variables.leaving_person)) {
    var ids = new ContosoEntraAccess().removeAll(current, person);
    if (ids === null) gs.addErrorMessage('Entra removal stopped: see the work notes.');
    else gs.addInfoMessage(ids.length ? 'Sent to Entra: ' + ids.length + ' removal request(s).' : 'Nothing to remove.');
}
action.setRedirectURL(current);
