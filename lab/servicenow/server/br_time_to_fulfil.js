// Business rule: "Contoso - time to fulfil" (sc_req_item and sc_task, before update)
// Condition: current.state.changesTo(3) || current.state.changesTo(4)
// Stores opened -> closed as calendar_duration, which the
// "Access requests: time to fulfil" report averages.
(function executeRule(current, previous) {
    var closed = new GlideDateTime();
    current.calendar_duration = GlideDateTime.subtract(new GlideDateTime(current.opened_at), closed);
})(current, previous);
