// Scheduled job "Contoso - check Entra access requests" (every minute):
// closes tickets whose Entra request is Delivered; sends failures to IAM.
new ContosoEntraAccess().checkInFlight();
