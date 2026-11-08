# AD FS migration: local checks (no tenant, no DC01)

Capture log row L10. What ran on the operator's Mac, 20261107T010434Z:

- `compare_claims.unittest.txt`: lab/adfs/compare/tests (7 tests).
- `apps-claims_viewer.tftest.txt`: modules/apps claims_viewer.tftest.hcl, mocked azuread (4 runs).
- `dc-vm.tftest.txt`: modules/dc-vm tests, mocked azurerm, incl. the 3 new 443 runs (14 runs).
- `claims-viewer-authnrequest.txt`: the Claims Viewer container (SimpleSAMLphp 2.4.10,
  release SHA-256 checked) trusting the lab tenant's PUBLIC federation metadata: an
  unauthenticated request is sent to Entra's SAML endpoint with an AuthnRequest whose
  Issuer is urn:contoso:claims-viewer and whose AssertionConsumerServiceURL is the
  reply URL in claims_viewer.tf and 11-Add-ClaimsViewerRp.ps1. No sign-in happened:
  the app has no Entra enterprise app yet.

NOT run here: anything on DC01 (AD FS), Connect Health, the Entra app, a cutover.
