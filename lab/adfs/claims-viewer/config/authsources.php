<?php
// One SAML service provider: entity ID urn:contoso:claims-viewer, the same
// identifier the AD FS relying party trust and the Entra enterprise app use.
// 'idp' is the entity ID found in the one metadata file in use (config.php),
// so switching IdP never needs an edit here.
$idpFile = '/var/simplesamlphp/idp-metadata/' . (getenv('CV_IDP_FILE') ?: 'adfs.xml');
$idp = null;
if (is_readable($idpFile)) {
    $xml = new DOMDocument();
    if (@$xml->load($idpFile, LIBXML_NONET)) {
        $idp = $xml->documentElement->getAttribute('entityID') ?: null;
    }
}

$config = [
    'default-sp' => [
        'saml:SP',
        'entityID' => 'urn:contoso:claims-viewer',
        'idp' => $idp,
        'name' => ['en' => 'Contoso Claims Viewer'],
        // Ask for no particular authentication method: AD FS (forms) and
        // Entra (password + MFA, passkeys) differ, and a fixed
        // RequestedAuthnContext makes passwordless users fail (the lab hit
        // this on ServiceNow, AADSTS75011).
        'proxymode.passAuthnContextClassRef' => false,
        // Name ID format "unspecified", asked for explicitly, so AD FS (rule 2)
        // and Entra both answer in the same format.
        'NameIDPolicy' => [
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'AllowCreate' => true,
        ],
    ],
];
