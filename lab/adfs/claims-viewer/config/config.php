<?php
// Contoso Claims Viewer: SimpleSAMLphp settings. Starts from the release's
// own defaults (config.php.dist) and changes only what this app needs.
require __DIR__ . '/config.php.dist';

$config['baseurlpath'] = 'https://localhost:8443/simplesaml/';
$config['secretsalt'] = trim(file_get_contents(__DIR__ . '/.salt'));
$config['auth.adminpassword'] = trim(file_get_contents(__DIR__ . '/.adminpw'));
$config['technicalcontact_name'] = 'Contoso Health lab';
$config['technicalcontact_email'] = 'lab@contosohealthlab.com';
$config['timezone'] = 'UTC';
$config['logging.handler'] = 'stderr';
$config['logging.level'] = SimpleSAML\Logger::NOTICE;
$config['trusted.url.domains'] = ['localhost:8443', 'localhost'];
// The SAML response arrives as a cross-site POST from the identity provider,
// so the session cookie must be SameSite=None, which browsers allow only on
// Secure cookies.
$config['session.cookie.secure'] = true;
$config['session.cookie.samesite'] = 'None';
// Only the SP module. No admin pages: the app itself shows the claims.
$config['module.enable'] = ['saml' => true, 'admin' => false, 'core' => true];

// The trusted identity provider comes from ONE federation metadata file in
// idp-metadata/, chosen by CV_IDP_FILE (cutover.sh). Only that file is
// loaded, so the app trusts exactly one IdP at a time: after the cutover an
// AD FS-signed response is refused, and after a roll-back an Entra one is.
$idpFile = getenv('CV_IDP_FILE') ?: 'adfs.xml';
if (!preg_match('/^[a-z0-9-]+\.xml$/', $idpFile)) {
    throw new Exception('CV_IDP_FILE must be a bare file name like adfs.xml');
}
// Passed as 'xml' (the file's content): in 2.4.10 the 'file' form of the
// XML source never reads the file (MetaDataStorageHandlerXML, found in the
// local smoke test 2026-11-07).
$idpXml = @file_get_contents('/var/simplesamlphp/idp-metadata/' . $idpFile);
if ($idpXml === false || strpos($idpXml, 'IDPSSODescriptor') === false) {
    throw new Exception('No SAML IdP metadata in idp-metadata/' . $idpFile . ' (fetch-metadata.sh)');
}
$config['metadata.sources'] = [
    ['type' => 'xml', 'xml' => $idpXml],
];
