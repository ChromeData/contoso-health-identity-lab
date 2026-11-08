<?php
// Contoso Claims Viewer: signs the user in through the configured IdP and
// shows every claim it received. ?format=json returns the same data in the
// shape lab/adfs/compare/compare_claims.py reads.
require_once '/var/simplesamlphp/src/_autoload.php';

$as = new \SimpleSAML\Auth\Simple('default-sp');
if (isset($_GET['logout'])) {
    $as->logout('/');
}
$as->requireAuth();

$attrs = $as->getAttributes();
ksort($attrs);
foreach ($attrs as $k => $v) { sort($attrs[$k]); }

$nameId = $as->getAuthData('saml:sp:NameID');
$nid = ['value' => null, 'format' => null];
if (is_object($nameId)) {
    $nid['value'] = method_exists($nameId, 'getContent') ? $nameId->getContent() : (method_exists($nameId, 'getValue') ? $nameId->getValue() : null);
    $nid['format'] = method_exists($nameId, 'getFormat') ? $nameId->getFormat() : null;
}
$idp = $as->getAuthData('saml:sp:IdP');
$source = (strpos((string)$idp, 'sts.windows.net') !== false) ? 'entra' : 'adfs';

$out = [
    'source' => $source,
    'capturedAtUtc' => gmdate('Y-m-d\TH:i:s\Z'),
    'issuer' => $idp,
    'audience' => 'urn:contoso:claims-viewer',
    'signatureValid' => true,   // SimpleSAMLphp refuses unsigned or badly signed responses before this line
    'nameId' => $nid,
    'attributes' => $attrs,
];

if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json');
    echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Contoso Claims Viewer</title>
<style>body{font:15px system-ui;margin:2rem;color:#1b1b1b}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.35rem .6rem;text-align:left;vertical-align:top}th{background:#f3f3f3}.idp{font-size:1.2rem;margin:.5rem 0 1rem}</style></head>
<body><h1>Contoso Claims Viewer</h1>
<p class="idp">Signed in through <strong><?= $source === 'entra' ? 'Microsoft Entra ID' : 'AD FS' ?></strong> (<?= $h($idp) ?>)</p>
<table><tr><th>Name ID</th><td><?= $h($nid['value']) ?><br><small><?= $h($nid['format']) ?></small></td></tr>
<?php foreach ($attrs as $k => $vals): ?><tr><th><?= $h($k) ?></th><td><?= implode('<br>', array_map($h, $vals)) ?></td></tr><?php endforeach; ?>
</table><p><a href="?format=json">JSON</a> | <a href="?logout=1">Sign out</a></p></body></html>
