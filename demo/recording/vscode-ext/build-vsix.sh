#!/usr/bin/env bash
# Package the bridge as a .vsix (a zip in the Open Packaging layout VS Code
# reads) with no npm downloads, then install it into VS Code.
#   ./build-vsix.sh            package + install
#   ./build-vsix.sh --no-install
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
CODE="${CODE_CLI:-/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code}"
ver="$(node -p "require('$here/package.json').version")"
pub="$(node -p "require('$here/package.json').publisher")"; name="$(node -p "require('$here/package.json').name")"
out="$here/$name-$ver.vsix"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/extension"
cp "$here/package.json" "$here/extension.js" "$tmp/extension/"
cat > "$tmp/[Content_Types].xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
XML
cat > "$tmp/extension.vsixmanifest" <<XML
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="$name" Version="$ver" Publisher="$pub" />
    <DisplayName>Contoso cockpit bridge</DisplayName>
    <Description xml:space="preserve">Lets the local recording cockpit drive the Contoso demo window.</Description>
    <Categories>Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.90.0" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="vscode.git" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
    </Properties>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" /></Assets>
</PackageManifest>
XML
rm -f "$out"
(cd "$tmp" && zip -qX -r "$out" "[Content_Types].xml" extension.vsixmanifest extension)
echo "built $out"
# Installed into the demo profile (the cockpit opens every demo window there)
# and the default profile.
if [ "${1:-}" != "--no-install" ]; then
  "$CODE" --profile "${COCKPIT_VSCODE_PROFILE:-Contoso Demo}" --install-extension "$out" --force
  "$CODE" --install-extension "$out" --force
fi
