#!/usr/bin/env python3
"""
tier2-device.py - build (or delete) ONE small, temporary Windows test machine
that joins the lab domain into OU=Devices,OU=Tier2, so the GPO
"Tier0 - Deny logon to Tier1 and Tier2" (PR #225, Set-AdTiering.ps1) has a
real computer to act on.

  lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py build
  lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py delete

WHY THIS SHAPE (read 2026-11-07, all as the operator):
  * The Azure Free Trial allows 4 vCPUs per region. eastus2 is full: DC01 and
    the Intune VM use 2 + 2, and a DEALLOCATED VM still counts (vm-win11-01
    was deallocated and `az vm list-usage -l eastus2` still read cores 4/4).
    Microsoft Learn ("Check vCPU quotas") says the same: quota counts
    allocated and deallocated cores.
  * The Intune VM cannot be the test machine: it is Entra joined (Intune +
    the EPM pilot). Windows cannot be AD joined and Entra joined at once, and
    hybrid join needs device sync, which Entra Cloud Sync (the lab's sync)
    does not do. Joining it to AD would break its Entra join.
  * eastus has its own 4 vCPUs (0 used). No B-series size is offered to this
    subscription there; the smallest unrestricted Windows size is
    Standard_F1als_v7 (1 vCPU, 2 GiB): $0.107/hour Windows, eastus retail
    price, read 2026-11-07.
  * The machine reaches DC01 over global VNet peering (eastus <-> eastus2).
    The default NSG rule AllowVnetInBound covers peered address space, so
    DC01's NSG needs no change. No public IP: every step uses run commands.

COST: about $0.11/hour while it exists, plus a 30 GB Standard HDD (cents per
day) and peering traffic (cents). The run is about 1-2 hours, then `delete`.
Everything lives in ONE resource group (rg-identity-lab-tiertest) except the
peering on DC01's VNet, which `delete` removes first.

SECRETS: the local admin password is made here and sent to ARM in a request
BODY, never argv. It is never printed. Same rules as run-on-dc.py.
  * `build` REFUSES when the VM already exists. A second PUT on a live VM
    would try to change its password; if Azure then refused the request, the
    Keychain would hold a password the VM never got, and the old one would be
    lost. Run `delete` first.
  * The password is written to the Keychain (contoso-lab-tiertest-admin,
    over stdin) only AFTER Azure accepts the VM request (HTTP 200/201). From
    that moment the VM can hold that password, even if provisioning later
    fails, so it must be saved before the wait.
  * `test-passwords` makes the three DISPOSABLE test-account passwords
    (README "Credentials"): contoso-lab-tiertest-t0 / -t2 / -join. It needs
    no Azure. The accounts are made and deleted on DC01 by
    New-TierTestAccounts.ps1 / Remove-TierTestAccounts.ps1.
"""
import argparse
import json
import secrets
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
from importlib import import_module  # noqa: E402

LAB_RG = "rg-identity-lab"
LAB_VNET = "vnet-identity-lab"
RG = "rg-identity-lab-tiertest"
LOC = "eastus"
VNET = "vnet-tiertest"
PREFIX = "10.43.0.0/24"          # must not overlap 10.42.0.0/16 (lab VNet)
DC_IP = "10.42.2.4"              # DC01: the domain's DNS server
VM = "vm-t2dev-01"
SIZE = "Standard_F1als_v7"
KEYCHAIN = "contoso-lab-tiertest-admin"
ADMIN = "t2devadmin"
TAGS = {"lab": "contoso-identity", "purpose": "tier-gpo-proof", "temporary": "delete-after-capture",
        "code": "lab/scripts/dc/tier-test/tier2-device.py"}

NET_API = "2024-05-01"
CMP_API = "2024-07-01"
RG_API = "2021-04-01"


def sh(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


LAB_SUB = "de0b2a93-1c62-47b3-aaaf-1bdd1939a274"
# Filled by connect() at run time, not at import, so the tests can import
# this file without az (tests/test_tier2_device.py).
CTX = None
SUB = None
TOKEN = None
SECRET_VALUES = []
# Disposable test accounts (README "Credentials"): Keychain service -> account.
TEST_PASSWORDS = {"contoso-lab-tiertest-t0": "t0-tiertest",
                  "contoso-lab-tiertest-t2": "t2-tiertest",
                  "contoso-lab-tiertest-join": "tiertest-join"}


def connect():
    global CTX, SUB, TOKEN
    rod = import_module("run-on-dc")   # reuse its TLS context
    CTX = rod.tls_context()
    SUB = sh("az", "account", "show", "--query", "id", "-o", "tsv")
    TOKEN = sh("az", "account", "get-access-token", "--resource", "https://management.azure.com",
               "--query", "accessToken", "-o", "tsv")


def arm(method, path, body=None, ok404=False):
    url = f"https://management.azure.com/subscriptions/{SUB}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            txt = r.read().decode()
            return r.status, (json.loads(txt) if txt else {})
    except urllib.error.HTTPError as e:
        txt = e.read().decode()
        if e.code == 404 and ok404:
            return 404, {}
        for v in SECRET_VALUES:
            txt = txt.replace(v, "***")
        raise SystemExit(f"{method} {path}: HTTP {e.code}: {txt[:800]}")


def wait(path, api, want="Succeeded", tries=90):
    for _ in range(tries):
        _, j = arm("GET", f"{path}?api-version={api}")
        st = j.get("properties", {}).get("provisioningState")
        if st == want:
            return j
        if st == "Failed":
            raise SystemExit(f"{path}: provisioning Failed")
        time.sleep(10)
    raise SystemExit(f"{path}: not {want} after {tries * 10}s")


def new_password():
    # 24 chars, every class, no shell-special quoting issues.
    alphabet = string.ascii_letters + string.digits + "-_.~+="
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(24))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) \
                and any(c in "-_.~+=" for c in pw):
            return pw


def save_to_keychain(service, account, label, pw):
    # security -i reads commands from stdin: the password never reaches argv.
    # Failure output is not shown: it would echo the command line (the password).
    cmd = f'add-generic-password -U -s {service} -a {account} -l "{label}" -w "{pw}"\n'
    r = subprocess.run(["security", "-i"], input=cmd, text=True, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"Keychain write for {service} failed (exit {r.returncode}); output hidden (it holds the password).")


def test_passwords():
    for service, account in TEST_PASSWORDS.items():
        save_to_keychain(service, account, f"Tier GPO proof disposable account {account} (temporary)", new_password())
        print(f"Keychain {service}: new password for {account}")


def build():
    rgp = f"/resourceGroups/{RG}"
    vm = f"{rgp}/providers/Microsoft.Compute/virtualMachines/{VM}"
    code, _ = arm("GET", f"{vm}?api-version={CMP_API}", ok404=True)
    if code != 404:
        raise SystemExit(f"Refusing: {VM} already exists in {RG}. Its password stays as it is in the Keychain. "
                         "Run `delete` first, then `build`.")
    print(f"resource group {RG} ({LOC})")
    arm("PUT", f"{rgp}?api-version={RG_API}", {"location": LOC, "tags": TAGS})

    nsg = f"{rgp}/providers/Microsoft.Network/networkSecurityGroups/nsg-{VM}"
    print("NSG (default rules only: VNet in, nothing from the internet)")
    arm("PUT", f"{nsg}?api-version={NET_API}", {"location": LOC, "tags": TAGS, "properties": {"securityRules": []}})
    wait(nsg, NET_API)

    vnet = f"{rgp}/providers/Microsoft.Network/virtualNetworks/{VNET}"
    print(f"VNet {VNET} {PREFIX}, DNS -> DC01 {DC_IP}")
    arm("PUT", f"{vnet}?api-version={NET_API}", {
        "location": LOC, "tags": TAGS,
        "properties": {
            "addressSpace": {"addressPrefixes": [PREFIX]},
            "dhcpOptions": {"dnsServers": [DC_IP]},
            # Outbound internet only for the VM agent / Windows activation; no inbound path exists.
            "subnets": [{"name": "snet-tier2-devices", "properties": {
                "addressPrefix": PREFIX, "defaultOutboundAccess": True,
                "networkSecurityGroup": {"id": f"/subscriptions/{SUB}{nsg}"}}}],
        }})
    wait(vnet, NET_API)

    lab_vnet = f"/resourceGroups/{LAB_RG}/providers/Microsoft.Network/virtualNetworks/{LAB_VNET}"
    for src, dst, name in ((vnet, lab_vnet, "peer-tiertest-to-lab"), (lab_vnet, vnet, "peer-lab-to-tiertest")):
        print(f"peering {name}")
        arm("PUT", f"{src}/virtualNetworkPeerings/{name}?api-version={NET_API}", {"properties": {
            "remoteVirtualNetwork": {"id": f"/subscriptions/{SUB}{dst}"},
            "allowVirtualNetworkAccess": True, "allowForwardedTraffic": False,
            "allowGatewayTransit": False, "useRemoteGateways": False}})
        wait(f"{src}/virtualNetworkPeerings/{name}", NET_API)

    nic = f"{rgp}/providers/Microsoft.Network/networkInterfaces/nic-{VM}"
    print("NIC (no public IP)")
    arm("PUT", f"{nic}?api-version={NET_API}", {"location": LOC, "tags": TAGS, "properties": {
        "ipConfigurations": [{"name": "ipconfig1", "properties": {
            "subnet": {"id": f"/subscriptions/{SUB}{vnet}/subnets/snet-tier2-devices"},
            "privateIPAllocationMethod": "Dynamic"}}]}})
    wait(nic, NET_API)

    pw = new_password()
    SECRET_VALUES.append(pw)
    print(f"VM {VM} {SIZE} (Windows Server 2022 Azure Edition, Trusted Launch, like DC01)")
    status, _ = arm("PUT", f"{vm}?api-version={CMP_API}", {"location": LOC, "tags": TAGS, "properties": {
        "hardwareProfile": {"vmSize": SIZE},
        "storageProfile": {
            "imageReference": {"publisher": "MicrosoftWindowsServer", "offer": "WindowsServer",
                               "sku": "2022-datacenter-azure-edition-smalldisk", "version": "latest"},
            "osDisk": {"createOption": "FromImage", "deleteOption": "Delete", "diskSizeGB": 30,
                       "managedDisk": {"storageAccountType": "Standard_LRS"}},
            "diskControllerType": "NVMe"},
        "osProfile": {"computerName": "T2DEV01", "adminUsername": ADMIN, "adminPassword": pw,
                      "windowsConfiguration": {"provisionVMAgent": True, "enableAutomaticUpdates": False,
                                               "patchSettings": {"patchMode": "Manual"}}},
        "securityProfile": {"securityType": "TrustedLaunch",
                            "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}},
        "networkProfile": {"networkInterfaces": [{"id": f"/subscriptions/{SUB}{nic}",
                                                  "properties": {"deleteOption": "Delete"}}]},
        "diagnosticsProfile": {"bootDiagnostics": {"enabled": True}}}})
    if status not in (200, 201):
        raise SystemExit(f"VM PUT: unexpected HTTP {status}; nothing saved to the Keychain")
    # Accepted: the VM may now hold this password. Save it before the wait.
    save_to_keychain(KEYCHAIN, ADMIN, "Tier 2 test device local admin (temporary)", pw)
    wait(vm, CMP_API)
    _, j = arm("GET", f"{nic}?api-version={NET_API}")
    ip = j["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]
    print(json.dumps({"vm": VM, "rg": RG, "location": LOC, "size": SIZE, "privateIp": ip,
                      "adminPasswordKeychain": KEYCHAIN}, indent=2))


def delete():
    lab_vnet = f"/resourceGroups/{LAB_RG}/providers/Microsoft.Network/virtualNetworks/{LAB_VNET}"
    # The lab side first: it is the only piece outside the test resource group.
    code, _ = arm("DELETE", f"{lab_vnet}/virtualNetworkPeerings/peer-lab-to-tiertest?api-version={NET_API}", ok404=True)
    print(f"peering on {LAB_VNET}: {'deleted' if code != 404 else 'already gone'}")
    for _ in range(30):
        c, _ = arm("GET", f"{lab_vnet}/virtualNetworkPeerings/peer-lab-to-tiertest?api-version={NET_API}", ok404=True)
        if c == 404:
            break
        time.sleep(10)
    code, _ = arm("DELETE", f"/resourceGroups/{RG}?api-version={RG_API}", ok404=True)
    if code == 404:
        print(f"{RG}: already gone")
        return
    for _ in range(120):
        c, _ = arm("GET", f"/resourceGroups/{RG}?api-version={RG_API}", ok404=True)
        if c == 404:
            print(f"{RG}: deleted (VM, disk, NIC, NSG, VNet)")
            return
        time.sleep(15)
    raise SystemExit(f"{RG}: still exists after 30 min - check the portal")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["build", "delete", "test-passwords"])
    a = ap.parse_args()
    if a.action == "test-passwords":
        test_passwords()
        sys.exit(0)
    connect()
    if SUB != LAB_SUB:
        raise SystemExit(f"Refusing: az is on subscription {SUB}, not the lab subscription.")
    build() if a.action == "build" else delete()
