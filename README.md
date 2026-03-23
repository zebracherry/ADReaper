# ADReaper

```
    ___  ____  ____  ___  __   ____  ____  ____
   / _ \|  _ \| ___|| _ \ \ \ / /\ \/ /\ \/ /\ \
  | | | | | | | |_  | |_) | \ V /  \/  \/  \/  |
  | |_| | |_| | |_  |  _ <   | |   /  \/  \/   |
   \___/|____/|___| |_| \_\  |_|  /_/\_\/_/\_\  |
```

**ADReaper — Active Directory & Windows Privilege Escalation Recon Tool**
**OSCP-compliant: enumeration only, no exploitation.**
**Author: Built for OSCP AD + PrivEsc enumeration workflow**

---

## What it does

ADReaper is a Python-based Active Directory recon and Windows privilege escalation enumeration tool designed for OSCP exam use. It runs entirely from Kali, connects to the Domain Controller over LDAP, and produces a colour-coded terminal report plus three output files — giving you a complete attack surface in under 5 minutes.

**No exploitation. No hash capture. No OSCP policy violations.** It tells you *what* to attack and gives you the exact commands to run manually.

---

## Features

### Active Directory Modules
| Module | What it finds |
|--------|--------------|
| Domain baseline | Password policy, lockout threshold, MAQ, DCs |
| User enumeration | ASREPRoastable, Kerberoastable, passwords in descriptions, PASSWD_NOTREQD |
| Computer enumeration | Unconstrained delegation, legacy OS (EternalBlue candidates), stale machines |
| Group enumeration | Privileged group memberships (Domain Admins, Backup Operators, etc.) |
| Delegation | Constrained + RBCD paths with exact attack commands |
| Domain trusts | Cross-domain attack paths |
| GPO analysis | Writable GPO detection |
| ACL checks | DCSync rights, dangerous DACL paths, BloodHound ingestion command |

### Windows Privilege Escalation (13 vectors)
Covers every common OSCP privesc path — checks and exploit commands generated for each:

- `SeImpersonatePrivilege` → PrintSpoofer / GodPotato / JuicyPotatoNG
- `SeDebugPrivilege` → LSASS dump via ProcDump + Mimikatz
- `SeBackupPrivilege` → NTDS.dit extraction via diskshadow
- `SeTakeOwnershipPrivilege` → SAM / web.config / sensitive file access
- AlwaysInstallElevated → MSI as SYSTEM
- Unquoted service paths
- Weak service binary permissions
- Writable scheduled task scripts
- MSSQL `xp_cmdshell` → token impersonation
- DLL hijacking
- Credential hunting (PowerShell history, registry, LaZagne, SessionGopher)
- Kernel exploit checker (WES-NG / Sherlock workflow)
- WinPEAS + PowerUp transfer and run commands

### Output files
Every run saves three files to `./adreaper_out/` (or your chosen directory):

| File | Contents |
|------|----------|
| `adreaper_results.json` | Full machine-readable results |
| `adreaper_report.md` | Complete Markdown report for your notes |
| `adreaper_commands.sh` | All commands pre-populated with your DC IP, domain, and LHOST |

---

## Installation

```bash
pip3 install ldap3 rich --break-system-packages
chmod +x adreaper.py
```

---

## Usage

```bash
# Password authentication
python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123

# Pass-the-hash
python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john --hash :aad3b435b51404eeaad3b435b51404ee

# Full run — with compromised host + reverse shell listener info
python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123 \
  --target-host 10.10.10.20 --lhost 10.10.14.5 --lport 4444

# Anonymous (limited — no creds needed)
python3 adreaper.py -d corp.local -dc 10.10.10.10

# Skip Windows PrivEsc section (AD only)
python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123 --no-privesc

# Custom output directory
python3 adreaper.py -d corp.local -dc 10.10.10.10 -u john -p Password123 -o /root/engagement/
```

### All flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Domain name (e.g. `corp.local`) — **required** |
| `-dc`, `--dc-ip` | Domain Controller IP — **required** |
| `-u`, `--user` | Username |
| `-p`, `--password` | Password |
| `--hash` | NTLM hash (`LM:NT` or `:NT`) |
| `--target-host` | Compromised Windows host IP — tailors PrivEsc commands |
| `--lhost` | Your Kali IP — used in reverse shell commands |
| `--lport` | Listener port (default: `4444`) |
| `-o`, `--output` | Output directory (default: `./adreaper_out`) |
| `--no-privesc` | Skip Windows PrivEsc section |
| `--threads` | Thread count (default: `5`) |

---

## Workflow

```
1. Get initial creds (spray, anonymous, OSINT)
        ↓
2. Run ADReaper immediately on domain join
   python3 adreaper.py -d corp.local -dc <DC_IP> -u <user> -p <pass> --lhost <kali_ip>
        ↓
3. While it runs — work other machines
        ↓
4. Come back to ranked findings:
   [CRITICAL] Password in description: svc_backup — "Pass: Backup2023!"
   [HIGH]     3 Kerberoastable accounts — run: GetUserSPNs.py ...
   [HIGH]     WS03 has unconstrained delegation — coerce DC auth
   [MEDIUM]   No account lockout — spray is safe
        ↓
5. Run the pre-built commands from adreaper_commands.sh
        ↓
6. On each compromised host — check PrivEsc section for the right attack
```

---

## Output example

```
╔══════════════════════════════════════════════════════╗
║              A D R e a p e r                         ║
║  ADReaper — Active Directory & Windows PrivEsc Recon ║
║  OSCP-compliant: enumeration only, no exploitation.  ║
║  Author: Built for OSCP AD + PrivEsc enumeration     ║
║                                                      ║
║  Target DC : 10.10.10.10                             ║
║  Domain    : corp.local                              ║
║  User      : john                                    ║
╚══════════════════════════════════════════════════════╝

  [CRITICAL]  Password in description: svc_sql
              Description: "Summer2023! set by IT"

  [HIGH]      Kerberoastable accounts found (3)
              svc_mssql: MSSQLSvc/SQL01:1433
              svc_iis:   HTTP/WEB01
              svc_backup: BackupSvc/FS01

  [HIGH]      ASREPRoastable accounts found (1)
              jenna.smith

  [HIGH]      Unconstrained delegation: WS03.corp.local
              Last seen: 142 days ago — likely unpatched

  [MEDIUM]    No account lockout policy — spray is safe

═  COMMANDS TO RUN  ════════════════════════════════════

  # Kerberoastable accounts found (3)
  $ GetUserSPNs.py corp.local/john:Password123 -dc-ip 10.10.10.10 -request -outputfile kerberoast_hashes.txt
  $ hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

  # ASREPRoastable accounts found (1)
  $ GetNPUsers.py corp.local/john -dc-ip 10.10.10.10 -no-pass -usersfile asrep_users.txt -format hashcat
```

---

## Dependencies

- Python 3.x
- `ldap3` — LDAP queries to the DC
- `rich` — terminal formatting
- Standard Kali tools referenced in commands: `impacket`, `crackmapexec`, `kerbrute`, `bloodhound-python`

---

## OSCP Policy

ADReaper performs **enumeration only**. It does not:
- Capture or crack hashes
- Exploit any vulnerability
- Modify any AD objects
- Execute payloads

All generated commands must be run manually by the operator.

---

## Notes

- Run BloodHound alongside ADReaper for full attack path visualisation — the tool generates the ingestion command for you
- The PrivEsc section is static (not live) — it generates tailored commands based on your `--target-host` and `--lhost` flags to run on each compromised machine
- For NTDS.dit extraction paths and DCSync rights, BloodHound + PowerView are more reliable than LDAP alone — commands for both are included in the output
