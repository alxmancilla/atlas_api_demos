# atlas-security-ops

Python toolkit for auditing and enforcing security best practices on MongoDB Atlas projects and organizations via the Atlas Administration API v2. Covers IP access control, TLS enforcement, encryption, auditing, alert configuration, private endpoints, and cluster inspection.

## Scripts Overview

### 1. **atlas_security_auditor.py** — Project-Level Security Audit
Comprehensive security audit for a single MongoDB Atlas project. Checks and enforces 7 critical security best practices:
- **IP Access List** — Removes `0.0.0.0/0` wildcard entries
- **Database Users** — Flags users with `atlasAdmin` role
- **TLS Minimum Version** — Enforces TLS 1.2+
- **Encryption at Rest** — Verifies customer-managed key encryption
- **Auditing** — Enables audit logs with event filters
- **Alerts** — Creates missing alert configurations
- **Private Endpoints** — Validates private endpoint setup

### 2. **atlas_organization_security_audit.py** — Organization-Level Security Audit
Audits all projects in a MongoDB Atlas organization. Automatically discovers and audits each project using all 7 security checks, with aggregated reporting.

### 3. **atlas_ip_access_analyzer.py** — IP Access List Analysis
Audits IP whitelisting across all projects in an organization. Identifies and reports on projects open to the internet.

## Quick Start

```bash
# 1. Setup
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Create .env file with your credentials
cat > .env << EOF
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
ATLAS_PROJECT_ID=your_project_id_here
ATLAS_ORG_ID=your_org_id_here
ALERT_EMAIL=security@example.com
DRY_RUN=true
EOF

# 3. Run a script
python3 atlas_security_auditor.py

python3 atlas_ip_access_analyzer.py
```

> **Need API keys?** See [Creating API Keys](#creating-api-keys) section below for detailed instructions.

## Features

**Security Auditor (Project-Level)**
- ✅ Audits 7 security best practices per project
- ✅ Automatically fixes security issues (IP access, TLS, auditing, alerts)
- ✅ Dry-run mode to preview changes without applying them
- ✅ Detailed findings and remediation actions
- ✅ Exit codes for CI/CD integration

**Organization Auditor**
- ✅ Discovers all projects in organization automatically
- ✅ Runs all 7 security checks on every project
- ✅ Aggregated reporting across organization
- ✅ Per-project findings and issue summary

**IP Access Analyzer**
- ✅ Retrieves all projects from a given organization
- ✅ Fetches IP access lists for each project
- ✅ Groups IP addresses by project
- ✅ Highlights projects open to the internet (`0.0.0.0/0` or `0.0.0.0`)
- ✅ Color-coded terminal output for easy identification
- ✅ **Security Summary Report** — Lists all projects with open internet access
- ✅ Distinguishes between CIDR blocks (`0.0.0.0/0`) and IP addresses (`0.0.0.0`)
- ✅ Provides security recommendations for remediation
- ✅ Exports results to JSON file for further processing

## Prerequisites

- Python 3.12+
- MongoDB Atlas account with API access enabled
- Atlas API credentials (public and private keys)

## Installation

1. Clone or download this repository:
```bash
cd atlas_api_demos
```

2. Create and activate a virtual environment (recommended):
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:
- `requests>=2.32.0` - HTTP library for API calls (requires Python 3.10+)
- `python-dotenv>=1.0.0` - Loads environment variables from `.env` file
- `certifi>=2024.2.2` - Up-to-date CA certificate bundle for TLS verification

## Usage

### Project-Level Security Audit

Audit a single project for 7 critical security best practices:

```bash
# Using .env file (recommended)
export ATLAS_PROJECT_ID=your_project_id_here
python3 atlas_security_auditor.py

# Dry-run mode (preview changes without applying)
export DRY_RUN=true
python3 atlas_security_auditor.py

# Apply fixes automatically (dry-run is the default unless explicitly disabled)
export DRY_RUN=false
python3 atlas_security_auditor.py
```

**Configuration:**
```bash
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
ATLAS_PROJECT_ID=your_project_id_here
ALERT_EMAIL=security@example.com
DRY_RUN=true
```

### Organization-Level Security Audit

Audit all projects in an organization:

```bash
# Discover all projects and audit each one
export ATLAS_ORG_ID=your_org_id_here
python3 atlas_organization_security_audit.py

# Dry-run mode
export DRY_RUN=true
python3 atlas_organization_security_audit.py
```

**Configuration:**
```bash
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
ATLAS_ORG_ID=your_org_id_here
ALERT_EMAIL=security@example.com
DRY_RUN=true
```

### IP Access List Analysis

Analyze IP whitelisting across all projects:

```bash
python3 atlas_ip_access_analyzer.py
```

**Configuration:**
```bash
ATLAS_ORG_ID=your_org_id_here
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
```

### Method 1: Environment Variables (Recommended)

```bash
export ATLAS_ORG_ID=your_org_id_here
export ATLAS_PUBLIC_KEY=your_public_key_here
export ATLAS_PRIVATE_KEY=your_private_key_here
python3 atlas_ip_access_analyzer.py
```

Avoid passing private API keys as command-line arguments because they can be exposed through shell history and process listings.

### Method 2: `.env` File

#### Using a `.env` file

1. Create a `.env` file in the project directory:
```bash
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
ATLAS_PROJECT_ID=your_project_id_here
ATLAS_ORG_ID=your_org_id_here
ALERT_EMAIL=security@example.com
DRY_RUN=true
```

2. Run the scripts (they will automatically load the `.env` file):
```bash
python3 atlas_security_auditor.py
python3 atlas_organization_security_audit.py
python3 atlas_ip_access_analyzer.py
```

**Note:** The scripts use `python-dotenv` to automatically load environment variables from the `.env` file. Make sure `.env` is in your `.gitignore` to avoid committing credentials.

#### Using shell environment variables

Alternatively, you can export environment variables in your shell:

```bash
export ATLAS_PUBLIC_KEY="your_public_key_here"
export ATLAS_PRIVATE_KEY="your_private_key_here"
export ATLAS_PROJECT_ID="your_project_id_here"
export ATLAS_ORG_ID="your_org_id_here"
export ALERT_EMAIL="security@example.com"
export DRY_RUN="true"

python3 atlas_security_auditor.py
python3 atlas_organization_security_audit.py
python3 atlas_ip_access_analyzer.py
```

## Security Checks Reference

The security auditor performs the following checks:

| Check | Status | Finding | Action | Notes |
|-------|--------|---------|--------|-------|
| **IP Access List** | PASS/FAIL/FIXED | Detects `0.0.0.0/0` or `0.0.0.0` | Removes wildcard entries | Enforces explicit IP/CIDR only |
| **Database Users** | PASS/WARN | Flags `atlasAdmin` role assignments | Lists users (no auto-delete) | Production concern only |
| **TLS Minimum Version** | PASS/FAIL/FIXED | TLS < 1.2 detected | Sets `minimumEnabledTlsProtocol: TLS1_2` | All clusters affected |
| **Encryption at Rest** | PASS/WARN | Customer-managed keys disabled | Reports only | AWS KMS, Azure KV, GCP KMS |
| **Auditing** | PASS/FAIL/FIXED | Auditing disabled/filters missing | Enables with event filter | Captures auth, user, collection events |
| **Alerts** | PASS/FAIL/FIXED | Missing alert configs | Creates `USER_ROLES_CHANGED_AUDIT` and `NO_PRIMARY` alerts | Uses `ALERT_EMAIL`; event names must be valid Atlas v2 `eventTypeName` values |
| **Private Endpoints** | PASS/WARN | No private endpoints with public IPs | Reports only | Suggests private endpoint setup |

**Check Status Codes:**
- `PASS` — Control is compliant; no action needed
- `WARN` — Issue detected but requires manual review/approval
- `FAIL` — Control failed; manual or automatic remediation available
- `FIXED` — Control was non-compliant and has been automatically remediated

## Exit Codes

Scripts return OS exit codes for CI/CD integration:
- `0` — All checks PASS or FIXED successfully
- `1` — One or more checks FAIL or WARN

## Finding Your Organization ID

1. Log in to MongoDB Atlas
2. Click the Organization menu (top-left corner)
3. Click "Organization Settings"
4. Your Organization ID appears under "General"

## Creating API Keys

To create API keys with read-only access to all projects in your organization:

### Step 1: Navigate to API Keys

1. Log in to [MongoDB Atlas](https://cloud.mongodb.com/)
2. Click on your **Organization** name in the top-left corner
3. Select **Organization Settings** from the dropdown
4. In the left sidebar, click **Access Manager**
5. Click on the **API Keys** tab
6. Click the **Create API Key** button

### Step 2: Configure API Key

1. **Description**: Enter a descriptive name (e.g., "IP Access List Analyzer - Read Only")

2. **Organization Permissions**: Select **Organization Read Only**
   - This grants read access to all projects in the organization
   - Sufficient for viewing IP access lists across all projects
   - More secure than "Organization Owner" for audit purposes

   **Alternative (if you need broader access):**
   - **Organization Project Creator**: Read access + ability to create projects
   - **Organization Owner**: Full administrative access (not recommended for this script)

### Step 3: Save and Copy Keys

1. Click **Next**
2. **IMPORTANT**: Copy both the **Public Key** and **Private Key** immediately
   - The private key will only be shown once
   - Store them securely (e.g., in a password manager)
3. Click **Done**

### Step 4: Add API Key to IP Access List (if required)

If your organization requires API key IP access lists:

1. After creating the key, you'll see it in the API Keys list
2. Click on the key you just created
3. Click **Add Access List Entry**
4. Add your IP address or CIDR block
   - For testing: Add your current IP
   - For production: Add your server/automation IP ranges
5. Click **Save**

### Step 5: Add Keys to .env File

Add the keys to your `.env` file:

```bash
ATLAS_ORG_ID=your_organization_id_here
ATLAS_PUBLIC_KEY=your_public_key_here
ATLAS_PRIVATE_KEY=your_private_key_here
```

### Recommended Permissions

For this script, the **minimum required permission** is:
- ✅ **Organization Read Only** - Can read all projects and their IP access lists

**Why not Organization Owner?**
- Following the principle of least privilege
- Read-only access is sufficient for auditing
- Reduces security risk if keys are compromised

## Output

The script produces:

1. **Console Output**: Color-coded display of projects and their IP access lists
   - 🟢 Green ✓ for projects without open internet access
   - 🔴 Red ⚠️ OPEN for projects with `0.0.0.0/0`

2. **JSON File** (`ip_access_analysis.json`): Structured data for programmatic access
   ```json
   {
     "organization_id": "...",
     "projects": {
       "ProjectName": {
         "ip_access_list": ["192.168.1.0/24", "10.0.0.0/8"],
         "has_0_0_0_0": false,
         "entry_count": 2
       }
     }
   }
   ```

## Example Output

```
================================================================================
MongoDB Atlas IP Access List Analysis
================================================================================

Summary:
  Total Projects: 3
  Projects with 0.0.0.0/0: 1

Production ✓
IP Access List:
  192.168.1.0/24
  10.0.0.0/8

Staging ⚠️  OPEN
IP Access List:
  0.0.0.0/0 ← OPEN TO INTERNET

Development ✓
IP Access List:
  203.0.113.0/24
  198.51.100.0/24

================================================================================
⚠️  SECURITY SUMMARY: OPEN INTERNET ACCESS DETECTED
================================================================================

WARNING: The following 1 project(s) have open internet access:

1. Staging
   └─ 0.0.0.0/0 (CIDR block)

RECOMMENDATION:
  • Review and restrict IP access to specific IP addresses or CIDR blocks
  • Remove 0.0.0.0/0 and 0.0.0.0 entries from production environments
  • Use VPN or bastion hosts for secure database access
  • Regularly audit IP access lists for compliance

✓ Results saved to: ip_access_analysis.json
```

### Example Output (All Clear)

When no projects have open internet access:

```
================================================================================
🎉 SECURITY SUMMARY: ALL CLEAR
================================================================================

✓ No projects found with open internet access (0.0.0.0/0 or 0.0.0.0)

All projects have proper IP access restrictions configured.
```

## Use Cases

### Identify Security Risks
Find projects with open internet access that should be restricted to specific IPs.

### Compliance Auditing
Generate reports on IP whitelisting configurations for compliance reviews.

### Migration Planning
Document current IP access lists before reconfiguring network access.

## Troubleshooting

### "401 Unauthorized" Error
- **Verify your API keys are correct**
  - Check that you copied both public and private keys correctly
  - Ensure there are no extra spaces or newlines in your `.env` file
- **Check API key permissions**
  - Minimum required: **Organization Read Only**
  - The key must have organization-level access (not just project-level)
- **Verify the Organization ID is correct**
  - Make sure you're using the Organization ID, not a Project ID
- **Check API key IP access list** (if enabled)
  - Your current IP must be in the API key's access list
  - Go to Organization Settings → Access Manager → API Keys → [Your Key] → Access List

### "404 Not Found" Error
- **Verify the Organization ID is correct**
  - Organization ID is a 24-character hexadecimal string
  - Find it in Organization Settings → General
- **Ensure your API key has access to the organization**
  - The API key must be created at the organization level
  - Project-level API keys won't work for this script

### "403 Forbidden" Error
- **API key lacks sufficient permissions**
  - Upgrade to at least **Organization Read Only** permission
  - Go to Organization Settings → Access Manager → API Keys
  - Edit the key and change permissions

### Empty IP Access List
- An empty Atlas project access list means no client IP entries are configured
- This is not equivalent to `0.0.0.0/0`; open internet access is represented by an explicit `0.0.0.0/0` or `0.0.0.0` entry
- Verify expected client, app server, VPN, or private endpoint access before assuming the project is reachable

### Script Hangs or Times Out
- Scripts use 30-second HTTP request timeouts and retry transient Atlas/API errors
- **Check your internet connection**
- **Verify Atlas API is accessible**
  - Some corporate networks block Atlas API endpoints
  - Try from a different network or use a VPN
- **Large number of projects**
  - The script may take time if you have many projects
  - This is normal behavior

## Virtual Environment

When you're done using the script, you can deactivate the virtual environment:
```bash
deactivate
```

To reactivate it later, simply run:
```bash
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

## Security Notes

- ⚠️ **Never commit API keys to version control**
- Use environment variables or `.env` files locally (add `.env` to `.gitignore`)
- Add `venv/` to `.gitignore` to avoid committing virtual environment files
- Rotate API keys regularly
- Use minimal necessary permissions for API keys

## API Documentation

All scripts use **MongoDB Atlas Administration API v2** with HTTP Digest authentication. For more information:
- [MongoDB Atlas Admin API v2](https://www.mongodb.com/docs/atlas/reference/api-resources-spec/v2/)

**Endpoints Used:**

**Organization & Projects**
- [GET /orgs/{orgId}/projects](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroups) — List projects in organization

**IP Access Lists**
- [GET /groups/{groupId}/accessList](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listprojectipaddresses) — List IP access entries
- [DELETE /groups/{groupId}/accessList/{entryValue}](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-deleteipaddress) — Remove IP access entry. **CIDR blocks must be URL-encoded** — the `/` in `0.0.0.0/0` must be percent-encoded as `0.0.0.0%2F0`, otherwise the gateway interprets it as a path separator and returns 404.

**Clusters**
- [GET /groups/{groupId}/clusters](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listclusters) — List clusters
- [PATCH /groups/{groupId}/clusters/{clusterName}](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-updatecluster) — Update cluster settings

**Database Users**
- [GET /groups/{groupId}/databaseUsers](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listdatabaseusers) — List database users

**Encryption at Rest**
- [GET /groups/{groupId}/encryptionAtRest](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-getencryptionatrest) — Check encryption config

**Audit Logs**
- [GET /groups/{groupId}/auditLog](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-getgroupauditlog) — Retrieve audit configuration
- [PATCH /groups/{groupId}/auditLog](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-updategroupauditlog) — Update audit configuration

**Alerts**
- [GET /groups/{groupId}/alertConfigs](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listmatchingalerts) — List alert configurations
- [POST /groups/{groupId}/alertConfigs](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-createalertconfiguration) — Create alert configuration

**Private Endpoints**
- [GET /groups/{groupId}/privateEndpoint/{cloudProvider}/endpointService](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroupprivateendpointendpointservice) — List private endpoint services per cloud provider (AWS, AZURE, GCP). **Returns a plain JSON array**, not the standard paginated `{results, totalCount}` envelope; must be called with a plain GET, not through a pagination helper.

## License

Use as needed for your MongoDB Atlas administration.
