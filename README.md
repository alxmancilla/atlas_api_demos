# MongoDB Atlas API demos

Collection of Python scripts demonstrating MongoDB Atlas API capabilities. Includes examples for auditing security configurations, managing IP access lists, and retrieving organization/project data through the Atlas Admin API v2.

## Quick Start

```bash
# 1. Setup
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Create .env file with your credentials
cat > .env << EOF
ATLAS_ORG_ID=your_org_id_here
ATLAS_API_PUBLIC_KEY=your_public_key_here
ATLAS_API_PRIVATE_KEY=your_private_key_here
EOF

# 3. Run the script
python atlas_ip_access_analyzer.py
```

> **Need API keys?** See [Creating API Keys](#creating-api-keys) section below for detailed instructions.

## Features

- ✅ Retrieves all projects from a given organization
- ✅ Fetches IP access lists for each project
- ✅ Groups IP addresses by project
- ✅ Highlights projects open to the internet (`0.0.0.0/0` or `0.0.0.0`)
- ✅ Color-coded terminal output for easy identification
- ✅ **Security Summary Report** - Final report listing all projects with open internet access
- ✅ Distinguishes between CIDR blocks (`0.0.0.0/0`) and IP addresses (`0.0.0.0`)
- ✅ Provides security recommendations for remediation
- ✅ Exports results to JSON file for further processing

## Prerequisites

- Python 3.6+
- MongoDB Atlas account with API access enabled
- Atlas API credentials (public and private keys)

## Installation

1. Clone or download this repository:
```bash
cd atlas_accesslist_validation
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
- `requests` - HTTP library for API calls
- `python-dotenv` - Loads environment variables from `.env` file

## Usage

### Method 1: Command Line Arguments

```bash
python atlas_ip_access_analyzer.py <ORG_ID> <API_PUBLIC_KEY> <API_PRIVATE_KEY>
```

Example:
```bash
python atlas_ip_access_analyzer.py 5f1a2b3c4d5e6f7g8h9i0j1k your_public_key_here your_private_key_here
```

### Method 2: Environment Variables (Recommended)

#### Using a `.env` file

1. Create a `.env` file in the project directory:
```bash
ATLAS_ORG_ID=5f1a2b3c4d5e6f7g8h9i0j1k
ATLAS_API_PUBLIC_KEY=your_public_key_here
ATLAS_API_PRIVATE_KEY=your_private_key_here
```

2. Run the script (it will automatically load the `.env` file):
```bash
python atlas_ip_access_analyzer.py
```

**Note:** The script uses `python-dotenv` to automatically load environment variables from the `.env` file. Make sure `.env` is in your `.gitignore` to avoid committing credentials.

#### Using shell environment variables

Alternatively, you can export environment variables in your shell:

```bash
export ATLAS_ORG_ID="5f1a2b3c4d5e6f7g8h9i0j1k"
export ATLAS_API_PUBLIC_KEY="your_public_key_here"
export ATLAS_API_PRIVATE_KEY="your_private_key_here"

python atlas_ip_access_analyzer.py
```

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
ATLAS_API_PUBLIC_KEY=your_public_key_here
ATLAS_API_PRIVATE_KEY=your_private_key_here
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
- An empty list means no IP restrictions are configured
- All IPs can access that project (equivalent to `0.0.0.0/0`)
- This is a security risk and should be addressed

### Script Hangs or Times Out
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

This script uses **MongoDB Atlas API v2** with digest authentication. For more information, see:
- [MongoDB Atlas Admin API v2](https://www.mongodb.com/docs/atlas/reference/api-resources-spec/v2/)
- [Return All Projects](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listgroups)
- [Return All IP Access List Entries](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-listprojectipaddresses)

## License

Use as needed for your MongoDB Atlas administration.
