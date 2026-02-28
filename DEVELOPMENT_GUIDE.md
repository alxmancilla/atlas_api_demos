# MongoDB Atlas API Demos - Development Guide

## Project Architecture Overview

This project provides security audit scripts for MongoDB Atlas using the Atlas Administration API v2. The codebase consists of:

- **atlas_security_auditor.py** - Single project security auditor with reusable check functions
- **atlas_organization_security_audit.py** - Organization-level auditor that iterates through projects
- **Individual demo scripts** - atlas_ip_access_analyzer.py, atlas_cluster_databases_lister.py, etc.

## Critical Design Patterns & Lessons Learned

### 1. **Exception Class Isolation Issue**

**Problem:**
When two files define their own `AtlasAPIError` exception class, catching exceptions from another module's `AtlasClient` fails silently because the exception types don't match in Python, even though they're named identically.

**Example of the Problem:**
```python
# atlas_security_auditor.py
class AtlasAPIError(Exception):
    pass

# atlas_organization_security_audit.py
class AtlasAPIError(Exception):  # Different class, same name!
    pass

# In check_auditing() called from organization_security_audit.py:
try:
    audit_config = client.get(endpoint)  # client is from org module
except AtlasAPIError as e:  # This won't catch org module's AtlasAPIError!
    pass  # Exception escapes!
```

**Solution:**
Catch generic `Exception` in all check functions instead of catching specific exception classes. This works regardless of which module's client is used.

```python
# CORRECT - Works with any AtlasClient implementation
try:
    result = client.get_all_pages(f"/groups/{client.project_id}/clusters")
except Exception as e:
    result.status = CheckStatus.FAIL
    result.findings.append(f"API Error: {e}")
    return result
```

**Rule for New Scripts:**
- **Never catch domain-specific exceptions (like `AtlasAPIError`) in reusable check functions**
- **Always catch generic `Exception` when check functions might be called with different client implementations**

---

### 2. **Error Handling Strategy for API Operations**

**Problem:**
API calls can fail with different status codes that mean different things:
- 404 Not Found → Feature not available on this tier (e.g., auditing requires M10+)
- 409 Conflict → Resource is in invalid state (e.g., cluster is paused)
- 400 Bad Request → Invalid configuration or unsupported enum value

Simply raising exceptions loses this context.

**Solution:**
Create specific exception handling branches for different error scenarios within check functions:

```python
try:
    client.patch(f"/groups/{client.project_id}/clusters/{cluster_name}", data)
    result.status = CheckStatus.FIXED
except Exception as e:
    error_str = str(e)
    if '409' in error_str:  # Conflict
        logger.debug(f"Cannot update {cluster_name}: cluster is paused")
        result.findings[-1] = f"Cluster '{cluster_name}' cannot be updated (paused)"
        result.status = CheckStatus.FAIL
    elif '404' in error_str:  # Not found
        result.status = CheckStatus.WARN
        result.findings.append("Feature not available on this cluster tier")
    else:
        logger.error(f"Failed to update: {e}")
        result.status = CheckStatus.FAIL
```

**CheckStatus Mapping:**
- `PASS` → All checks passed
- `FAIL` → Critical issue found or operation failed
- `WARN` → Warning (e.g., feature not available, suboptimal config)
- `FIXED` → Issue was found and successfully remediated

---

### 3. **Handling Optional Features by Cluster Tier**

**Problem:**
Atlas features vary by cluster tier:
- Auditing only available on M10+ (free/shared tiers return 404)
- Some encryption options only on paid tiers
- Private endpoints not available on all tiers

Trying to access these endpoints throws 404 errors that crash scripts.

**Solution:**
Implement a feature discovery pattern:

```python
# For optional endpoints that may not exist
audit_endpoints = [
    f"/groups/{client.project_id}/auditLogs",
    f"/groups/{client.project_id}/auditLog",  # Try alternate names
]

for endpoint in audit_endpoints:
    try:
        audit_config = client.get(endpoint)
        break  # Found it!
    except Exception as e:
        last_error = e
        continue

if audit_config is None:
    # Feature unavailable
    if last_error and '404' in str(last_error):
        result.status = CheckStatus.WARN
        result.findings.append("Auditing not available (requires M10+ tier)")
    return result
```

Add a helper method to `AtlasClient`:

```python
def get_if_available(self, endpoint: str) -> Optional[Dict[str, Any]]:
    """Returns None if endpoint is 404, raises on other errors."""
    try:
        return self.get(endpoint)
    except Exception as e:
        if '404' in str(e):
            logger.debug(f"Feature not available: {endpoint}")
            return None
        raise
```

---

### 4. **Shared AtlasClient Implementation**

**Pattern:**
When one script (`atlas_organization_security_audit.py`) imports check functions from another (`atlas_security_auditor.py`), they need compatible `AtlasClient` implementations.

**Current Status:**
Both files have identical `AtlasClient` classes. This works but violates DRY principle.

**Recommendation for Future:**
Eventually extract `AtlasClient` to a shared module:

```
atlas_client.py  (shared)
  ├── AtlasClient
  ├── AtlasAPIError
  └── Common auth/request utilities

atlas_security_auditor.py  (import from atlas_client)
atlas_organization_security_audit.py  (import from atlas_client)
atlas_ip_access_analyzer.py  (import from atlas_client)
```

**Required Methods for AtlasClient:**
- `get(endpoint)` - GET request
- `post(endpoint, data)` - POST request (respects dry_run)
- `patch(endpoint, data)` - PATCH request (respects dry_run)
- `delete(endpoint)` - DELETE request (respects dry_run)
- `get_all_pages(endpoint, page_size)` - Paginated GET
- `get_if_available(endpoint)` - Optional: GET that returns None on 404
- Properties: `project_id`, `dry_run`, `session`

---

### 5. **Proper Logging at the Right Levels**

**Pattern:**
```python
# DEBUG: Low-level details (request/response, expected failures)
logger.debug(f"Cannot update {cluster_name}: cluster is paused")
logger.debug(f"Feature not available: {endpoint}")

# ERROR: Unexpected failures that need investigation
logger.error(f"Failed to create alert for {alert_type}: {e}")
logger.error(f"Failed to update TLS for {cluster_name}: {e}")

# INFO: High-level progress
logger.info("Running in DRY RUN mode - no changes will be made")
logger.info(f"Found {len(projects)} project(s) to audit")

# EXCEPTION: Full traceback for debugging
logger.exception(f"Check {check_name} raised exception")
```

---

### 6. **Valid Atlas API Values**

**Alert Event Types:**
- ❌ `USER_CREATED` (invalid - returns 400)
- ❌ `AUTHENTICATION_FAILED` (invalid - returns 400)
- ✅ `AUTHENTICATION_FAILED_ATTEMPTS`
- ✅ `GROUP_CREATED`
- Other valid types: Check Atlas API documentation

**Notification Types:**
- `EMAIL` (requires `emailAddress`)
- `SMS` (requires `mobileNumber`)
- `WEBHOOK` (requires `url`)
- `PAGERDUTY` (requires `serviceKey`)
- `OPS_GENIE` (requires `apiKey`, `regionName`)
- `DATADOG` (requires `apiKey`, `datadog_org_id`)

**TLS Versions:**
- ✅ `TLS1_2`, `TLS1_3`
- ✅ String comparison works: `tls_version < "TLS1_2"` is valid

**Cluster States:**
- `PAUSED` - Cannot be modified (409 errors)
- `IDLE` - Can be modified
- `CREATING`, `UPDATING`, `DELETING` - Cannot be modified during transitions

---

## Template for New Check Functions

```python
def check_my_feature(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check and optionally remediate a specific security feature.
    
    Args:
        client: AtlasClient instance with project_id set
        cfg: Configuration dict (typically contains 'ALERT_EMAIL', 'DRY_RUN', etc.)
        
    Returns:
        CheckResult with findings and actions taken
    """
    result = CheckResult(name="My Feature", status=CheckStatus.PASS)
    
    try:
        # Get resource details
        resource = client.get(f"/groups/{client.project_id}/myResource")
        
        # Check conditions
        if not resource.get('isOptimal'):
            result.status = CheckStatus.FAIL
            result.findings.append("Resource not in optimal state")
            
            # Remediate if not in dry-run
            if not client.dry_run:
                try:
                    client.patch(
                        f"/groups/{client.project_id}/myResource",
                        {'isOptimal': True}
                    )
                    result.status = CheckStatus.FIXED
                    result.actions_taken.append("Fixed resource state")
                except Exception as patch_error:
                    # Handle specific error codes
                    if '409' in str(patch_error):
                        logger.debug("Resource is in transition state")
                        result.findings[-1] = "Cannot update while resource is transitioning"
                    else:
                        logger.error(f"Failed to fix resource: {patch_error}")
                    result.status = CheckStatus.FAIL
            else:
                result.actions_taken.append("Would fix resource state")
    
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
        logger.debug(f"Check failed: {e}")
    
    return result
```

---

## Configuration & Environment Variables

**Required:**
- `ATLAS_PUBLIC_KEY` - API key ID from Atlas UI
- `ATLAS_PRIVATE_KEY` - API private key from Atlas UI
- `ATLAS_PROJECT_ID` (single project audit) or `ATLAS_ORG_ID` (org audit)

**Optional:**
- `ALERT_EMAIL` - Email for alert notifications (required if creating alerts)
- `DRY_RUN` - Set to `true` to run in read-only mode (default: false)

**Loading Pattern:**
```python
from dotenv import load_dotenv

load_dotenv()  # Load from .env file

config = load_config()  # Custom function to validate required vars

if not config.get('required_var'):
    logger.error("Missing required environment variable")
    return 1
```

---

## Testing Anti-Patterns to Avoid

### ❌ Using Try-Except Only at Outer Level
```python
# BAD - Exception escapes from check function
def check_feature(client):
    result = CheckResult(name="Feature", status=CheckStatus.PASS)
    # If client.get() fails, exception escapes!
    config = client.get("/groups/123/config")
    return result

# In main:
try:
    result = check_feature(client)
except Exception:  # Has to catch here
    # Can't convert to CheckResult anymore
```

### ✅ Catching Exceptions Inside Check Functions
```python
# GOOD - Check function always returns CheckResult
def check_feature(client):
    result = CheckResult(name="Feature", status=CheckStatus.PASS)
    try:
        config = client.get("/groups/123/config")
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
    return result

# In main:
result = check_feature(client)  # Always get a CheckResult
```

---

## Performance Considerations

1. **Pagination:** Use `get_all_pages()` for endpoints that return lists
   ```python
   # Gets all results across all pages automatically
   users = client.get_all_pages(f"/groups/{client.project_id}/databaseUsers")
   ```

2. **Batch Operations:** For multiple clusters, iterate efficiently
   ```python
   clusters = client.get_all_pages(f"/groups/{client.project_id}/clusters")
   for cluster in clusters:
       # Check cluster
   ```

3. **Early Returns:** Return from check functions early when feature unavailable
   ```python
   if audit_config is None:
       result.status = CheckStatus.WARN
       result.findings.append("Feature not available")
       return result  # Don't continue checking
   ```

---

## Common Error Messages & Meanings

| Error Code | Status | Typical Message | Solution |
|-----------|--------|-----------------|----------|
| 400 | Bad Request | "Invalid enumeration value X" | Use valid enum from API docs |
| 401 | Unauthorized | "Unauthorized" | Check API key/secret in .env |
| 403 | Forbidden | "Forbidden" | User doesn't have permission |
| 404 | Not Found | "Cannot find resource" | Feature unavailable on tier or wrong endpoint |
| 409 | Conflict | "Cannot update cluster while paused" | Resource in invalid state for operation |
| 429 | Rate Limited | "Too many requests" | Add retry logic with backoff |
| 500+ | Server Error | Server error message | Retry after delay |

---

## Future Improvements

1. **Consolidate AtlasClient** into shared module
2. **Add retry logic** with exponential backoff for rate limiting (429)
3. **Implement logging configuration** via environment variable
4. **Add configuration schema validation** upfront
5. **Create utility functions** for common Atlas API patterns
6. **Add type hints** throughout (mypy compatibility)
7. **Implement alert aggregation** across multiple organizations
8. **Add output formatters** (JSON, CSV, HTML reports)

---

## Quick Reference: Exception Handling Checklist

When adding a new check function:

- [ ] Wrap entire function body in outer try-except for unexpected errors
- [ ] Catch generic `Exception`, not domain-specific exceptions
- [ ] Handle specific HTTP error codes (400, 404, 409) if relevant
- [ ] Always return a `CheckResult` object (never let exception escape)
- [ ] Use appropriate `CheckStatus` (FAIL for issues, WARN for unavailable features)
- [ ] Log at DEBUG level for expected failures, ERROR for unexpected ones
- [ ] Test with different cluster tiers to catch 404s
- [ ] Test with paused clusters to catch 409s
- [ ] Test dry-run mode to verify it skips mutations
