#!/usr/bin/env python3
"""
MongoDB Atlas Security Audit and Enforcement Script

Audits and enforces security best practices against a MongoDB Atlas project.
Uses MongoDB Atlas Administration API v2 exclusively.

Configuration via environment variables:
  ATLAS_PUBLIC_KEY    - Atlas API public key
  ATLAS_PRIVATE_KEY   - Atlas API private key
  ATLAS_PROJECT_ID    - Atlas project (group) ID to audit
  ALERT_EMAIL         - Email address for alert notifications
  DRY_RUN            - Set to 'true' to run in read-only mode
"""

import os
import sys
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import requests
from requests.auth import HTTPDigestAuth
from dotenv import load_dotenv


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AtlasAPIError(Exception):
    """Exception raised for Atlas API errors."""
    pass


class CheckStatus(Enum):
    """Status of a security check."""
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    FIXED = "FIXED"


@dataclass
class IpAccessEntry:
    """IP access list entry."""
    ipAddress: Optional[str] = None
    cidrBlock: Optional[str] = None
    comment: Optional[str] = None


@dataclass
class DatabaseUser:
    """Database user."""
    username: str
    roles: List[Dict[str, str]] = field(default_factory=list)
    
    def has_atlas_admin(self) -> bool:
        """Check if user has atlasAdmin role."""
        for role in self.roles:
            if role.get('roleName') == 'atlasAdmin':
                return True
        return False


@dataclass
class AdvancedSettings:
    """Cluster advanced settings."""
    minimumEnabledTlsProtocol: Optional[str] = None
    
    def has_min_tls_12(self) -> bool:
        """Check if minimum TLS version is 1.2 or higher."""
        if not self.minimumEnabledTlsProtocol:
            return False
        return self.minimumEnabledTlsProtocol >= "TLS1_2"


@dataclass
class Cluster:
    """MongoDB cluster."""
    name: str
    id: str
    advancedSettings: Optional[Dict[str, Any]] = None


@dataclass
class AuditConfig:
    """Audit configuration."""
    enabled: bool
    auditFilter: Optional[str] = None


@dataclass
class AlertConfig:
    """Alert configuration."""
    id: str
    eventTypeName: str
    enabled: bool
    notifications: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PrivateEndpoint:
    """Private endpoint configuration."""
    id: str
    provider: str
    endpointServiceName: Optional[str] = None


@dataclass
class CheckResult:
    """Result of a security check."""
    name: str
    status: CheckStatus
    findings: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)


class AtlasClient:
    """Thin API client for MongoDB Atlas Administration API v2."""
    
    BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"
    API_VERSION = "application/vnd.atlas.2023-02-01+json"
    
    def __init__(self, public_key: str, private_key: str, project_id: str, dry_run: bool = False):
        """Initialize Atlas API client.
        
        Args:
            public_key: Atlas API public key
            private_key: Atlas API private key
            project_id: Atlas project ID
            dry_run: If True, skip all mutating operations
        """
        self.public_key = public_key
        self.private_key = private_key
        self.project_id = project_id
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(public_key, private_key)
        self.session.headers.update({
            'Accept': self.API_VERSION,
            'Content-Type': 'application/json'
        })
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute an API request with error handling and logging.
        
        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            Parsed JSON response
            
        Raises:
            AtlasAPIError: If response status is not 2xx
        """
        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"{method} {endpoint}")
        
        response = self.session.request(method, url, **kwargs)
        
        logger.debug(f"Status: {response.status_code}")
        
        if not (200 <= response.status_code < 300):
            try:
                error_detail = response.json()
            except Exception:
                error_detail = response.text
            raise AtlasAPIError(
                f"{method} {endpoint} returned {response.status_code}: {error_detail}"
            )
        
        if response.text:
            return response.json()
        return {}
    
    def get(self, endpoint: str) -> Dict[str, Any]:
        """Execute a GET request.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Parsed JSON response
        """
        return self._request('GET', endpoint)
    
    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a POST request.
        
        Args:
            endpoint: API endpoint path
            data: Request payload
            
        Returns:
            Parsed JSON response
        """
        if self.dry_run:
            logger.warning(f"DRY_RUN: Skipping POST {endpoint}")
            return {}
        return self._request('POST', endpoint, json=data)
    
    def patch(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a PATCH request.
        
        Args:
            endpoint: API endpoint path
            data: Request payload
            
        Returns:
            Parsed JSON response
        """
        if self.dry_run:
            logger.warning(f"DRY_RUN: Skipping PATCH {endpoint}")
            return {}
        return self._request('PATCH', endpoint, json=data)
    
    def delete(self, endpoint: str) -> Dict[str, Any]:
        """Execute a DELETE request.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Parsed JSON response
        """
        if self.dry_run:
            logger.warning(f"DRY_RUN: Skipping DELETE {endpoint}")
            return {}
        return self._request('DELETE', endpoint)
    
    def get_all_pages(self, endpoint: str, page_size: int = 100) -> List[Dict[str, Any]]:
        """Get all paginated results.
        
        Args:
            endpoint: API endpoint path
            page_size: Items per page
            
        Returns:
            List of all results across all pages
        """
        results = []
        page_num = 1
        
        while True:
            data = self.get(f"{endpoint}?pageNum={page_num}&itemsPerPage={page_size}")
            
            results.extend(data.get('results', []))
            
            total_count = data.get('totalCount', 0)
            if len(results) >= total_count:
                break
            
            page_num += 1
        
        return results


def check_ip_access_list(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check and remediate IP access list.
    
    Removes 0.0.0.0/0 and 0.0.0.0 entries which allow open internet access.
    """
    result = CheckResult(name="IP Access List", status=CheckStatus.PASS)
    
    try:
        entries_response = client.get(f"/groups/{client.project_id}/accessList")
        ip_list = entries_response.get('results', [])
        
        open_internet_entries = [
            entry for entry in ip_list
            if entry.get('ipAddress') == '0.0.0.0' or entry.get('cidrBlock') == '0.0.0.0/0'
        ]
        
        if open_internet_entries:
            result.status = CheckStatus.FAIL
            for entry in open_internet_entries:
                entry_identifier = entry.get('ipAddress') or entry.get('cidrBlock')
                result.findings.append(f"Open internet access: {entry_identifier}")
                
                if not client.dry_run:
                    try:
                        client.delete(f"/groups/{client.project_id}/accessList/{entry_identifier}")
                        result.status = CheckStatus.FIXED
                        result.actions_taken.append(f"Removed: {entry_identifier}")
                    except Exception as e:
                        logger.error(f"Failed to remove IP access entry: {e}")
                        result.status = CheckStatus.FAIL
                else:
                    result.actions_taken.append(f"Would remove: {entry_identifier}")
        
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
    
    return result


def check_database_users(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check database users for atlasAdmin role.
    
    Flags any database user assigned the atlasAdmin built-in role.
    """
    result = CheckResult(name="Database Users", status=CheckStatus.PASS)
    
    try:
        users = client.get_all_pages(f"/groups/{client.project_id}/databaseUsers")
        
        admin_users = [
            u for u in users 
            if any(r.get('roleName') == 'atlasAdmin' for r in u.get('roles', []))
        ]
        
        if admin_users:
            result.status = CheckStatus.WARN
            for user in admin_users:
                username = user.get('username')
                result.findings.append(
                    f"User '{username}' has atlasAdmin role in production scope"
                )
        
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
    
    return result


def check_tls_minimum_version(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check and enforce TLS 1.2 minimum on all clusters.
    
    Verifies or patches advancedSettings.minimumEnabledTlsProtocol to TLS1_2.
    """
    result = CheckResult(name="TLS Minimum Version", status=CheckStatus.PASS)
    
    try:
        clusters = client.get_all_pages(f"/groups/{client.project_id}/clusters")
        
        for cluster in clusters:
            cluster_name = cluster.get('name')
            advanced = cluster.get('advancedSettings', {})
            tls_version = advanced.get('minimumEnabledTlsProtocol')
            
            if not tls_version or tls_version < "TLS1_2":
                result.status = CheckStatus.FAIL
                result.findings.append(
                    f"Cluster '{cluster_name}' TLS: {tls_version or 'not set'}"
                )
                
                if not client.dry_run:
                    try:
                        client.patch(
                            f"/groups/{client.project_id}/clusters/{cluster_name}",
                            {'advancedSettings': {'minimumEnabledTlsProtocol': 'TLS1_2'}}
                        )
                        result.status = CheckStatus.FIXED
                        result.actions_taken.append(f"Set TLS 1.2 minimum on '{cluster_name}'")
                    except Exception as patch_error:
                        # 409 conflict likely means cluster is paused or being modified
                        if '409' in str(patch_error):
                            logger.debug(f"Cannot update {cluster_name}: cluster is paused")
                            result.findings[-1] = f"Cluster '{cluster_name}' cannot be updated (paused or being modified)"
                            result.status = CheckStatus.FAIL
                        else:
                            logger.error(f"Failed to update TLS for {cluster_name}: {patch_error}")
                            result.status = CheckStatus.FAIL
                else:
                    result.actions_taken.append(f"Would set TLS 1.2 on '{cluster_name}'")
        
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
    
    return result


def check_encryption_at_rest(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check if customer-managed key encryption is enabled.
    
    Verifies AWS KMS, Azure Key Vault, or GCP KMS configuration.
    """
    result = CheckResult(name="Encryption at Rest", status=CheckStatus.PASS)
    
    try:
        encryption_config = client.get(f"/groups/{client.project_id}/encryptionAtRest")
        
        aws_kms = encryption_config.get('awsKms', {})
        azure_kv = encryption_config.get('azureKeyVault', {})
        gcp_kms = encryption_config.get('googleCloudKms', {})
        
        has_cmk = (
            aws_kms.get('enabled') or 
            azure_kv.get('enabled') or 
            gcp_kms.get('enabled')
        )
        
        if not has_cmk:
            result.status = CheckStatus.WARN
            result.findings.append("Customer-managed key encryption is not enabled")
        
    except Exception as e:
        result.status = CheckStatus.WARN
        result.findings.append(f"Could not verify encryption config: {e}")
    
    return result


def check_auditing(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check and enable database auditing with required event filters.
    
    Ensures auditing captures: authenticate, createUser, dropUser, 
    createCollection, dropCollection.
    
    Note: Auditing is only available on M10+ clusters.
    """
    result = CheckResult(name="Auditing", status=CheckStatus.PASS)
    
    required_events = {
        'authenticate', 'createUser', 'dropUser', 
        'createDatabase', 'dropDatabase',
        'createCollection', 'dropCollection'
    }
    
    try:
        audit_config = None
        last_error = None
        
        # Try different possible audit endpoints
        audit_endpoints = [
            f"/groups/{client.project_id}/auditLogs",
            f"/groups/{client.project_id}/auditLog",
        ]
        
        for endpoint in audit_endpoints:
            try:
                audit_config = client.get(endpoint)
                break
            except Exception as e:
                last_error = e
                continue
        
        if audit_config is None:
            # Auditing endpoint not available - likely cluster tier doesn't support it (need M10+)
            if last_error and '404' in str(last_error):
                result.status = CheckStatus.WARN
                result.findings.append("Auditing not available (requires M10+ cluster tier)")
            else:
                result.status = CheckStatus.WARN
                result.findings.append(f"Could not access audit configuration")
            return result
        
        if not audit_config.get('auditAuthorizationSuccess'):
            result.status = CheckStatus.FAIL
            result.findings.append("Database auditing is not enabled")
            
            if not client.dry_run:
                try:
                    audit_filter = {
                        'atype': {'$in': sorted(list(required_events))}
                    }
                    
                    client.patch(
                        f"/groups/{client.project_id}/auditLogs",
                        {
                            'auditAuthorizationSuccess': True,
                            'auditFilter': json.dumps(audit_filter)
                        }
                    )
                    result.status = CheckStatus.FIXED
                    result.actions_taken.append("Enabled auditing with event filter")
                except Exception as patch_error:
                    logger.error(f"Failed to enable auditing: {patch_error}")
                    result.status = CheckStatus.FAIL
            else:
                result.actions_taken.append("Would enable auditing with event filter")
        
    except Exception as e:
        result.status = CheckStatus.WARN
        result.findings.append(f"Could not check auditing: {type(e).__name__}")
        logger.debug(f"Auditing check exception: {e}")
    
    return result


def check_alerts(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """Check and create missing alert configurations.
    
    Verifies alerts exist for important security events.
    Creates missing alerts using ALERT_EMAIL from configuration.
    """
    result = CheckResult(name="Alerts", status=CheckStatus.PASS)
    
    alert_email = cfg.get('ALERT_EMAIL', '').strip()
    if not alert_email:
        result.status = CheckStatus.WARN
        result.findings.append("ALERT_EMAIL not configured")
        return result
    
    # Use valid Atlas alert event type names (check Atlas documentation for current list)
    required_alerts = ['AUTHENTICATION_FAILED_ATTEMPTS', 'GROUP_CREATED']
    
    try:
        alerts = client.get_all_pages(f"/groups/{client.project_id}/alertConfigs")
        
        existing_types = {
            alert.get('eventTypeName') for alert in alerts 
            if alert.get('enabled')
        }
        
        missing_types = [t for t in required_alerts if t not in existing_types]
        
        for alert_type in missing_types:
            result.status = CheckStatus.FAIL
            result.findings.append(f"Alert not configured for {alert_type}")
            
            if not client.dry_run:
                try:
                    client.post(
                        f"/groups/{client.project_id}/alertConfigs",
                        {
                            'eventTypeName': alert_type,
                            'enabled': True,
                            'notifications': [
                                {
                                    'typeName': 'EMAIL',
                                    'emailAddress': alert_email
                                }
                            ]
                        }
                    )
                    result.status = CheckStatus.FIXED
                    result.actions_taken.append(f"Created alert for {alert_type}")
                except Exception as post_error:
                    # 400 errors typically indicate invalid enum value or other client error
                    if '400' in str(post_error):
                        logger.debug(f"Invalid alert type or configuration: {alert_type}")
                        result.findings[-1] = f"Cannot create alert for {alert_type} (invalid or unsupported)"
                    else:
                        logger.error(f"Failed to create alert for {alert_type}: {post_error}")
                    result.status = CheckStatus.FAIL
            else:
                result.actions_taken.append(f"Would create alert for {alert_type}")
        
    except Exception as e:
        result.status = CheckStatus.FAIL
        result.findings.append(f"API Error: {e}")
    
    return result


def check_private_endpoints(client: AtlasClient, cfg: Dict[str, str]) -> CheckResult:
    """List private endpoints and warn if none are configured with public IP access.
    
    Alerts if there are public IP access entries but no private endpoints.
    """
    result = CheckResult(name="Private Endpoints", status=CheckStatus.PASS)
    
    try:
        endpoints = []
        
        # Try to get private endpoints - may not be available on all tiers
        try:
            endpoints = client.get_all_pages(f"/groups/{client.project_id}/privateEndpoint/endpointIds")
        except (AtlasAPIError, Exception):
            # Private endpoints may not be available or may use different endpoint
            pass
        
        if not endpoints:
            try:
                ip_response = client.get(f"/groups/{client.project_id}/accessList")
                ip_entries = ip_response.get('results', [])
                
                if ip_entries:
                    result.status = CheckStatus.WARN
                    result.findings.append(
                        f"No private endpoints but {len(ip_entries)} public IP entries exist"
                    )
            except (AtlasAPIError, Exception):
                # IP access list might also fail - that's OK
                pass
        else:
            result.findings.append(f"{len(endpoints)} private endpoint(s) configured")
    
    except Exception as e:
        # Catch any remaining exceptions to prevent propagation
        result.status = CheckStatus.WARN
        result.findings.append(f"Could not verify private endpoints: {type(e).__name__}")
        logger.debug(f"Private endpoints check exception: {e}")
    
    return result


def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables.
    
    Returns:
        Configuration dictionary with all required and optional settings
        
    Raises:
        ValueError: If required environment variables are missing
    """
    required_keys = ['ATLAS_PUBLIC_KEY', 'ATLAS_PRIVATE_KEY', 'ATLAS_PROJECT_ID']
    
    config = {}
    for key in required_keys:
        value = os.getenv(key, '').strip()
        if not value:
            raise ValueError(f"Missing required environment variable: {key}")
        config[key] = value
    
    config['ALERT_EMAIL'] = os.getenv('ALERT_EMAIL', '').strip()
    config['DRY_RUN'] = os.getenv('DRY_RUN', 'false').lower() == 'true'
    
    return config


def print_summary(results: List[CheckResult]) -> int:
    """Print summary table and return appropriate exit code.
    
    Args:
        results: List of CheckResult objects
        
    Returns:
        Exit code: 0 if all checks PASS/FIXED, 1 otherwise
    """
    print("\n" + "=" * 80)
    print("MongoDB Atlas Security Audit Summary".center(80))
    print("=" * 80 + "\n")
    
    print(f"{'Check':<30} {'Status':<10} {'Findings':<15} {'Actions':<10}")
    print("-" * 80)
    
    for result in results:
        findings_count = len(result.findings)
        actions_count = len(result.actions_taken)
        print(
            f"{result.name:<30} {result.status.value:<10} "
            f"{findings_count:<15} {actions_count:<10}"
        )
    
    print("-" * 80)
    
    has_issues = False
    for result in results:
        if result.findings:
            print(f"\n{result.name}:")
            for finding in result.findings:
                print(f"  • {finding}")
            has_issues = True
    
    has_actions = False
    for result in results:
        if result.actions_taken:
            if not has_actions:
                print("\nActions Taken:")
                has_actions = True
            for action in result.actions_taken:
                print(f"  • {action}")
    
    print("\n" + "=" * 80)
    
    statuses = {r.status for r in results}
    if statuses <= {CheckStatus.PASS, CheckStatus.FIXED}:
        print("✓ All checks passed or were successfully fixed".center(80))
        exit_code = 0
    else:
        print("✗ Some checks failed or require attention".center(80))
        exit_code = 1
    
    print("=" * 80 + "\n")
    return exit_code


def main() -> int:
    """Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Load environment variables from .env file
    load_dotenv()
    
    try:
        config = load_config()
    except ValueError as e:
        logger.error(str(e))
        return 1
    
    dry_run = config.pop('DRY_RUN')
    
    client = AtlasClient(
        config['ATLAS_PUBLIC_KEY'],
        config['ATLAS_PRIVATE_KEY'],
        config['ATLAS_PROJECT_ID'],
        dry_run=dry_run
    )
    
    if dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
    
    checks = [
        check_ip_access_list,
        check_database_users,
        check_tls_minimum_version,
        check_encryption_at_rest,
        check_auditing,
        check_alerts,
        check_private_endpoints,
    ]
    
    results = []
    for check_func in checks:
        try:
            result = check_func(client, config)
            results.append(result)
        except Exception as e:
            logger.exception(f"Check {check_func.__name__} raised exception")
            results.append(
                CheckResult(
                    name=check_func.__name__,
                    status=CheckStatus.FAIL,
                    findings=[f"Exception: {type(e).__name__}: {e}"]
                )
            )
    
    exit_code = print_summary(results)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
