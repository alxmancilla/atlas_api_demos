#!/usr/bin/env python3
"""
MongoDB Atlas Organization-Level Security Audit Script

Audits security best practices across all projects in a MongoDB Atlas organization.
Iterates through each project and runs comprehensive security checks.

Configuration via environment variables:
  ATLAS_PUBLIC_KEY    - Atlas API public key
  ATLAS_PRIVATE_KEY   - Atlas API private key
  ATLAS_ORG_ID        - Atlas organization ID
  ALERT_EMAIL         - Email address for alert notifications
  DRY_RUN            - Set to 'true' to run in read-only mode
"""

import os
import sys
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
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
class CheckResult:
    """Result of a security check."""
    name: str
    status: CheckStatus
    findings: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)


@dataclass
class ProjectAuditResult:
    """Result of auditing a single project."""
    project_id: str
    project_name: str
    checks: List[CheckResult] = field(default_factory=list)
    
    def overall_status(self) -> CheckStatus:
        """Determine overall status across all checks."""
        statuses = {c.status for c in self.checks}
        if CheckStatus.FAIL in statuses:
            return CheckStatus.FAIL
        elif CheckStatus.WARN in statuses:
            return CheckStatus.WARN
        elif CheckStatus.FIXED in statuses:
            return CheckStatus.FIXED
        else:
            return CheckStatus.PASS


class AtlasClient:
    """Thin API client for MongoDB Atlas Administration API v2."""
    
    BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"
    API_VERSION = "application/vnd.atlas.2023-02-01+json"
    
    def __init__(self, public_key: str, private_key: str, dry_run: bool = False):
        """Initialize Atlas API client.
        
        Args:
            public_key: Atlas API public key
            private_key: Atlas API private key
            dry_run: If True, skip all mutating operations
        """
        self.public_key = public_key
        self.private_key = private_key
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
    
    def get(self, endpoint: str) -> Dict[str, Any]:
        """Execute a GET request.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Parsed JSON response
        """
        return self._request('GET', endpoint)
    
    def get_if_available(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Execute a GET request, returning None if the endpoint is not available (404).
        
        This is useful for checking optional features that may not be available
        on all project tiers.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Parsed JSON response, or None if the endpoint returns 404
        """
        try:
            return self.get(endpoint)
        except AtlasAPIError as e:
            # If the feature isn't available (404), return None instead of raising
            if '404' in str(e):
                logger.debug(f"Feature not available: {endpoint}")
                return None
            raise
    
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


def get_organization_projects(client: AtlasClient, org_id: str) -> List[Dict[str, Any]]:
    """Retrieve all projects in an organization.
    
    Args:
        client: AtlasClient instance
        org_id: Organization ID
        
    Returns:
        List of project details
        
    Raises:
        AtlasAPIError: If API call fails
    """
    return client.get_all_pages(f"/orgs/{org_id}/groups")


def import_security_checks():
    """Dynamically import security check functions from auditor script.
    
    Returns:
        Dictionary mapping check names to their functions
    """
    try:
        import importlib.util
        import sys
        
        # Clear any cached module to ensure we get the fresh/updated version
        if 'atlas_security_auditor' in sys.modules:
            del sys.modules['atlas_security_auditor']
        
        spec = importlib.util.spec_from_file_location(
            "atlas_security_auditor",
            os.path.join(os.path.dirname(__file__), "atlas_security_auditor.py")
        )
        auditor_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(auditor_module)
        
        return {
            'check_ip_access_list': auditor_module.check_ip_access_list,
            'check_database_users': auditor_module.check_database_users,
            'check_tls_minimum_version': auditor_module.check_tls_minimum_version,
            'check_encryption_at_rest': auditor_module.check_encryption_at_rest,
            'check_auditing': auditor_module.check_auditing,
            'check_alerts': auditor_module.check_alerts,
            'check_private_endpoints': auditor_module.check_private_endpoints,
        }
    except Exception as e:
        logger.exception("Failed to import security checks")
        raise


def run_project_audit(
    client: AtlasClient,
    project_id: str,
    project_name: str,
    config: Dict[str, str],
    check_functions: Dict[str, callable]
) -> ProjectAuditResult:
    """Run all security checks for a single project.
    
    Args:
        client: AtlasClient instance (used as an AtlasClient for project-level operations)
        project_id: Project ID to audit
        project_name: Project name for display
        config: Configuration dictionary
        check_functions: Dictionary of check functions
        
    Returns:
        ProjectAuditResult with all check results for this project
    """
    result = ProjectAuditResult(project_id=project_id, project_name=project_name)
    
    # Create a project-specific client by wrapping the organization client
    # We'll create a new client with the same credentials but tracking the project_id
    project_client = AtlasClient(
        client.public_key,
        client.private_key,
        dry_run=client.dry_run
    )
    project_client.project_id = project_id
    
    logger.info(f"Auditing project: {project_name} ({project_id})")
    
    for check_name, check_func in check_functions.items():
        try:
            check_result = check_func(project_client, config)
            result.checks.append(check_result)
        except Exception as e:
            logger.exception(f"Check {check_name} raised exception for project {project_name}")
            result.checks.append(
                CheckResult(
                    name=check_name,
                    status=CheckStatus.FAIL,
                    findings=[f"Exception: {type(e).__name__}: {e}"]
                )
            )
    
    return result


def print_organization_summary(org_id: str, project_results: List[ProjectAuditResult]) -> int:
    """Print comprehensive summary of organization audit.
    
    Args:
        org_id: Organization ID
        project_results: List of ProjectAuditResult objects
        
    Returns:
        Exit code: 0 if all projects PASS/FIXED, 1 otherwise
    """
    print("\n" + "=" * 100)
    print("MongoDB Atlas Organization Security Audit Summary".center(100))
    print(f"Organization ID: {org_id}".center(100))
    print("=" * 100 + "\n")
    
    # Summary table by project
    print(f"{'Project':<35} {'Overall Status':<15} {'Checks':<10} {'Issues':<10} {'Actions':<10}")
    print("-" * 100)
    
    overall_statuses = set()
    for proj_result in project_results:
        status = proj_result.overall_status()
        overall_statuses.add(status)
        
        total_checks = len(proj_result.checks)
        total_issues = sum(len(c.findings) for c in proj_result.checks)
        total_actions = sum(len(c.actions_taken) for c in proj_result.checks)
        
        print(
            f"{proj_result.project_name:<35} {status.value:<15} "
            f"{total_checks:<10} {total_issues:<10} {total_actions:<10}"
        )
    
    print("-" * 100)
    
    # Detailed findings by project
    for proj_result in project_results:
        if any(c.findings for c in proj_result.checks):
            print(f"\n{proj_result.project_name}:")
            for check in proj_result.checks:
                if check.findings:
                    print(f"  {check.name}:")
                    for finding in check.findings:
                        print(f"    • {finding}")
    
    # Detailed actions by project
    has_actions = False
    for proj_result in project_results:
        if any(c.actions_taken for c in proj_result.checks):
            if not has_actions:
                print("\nActions Taken by Project:")
                has_actions = True
            print(f"  {proj_result.project_name}:")
            for check in proj_result.checks:
                if check.actions_taken:
                    for action in check.actions_taken:
                        print(f"    • {action}")
    
    print("\n" + "=" * 100)
    
    # Overall result
    if overall_statuses <= {CheckStatus.PASS, CheckStatus.FIXED}:
        print(
            f"✓ All {len(project_results)} project(s) passed or were successfully fixed".center(100)
        )
        exit_code = 0
    else:
        print(
            f"✗ {len([s for s in overall_statuses if s in {CheckStatus.FAIL, CheckStatus.WARN}])} "
            f"project(s) have issues requiring attention".center(100)
        )
        exit_code = 1
    
    print("=" * 100 + "\n")
    
    return exit_code


def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables.
    
    Returns:
        Configuration dictionary with all required and optional settings
        
    Raises:
        ValueError: If required environment variables are missing
    """
    required_keys = ['ATLAS_PUBLIC_KEY', 'ATLAS_PRIVATE_KEY', 'ATLAS_ORG_ID']
    
    config = {}
    for key in required_keys:
        value = os.getenv(key, '').strip()
        if not value:
            raise ValueError(f"Missing required environment variable: {key}")
        config[key] = value
    
    config['ALERT_EMAIL'] = os.getenv('ALERT_EMAIL', '').strip()
    config['DRY_RUN'] = os.getenv('DRY_RUN', 'false').lower() == 'true'
    
    return config


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
    
    org_id = config.pop('ATLAS_ORG_ID')
    dry_run = config.pop('DRY_RUN')
    
    # Initialize client for organization-level operations
    org_client = AtlasClient(
        config['ATLAS_PUBLIC_KEY'],
        config['ATLAS_PRIVATE_KEY'],
        dry_run=dry_run
    )
    
    if dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
    
    # Get all projects in organization
    try:
        logger.info(f"Retrieving projects for organization {org_id}")
        projects = get_organization_projects(org_client, org_id)
    except AtlasAPIError as e:
        logger.error(f"Failed to retrieve organization projects: {e}")
        print(f"\nError: Failed to retrieve projects from organization {org_id}")
        print(f"Details: {e}\n")
        return 1
    
    if not projects:
        print(f"\nNo projects found in organization {org_id}\n")
        return 0
    
    logger.info(f"Found {len(projects)} project(s) to audit")
    
    # Import security check functions
    try:
        check_functions = import_security_checks()
    except Exception as e:
        logger.error(f"Failed to import security checks: {e}")
        return 1
    
    # Run audits for each project
    project_results = []
    for project in projects:
        project_id = project.get('id')
        project_name = project.get('name')
        
        try:
            proj_result = run_project_audit(
                org_client,
                project_id,
                project_name,
                config,
                check_functions
            )
            project_results.append(proj_result)
        except Exception as e:
            logger.exception(f"Failed to audit project {project_name} ({project_id})")
            project_results.append(
                ProjectAuditResult(
                    project_id=project_id,
                    project_name=project_name,
                    checks=[
                        CheckResult(
                            name="Project Audit",
                            status=CheckStatus.FAIL,
                            findings=[f"Failed to audit project: {e}"]
                        )
                    ]
                )
            )
    
    exit_code = print_organization_summary(org_id, project_results)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
