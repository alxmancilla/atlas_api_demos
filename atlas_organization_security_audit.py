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
import logging
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any
from dotenv import load_dotenv

from atlas_security_auditor import (
    AtlasAPIError,
    AtlasClient,
    CheckResult,
    CheckStatus,
    check_alerts,
    check_auditing,
    check_database_users,
    check_encryption_at_rest,
    check_ip_access_list,
    check_private_endpoints,
    check_tls_minimum_version,
)


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ProjectAuditResult:
    """Result of auditing a single project."""
    project_id: str
    project_name: str
    checks: list[CheckResult] = field(default_factory=list)
    
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

def get_organization_projects(client: AtlasClient, org_id: str) -> list[dict[str, Any]]:
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
    """Return security check functions from the project-level auditor.
    
    Returns:
        Dictionary mapping check names to their functions
    """
    return {
        'check_ip_access_list': check_ip_access_list,
        'check_database_users': check_database_users,
        'check_tls_minimum_version': check_tls_minimum_version,
        'check_encryption_at_rest': check_encryption_at_rest,
        'check_auditing': check_auditing,
        'check_alerts': check_alerts,
        'check_private_endpoints': check_private_endpoints,
    }


def run_project_audit(
    client: AtlasClient,
    project_id: str,
    project_name: str,
    config: dict[str, str],
    check_functions: dict[str, Callable[[AtlasClient, dict[str, str]], CheckResult]]
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
        project_id,
        dry_run=client.dry_run,
        timeout=client.timeout,
        max_retries=client.max_retries,
    )
    
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


def print_organization_summary(org_id: str, project_results: list[ProjectAuditResult]) -> int:
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
        projects_with_issues = sum(
            1 for pr in project_results
            if pr.overall_status() in {CheckStatus.FAIL, CheckStatus.WARN}
        )
        print(
            f"✗ {projects_with_issues} project(s) have issues requiring attention".center(100)
        )
        exit_code = 1
    
    print("=" * 100 + "\n")
    
    return exit_code


def load_config() -> dict[str, Any]:
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
    config['DRY_RUN'] = os.getenv('DRY_RUN', 'true').lower() == 'true'
    
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
