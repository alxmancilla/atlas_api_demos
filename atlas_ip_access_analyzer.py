#!/usr/bin/env python3
"""
MongoDB Atlas IP Access List Analyzer

This script retrieves all projects from a given organization and displays
all authorized IP addresses/CIDR blocks in each project's IP access list.
It highlights when 0.0.0.0/0 (open to the internet) is included.

Usage:
    python atlas_ip_access_analyzer.py <ORG_ID> <API_PUBLIC_KEY> <API_PRIVATE_KEY>

Environment variables:
    ATLAS_ORG_ID - Organization ID
    ATLAS_API_PUBLIC_KEY - API public key
    ATLAS_API_PRIVATE_KEY - API private key
"""

import sys
import os
import requests
from requests.auth import HTTPDigestAuth
from typing import Dict, List, Tuple
from urllib.parse import urljoin
import json
from dotenv import load_dotenv

# Atlas API base URL (must end with / for urljoin to work correctly)
ATLAS_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2/"

# ANSI color codes for terminal output
class Colors:
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


class AtlasAPIClient:
    """Client for interacting with MongoDB Atlas API."""
    
    def __init__(self, public_key: str, private_key: str):
        """
        Initialize the Atlas API client.

        Args:
            public_key: Atlas API public key
            private_key: Atlas API private key
        """
        self.public_key = public_key
        self.private_key = private_key
        self.session = requests.Session()
        # MongoDB Atlas API requires digest authentication
        self.session.auth = HTTPDigestAuth(public_key, private_key)
    
    def _make_request(self, endpoint: str, method: str = "GET") -> Dict:
        """
        Make an authenticated request to the Atlas API.

        Args:
            endpoint: API endpoint (relative to base URL)
            method: HTTP method (GET, POST, etc.)

        Returns:
            Response JSON as dictionary

        Raises:
            Exception: If API request fails
        """
        url = urljoin(ATLAS_BASE_URL, endpoint)

        # Add Accept header with API version as per MongoDB Atlas API v2 documentation
        headers = {
            "Accept": "application/vnd.atlas.2025-03-12+json"
        }

        try:
            response = self.session.request(method, url, headers=headers)
            response.raise_for_status()

            # Some endpoints return 204 No Content
            if response.status_code == 204:
                return {}

            return response.json()

        except requests.exceptions.HTTPError as e:
            raise Exception(f"Atlas API Error: {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request Error: {str(e)}")
    
    def get_projects(self, org_id: str) -> List[Dict]:
        """
        Get all projects in an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of project dictionaries filtered by organization
        """
        # Use the endpoint pattern from MongoDB Atlas API v2 documentation
        endpoint = "groups?pretty=true"
        response = self._make_request(endpoint)
        all_projects = response.get("results", [])

        # Filter projects by organization ID since the API doesn't support orgId query parameter
        return [project for project in all_projects if project.get("orgId") == org_id]
    
    def get_ip_access_list(self, project_id: str) -> List[Dict]:
        """
        Get the IP access list for a project.
        
        Args:
            project_id: Project ID
        
        Returns:
            List of IP access list entry dictionaries
        """
        endpoint = f"groups/{project_id}/accessList"
        response = self._make_request(endpoint)
        return response.get("results", [])


def analyze_ip_entries(entries: List[Dict]) -> Tuple[List[str], bool]:
    """
    Analyze IP access list entries.
    
    Args:
        entries: List of IP access list entries
    
    Returns:
        Tuple of (ip_list, has_open_internet)
        - ip_list: List of IP/CIDR strings
        - has_open_internet: True if 0.0.0.0/0 is present
    """
    ips = []
    has_open_internet = False
    
    for entry in entries:
        if "cidrBlock" in entry:
            ip = entry["cidrBlock"]
            ips.append(ip)
            if ip == "0.0.0.0/0":
                has_open_internet = True
        elif "ipAddress" in entry:
            ip = entry["ipAddress"]
            ips.append(ip)
            if ip == "0.0.0.0":
                has_open_internet = True
    
    return sorted(ips), has_open_internet


def print_security_summary(results: Dict[str, Tuple[List[str], bool]]):
    """
    Print a final security summary report of projects with open internet access.

    Args:
        results: Dictionary mapping project names to (ip_list, has_open_internet)
    """
    # Collect projects with open internet access
    open_projects = []
    for project_name, (ips, has_open_internet) in sorted(results.items()):
        if has_open_internet:
            # Find which specific entries are open
            open_entries = [ip for ip in ips if ip in ["0.0.0.0/0", "0.0.0.0"]]
            open_projects.append((project_name, open_entries))

    if not open_projects:
        print(f"{Colors.BOLD}{'='*80}")
        print(f"🎉 SECURITY SUMMARY: ALL CLEAR")
        print(f"{'='*80}{Colors.RESET}\n")
        print(f"{Colors.GREEN}✓ No projects found with open internet access (0.0.0.0/0 or 0.0.0.0){Colors.RESET}\n")
        print(f"{Colors.GREEN}All projects have proper IP access restrictions configured.{Colors.RESET}\n")
    else:
        print(f"{Colors.BOLD}{'='*80}")
        print(f"⚠️  SECURITY SUMMARY: OPEN INTERNET ACCESS DETECTED")
        print(f"{'='*80}{Colors.RESET}\n")
        print(f"{Colors.RED}{Colors.BOLD}WARNING: The following {len(open_projects)} project(s) have open internet access:{Colors.RESET}\n")

        for idx, (project_name, open_entries) in enumerate(open_projects, 1):
            print(f"{Colors.RED}{idx}. {Colors.BOLD}{project_name}{Colors.RESET}")
            for entry in open_entries:
                entry_type = "CIDR block" if "/" in entry else "IP address"
                print(f"   {Colors.RED}└─ {entry} ({entry_type}){Colors.RESET}")
            print()

        print(f"{Colors.YELLOW}RECOMMENDATION:{Colors.RESET}")
        print(f"  • Review and restrict IP access to specific IP addresses or CIDR blocks")
        print(f"  • Remove 0.0.0.0/0 and 0.0.0.0 entries from production environments")
        print(f"  • Use VPN or bastion hosts for secure database access")
        print(f"  • Regularly audit IP access lists for compliance\n")


def print_results(results: Dict[str, Tuple[List[str], bool]]):
    """
    Print formatted results.

    Args:
        results: Dictionary mapping project names to (ip_list, has_open_internet)
    """
    print(f"\n{Colors.BOLD}{'='*80}")
    print(f"MongoDB Atlas IP Access List Analysis")
    print(f"{'='*80}{Colors.RESET}\n")

    if not results:
        print(f"{Colors.YELLOW}No projects found.{Colors.RESET}")
        return

    total_projects = len(results)
    open_internet_projects = sum(1 for _, (_, has_open) in results.items() if has_open)

    print(f"{Colors.BLUE}Summary:{Colors.RESET}")
    print(f"  Total Projects: {total_projects}")
    print(f"  Projects with 0.0.0.0/0: {Colors.RED}{open_internet_projects}{Colors.RESET}\n")

    for project_name, (ips, has_open_internet) in sorted(results.items()):
        status_icon = f"{Colors.RED}⚠️  OPEN{Colors.RESET}" if has_open_internet else f"{Colors.GREEN}✓{Colors.RESET}"

        print(f"{Colors.BOLD}{project_name}{Colors.RESET} {status_icon}")
        print(f"{Colors.BLUE}IP Access List:{Colors.RESET}")

        if not ips:
            print(f"  {Colors.YELLOW}(empty - no IP restrictions){Colors.RESET}")
        else:
            for ip in ips:
                if ip in ["0.0.0.0/0", "0.0.0.0"]:
                    print(f"  {Colors.RED}{ip} {Colors.BOLD}← OPEN TO INTERNET{Colors.RESET}")
                else:
                    print(f"  {ip}")

        print()

    # Print final security summary report
    print_security_summary(results)


def main():
    """Load environment variables from .env file"""
    load_dotenv()
    
    # "Main entry point."""
    # Get credentials from arguments or environment variables
    org_id = None
    public_key = None
    private_key = None
    
    if len(sys.argv) == 4:
        org_id = sys.argv[1]
        public_key = sys.argv[2]
        private_key = sys.argv[3]
    else:
        org_id = os.getenv("ATLAS_ORG_ID")
        public_key = os.getenv("ATLAS_API_PUBLIC_KEY")
        private_key = os.getenv("ATLAS_API_PRIVATE_KEY")
    
    # Validate credentials
    if not all([org_id, public_key, private_key]):
        print(f"{Colors.RED}Error: Missing credentials{Colors.RESET}")
        print("\nUsage:")
        print("  python atlas_ip_access_analyzer.py <ORG_ID> <API_PUBLIC_KEY> <API_PRIVATE_KEY>")
        print("\nOr set environment variables:")
        print("  ATLAS_ORG_ID")
        print("  ATLAS_API_PUBLIC_KEY")
        print("  ATLAS_API_PRIVATE_KEY")
        sys.exit(1)
    
    try:
        # Initialize API client
        client = AtlasAPIClient(public_key, private_key)
        
        print(f"\n{Colors.BLUE}Fetching projects from organization {org_id}...{Colors.RESET}")
        projects = client.get_projects(org_id)
        
        if not projects:
            print(f"{Colors.YELLOW}No projects found in organization.{Colors.RESET}")
            sys.exit(0)
        
        print(f"Found {len(projects)} project(s)")
        
        # Collect results
        results = {}
        
        print(f"{Colors.BLUE}Retrieving IP access lists...{Colors.RESET}\n")
        
        for project in projects:
            project_id = project["id"]
            project_name = project["name"]
            
            try:
                print(f"  Processing: {project_name}...", end=" ", flush=True)
                ip_entries = client.get_ip_access_list(project_id)
                ips, has_open = analyze_ip_entries(ip_entries)
                results[project_name] = (ips, has_open)
                print("✓")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
                results[project_name] = ([], False)
        
        # Print formatted results
        print_results(results)
        
        # Output JSON summary to file
        json_output = {
            "organization_id": org_id,
            "projects": {}
        }
        
        for project_name, (ips, has_open) in results.items():
            json_output["projects"][project_name] = {
                "ip_access_list": ips,
                "has_0_0_0_0": has_open,
                "entry_count": len(ips)
            }
        
        with open("ip_access_analysis.json", "w") as f:
            json.dump(json_output, f, indent=2)
        
        print(f"{Colors.BLUE}✓ Results saved to: ip_access_analysis.json{Colors.RESET}\n")
    
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
