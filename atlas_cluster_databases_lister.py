#!/usr/bin/env python3
"""
MongoDB Atlas Cluster Connection URIs Lister

This script retrieves all projects from a given organization and displays
the connection URI for each cluster in every project.

Usage:
    python3 atlas_cluster_databases_lister.py

Environment variables:
    ATLAS_ORG_ID - Organization ID
    ATLAS_PUBLIC_KEY - API public key
    ATLAS_PRIVATE_KEY - API private key
"""

import sys
import os
import time
import requests
from requests.auth import HTTPDigestAuth
from urllib.parse import urljoin
import json
from dotenv import load_dotenv
import certifi

# Atlas API base URL (must end with / for urljoin to work correctly)
ATLAS_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2/"

# ANSI color codes for terminal output
class Colors:
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'


class AtlasAPIClient:
    """Client for interacting with MongoDB Atlas API."""

    RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
    
    def __init__(self, public_key: str, private_key: str, timeout: float = 30.0, max_retries: int = 2):
        """
        Initialize the Atlas API client.

        Args:
            public_key: Atlas API public key
            private_key: Atlas API private key
            timeout: Request timeout in seconds
            max_retries: Number of retries for transient request failures
        """
        self.public_key = public_key
        self.private_key = private_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        # MongoDB Atlas API requires digest authentication
        self.session.auth = HTTPDigestAuth(public_key, private_key)
    
    def _make_request(self, endpoint: str, method: str = "GET") -> dict:
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

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    verify=certifi.where(),
                    timeout=self.timeout,
                )

                if response.status_code in self.RETRY_STATUS_CODES and attempt < self.max_retries:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        delay = float(retry_after) if retry_after else 2 ** attempt
                    except ValueError:
                        delay = 2 ** attempt
                    time.sleep(delay)
                    continue

                response.raise_for_status()

                # Some endpoints return 204 No Content
                if response.status_code == 204:
                    return {}

                return response.json()

            except requests.exceptions.HTTPError as e:
                raise Exception(f"Atlas API Error: {e.response.status_code} - {e.response.text}")
            except requests.exceptions.RequestException as e:
                if attempt >= self.max_retries:
                    raise Exception(f"Request Error: {str(e)}")
                time.sleep(2 ** attempt)

        raise Exception("Request Error: exhausted retries")
    
    def get_projects(self, org_id: str) -> list[dict]:
        """
        Get all projects in an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of project dictionaries belonging to the organization
        """
        # Use the org-scoped endpoint to avoid fetching all accessible projects
        # and to correctly handle pagination beyond 100 results.
        results = []
        page_num = 1
        page_size = 100
        while True:
            endpoint = f"orgs/{org_id}/groups?pageNum={page_num}&itemsPerPage={page_size}"
            response = self._make_request(endpoint)
            page_results = response.get("results", [])
            results.extend(page_results)
            total_count = response.get("totalCount", 0)
            if len(results) >= total_count:
                break
            page_num += 1
        return results
    
    def get_clusters(self, project_id: str) -> list[dict]:
        """
        Get all clusters for a project (all pages).

        Args:
            project_id: Project ID

        Returns:
            List of cluster dictionaries
        """
        results = []
        page_num = 1
        page_size = 100
        while True:
            endpoint = f"groups/{project_id}/clusters?pageNum={page_num}&itemsPerPage={page_size}"
            response = self._make_request(endpoint)
            page_results = response.get("results", [])
            results.extend(page_results)
            total_count = response.get("totalCount", 0)
            if len(results) >= total_count:
                break
            page_num += 1
        return results
    



def print_results(results: dict[str, dict[str, str]]):
    """
    Print formatted results showing connection URIs for each cluster.

    Args:
        results: Dictionary mapping project names to clusters and their URIs
                 Structure: {project_name: {cluster_name: connection_uri}}
    """
    print(f"\n{Colors.BOLD}{'='*80}")
    print(f"MongoDB Atlas Cluster Connection URIs")
    print(f"{'='*80}{Colors.RESET}\n")

    if not results:
        print(f"{Colors.YELLOW}No projects found.{Colors.RESET}")
        return

    total_projects = 0
    total_clusters = 0

    # Calculate totals
    for project_data in results.values():
        total_projects += 1
        total_clusters += len(project_data)

    print(f"{Colors.BLUE}Summary:{Colors.RESET}")
    print(f"  Total Projects: {total_projects}")
    print(f"  Total Clusters: {total_clusters}\n")

    # Print detailed results
    for project_name, clusters_data in sorted(results.items()):
        print(f"{Colors.BOLD}{Colors.CYAN}📦 Project: {project_name}{Colors.RESET}")
        
        if not clusters_data:
            print(f"  {Colors.YELLOW}(no clusters found){Colors.RESET}\n")
            continue
        
        for idx, (cluster_name, uri) in enumerate(sorted(clusters_data.items())):
            is_last = idx == len(clusters_data) - 1
            prefix = "└─" if is_last else "├─"
            print(f"  {Colors.BLUE}{prefix}{Colors.RESET} {Colors.BOLD}{cluster_name}{Colors.RESET}")
            print(f"  {Colors.BLUE}{'   ' if is_last else '│  '}{Colors.GREEN}{uri}{Colors.RESET}\n")


def main():
    """Main entry point."""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get credentials from arguments or environment variables
    org_id = None
    public_key = None
    private_key = None
    
    if len(sys.argv) == 2:
        org_id = sys.argv[1]
        public_key = os.getenv("ATLAS_PUBLIC_KEY")
        private_key = os.getenv("ATLAS_PRIVATE_KEY")
    elif len(sys.argv) > 1:
        print(f"{Colors.RED}Error: Pass API keys through environment variables, not command-line arguments.{Colors.RESET}")
        sys.exit(1)
    else:
        org_id = os.getenv("ATLAS_ORG_ID")
        public_key = os.getenv("ATLAS_PUBLIC_KEY")
        private_key = os.getenv("ATLAS_PRIVATE_KEY")
    
    # Validate credentials
    if not all([org_id, public_key, private_key]):
        print(f"{Colors.RED}Error: Missing credentials{Colors.RESET}")
        print("\nUsage:")
        print("  python3 atlas_cluster_databases_lister.py")
        print("  python3 atlas_cluster_databases_lister.py <ORG_ID>")
        print("\nSet environment variables:")
        print("  ATLAS_ORG_ID")
        print("  ATLAS_PUBLIC_KEY")
        print("  ATLAS_PRIVATE_KEY")
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
        
        print(f"{Colors.BLUE}Retrieving clusters and connection URIs...{Colors.RESET}\n")
        
        for project in projects:
            project_id = project["id"]
            project_name = project["name"]
            
            try:
                print(f"  Processing: {project_name}...", end=" ", flush=True)
                clusters = client.get_clusters(project_id)
                
                # Build results with cluster URIs
                clusters_data = {}
                for cluster in clusters:
                    cluster_name = cluster["name"]
                    # Extract the standard connection string
                    connection_strings = cluster.get("connectionStrings", {})
                    uri = connection_strings.get("standard", "N/A")
                    clusters_data[cluster_name] = uri
                
                results[project_name] = clusters_data
                print("✓")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
                results[project_name] = {}
        
        # Print formatted results
        print_results(results)
        
        # Output JSON summary to file
        json_output = {
            "organization_id": org_id,
            "projects": {}
        }
        
        for project_name, clusters_data in results.items():
            project_summary = {
                "clusters": {}
            }
            
            for cluster_name, uri in clusters_data.items():
                project_summary["clusters"][cluster_name] = {
                    "connection_uri": uri
                }
            
            project_summary["total_clusters"] = len(clusters_data)
            json_output["projects"][project_name] = project_summary
        
        with open("cluster_uris.json", "w") as f:
            json.dump(json_output, f, indent=2)
        
        print(f"{Colors.BLUE}✓ Results saved to: cluster_uris.json{Colors.RESET}\n")
    
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
