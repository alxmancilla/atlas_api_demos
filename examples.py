#!/usr/bin/env python3
"""
Example usage of the Atlas IP Access Analyzer script.

This file demonstrates different ways to use the analyzer in your own code.
"""

from atlas_ip_access_analyzer import AtlasAPIClient, analyze_ip_entries, print_results


def example_1_command_line():
    """Example: Using the analyzer as a command-line tool (see README)"""
    print("Example 1: Command-line usage")
    print("=" * 60)
    print("""
    python atlas_ip_access_analyzer.py <ORG_ID> <PUBLIC_KEY> <PRIVATE_KEY>
    """)


def example_2_programmatic_usage():
    """Example: Using the analyzer programmatically in Python"""
    print("\nExample 2: Programmatic usage")
    print("=" * 60)
    
    # Initialize the API client
    client = AtlasAPIClient(
        public_key="your_public_key",
        private_key="your_private_key"
    )
    
    org_id = "your_organization_id"
    
    # Get all projects
    projects = client.get_projects(org_id)
    print(f"Found {len(projects)} projects")
    
    # Analyze each project
    results = {}
    for project in projects:
        project_id = project["id"]
        project_name = project["name"]
        
        # Get IP access list
        ip_entries = client.get_ip_access_list(project_id)
        
        # Analyze entries
        ips, has_open_internet = analyze_ip_entries(ip_entries)
        
        results[project_name] = (ips, has_open_internet)
        
        print(f"\nProject: {project_name}")
        print(f"  IP Count: {len(ips)}")
        print(f"  Open to Internet: {has_open_internet}")
    
    # Print formatted results
    print_results(results)


def example_3_filtering_open_projects():
    """Example: Finding and reporting only open projects"""
    print("\nExample 3: Filter and report only open projects")
    print("=" * 60)
    
    client = AtlasAPIClient(
        public_key="your_public_key",
        private_key="your_private_key"
    )
    
    org_id = "your_organization_id"
    projects = client.get_projects(org_id)
    
    # Find projects with 0.0.0.0/0
    open_projects = []
    
    for project in projects:
        ip_entries = client.get_ip_access_list(project["id"])
        ips, has_open = analyze_ip_entries(ip_entries)
        
        if has_open:
            open_projects.append({
                "name": project["name"],
                "id": project["id"],
                "ips": ips
            })
    
    print(f"\nFound {len(open_projects)} projects open to the internet:\n")
    for proj in open_projects:
        print(f"  - {proj['name']} (ID: {proj['id']})")
        print(f"    IPs: {', '.join(proj['ips'])}\n")


def example_4_export_csv():
    """Example: Export results to CSV format"""
    print("\nExample 4: Export to CSV")
    print("=" * 60)
    
    import csv
    
    client = AtlasAPIClient(
        public_key="your_public_key",
        private_key="your_private_key"
    )
    
    org_id = "your_organization_id"
    projects = client.get_projects(org_id)
    
    # Export to CSV
    with open("ip_access_list.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Project", "IP Address", "Open to Internet"])
        
        for project in projects:
            ip_entries = client.get_ip_access_list(project["id"])
            ips, has_open = analyze_ip_entries(ip_entries)
            
            if not ips:
                writer.writerow([project["name"], "N/A", "N/A"])
            else:
                for ip in ips:
                    is_open = "Yes" if ip in ["0.0.0.0/0", "0.0.0.0"] else "No"
                    writer.writerow([project["name"], ip, is_open])
    
    print("Results exported to: ip_access_list.csv")


def example_5_generate_html_report():
    """Example: Generate an HTML report"""
    print("\nExample 5: Generate HTML report")
    print("=" * 60)
    
    client = AtlasAPIClient(
        public_key="your_public_key",
        private_key="your_private_key"
    )
    
    org_id = "your_organization_id"
    projects = client.get_projects(org_id)
    
    html_content = """
    <html>
    <head>
        <title>MongoDB Atlas IP Access List Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #13aa52; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #13aa52; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .open { background-color: #ffcccc; color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>MongoDB Atlas IP Access List Report</h1>
        <p>Generated for organization: {org_id}</p>
        <table>
            <tr>
                <th>Project</th>
                <th>IP Address</th>
                <th>Status</th>
            </tr>
    """.format(org_id=org_id)
    
    for project in projects:
        ip_entries = client.get_ip_access_list(project["id"])
        ips, has_open = analyze_ip_entries(ip_entries)
        
        if not ips:
            ips = ["(empty - no restrictions)"]
        
        for ip in ips:
            is_open = "0.0.0.0/0" in ip or ip == "0.0.0.0"
            status_class = "open" if is_open else ""
            status_text = "⚠️ OPEN" if is_open else "✓ Restricted"
            
            html_content += f"""
            <tr>
                <td>{project['name']}</td>
                <td>{ip}</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
            """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open("ip_access_report.html", "w") as f:
        f.write(html_content)
    
    print("HTML report generated: ip_access_report.html")


if __name__ == "__main__":
    print("MongoDB Atlas IP Access Analyzer - Usage Examples")
    print("=" * 60)
    
    # Show examples (don't execute as they need real credentials)
    example_1_command_line()
    print("\nNote: The following examples show how to use the analyzer")
    print("programmatically. They require valid credentials to run.\n")
    print("""
example_2_programmatic_usage()      # Basic usage
example_3_filtering_open_projects() # Find risky projects
example_4_export_csv()              # Export to CSV
example_5_generate_html_report()    # Generate HTML report
    """)
