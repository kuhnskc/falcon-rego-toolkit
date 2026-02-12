#!/usr/bin/env python3
"""
🛠️  CrowdStrike Custom IOM (Indicators of Misconfiguration) Toolkit

A comprehensive, user-friendly toolkit for managing Custom IOMs in CrowdStrike CSPM.

Features:
- 📋 List and view existing custom policies
- ✏️  Update existing policies
- 🗑️  Delete policies
- ➕ Create new custom policies
- 🔍 Test policies against real resources
- 🌐 Discover cloud resources with enriched data

Usage:
    python custom_iom_toolkit.py
"""

import json
import os
import sys
import tempfile
import subprocess
from datetime import datetime
from typing import List, Dict, Optional
import requests

# Configuration
DEFAULT_BASE_URL = "https://api.crowdstrike.com"
API_TIMEOUT = 30

# CrowdStrike Cloud Environment URLs
CROWDSTRIKE_CLOUDS = {
    "US-1": "https://api.crowdstrike.com",
    "US-2": "https://api.us-2.crowdstrike.com",
    "EU-1": "https://api.eu-1.crowdstrike.com",
    "US-GOV-1": "https://api.laggar.gcw.crowdstrike.com",
    "US-GOV-2": "https://api.govcloud-us-east-1.crowdstrike.com"
}

def determine_cloud_provider_from_resource_type(resource_type):
    """
    Dynamically determine cloud provider and platform from resource type.
    Replaces hardcoded AWS values with dynamic detection.
    """
    if not resource_type:
        return {"platform": "AWS", "provider": "AWS"}  # Default fallback

    # GCP/Google Cloud Platform
    if "googleapis.com" in resource_type.lower():
        return {"platform": "GCP", "provider": "GCP"}

    # AWS
    if resource_type.startswith("AWS::"):
        return {"platform": "AWS", "provider": "AWS"}

    # Azure/Microsoft
    if resource_type.startswith("Microsoft."):
        return {"platform": "Azure", "provider": "Azure"}

    # Kubernetes (could be any cloud)
    if "kubernetes" in resource_type.lower():
        return {"platform": "Kubernetes", "provider": "Kubernetes"}

    # Default to AWS for unknown types (maintaining backward compatibility)
    return {"platform": "AWS", "provider": "AWS"}

class Colors:
    """ANSI color codes for pretty output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}")
    print(f"  {text}")
    print(f"{'=' * 80}{Colors.ENDC}")

def print_subheader(text: str):
    """Print a formatted subheader"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{text}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'-' * len(text)}{Colors.ENDC}")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}SUCCESS: {text}{Colors.ENDC}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}ERROR: {text}{Colors.ENDC}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}WARNING: {text}{Colors.ENDC}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}INFO: {text}{Colors.ENDC}")

def convert_processed_to_pipe_format(processed_text: str) -> str:
    """
    Convert API processed format back to pipe-separated format for editing
    Handles both alert format: "1. Point 1\n2. Point 2" → "Point 1|Point 2"
    And remediation format: "Step 1. Point 1\nStep 2. Point 2" → "Point 1|Point 2"
    """
    if not processed_text:
        return ""

    # Split by lines and extract content after numbering
    lines = processed_text.strip().split('\n')
    extracted_points = []

    for line in lines:
        line = line.strip()
        if line:
            # Remove multiple numbering patterns:
            # 1. Basic numbered format: "1. text", "2. text", etc.
            # 2. Step format: "Step 1. text", "Step 2. text", etc.
            # 3. Handle duplicated patterns like "Step 1. Step 1. text"

            import re
            cleaned_line = line

            # First remove any "Step X. " patterns (including duplicates)
            cleaned_line = re.sub(r'^(Step \d+\.\s*)+', '', cleaned_line)

            # Then remove any basic "X. " patterns (including duplicates)
            cleaned_line = re.sub(r'^(\d+\.\s*)+', '', cleaned_line)

            # Clean up any remaining whitespace
            cleaned_line = cleaned_line.strip()

            if cleaned_line:
                extracted_points.append(cleaned_line)

    # Join with pipe separator
    return '|'.join(extracted_points)

def clean_remediation_format(remediation_text: str) -> str:
    """Convert API's processed remediation format back to clean pipe-separated format"""
    # Use the robust conversion function that handles all numbering patterns
    return convert_processed_to_pipe_format(remediation_text)

def format_rule_card(rule: Dict, index: int = None) -> str:
    """Format a rule as a nice card"""
    card = []

    if index:
        card.append(f"{Colors.BOLD}{Colors.BLUE}┌─ Rule #{index}: {rule.get('name', 'Unnamed')} {Colors.ENDC}")
    else:
        card.append(f"{Colors.BOLD}{Colors.BLUE}┌─ {rule.get('name', 'Unnamed')} {Colors.ENDC}")

    card.append(f"{Colors.BLUE}│{Colors.ENDC}")
    card.append(f"{Colors.BLUE}│{Colors.ENDC} UUID: {Colors.CYAN}{rule.get('uuid', 'N/A')}{Colors.ENDC}")
    card.append(f"{Colors.BLUE}│{Colors.ENDC} Description: {rule.get('description', 'No description')[:80]}...")

    resource_types = rule.get('resource_types', [])
    if resource_types and isinstance(resource_types, list) and len(resource_types) > 0:
        resource_type = resource_types[0].get('resource_type', 'Unknown')
        service = resource_types[0].get('service', 'Unknown')
        card.append(f"{Colors.BLUE}│{Colors.ENDC} Resource: {Colors.YELLOW}{resource_type}{Colors.ENDC} ({service})")

    severity_colors = {0: Colors.RED, 1: Colors.RED, 2: Colors.YELLOW, 3: Colors.GREEN}
    severity_labels = {0: "Critical", 1: "High", 2: "Medium", 3: "Informational"}
    severity = rule.get('severity', 3)
    color = severity_colors.get(severity, Colors.CYAN)
    label = severity_labels.get(severity, "Unknown")

    card.append(f"{Colors.BLUE}│{Colors.ENDC} Severity: {color}{label} ({severity}){Colors.ENDC}")
    card.append(f"{Colors.BLUE}│{Colors.ENDC} Created: {rule.get('created_at', 'N/A')[:19]}")
    card.append(f"{Colors.BLUE}│{Colors.ENDC} Updated: {rule.get('updated_at', 'Never')[:19] if rule.get('updated_at') else 'Never'}")

    # Add Rego logic display
    rego_logic = get_rego_logic(rule)
    if rego_logic:
        # Show first 2 lines of Rego code as preview
        rego_lines = rego_logic.split('\n')
        preview = rego_lines[0][:60] + "..." if len(rego_lines[0]) > 60 else rego_lines[0]
        if len(rego_lines) > 1:
            preview += f" ({len(rego_lines)} lines total)"
        card.append(f"{Colors.BLUE}│{Colors.ENDC} Rego Logic: {Colors.HEADER}{preview}{Colors.ENDC}")
    else:
        card.append(f"{Colors.BLUE}│{Colors.ENDC} Rego Logic: {Colors.RED}Not available{Colors.ENDC}")

    card.append(f"{Colors.BLUE}└{'─' * 78}{Colors.ENDC}")

    return "\n".join(card)

def get_rego_logic(rule: Dict) -> str:
    """Extract Rego logic from rule object"""
    # Check rule_logic_list first (newer format)
    if rule.get('rule_logic_list') and len(rule['rule_logic_list']) > 0:
        return rule['rule_logic_list'][0].get('logic', '')

    # Fall back to direct logic field
    return rule.get('logic', '')

def display_full_rego_logic(rule: Dict):
    """Display the complete Rego logic for a rule"""
    rego_logic = get_rego_logic(rule)

    if not rego_logic:
        print_warning("No Rego logic found for this policy")
        return

    print_subheader(f"Rego Logic for: {rule.get('name', 'Unnamed')}")
    print(f"{Colors.CYAN}Complete Rego Code:{Colors.ENDC}")
    print("─" * 60)
    print(f"{Colors.HEADER}{rego_logic}{Colors.ENDC}")
    print("─" * 60)
    print(f"{Colors.CYAN}This is the current policy logic. You can copy and modify it.{Colors.ENDC}")

def get_editor_command():
    """Get the user's preferred text editor"""
    # Try environment variable first
    editor = os.getenv('EDITOR')
    if editor:
        return editor

    # Try common editors in order of preference
    editors = ['code', 'vim', 'vi', 'nano', 'emacs']
    for ed in editors:
        try:
            # Check if editor is available
            subprocess.run(['which', ed], capture_output=True, check=True)
            return ed
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    # Fallback to system default
    return 'vi'

def edit_rego_policy(initial_content: str = "") -> str:
    """Open a text editor to edit Rego policy content"""
    editor = get_editor_command()

    # Create a temporary file with .rego extension for syntax highlighting
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
        temp_file = f.name
        if initial_content:
            f.write(initial_content)
        else:
            # Write a template if no initial content
            f.write("""package crowdstrike

# Default result - required by CrowdStrike CSPM
default result = "fail"

# This rule applies to specific resource types
is_applicable if {
    input.resource_type == "AWS::YourResourceType"
}

# Your policy logic here - return "pass" if compliant
result = "pass" if {
    is_applicable
    # Add your compliance conditions here
    # Example: input.configuration.some_field == "good_value"
}

# Alternative: Use deny rules that return "fail" with details
result = "fail" if {
    is_applicable
    # Add your violation conditions here
    # This will automatically fail when conditions are met
}
""")

    try:
        print_info(f"Opening {editor} to edit Rego policy...")
        print_info("💡 Save and close the editor when you're done")

        # Store initial modification time to detect changes
        initial_mtime = os.path.getmtime(temp_file)

        # Handle editors that fork (like VS Code)
        editor_cmd = [editor, temp_file]
        if editor == 'code':
            # VS Code: use --wait flag to block until file is closed
            editor_cmd = ['code', '--wait', temp_file]
        elif editor in ['subl', 'sublime']:
            # Sublime Text: use --wait flag
            editor_cmd = [editor, '--wait', temp_file]

        # Open the editor and wait for it to close
        subprocess.run(editor_cmd, check=True)

        # Double-check file was modified if using a potentially forking editor
        final_mtime = os.path.getmtime(temp_file)
        if final_mtime == initial_mtime and editor in ['code', 'subl', 'sublime']:
            print_warning("File doesn't appear to have been modified. Did you save your changes?")
            retry = input(f"{Colors.BOLD}Continue anyway? (y/N): {Colors.ENDC}")
            if retry.lower() != 'y':
                return ""

        # Read the content back
        with open(temp_file, 'r') as f:
            content = f.read().strip()

        return content

    except subprocess.CalledProcessError:
        print_error(f"Failed to open editor: {editor}")
        return ""
    except KeyboardInterrupt:
        print_warning("Editor interrupted by user")
        return ""
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_file)
        except OSError:
            pass

def edit_alert_remediation_info(current_alert: str = "", current_remediation: str = "") -> tuple:
    """Open a text editor to edit alert and remediation information"""
    editor = get_editor_command()

    # Convert current API-processed format back to clean pipe-separated format for editing
    current_alert_clean = ""
    current_remediation_clean = ""

    if current_alert:
        # Use the robust conversion function to handle API numbering
        current_alert_clean = convert_processed_to_pipe_format(current_alert)

    if current_remediation:
        # Use the robust conversion function to handle API numbering
        current_remediation_clean = convert_processed_to_pipe_format(current_remediation)

    # Create initial content with current values or template
    if current_alert_clean or current_remediation_clean:
        initial_content = f"""# ═══════════════════════════════════════════════════════════════════
# CROWDSTRIKE CSPM POLICY ALERT & REMEDIATION EDITOR
# ═══════════════════════════════════════════════════════════════════
#
# ✅ FORMAT CONFIRMED WORKING: Use PIPE-SEPARATED format (| symbol)
#
# HOW IT WORKS:
# - Separate each step/point with the pipe symbol: |
# - CrowdStrike automatically adds numbering in the console
# - Each item between pipes becomes a separate numbered line
#
# EXAMPLE:
#   Input:  "First point|Second point|Third point"
#   Output: 1. First point
#           2. Second point
#           3. Third point
# ═══════════════════════════════════════════════════════════════════

# ALERT MESSAGE
# What does this policy detect? Why does it matter?
# Use pipe (|) to separate different points - each becomes a numbered item
{current_alert_clean if current_alert_clean else "ECR cross-account access violation detected|Unauthorized external account found in registry policy|Security compliance breach identified|Immediate remediation required"}

# REMEDIATION STEPS
# How to fix this issue? Provide clear step-by-step instructions
# Use pipe (|) to separate each step - each becomes "Step 1.", "Step 2.", etc.
{current_remediation_clean if current_remediation_clean else "Navigate to AWS ECR console and locate the affected repository|Click on the repository name to access repository settings|Go to the Permissions tab and review the current policy|Remove unauthorized account IDs from the policy document|Update the policy to include only whitelisted accounts|Save changes and verify unauthorized access is blocked|Document the remediation action for compliance records"}
"""
    else:
        initial_content = """# ═══════════════════════════════════════════════════════════════════
# CROWDSTRIKE CSPM POLICY ALERT & REMEDIATION EDITOR
# ═══════════════════════════════════════════════════════════════════
#
# ✅ FORMAT CONFIRMED WORKING: Use PIPE-SEPARATED format (| symbol)
#
# HOW IT WORKS:
# - Separate each step/point with the pipe symbol: |
# - CrowdStrike automatically adds numbering in the console
# - Each item between pipes becomes a separate numbered line
#
# EXAMPLE:
#   Input:  "First point|Second point|Third point"
#   Output: 1. First point
#           2. Second point
#           3. Third point
# ═══════════════════════════════════════════════════════════════════

# ALERT MESSAGE
# What does this policy detect? Why does it matter?
# Use pipe (|) to separate different points - each becomes a numbered item
Security policy violation detected|Configuration does not meet compliance requirements|Immediate attention required

# REMEDIATION STEPS
# How to fix this issue? Provide clear step-by-step instructions
# Use pipe (|) to separate each step - each becomes "Step 1.", "Step 2.", etc.
Access the cloud console and navigate to the affected resource|Review the current configuration settings and identify the issue|Update the configuration to meet security requirements|Test the changes to ensure they work correctly|Document the remediation for compliance records
"""

    # Create a temporary file with .txt extension
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        temp_file = f.name
        f.write(initial_content)

    try:
        print_info(f"Opening {editor} to edit alert & remediation info...")
        print_info("Use PIPE-SEPARATED format: 'Point 1|Point 2|Point 3'")
        print_info("CrowdStrike will automatically number each section")
        print_info("Save and close the editor when finished")

        # Store initial modification time to detect changes
        initial_mtime = os.path.getmtime(temp_file)

        # Handle editors that fork (like VS Code)
        editor_cmd = [editor, temp_file]
        if editor == 'code':
            editor_cmd = ['code', '--wait', temp_file]
        elif editor in ['subl', 'sublime']:
            editor_cmd = [editor, '--wait', temp_file]

        # Open the editor and wait for it to close
        subprocess.run(editor_cmd, check=True)

        # Double-check file was modified if using a potentially forking editor
        final_mtime = os.path.getmtime(temp_file)
        if final_mtime == initial_mtime and editor in ['code', 'subl', 'sublime']:
            print_warning("File doesn't appear to have been modified. Did you save your changes?")
            retry = input(f"{Colors.BOLD}Continue anyway? (y/N): {Colors.ENDC}")
            if retry.lower() != 'y':
                return "", ""

        # Read and parse the content back
        with open(temp_file, 'r') as f:
            content = f.read().strip()

        # Parse the content to extract alert and remediation pipe-separated strings
        lines = content.split('\n')
        alert_lines = []
        remediation_lines = []
        current_section = None

        for line in lines:
            line = line.strip()
            if line.startswith('# ALERT MESSAGE'):
                current_section = 'alert'
                continue
            elif line.startswith('# REMEDIATION STEPS'):
                current_section = 'remediation'
                continue
            elif line.startswith('#') or not line:
                continue

            if current_section == 'alert':
                alert_lines.append(line)
            elif current_section == 'remediation':
                remediation_lines.append(line)

        # Join each section and keep pipe-separated format
        alert_message = ' '.join(alert_lines).strip()
        remediation_message = ' '.join(remediation_lines).strip()

        return alert_message, remediation_message

    except subprocess.CalledProcessError:
        print_error(f"Failed to open editor: {editor}")
        return "", ""
    except KeyboardInterrupt:
        print_warning("Editor interrupted by user")
        return "", ""
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_file)
        except OSError:
            pass

class CustomIOMToolkit:
    """Enhanced Custom IOM Toolkit with beautiful interface"""

    def __init__(self, base_url: str = None):
        # Check for base URL in environment variable first, then use parameter, then default
        if base_url is None:
            base_url = os.getenv('FALCON_BASE_URL', DEFAULT_BASE_URL)

        self.base_url = base_url.rstrip('/')
        self.client_id = os.getenv('FALCON_CLIENT_ID', '')
        self.client_secret = os.getenv('FALCON_CLIENT_SECRET', '')
        self.token: Optional[str] = None

        # Print which cloud environment we're connecting to
        cloud_name = self._get_cloud_name_from_url(self.base_url)
        if cloud_name:
            print_info(f"Connecting to CrowdStrike {cloud_name} cloud: {self.base_url}")
        else:
            print_info(f"Using custom base URL: {self.base_url}")

    def _get_cloud_name_from_url(self, url: str) -> Optional[str]:
        """Get cloud environment name from URL"""
        for cloud_name, cloud_url in CROWDSTRIKE_CLOUDS.items():
            if url == cloud_url:
                return cloud_name
        return None

    def authenticate(self) -> bool:
        """Authenticate with CrowdStrike API"""
        if not self.client_id or not self.client_secret:
            print_error("Missing credentials!")
            print("Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables")
            return False

        url = f"{self.base_url}/oauth2/token"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        try:
            response = requests.post(url, headers=headers, data=data, timeout=API_TIMEOUT)
            response.raise_for_status()
            self.token = response.json()["access_token"]
            print_success("Authentication successful")
            return True
        except Exception as e:
            print_error(f"Authentication failed: {e}")
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get standard headers with authentication"""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def discover_custom_rules(self) -> List[Dict]:
        """Discover all custom rules"""
        headers = self._get_headers()

        # Get rule IDs
        queries_url = f"{self.base_url}/cloud-policies/queries/rules/v1"
        params = {"filter": "rule_origin:'Custom'", "limit": 500}

        try:
            response = requests.get(queries_url, headers=headers, params=params)

            if response.status_code != 200:
                # Fallback to get all rules
                response = requests.get(queries_url, headers=headers, params={"limit": 500})

            if response.status_code == 200:
                rule_ids = response.json().get("resources", [])

                if not rule_ids:
                    return []

                # Get rule details
                entities_url = f"{self.base_url}/cloud-policies/entities/rules/v1"
                all_custom_rules = []

                # Process in batches
                for i in range(0, len(rule_ids), 50):
                    batch_ids = rule_ids[i:i+50]
                    detail_params = {"ids": batch_ids}
                    detail_response = requests.get(entities_url, headers=headers, params=detail_params)

                    if detail_response.status_code == 200:
                        batch_rules = detail_response.json().get("resources", [])
                        custom_rules = [r for r in batch_rules if r.get('origin') == 'Custom']
                        all_custom_rules.extend(custom_rules)

                return all_custom_rules
            return []
        except Exception as e:
            print_error(f"Failed to discover rules: {e}")
            return []

    def list_existing_policies(self):
        """List all existing custom policies with beautiful formatting"""
        print_header("📋 EXISTING CUSTOM POLICIES")

        print("🔍 Discovering custom policies in your CrowdStrike tenant...")
        rules = self.discover_custom_rules()

        if not rules:
            print_warning("No custom policies found in your tenant")
            print("💡 You can create your first policy using the 'Create New Policy' option")
            return

        print_success(f"Found {len(rules)} custom policies")

        for i, rule in enumerate(rules, 1):
            print(f"\n{format_rule_card(rule, i)}")

        print(f"\n{Colors.BOLD}{Colors.GREEN}📊 Summary: {len(rules)} custom policies total{Colors.ENDC}")

        # Ask if user wants to view full Rego logic for any policy
        if rules:
            view_logic = input(f"\n{Colors.BOLD}Would you like to view the full Rego logic for any policy? (y/N): {Colors.ENDC}")
            if view_logic.lower() == 'y':
                print("\n📋 Select a policy to view its Rego logic:")
                for i, rule in enumerate(rules, 1):
                    name = rule.get('name', 'Unnamed')[:50]
                    uuid_short = rule.get('uuid', '')[:8]
                    print(f"  {Colors.CYAN}{i:2}.{Colors.ENDC} {name}... ({uuid_short}...)")

                try:
                    selection = input(f"\n{Colors.BOLD}Enter policy number (1-{len(rules)}): {Colors.ENDC}")
                    index = int(selection) - 1

                    if 0 <= index < len(rules):
                        display_full_rego_logic(rules[index])
                    else:
                        print_error("Invalid selection")
                except ValueError:
                    print_error("Please enter a valid number")

    def update_existing_policy(self):
        """Update an existing policy"""
        print_header("✏️  UPDATE EXISTING POLICY")

        rules = self.discover_custom_rules()
        if not rules:
            print_warning("No custom policies found to update")
            return

        print_success(f"Found {len(rules)} policies available for update")

        # Display rules for selection
        print("\n📋 Select a policy to update:")
        for i, rule in enumerate(rules, 1):
            name = rule.get('name', 'Unnamed')[:50]
            uuid_short = rule.get('uuid', '')[:8]
            print(f"  {Colors.CYAN}{i:2}.{Colors.ENDC} {name}... ({uuid_short}...)")

        try:
            selection = input(f"\n{Colors.BOLD}Enter policy number (1-{len(rules)}): {Colors.ENDC}")
            index = int(selection) - 1

            if 0 <= index < len(rules):
                rule = rules[index]
                self._update_policy_interactive(rule)
            else:
                print_error("Invalid selection")
        except ValueError:
            print_error("Please enter a valid number")

    def _update_policy_interactive(self, rule: Dict):
        """Interactive policy update"""
        while True:  # Keep user in update menu until they choose to exit
            print_subheader(f"Updating: {rule.get('name', 'Unnamed')}")

            print(f"\nCurrent details:")
            print(format_rule_card(rule))

            print(f"\n{Colors.BOLD}What would you like to update?{Colors.ENDC}")
            print(f"1. {Colors.BLUE}Description{Colors.ENDC}")
            print(f"2. {Colors.RED}Severity{Colors.ENDC}")
            print(f"3. {Colors.YELLOW}Edit Policy Logic (Rego code){Colors.ENDC}")
            print(f"4. {Colors.CYAN}View Full Rego Logic (read-only){Colors.ENDC}")
            print(f"5. {Colors.BLUE}View Sample Asset Data (from your CSPM){Colors.ENDC}")
            print(f"6. {Colors.GREEN}Test Policy Logic (against real assets){Colors.ENDC}")
            print(f"7. {Colors.HEADER}Edit Alert & Remediation Info{Colors.ENDC}")
            print("8. Return to Main Menu")

            choice = input(f"\n{Colors.BOLD}Choose option (1-8): {Colors.ENDC}")

            if choice == "4":
                display_full_rego_logic(rule)
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue  # Continue to next iteration of update menu

            if choice == "5":
                # Get resource type from rule
                resource_type = "Unknown"
                if rule.get('resource_types') and len(rule['resource_types']) > 0:
                    resource_type = rule['resource_types'][0].get('resource_type', 'Unknown')

                if resource_type != "Unknown":
                    sample_data = self.get_sample_asset_data(resource_type)
                    if sample_data:
                        self.display_and_save_asset_data(resource_type, sample_data)
                else:
                    print_warning("Could not determine resource type for this policy")

                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue  # Continue to next iteration of update menu

            if choice == "6":
                # Test current policy logic
                current_logic = get_rego_logic(rule)
                if not current_logic:
                    print_warning("No Rego logic found for this policy - cannot test")
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                    continue

                resource_type = "Unknown"
                if rule.get('resource_types') and len(rule['resource_types']) > 0:
                    resource_type = rule['resource_types'][0].get('resource_type', 'Unknown')

                if resource_type == "Unknown":
                    print_warning("Could not determine resource type for this policy - cannot test")
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                    continue

                test_success = self.test_policy_logic(current_logic, resource_type)
                if test_success:
                    print(f"\n{Colors.GREEN}Policy testing completed successfully!{Colors.ENDC}")
                else:
                    print(f"\n{Colors.RED}Policy testing encountered issues{Colors.ENDC}")

                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue  # Continue to next iteration of update menu

            # Handle cancel/exit option
            if choice == "8":
                print("Returning to main menu...")
                return  # Exit the update loop

            # Handle update operations (1, 2, 3, 7)
            headers = self._get_headers()
            update_url = f"{self.base_url}/cloud-policies/entities/rules/v1"
            payload = {"uuid": rule['uuid']}
            update_performed = False

            if choice == "1":
                new_desc = input(f"\n{Colors.BOLD}Enter new description: {Colors.ENDC}")
                if new_desc.strip():
                    payload["description"] = new_desc.strip()
                    update_performed = True
            elif choice == "2":
                print("\nSeverity levels: 0=Critical, 1=High, 2=Medium, 3=Informational")
                try:
                    new_severity = int(input(f"{Colors.BOLD}Enter severity (0-3): {Colors.ENDC}"))
                    if 0 <= new_severity <= 3:
                        payload["severity"] = new_severity
                        update_performed = True
                    else:
                        print_error("Severity must be 0-3")
                        input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                        continue
                except ValueError:
                    print_error("Please enter a valid number")
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                    continue
            elif choice == "3":
                # Edit Policy Logic with testing capability
                current_logic = get_rego_logic(rule)
                resource_type = "Unknown"
                if rule.get('resource_types') and len(rule['resource_types']) > 0:
                    resource_type = rule['resource_types'][0].get('resource_type', 'Unknown')

                if current_logic:
                    print(f"\n{Colors.CYAN}📋 Current Rego Logic:{Colors.ENDC}")
                    print("─" * 60)
                    print(f"{Colors.HEADER}{current_logic}{Colors.ENDC}")
                    print("─" * 60)
                    print(f"\n{Colors.YELLOW}📝 Opening text editor to modify Rego policy logic...{Colors.ENDC}")
                else:
                    print(f"\n{Colors.YELLOW}📝 Opening text editor to create new Rego policy logic...{Colors.ENDC}")

                # Edit and test loop
                new_logic = current_logic
                while True:
                    # Use text editor to edit the policy
                    edited_logic = edit_rego_policy(new_logic)
                    if not edited_logic:
                        print_info("No changes made to Rego logic")
                        break  # Changed from return to break to continue in update menu

                    new_logic = edited_logic

                    # Offer testing and options
                    print(f"\n{Colors.BOLD}Policy logic updated. What would you like to do?{Colors.ENDC}")
                    print(f"1. {Colors.GREEN}Test Updated Logic{Colors.ENDC} (against real assets)")
                    print(f"2. {Colors.BLUE}Edit Logic Again{Colors.ENDC}")
                    print(f"3. {Colors.YELLOW}Save Changes{Colors.ENDC}")
                    print(f"4. {Colors.RED}Cancel (discard changes){Colors.ENDC}")

                    test_action = input(f"\n{Colors.BOLD}Choose action (1-4): {Colors.ENDC}")

                    if test_action == "1":
                        # Test the new logic
                        if resource_type != "Unknown":
                            test_success = self.test_policy_logic(new_logic, resource_type)
                            if test_success:
                                print(f"\n{Colors.GREEN}Policy testing completed successfully!{Colors.ENDC}")
                                # After successful test, offer next steps without reopening editor
                                print(f"\n{Colors.BOLD}Testing successful! What would you like to do next?{Colors.ENDC}")
                                print(f"1. {Colors.YELLOW}Save Changes{Colors.ENDC}")
                                print(f"2. {Colors.BLUE}Edit Logic Again{Colors.ENDC}")
                                print(f"3. {Colors.RED}Cancel (discard changes){Colors.ENDC}")

                                post_test_action = input(f"\n{Colors.BOLD}Choose action (1-3): {Colors.ENDC}")

                                if post_test_action == "1":
                                    # Save changes
                                    if new_logic != current_logic:
                                        # Preserve existing remediation_info when updating logic
                                        existing_remediation = None
                                        if rule.get('rule_logic_list') and len(rule['rule_logic_list']) > 0:
                                            raw_remediation = rule['rule_logic_list'][0].get('remediation_info')
                                            if raw_remediation:
                                                # Clean the remediation format to prevent duplication
                                                existing_remediation = clean_remediation_format(raw_remediation)

                                        cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
                                        logic_item = {"logic": new_logic, "platform": cloud_provider["platform"]}
                                        if existing_remediation:
                                            logic_item["remediation_info"] = existing_remediation
                                            print_success("Rego policy logic will be updated (preserving existing remediation steps)")
                                        else:
                                            print_success("Rego policy logic will be updated")

                                        payload["rule_logic_list"] = [logic_item]
                                        update_performed = True
                                        break  # Exit edit loop to execute update
                                    else:
                                        print_info("No changes made to Rego logic")
                                        break  # Exit edit loop
                                elif post_test_action == "2":
                                    # Edit again
                                    continue
                                else:
                                    # Cancel
                                    print_info("Changes discarded")
                                    break  # Exit edit loop
                            else:
                                print(f"\n{Colors.RED}Policy testing encountered issues{Colors.ENDC}")
                                print_info("Consider editing your policy logic to address any errors")
                                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                                continue
                        else:
                            print_warning("Cannot test - resource type unknown")
                            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                            continue

                    elif test_action == "2":
                        # Edit again
                        continue

                    elif test_action == "3":
                        # Save changes
                        if new_logic != current_logic:
                            # Preserve existing remediation_info when updating logic
                            existing_remediation = None
                            if rule.get('rule_logic_list') and len(rule['rule_logic_list']) > 0:
                                raw_remediation = rule['rule_logic_list'][0].get('remediation_info')
                                if raw_remediation:
                                    # Clean the remediation format to prevent duplication
                                    existing_remediation = clean_remediation_format(raw_remediation)

                            cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
                            logic_item = {"logic": new_logic, "platform": cloud_provider["platform"]}
                            if existing_remediation:
                                logic_item["remediation_info"] = existing_remediation
                                print_success("Rego policy logic will be updated (preserving existing remediation steps)")
                            else:
                                print_success("Rego policy logic will be updated")

                            payload["rule_logic_list"] = [logic_item]
                            update_performed = True
                            break  # Exit edit loop to execute update
                        else:
                            print_info("No changes made to Rego logic")
                            break  # Exit edit loop

                    elif test_action == "4":
                        # Cancel
                        print_info("Changes discarded")
                        break  # Exit edit loop

                    else:
                        print_error("Invalid choice. Please enter 1, 2, 3, or 4.")
                        continue
            elif choice == "7":
                # Edit Alert & Remediation Info using text editor
                print_subheader("Edit Alert & Remediation Information")

                # Get current values from the correct locations
                current_alert = rule.get('alert_info', '')

                # The API stores pipe-separated format with automatic numbering
                # Our edit function will handle the conversion properly

                # Get remediation info from the correct location
                current_remediation = ""

                # Try rule_logic_list first (most reliable)
                if rule.get('rule_logic_list') and len(rule['rule_logic_list']) > 0:
                    logic_item = rule['rule_logic_list'][0]
                    remediation_from_logic = logic_item.get('remediation_info', '')
                    if remediation_from_logic:
                        current_remediation = remediation_from_logic

                # Fallback to remediation field
                if not current_remediation:
                    remediation_from_field = rule.get('remediation', '')
                    if remediation_from_field:
                        current_remediation = remediation_from_field

                # Clean up the display format for user viewing
                display_alert = convert_processed_to_pipe_format(current_alert) if current_alert else 'None defined'
                display_remediation = convert_processed_to_pipe_format(current_remediation) if current_remediation else 'None defined'

                print(f"Current alert message: {display_alert}")
                print(f"Current remediation steps: {display_remediation}")

                new_alert, new_remediation = edit_alert_remediation_info(current_alert, current_remediation)

                if new_alert or new_remediation:
                    if new_alert:
                        payload["alert_info"] = new_alert
                        print_success("Alert message updated")
                    if new_remediation:
                        # For policy updates, remediation_info must be sent in rule_logic_list format
                        # Get current Rego logic to preserve it
                        current_logic = get_rego_logic(rule)
                        if current_logic:
                            # Get resource type for dynamic provider detection
                            resource_type = "Unknown"
                            if rule.get('resource_types') and len(rule['resource_types']) > 0:
                                resource_type = rule['resource_types'][0].get('resource_type', 'Unknown')

                            cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
                            payload["rule_logic_list"] = [
                                {
                                    "logic": current_logic,
                                    "platform": cloud_provider["platform"],
                                    "remediation_info": new_remediation
                                }
                            ]
                            print_success("Remediation steps updated (using rule_logic_list format)")
                        else:
                            print_warning("Could not update remediation - no Rego logic found")
                    update_performed = True
                else:
                    print_info("No changes made to alert & remediation information")

            else:
                print_error("Invalid choice. Please enter 1-8.")
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue

            # Execute the update if any changes were made
            if update_performed and len(payload) > 1:  # More than just UUID
                try:
                    response = requests.patch(update_url, headers=headers, json=payload)
                    if response.status_code == 200:
                        print_success("Policy updated successfully!")
                        # Refresh rule data for next iteration
                        rules = self.discover_custom_rules()
                        rule = next((r for r in rules if r['uuid'] == rule['uuid']), rule)
                    else:
                        error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                        print_error(f"Update failed: {response.status_code}")
                        print(f"Error: {error_data}")
                except Exception as e:
                    print_error(f"Update failed: {e}")

                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue  # Return to update menu

    def delete_existing_policy(self):
        """Delete an existing policy"""
        print_header("🗑️  DELETE EXISTING POLICY")

        rules = self.discover_custom_rules()
        if not rules:
            print_warning("No custom policies found to delete")
            return

        print_success(f"Found {len(rules)} policies available for deletion")

        # Display rules for selection
        print("\n📋 Select a policy to delete:")
        for i, rule in enumerate(rules, 1):
            name = rule.get('name', 'Unnamed')[:50]
            uuid_short = rule.get('uuid', '')[:8]
            resource_type = "Unknown"
            if rule.get('resource_types') and len(rule['resource_types']) > 0:
                resource_type = rule['resource_types'][0].get('resource_type', 'Unknown')

            print(f"  {Colors.RED}{i:2}.{Colors.ENDC} {name}... ({resource_type}) [{uuid_short}...]")

        try:
            selection = input(f"\n{Colors.BOLD}Enter policy number (1-{len(rules)}) or 'cancel': {Colors.ENDC}")

            if selection.lower() == 'cancel':
                print("Deletion cancelled")
                return

            index = int(selection) - 1

            if 0 <= index < len(rules):
                rule = rules[index]
                self._delete_policy_interactive(rule)
            else:
                print_error("Invalid selection")
        except ValueError:
            print_error("Please enter a valid number or 'cancel'")

    def _delete_policy_interactive(self, rule: Dict):
        """Interactive policy deletion with confirmation"""
        print_subheader(f"Delete Policy: {rule.get('name', 'Unnamed')}")

        print(f"\n{Colors.RED}WARNING: You are about to delete this policy:{Colors.ENDC}")
        print(format_rule_card(rule))

        print(f"\n{Colors.RED}{Colors.BOLD}This action cannot be undone!{Colors.ENDC}")

        confirm = input(f"\n{Colors.BOLD}Type 'DELETE' to confirm deletion: {Colors.ENDC}")

        if confirm != "DELETE":
            print("Deletion cancelled - policy not deleted")
            return

        headers = self._get_headers()
        delete_url = f"{self.base_url}/cloud-policies/entities/rules/v1"
        params = {"ids": [rule['uuid']]}

        try:
            response = requests.delete(delete_url, headers=headers, params=params)
            if response.status_code == 200:
                print_success(f"Policy '{rule.get('name', 'Unnamed')}' deleted successfully!")
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                print_error(f"Delete failed: {response.status_code}")
                print(f"Error: {error_data}")
        except Exception as e:
            print_error(f"Delete failed: {e}")

    def test_policy_logic(self, logic: str, resource_type: str, num_assets: int = 3) -> tuple[bool, dict]:
        """Test Rego policy logic against real assets"""
        print_subheader(f"🧪 Testing Policy Logic Against Real {resource_type} Assets")

        headers = self._get_headers()

        # Step 1: Find assets of the target resource type
        print_info(f"Finding {num_assets} sample {resource_type} assets for testing...")

        discover_url = f"{self.base_url}/cloud-security-assets/queries/resources/v1"

        # Only test against ACTIVE assets of the specific resource type (matching GUI behavior)
        discover_params = {"filter": f"resource_type:'{resource_type}'+active:'true'", "limit": 10}

        print_info(f"Looking for active {resource_type} assets...")

        asset_ids = []
        try:
            discover_response = requests.get(discover_url, headers=headers, params=discover_params, timeout=API_TIMEOUT)
            if discover_response.status_code == 200:
                found_ids = discover_response.json().get("resources", [])
                if found_ids:
                    asset_ids = found_ids[:num_assets]
                    print_success(f"Found {len(asset_ids)} active {resource_type} assets for testing")
                else:
                    print_warning(f"No active {resource_type} assets found in your environment")
            else:
                print_warning(f"Asset discovery failed: {discover_response.status_code}")
        except Exception as e:
            print_warning(f"Exception during asset discovery: {e}")

        if not asset_ids:
            print_error("Could not find any assets for testing")
            print_warning("Policy testing requires sample assets to evaluate against")

            # Return empty results for GUI compatibility
            empty_results = {
                'total_assets': 0,
                'resource_type': resource_type,
                'test_results': [],
                'successful_tests': 0,
                'pass_count': 0,
                'fail_count': 0,
                'error_count': 0,
                'interpretation': f'No {resource_type} assets found for testing. Try with a different resource type or check if you have assets deployed.',
                'summary_text': f'No {resource_type} assets available for testing'
            }
            return False, empty_results

        # Step 2: Get enriched asset data for each asset
        print_info("Retrieving enriched asset data for policy testing...")

        enriched_url = f"{self.base_url}/cloud-policies/entities/enriched-resources/v1"
        evaluation_url = f"{self.base_url}/cloud-policies/entities/evaluation/v1"

        # Determine cloud provider from resource type
        cloud_provider = "gcp"  # Default
        if resource_type.startswith("AWS::"):
            cloud_provider = "aws"
        elif resource_type.startswith("Microsoft."):
            cloud_provider = "azure"
        elif "googleapis.com" in resource_type:
            cloud_provider = "gcp"

        test_results = []
        successful_tests = 0

        # Process each asset individually
        for i, asset_id in enumerate(asset_ids, 1):
            print_info(f"Testing asset {i}/{len(asset_ids)}: {asset_id[-30:]}")

            # Get enriched data for this asset
            tenant_id = asset_id.split('|')[0]
            enriched_headers = self._get_headers()
            enriched_headers["X-CS-CUSTID"] = tenant_id

            try:
                # Get enriched asset data
                enriched_params = {"ids": [asset_id]}
                enriched_response = requests.get(enriched_url, headers=enriched_headers, params=enriched_params, timeout=API_TIMEOUT)

                if enriched_response.status_code != 200:
                    print_warning(f"  Failed to get enriched data: {enriched_response.status_code}")
                    test_results.append({
                        "asset_id": asset_id,
                        "result": "error",
                        "error": f"Failed to get enriched data: {enriched_response.status_code}"
                    })
                    continue

                enriched_data = enriched_response.json()
                resources = enriched_data.get("resources", [])

                if not resources:
                    print_warning(f"  No enriched data returned")
                    test_results.append({
                        "asset_id": asset_id,
                        "result": "error",
                        "error": "No enriched data returned"
                    })
                    continue

                asset_data = resources[0]

                # Test policy against this asset
                evaluation_params = {
                    "cloud_provider": cloud_provider,
                    "resource_type": resource_type,
                    "ids": [asset_id]
                }

                evaluation_body = {
                    "logic": logic,
                    "input": asset_data  # Pass the actual asset data as input
                }

                evaluation_response = requests.post(
                    evaluation_url,
                    headers=headers,
                    params=evaluation_params,
                    json=evaluation_body,
                    timeout=API_TIMEOUT
                )

                if evaluation_response.status_code == 200:
                    eval_results = evaluation_response.json()
                    eval_resources = eval_results.get("resources", [])

                    if eval_resources:
                        result = eval_resources[0]
                        test_results.append({
                            "asset_id": asset_id,
                            "result": result.get("result", "unknown"),
                            "details": result.get("details", {})
                        })
                        successful_tests += 1
                        print_success(f"  Evaluation complete: {result.get('result', 'unknown')}")
                    else:
                        print_warning(f"  No evaluation results returned")
                        test_results.append({
                            "asset_id": asset_id,
                            "result": "error",
                            "error": "No evaluation results returned"
                        })
                else:
                    error_data = evaluation_response.json() if evaluation_response.headers.get('content-type', '').startswith('application/json') else evaluation_response.text
                    print_warning(f"  Policy evaluation failed: {evaluation_response.status_code}")
                    test_results.append({
                        "asset_id": asset_id,
                        "result": "error",
                        "error": f"Evaluation failed: {evaluation_response.status_code} - {error_data}"
                    })

            except Exception as e:
                print_warning(f"  Exception during testing: {e}")
                test_results.append({
                    "asset_id": asset_id,
                    "result": "error",
                    "error": f"Exception: {str(e)}"
                })

        # Display results
        if test_results:
            self._display_test_results_fixed(test_results, resource_type)

        # Prepare detailed results for GUI
        detailed_results = {
            'total_assets': len(test_results),
            'resource_type': resource_type,
            'test_results': test_results,
            'successful_tests': successful_tests,
            'pass_count': 0,
            'fail_count': 0,
            'error_count': 0,
            'interpretation': '',
            'summary_text': ''
        }

        # Calculate counts and generate summary
        if test_results:
            pass_count = sum(1 for r in test_results if r.get('result') == 'pass')
            fail_count = sum(1 for r in test_results if r.get('result') == 'fail')
            error_count = sum(1 for r in test_results if r.get('result') == 'error')
            total_assets = len(test_results)

            detailed_results.update({
                'pass_count': pass_count,
                'fail_count': fail_count,
                'error_count': error_count
            })

            # Generate interpretation
            if pass_count == total_assets:
                interpretation = "All assets passed - policy may be too permissive or assets are compliant"
            elif fail_count == total_assets:
                interpretation = "All assets failed - policy may be too strict or assets are non-compliant"
            elif pass_count > 0 and fail_count > 0:
                interpretation = "Mixed results - policy is detecting compliance issues as expected"
            else:
                interpretation = "Policy evaluation completed"

            if error_count > 0:
                interpretation += f" (Note: {error_count} assets had evaluation errors)"

            detailed_results['interpretation'] = interpretation

            # Generate summary text
            summary_text = f"Test Results for {total_assets} {resource_type} assets:\n"
            summary_text += f"Passed: {pass_count}/{total_assets} ({pass_count/total_assets*100:.1f}%)\n"
            summary_text += f"Failed: {fail_count}/{total_assets} ({fail_count/total_assets*100:.1f}%)"
            if error_count > 0:
                summary_text += f"\nErrors: {error_count}/{total_assets} ({error_count/total_assets*100:.1f}%)"

            detailed_results['summary_text'] = summary_text

        if successful_tests > 0:
            return True, detailed_results
        else:
            if successful_tests == 0:
                print_error("All policy evaluations failed")
                print_warning("This could indicate:")
                print("  • Rego syntax errors in your policy logic")
                print("  • Policy logic doesn't follow CrowdStrike CSPM format")
                print("  • Issues with asset data retrieval")
                detailed_results['interpretation'] = "All policy evaluations failed - check Rego syntax and policy format"
            return False, detailed_results

    def _display_test_results_fixed(self, test_results: List[Dict], resource_type: str):
        """Display policy test results in a user-friendly format"""
        print_success("Policy evaluation completed!")

        print(f"\n{Colors.BOLD}📊 Test Results for {len(test_results)} {resource_type} assets:{Colors.ENDC}")
        print("─" * 80)

        pass_count = 0
        fail_count = 0
        error_count = 0

        for i, result in enumerate(test_results, 1):
            asset_id = result.get("asset_id", "Unknown")
            evaluation_result = result.get("result", "unknown")

            # Truncate long asset IDs for display
            display_id = asset_id[-30:] if len(asset_id) > 30 else asset_id

            if evaluation_result == "pass":
                print(f"  {Colors.GREEN}PASS: Asset {i}: {display_id}{Colors.ENDC}")
                pass_count += 1
            elif evaluation_result == "fail":
                print(f"  {Colors.RED}FAIL: Asset {i}: {display_id}{Colors.ENDC}")
                fail_count += 1

                # Show failure details if available
                details = result.get("details", {})
                if details:
                    violations = details.get("violations", [])
                    if violations:
                        for violation in violations[:2]:  # Show first 2 violations
                            msg = violation.get("message", "No message")
                            print(f"     {Colors.YELLOW}└─ {msg}{Colors.ENDC}")
            else:
                error_msg = result.get("error", "Unknown error")
                print(f"  {Colors.YELLOW}ERROR: Asset {i}: {display_id}{Colors.ENDC}")
                print(f"     {Colors.YELLOW}└─ {error_msg}{Colors.ENDC}")
                error_count += 1

        print("─" * 80)

        # Summary
        total_assets = len(test_results)
        if total_assets > 0:
            print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
            print(f"  {Colors.GREEN}Passed: {pass_count}/{total_assets} ({pass_count/total_assets*100:.1f}%){Colors.ENDC}")
            print(f"  {Colors.RED}Failed: {fail_count}/{total_assets} ({fail_count/total_assets*100:.1f}%){Colors.ENDC}")
            if error_count > 0:
                print(f"  {Colors.YELLOW}Errors: {error_count}/{total_assets} ({error_count/total_assets*100:.1f}%){Colors.ENDC}")

            # Provide interpretation guidance
            print(f"\n{Colors.CYAN}💡 Interpretation:{Colors.ENDC}")
            if pass_count == total_assets:
                print(f"  {Colors.GREEN}All assets passed - policy may be too permissive or assets are compliant{Colors.ENDC}")
            elif fail_count == total_assets:
                print(f"  {Colors.RED}All assets failed - policy may be too strict or assets are non-compliant{Colors.ENDC}")
            elif pass_count > 0 and fail_count > 0:
                print(f"  {Colors.BLUE}Mixed results - policy is detecting compliance issues as expected{Colors.ENDC}")

            if error_count > 0:
                print(f"  {Colors.YELLOW}Errors suggest Rego syntax issues or asset data problems{Colors.ENDC}")

    def _display_test_results(self, results: Dict, asset_ids: List[str], resource_type: str):
        """Display policy test results in a user-friendly format"""
        print_success("Policy evaluation completed!")

        resources = results.get("resources", [])
        if not resources:
            print_warning("No evaluation results returned")
            return

        print(f"\n{Colors.BOLD}📊 Test Results for {len(asset_ids)} {resource_type} assets:{Colors.ENDC}")
        print("─" * 80)

        pass_count = 0
        fail_count = 0
        error_count = 0

        for i, result in enumerate(resources, 1):
            asset_id = result.get("resource_id", "Unknown")
            evaluation_result = result.get("result", "unknown")

            # Truncate long asset IDs for display
            display_id = asset_id[-30:] if len(asset_id) > 30 else asset_id

            if evaluation_result == "pass":
                print(f"  {Colors.GREEN}PASS: Asset {i}: {display_id}{Colors.ENDC}")
                pass_count += 1
            elif evaluation_result == "fail":
                print(f"  {Colors.RED}FAIL: Asset {i}: {display_id}{Colors.ENDC}")
                fail_count += 1

                # Show failure details if available
                details = result.get("details", {})
                if details:
                    violations = details.get("violations", [])
                    if violations:
                        for violation in violations[:2]:  # Show first 2 violations
                            msg = violation.get("message", "No message")
                            print(f"     {Colors.YELLOW}└─ {msg}{Colors.ENDC}")
            else:
                print(f"  {Colors.YELLOW}ERROR/UNKNOWN: Asset {i}: {display_id}{Colors.ENDC}")
                error_count += 1

        print("─" * 80)

        # Summary
        total_assets = len(resources)
        print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  {Colors.GREEN}Passed: {pass_count}/{total_assets} ({pass_count/total_assets*100:.1f}%){Colors.ENDC}")
        print(f"  {Colors.RED}Failed: {fail_count}/{total_assets} ({fail_count/total_assets*100:.1f}%){Colors.ENDC}")
        if error_count > 0:
            print(f"  {Colors.YELLOW}Errors: {error_count}/{total_assets} ({error_count/total_assets*100:.1f}%){Colors.ENDC}")

        # Provide interpretation guidance
        print(f"\n{Colors.CYAN}Interpretation:{Colors.ENDC}")
        if pass_count == total_assets:
            print(f"  {Colors.GREEN}All assets passed - policy may be too permissive or assets are compliant{Colors.ENDC}")
        elif fail_count == total_assets:
            print(f"  {Colors.RED}All assets failed - policy may be too strict or assets are non-compliant{Colors.ENDC}")
        else:
            print(f"  {Colors.BLUE}Mixed results - policy is detecting compliance issues as expected{Colors.ENDC}")

        if error_count > 0:
            print(f"  {Colors.YELLOW}Errors suggest Rego syntax issues or asset data problems{Colors.ENDC}")

    def get_sample_asset_data(self, resource_type: str) -> Optional[Dict]:
        """Fetch a sample enriched asset for the given resource type"""
        print_info(f"Fetching sample {resource_type} data from enriched API...")

        headers = self._get_headers()

        # Step 1: Discover resources of this type with improved filtering
        discover_url = f"{self.base_url}/cloud-security-assets/queries/resources/v1"

        # Try multiple filter approaches to handle different resource type formats
        filter_attempts = [
            f"resource_type:'{resource_type}'",  # Standard approach
            f"active:'true'"  # Fallback: get active resources and filter later
        ]

        resource_ids = []
        for filter_expr in filter_attempts:
            discover_params = {"filter": filter_expr, "limit": 10}

            try:
                discover_response = requests.get(discover_url, headers=headers, params=discover_params, timeout=API_TIMEOUT)
                if discover_response.status_code == 200:
                    found_ids = discover_response.json().get("resources", [])
                    if found_ids:
                        resource_ids = found_ids
                        print_success(f"Found {len(resource_ids)} resources using filter: {filter_expr}")
                        break
                else:
                    print_warning(f"Filter '{filter_expr}' failed: {discover_response.status_code}")
            except Exception as e:
                print_warning(f"Exception with filter '{filter_expr}': {e}")

        if not resource_ids:
            print_warning(f"Could not discover any resources")
            return None

        # Step 2: Try to get enriched data from multiple resources if needed
        for i, resource_id in enumerate(resource_ids[:3]):  # Try up to 3 resources
            print_info(f"Attempting resource {i+1}: {resource_id}")

            # Step 3: Get enriched data
            enriched_url = f"{self.base_url}/cloud-policies/entities/enriched-resources/v1"
            tenant_id = resource_id.split('|')[0]  # Extract tenant ID for header

            enriched_headers = self._get_headers()
            enriched_headers["X-CS-CUSTID"] = tenant_id

            enriched_params = {"ids": [resource_id]}

            try:
                enriched_response = requests.get(enriched_url, headers=enriched_headers, params=enriched_params, timeout=API_TIMEOUT)
                if enriched_response.status_code == 200:
                    enriched_data = enriched_response.json()
                    resources = enriched_data.get("resources", [])

                    if resources:
                        sample_asset = resources[0]
                        actual_type = sample_asset.get("resource_type", "unknown")

                        # Check if this matches our desired type or if we're in fallback mode
                        if resource_type == actual_type or filter_attempts[0] not in discover_params.get("filter", ""):
                            print_success(f"Retrieved enriched data for {actual_type}")
                            print_success(f"Asset has {len(sample_asset.keys())} top-level fields")

                            # If this was a fallback search, update the resource_type for display
                            if resource_type != actual_type:
                                print_info(f"Note: Found {actual_type} instead of {resource_type}")

                            return sample_asset
                        else:
                            print_info(f"Resource type mismatch: found {actual_type}, wanted {resource_type}")
                    else:
                        print_warning(f"No enriched data returned for resource {i+1}")
                else:
                    print_warning(f"Could not get enriched data for resource {i+1}: {enriched_response.status_code}")
            except Exception as e:
                print_warning(f"Exception getting enriched data for resource {i+1}: {e}")

        print_warning("Could not retrieve suitable asset data from any discovered resource")
        return None

    def display_and_save_asset_data(self, resource_type: str, asset_data: Dict):
        """Display asset data and optionally save to file"""
        print_subheader(f"Sample {resource_type} Asset Data")

        print(f"{Colors.CYAN}📊 Available Fields ({len(asset_data.keys())} total):{Colors.ENDC}")
        print("─" * 60)

        # Show key fields first
        key_fields = ["resource_id", "resource_type", "configuration", "tags", "region", "service"]

        for field in key_fields:
            if field in asset_data:
                value = asset_data[field]
                if isinstance(value, dict):
                    print(f"{Colors.HEADER}{field}{Colors.ENDC}: {Colors.YELLOW}(object with {len(value.keys())} fields){Colors.ENDC}")
                elif isinstance(value, list):
                    print(f"{Colors.HEADER}{field}{Colors.ENDC}: {Colors.YELLOW}(array with {len(value)} items){Colors.ENDC}")
                else:
                    display_value = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                    print(f"{Colors.HEADER}{field}{Colors.ENDC}: {Colors.CYAN}{display_value}{Colors.ENDC}")

        # Show other fields
        other_fields = [k for k in asset_data.keys() if k not in key_fields]
        if other_fields:
            print(f"\n{Colors.YELLOW}Other fields:{Colors.ENDC} {', '.join(other_fields[:10])}")
            if len(other_fields) > 10:
                print(f"{Colors.YELLOW}...and {len(other_fields) - 10} more{Colors.ENDC}")

        print("─" * 60)

        # Offer to save to file
        save_choice = input(f"\n{Colors.BOLD}Save complete asset data to JSON file? (y/N): {Colors.ENDC}")
        if save_choice.lower() == 'y':
            # Create a safe filename by replacing all special characters
            safe_resource_type = resource_type.replace('::', '_').replace('/', '_').replace('.', '_').lower()
            filename = f"sample_{safe_resource_type}_asset.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(asset_data, f, indent=2)
                print_success(f"Asset data saved to {filename}")
                print(f"{Colors.CYAN}💡 Use this file to understand available fields when writing your Rego policy{Colors.ENDC}")
                print(f"{Colors.CYAN}💡 The configuration object (including policy JSON) is included in this export{Colors.ENDC}")
            except Exception as e:
                print_error(f"Failed to save file: {e}")

    def discover_all_resource_types(self) -> List[str]:
        """Debug method to discover all available resource types in the environment"""
        print_header("🔍 DEBUG: DISCOVERING ALL RESOURCE TYPES")
        print_info("This will help us identify the correct resource type names for ECR and other resources...")

        headers = self._get_headers()
        discover_url = f"{self.base_url}/cloud-security-assets/queries/resources/v1"

        # Get a sample of resources to analyze their types
        params = {"limit": 500}

        try:
            response = requests.get(discover_url, headers=headers, params=params, timeout=API_TIMEOUT)
            if response.status_code != 200:
                print_error(f"Failed to discover resources: {response.status_code}")
                return []

            resource_ids = response.json().get("resources", [])
            if not resource_ids:
                print_warning("No resources found")
                return []

            print_success(f"Found {len(resource_ids)} total resources")

            # Get details for a batch to analyze resource types
            enriched_url = f"{self.base_url}/cloud-policies/entities/enriched-resources/v1"

            # Process first 100 resources to get a good sample
            sample_ids = resource_ids[:100]
            all_resource_types = set()

            # Get enriched data in batches of 10 (to avoid overwhelming the API)
            for i in range(0, min(100, len(sample_ids)), 10):
                batch_ids = sample_ids[i:i+10]

                # Extract tenant ID from first resource for header
                if batch_ids:
                    tenant_id = batch_ids[0].split('|')[0]
                    enriched_headers = self._get_headers()
                    enriched_headers["X-CS-CUSTID"] = tenant_id

                    enriched_params = {"ids": batch_ids}

                    enriched_response = requests.get(enriched_url, headers=enriched_headers, params=enriched_params, timeout=API_TIMEOUT)
                    if enriched_response.status_code == 200:
                        enriched_data = enriched_response.json()
                        resources = enriched_data.get("resources", [])

                        for resource in resources:
                            resource_type = resource.get("resource_type")
                            if resource_type:
                                all_resource_types.add(resource_type)

                        print_info(f"Processed batch {i//10 + 1}, found {len(all_resource_types)} unique resource types so far...")
                    else:
                        print_warning(f"Failed to get enriched data for batch {i//10 + 1}: {enriched_response.status_code}")

            resource_types_list = sorted(list(all_resource_types))

            print_subheader(f"Found {len(resource_types_list)} Unique Resource Types")
            print("─" * 80)

            # Group by service for better readability
            ecr_types = [rt for rt in resource_types_list if "ECR" in rt.upper()]
            s3_types = [rt for rt in resource_types_list if "S3" in rt.upper()]
            ec2_types = [rt for rt in resource_types_list if "EC2" in rt.upper()]
            iam_types = [rt for rt in resource_types_list if "IAM" in rt.upper()]
            lambda_types = [rt for rt in resource_types_list if "LAMBDA" in rt.upper()]

            if ecr_types:
                print(f"{Colors.YELLOW}🐳 ECR Resource Types:{Colors.ENDC}")
                for rt in ecr_types:
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                print()

            if s3_types:
                print(f"{Colors.YELLOW}🪣 S3 Resource Types:{Colors.ENDC}")
                for rt in s3_types:
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                print()

            if ec2_types:
                print(f"{Colors.YELLOW}💻 EC2 Resource Types:{Colors.ENDC}")
                for rt in ec2_types:
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                print()

            if iam_types:
                print(f"{Colors.YELLOW}🔐 IAM Resource Types:{Colors.ENDC}")
                for rt in iam_types:
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                print()

            if lambda_types:
                print(f"{Colors.YELLOW}⚡ Lambda Resource Types:{Colors.ENDC}")
                for rt in lambda_types:
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                print()

            # Show other types
            other_types = [rt for rt in resource_types_list if not any(service in rt.upper() for service in ["ECR", "S3", "EC2", "IAM", "LAMBDA"])]
            if other_types:
                print(f"{Colors.YELLOW}🔧 Other Resource Types:{Colors.ENDC}")
                for rt in other_types[:20]:  # Show first 20 to avoid overwhelming output
                    print(f"  - {Colors.CYAN}{rt}{Colors.ENDC}")
                if len(other_types) > 20:
                    print(f"  ... and {len(other_types) - 20} more")
                print()

            print("─" * 80)

            # Save to file for reference
            filename = f"discovered_resource_types_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write("# Discovered Resource Types from CrowdStrike CSPM\n")
                    f.write(f"# Generated: {datetime.now()}\n\n")
                    for rt in resource_types_list:
                        f.write(f"{rt}\n")
                print_success(f"Complete list saved to {filename}")
            except Exception as e:
                print_warning(f"Failed to save to file: {e}")

            return resource_types_list

        except Exception as e:
            print_error(f"Failed to discover resource types: {e}")
            return []

    def discover_resource_types(self) -> List[Dict]:
        """Discover resource types for GUI - returns structured data with counts"""
        headers = self._get_headers()
        discover_url = f"{self.base_url}/cloud-security-assets/queries/resources/v1"

        # Get a sample of resources to analyze their types
        params = {"limit": 500}

        try:
            response = requests.get(discover_url, headers=headers, params=params, timeout=API_TIMEOUT)
            if response.status_code != 200:
                return []

            resource_ids = response.json().get("resources", [])
            if not resource_ids:
                return []

            # Get details for a batch to analyze resource types
            enriched_url = f"{self.base_url}/cloud-policies/entities/enriched-resources/v1"

            # Process first 100 resources to get a good sample
            sample_ids = resource_ids[:100]
            resource_type_counts = {}

            # Get enriched data in batches of 10
            for i in range(0, min(100, len(sample_ids)), 10):
                batch_ids = sample_ids[i:i+10]

                if batch_ids:
                    tenant_id = batch_ids[0].split('|')[0]
                    enriched_headers = self._get_headers()
                    enriched_headers["X-CS-CUSTID"] = tenant_id

                    enriched_params = {"ids": batch_ids}

                    enriched_response = requests.get(enriched_url, headers=enriched_headers, params=enriched_params, timeout=API_TIMEOUT)
                    if enriched_response.status_code == 200:
                        enriched_data = enriched_response.json()
                        resources = enriched_data.get("resources", [])

                        for resource in resources:
                            resource_type = resource.get("resource_type")
                            if resource_type:
                                resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1

            # Convert to structured list for GUI
            resource_types_list = [
                {"resource_type": rt, "count": count}
                for rt, count in sorted(resource_type_counts.items())
            ]

            return resource_types_list

        except Exception as e:
            return []

    def create_new_policy(self):
        print_header("➕ CREATE NEW CUSTOM POLICY")

        print("🚀 Let's create a new custom policy step by step!")

        # Step 1: Basic Information
        print_subheader("Step 1: Basic Information")

        name = input(f"{Colors.BOLD}Policy Name: {Colors.ENDC}").strip()
        if not name:
            print_error("Policy name is required")
            return

        description = input(f"{Colors.BOLD}Description: {Colors.ENDC}").strip()
        if not description:
            description = f"Custom policy: {name}"

        # Step 2: Resource Type
        print_subheader("Step 2: Target Resource Type")
        print("📋 Available resource types in your environment:")
        print("(Based on discovered resources from your CSPM)")

        # Updated list based on actual discovered resources
        common_types = [
            # Google Cloud Platform (Primary)
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Disk",
            "compute.googleapis.com/Firewall",
            "container.googleapis.com/Cluster",
            "iam.googleapis.com/Role",
            "iam.googleapis.com/ServiceAccount",

            # AWS (Limited availability)
            "AWS::Logs::LogGroup",
            "AWS::Route53::HostedZone",
            "AWS::SSM::Parameter",

            # Microsoft Azure
            "Microsoft.Authorization/policyAssignments",
            "Microsoft.Resources/subscriptions",

            # Other useful types
            "artifactregistry.googleapis.com/Repository",
            "logging.googleapis.com/LogBucket"
        ]

        for i, rtype in enumerate(common_types, 1):
            print(f"  {i}. {rtype}")
        print(f"  {len(common_types) + 1}. Other (specify)")

        try:
            type_choice = input(f"\n{Colors.BOLD}Choose resource type (1-{len(common_types) + 1}): {Colors.ENDC}")
            type_index = int(type_choice) - 1

            if 0 <= type_index < len(common_types):
                resource_type = common_types[type_index]
            elif type_index == len(common_types):
                resource_type = input(f"{Colors.BOLD}Enter resource type: {Colors.ENDC}").strip()
                if not resource_type:
                    print_error("Resource type is required")
                    return
            else:
                print_error("Invalid selection")
                return
        except ValueError:
            print_error("Please enter a valid number")
            return

        # Step 2.5: Fetch Sample Asset Data
        print_subheader("Step 2.5: Sample Asset Data (Optional)")
        print("💡 To write effective Rego policies, you need to understand the asset data structure")

        get_sample = input(f"{Colors.BOLD}Fetch sample {resource_type} asset data? (Y/n): {Colors.ENDC}")
        sample_data = None
        if get_sample.lower() != 'n':
            sample_data = self.get_sample_asset_data(resource_type)
            if sample_data:
                self.display_and_save_asset_data(resource_type, sample_data)
                input(f"\n{Colors.BOLD}Press Enter to continue with policy creation...{Colors.ENDC}")

        # Step 3: Severity
        print_subheader("Step 3: Severity Level")
        print("Severity levels:")
        print("  0. Critical - Immediate action required")
        print("  1. High - Important security issue")
        print("  2. Medium - Moderate security concern")
        print("  3. Informational - Minor issue or informational")

        try:
            severity = int(input(f"\n{Colors.BOLD}Choose severity (0-3): {Colors.ENDC}"))
            if not (0 <= severity <= 3):
                print_error("Severity must be 0-3")
                return
        except ValueError:
            print_error("Please enter a valid number")
            return

        # Step 3.5: Alert and Remediation Information
        print_subheader("Step 3.5: Alert and Remediation Information")
        print("This information helps users understand the issue and how to fix it")
        print("Opening text editor to create alert message and remediation steps...")
        print("Use PIPE-SEPARATED format for automatic numbering in console")

        # Use the text editor for alert and remediation info
        alert_info, remediation_info = edit_alert_remediation_info()

        if not alert_info:
            alert_info = f"Policy violation detected for {resource_type}: {description}"
            print_info(f"Using default alert message")

        if alert_info:
            print_success("Alert message created")
        if remediation_info:
            print_success("Remediation steps created")

        # Step 4: Policy Logic
        print_subheader("Step 4: Policy Logic (Rego)")
        print("You can use example policies from simple_examples/ folder")
        if sample_data:
            print(f"Reference the sample asset data you just reviewed")
        print("Opening text editor to create your Rego policy logic...")

        # Create a better template with the actual resource type
        template = f"""package crowdstrike

# Default result - required by CrowdStrike CSPM
default result = "fail"

# This rule applies to {resource_type} resources
is_applicable if {{
    input.resource_type == "{resource_type}"
}}

# Your policy logic here - return "pass" if compliant
result = "pass" if {{
    is_applicable
    # Add your compliance conditions here
    # Example: input.configuration.some_field == "good_value"
}}

# Alternative: Use deny rules that return "fail" with details
result = "fail" if {{
    is_applicable
    # Add your violation conditions here
    # This will automatically fail when conditions are met
}}
"""

        # Step 4.5: Policy Logic with retry capability
        logic = None
        while not logic:
            logic = edit_rego_policy(template)
            if not logic:
                retry = input(f"{Colors.BOLD}Policy logic is required. Try again? (y/N): {Colors.ENDC}")
                if retry.lower() != 'y':
                    print("Policy creation cancelled")
                    return

        # Step 5: Review, Test, and Create with retry loop
        while True:
            print_subheader("Step 5: Review and Create")

            print(f"{Colors.BOLD}Policy Summary:{Colors.ENDC}")
            print(f"  Name: {name}")
            print(f"  Description: {description}")
            print(f"  Resource Type: {resource_type}")
            print(f"  Severity: {severity}")
            print(f"  Logic: {len(logic)} characters")

            print(f"\n{Colors.BOLD}What would you like to do?{Colors.ENDC}")
            print(f"1. {Colors.GREEN}Test Policy Logic{Colors.ENDC} (against real assets)")
            print(f"2. {Colors.BLUE}Edit Policy Logic{Colors.ENDC}")
            print(f"3. {Colors.CYAN}View Policy Logic{Colors.ENDC}")
            print(f"4. {Colors.YELLOW}Create Policy{Colors.ENDC}")
            print("5. Cancel")

            action = input(f"\n{Colors.BOLD}Choose action (1-5): {Colors.ENDC}")

            if action == "1":
                # Test the policy
                test_success = self.test_policy_logic(logic, resource_type)
                if test_success:
                    print(f"\n{Colors.GREEN}Policy testing completed successfully!{Colors.ENDC}")
                    # After successful test, offer next steps without going back to main menu
                    print(f"\n{Colors.BOLD}Testing successful! What would you like to do next?{Colors.ENDC}")
                    print(f"1. {Colors.YELLOW}Create Policy{Colors.ENDC}")
                    print(f"2. {Colors.BLUE}Edit Policy Logic{Colors.ENDC}")
                    print(f"3. {Colors.CYAN}View Policy Logic{Colors.ENDC}")
                    print("4. Cancel")

                    post_test_action = input(f"\n{Colors.BOLD}Choose action (1-4): {Colors.ENDC}")

                    if post_test_action == "1":
                        # Create the policy - break out to creation section
                        break
                    elif post_test_action == "2":
                        # Edit policy logic
                        logic = edit_rego_policy(logic)
                        if not logic:
                            print("Policy creation cancelled")
                            return
                        continue
                    elif post_test_action == "3":
                        # View policy logic
                        print_subheader("Current Policy Logic")
                        print(f"{Colors.CYAN}📋 Complete Rego Code:{Colors.ENDC}")
                        print("─" * 60)
                        print(f"{Colors.HEADER}{logic}{Colors.ENDC}")
                        print("─" * 60)
                        input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                        continue
                    else:
                        # Cancel
                        print("Policy creation cancelled")
                        return
                else:
                    print(f"\n{Colors.RED}Policy testing encountered issues{Colors.ENDC}")
                    print_info("Consider editing your policy logic to address any errors")
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                    continue

            elif action == "2":
                # Edit policy logic
                logic = edit_rego_policy(logic)  # Pass current logic as initial content
                if not logic:
                    print("Policy creation cancelled")
                    return
                continue  # Go back to review

            elif action == "3":
                # View policy logic
                print_subheader("Current Policy Logic")
                print(f"{Colors.CYAN}📋 Complete Rego Code:{Colors.ENDC}")
                print("─" * 60)
                print(f"{Colors.HEADER}{logic}{Colors.ENDC}")
                print("─" * 60)
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                continue

            elif action == "4":
                # Create the policy
                break  # Exit to policy creation

            elif action == "5":
                print("Policy creation cancelled")
                return

            else:
                print_error("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
                continue

            # Create the policy
            headers = self._get_headers()
            create_url = f"{self.base_url}/cloud-policies/entities/rules/v1"

            cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
            payload = {
                "name": name,
                "description": description,
                "logic": logic,
                "resource_type": resource_type,
                "severity": severity,
                "platform": cloud_provider["platform"],
                "provider": cloud_provider["provider"],
                "domain": "CSPM",
                "subdomain": "IOM",
                "alert_info": alert_info,
                "attack_types": "Misconfiguration"
            }

            # Add remediation info if provided
            if remediation_info:
                payload["remediation_info"] = remediation_info

            try:
                response = requests.post(create_url, headers=headers, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    resources = data.get("resources", [])
                    if resources:
                        created_rule = resources[0]
                        print_success("Policy created successfully!")
                        print(f"\n{format_rule_card(created_rule)}")
                    else:
                        print_success("Policy created successfully!")
                    return  # Success, exit the retry loop
                else:
                    error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                    print_error(f"Policy creation failed: {response.status_code}")
                    print(f"Error: {error_data}")

                    # Offer to retry with edited logic
                    print_warning("This is usually caused by Rego syntax errors or policy format issues")
                    retry_edit = input(f"\n{Colors.BOLD}Would you like to edit the Rego logic and try again? (Y/n): {Colors.ENDC}")

                    if retry_edit.lower() != 'n':
                        print_info("Opening editor to fix the Rego policy...")
                        logic = edit_rego_policy(logic)  # Pass current logic to edit
                        if not logic:
                            print("Policy creation cancelled")
                            return
                        continue  # Go back to review and retry
                    else:
                        print("Policy creation cancelled")
                        return

            except Exception as e:
                print_error(f"Policy creation failed: {e}")
                retry_edit = input(f"\n{Colors.BOLD}Would you like to edit the Rego logic and try again? (Y/n): {Colors.ENDC}")
                if retry_edit.lower() != 'n':
                    logic = edit_rego_policy(logic)
                    if not logic:
                        print("Policy creation cancelled")
                        return
                    continue  # Go back to review and retry
                else:
                    return

        # Create the policy (this section runs when user chooses "Create Policy")
        headers = self._get_headers()
        create_url = f"{self.base_url}/cloud-policies/entities/rules/v1"

        cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
        payload = {
            "name": name,
            "description": description,
            "logic": logic,
            "resource_type": resource_type,
            "severity": severity,
            "platform": cloud_provider["platform"],
            "provider": cloud_provider["provider"],
            "domain": "CSPM",
            "subdomain": "IOM",
            "alert_info": alert_info,
            "attack_types": "Misconfiguration"
        }

        # Add remediation info if provided
        if remediation_info:
            payload["remediation_info"] = remediation_info

        try:
            response = requests.post(create_url, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                resources = data.get("resources", [])
                if resources:
                    created_rule = resources[0]
                    print_success("Policy created successfully!")
                    print(f"\n{format_rule_card(created_rule)}")
                else:
                    print_success("Policy created successfully!")
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                print_error(f"Policy creation failed: {response.status_code}")
                print(f"Error: {error_data}")
        except Exception as e:
            print_error(f"Policy creation failed: {e}")

    def main_menu(self):
        """Main interactive menu"""
        print_header("🛠️  CROWDSTRIKE CUSTOM IOM TOOLKIT")

        print(f"{Colors.BOLD}Welcome to the CrowdStrike Custom IOM Management Toolkit!{Colors.ENDC}")
        print("This tool helps you manage Custom Indicators of Misconfiguration (IOMs) in your CrowdStrike CSPM environment.")

        if not self.authenticate():
            return

        while True:
            print(f"\n{Colors.BOLD}{Colors.BLUE}═══════════════════════════════════════════════════════════════════════════════════{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.BLUE}                            MAIN MENU                            {Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.BLUE}═══════════════════════════════════════════════════════════════════════════════════{Colors.ENDC}")

            print(f"\n{Colors.BOLD}What would you like to do?{Colors.ENDC}")
            print(f"\n  {Colors.CYAN}1.{Colors.ENDC} {Colors.BOLD}View Existing Policies{Colors.ENDC} - List and view details of your custom policies")
            print(f"  {Colors.YELLOW}2.{Colors.ENDC} {Colors.BOLD}Update Existing Policy{Colors.ENDC} - Modify an existing custom policy")
            print(f"  {Colors.RED}3.{Colors.ENDC} {Colors.BOLD}Delete Existing Policy{Colors.ENDC} - Remove a custom policy")
            print(f"  {Colors.GREEN}4.{Colors.ENDC} {Colors.BOLD}Create New Policy{Colors.ENDC} - Create a brand new custom policy")
            print(f"  {Colors.HEADER}5.{Colors.ENDC} {Colors.BOLD}Debug: Discover Resource Types{Colors.ENDC} - Find correct resource type names")
            print(f"  {Colors.BLUE}6.{Colors.ENDC} {Colors.BOLD}Exit{Colors.ENDC} - Exit the toolkit")

            try:
                choice = input(f"\n{Colors.BOLD}Enter your choice (1-6): {Colors.ENDC}").strip()

                if choice == "1":
                    self.list_existing_policies()
                elif choice == "2":
                    self.update_existing_policy()
                elif choice == "3":
                    self.delete_existing_policy()
                elif choice == "4":
                    self.create_new_policy()
                elif choice == "5":
                    self.discover_all_resource_types()
                elif choice == "6":
                    print(f"\n{Colors.GREEN}Thank you for using the CrowdStrike Custom IOM Toolkit!{Colors.ENDC}")
                    print(f"{Colors.CYAN}Remember: Your custom policies help strengthen your cloud security posture{Colors.ENDC}")
                    break
                else:
                    print_error("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")

                # Pause before showing menu again
                if choice in ["1", "2", "3", "4", "5"]:
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")

            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}👋 Interrupted by user. Goodbye!{Colors.ENDC}")
                break
            except Exception as e:
                print_error(f"An error occurred: {e}")

def main():
    """Main entry point"""
    # Check if credentials are available
    if not os.getenv('FALCON_CLIENT_ID') or not os.getenv('FALCON_CLIENT_SECRET'):
        print_error("Missing CrowdStrike API credentials!")
        print("\nPlease set your environment variables:")
        print(f"  {Colors.CYAN}export FALCON_CLIENT_ID='your_client_id'{Colors.ENDC}")
        print(f"  {Colors.CYAN}export FALCON_CLIENT_SECRET='your_client_secret'{Colors.ENDC}")
        print(f"\nOptional - Set CrowdStrike cloud environment:")
        print(f"  {Colors.CYAN}export FALCON_BASE_URL='https://api.us-2.crowdstrike.com'{Colors.ENDC}  # For US-2")
        print(f"\nAvailable cloud environments:")
        for cloud_name, cloud_url in CROWDSTRIKE_CLOUDS.items():
            print(f"  {Colors.YELLOW}{cloud_name:<10}{Colors.ENDC}: {cloud_url}")
        print("\nThen run the toolkit again.")
        return

    # Initialize and run toolkit
    toolkit = CustomIOMToolkit()
    toolkit.main_menu()

def run_cli():
    """Run CLI mode - wrapper for existing main function"""
    main()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='CrowdStrike Custom IOM Toolkit')
    parser.add_argument('--cli', action='store_true',
                       help='Use command line interface (default is GUI)')

    args = parser.parse_args()

    if args.cli:
        # Explicit CLI mode
        run_cli()
    else:
        # Default to GUI, fallback to CLI if GUI unavailable
        try:
            import dearpygui.dearpygui as dpg
            from custom_iom_gui_clean import run_gui
            print("Launching GUI mode...")
            print("Use --cli flag to use command line interface")
            run_gui()
        except ImportError as e:
            print("GUI mode not available:")
            print(f"   {e}")
            print("Install GUI support: pip install dearpygui")
            print("Falling back to CLI mode...")
            run_cli()
        except Exception as e:
            print(f"GUI error: {e}")
            print("Falling back to CLI mode...")
            run_cli()