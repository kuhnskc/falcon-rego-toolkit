#!/usr/bin/env python3

"""
CrowdStrike Custom IOM Toolkit - GUI Interface
Professional interface matching CLI functionality without emojis
"""

import dearpygui.dearpygui as dpg
import sys
import os
import tempfile
import subprocess
import requests
import re
import time
from typing import Dict, List, Any, Optional

# Import from existing CLI
try:
    from custom_iom_toolkit import CustomIOMToolkit, Colors, clean_remediation_format, CROWDSTRIKE_CLOUDS, determine_cloud_provider_from_resource_type
except ImportError as e:
    print(f"Error importing CLI: {e}")
    sys.exit(1)

# Professional themes collection
THEMES = {
    'crowdstrike': {
        'name': 'CrowdStrike Red',
        'bg_primary': [18, 18, 23],
        'bg_secondary': [28, 28, 33],
        'bg_tertiary': [38, 38, 43],
        'accent_red': [220, 53, 69],
        'accent_orange': [255, 131, 0],
        'accent_blue': [0, 123, 255],
        'text_primary': [255, 255, 255],
        'text_secondary': [180, 180, 185],
        'success_green': [40, 167, 69],
        'border': [70, 70, 80],
    },
    'ocean': {
        'name': 'Ocean Blue',
        'bg_primary': [15, 20, 25],
        'bg_secondary': [25, 35, 45],
        'bg_tertiary': [35, 45, 55],
        'accent_red': [72, 149, 239],
        'accent_orange': [52, 168, 182],
        'accent_blue': [0, 175, 255],
        'text_primary': [255, 255, 255],
        'text_secondary': [180, 190, 200],
        'success_green': [46, 204, 113],
        'border': [60, 80, 100],
    },
    'matrix': {
        'name': 'Matrix Green',
        'bg_primary': [0, 0, 0],
        'bg_secondary': [10, 10, 10],
        'bg_tertiary': [20, 20, 20],
        'accent_red': [0, 255, 65],
        'accent_orange': [50, 205, 50],
        'accent_blue': [0, 250, 154],
        'text_primary': [0, 0, 0],
        'text_secondary': [100, 200, 100],
        'success_green': [0, 255, 0],
        'border': [0, 128, 0],
    },
    'sunset': {
        'name': 'Sunset Orange',
        'bg_primary': [25, 18, 15],
        'bg_secondary': [35, 28, 25],
        'bg_tertiary': [45, 38, 35],
        'accent_red': [255, 94, 77],
        'accent_orange': [255, 154, 0],
        'accent_blue': [255, 193, 7],
        'text_primary': [255, 255, 255],
        'text_secondary': [220, 200, 180],
        'success_green': [76, 175, 80],
        'border': [100, 70, 50],
    },
    'discord': {
        'name': 'Discord Purple',
        'bg_primary': [32, 34, 37],
        'bg_secondary': [47, 49, 54],
        'bg_tertiary': [64, 68, 75],
        'accent_red': [114, 137, 218],
        'accent_orange': [153, 170, 181],
        'accent_blue': [88, 101, 242],
        'text_primary': [255, 255, 255],
        'text_secondary': [181, 186, 193],
        'success_green': [67, 181, 129],
        'border': [78, 80, 88],
    },
    'light': {
        'name': 'Light Mode',
        'bg_primary': [245, 245, 245],
        'bg_secondary': [255, 255, 255],
        'bg_tertiary': [250, 250, 250],
        'accent_red': [220, 53, 69],
        'accent_orange': [255, 131, 0],
        'accent_blue': [0, 123, 255],
        'text_primary': [33, 37, 41],
        'text_secondary': [108, 117, 125],
        'success_green': [40, 167, 69],
        'border': [200, 200, 200],
    }
}

# Current theme - default to CrowdStrike
THEME = THEMES['crowdstrike']

class CustomIOMGUI:
    def __init__(self):
        self.toolkit = None
        self.policies = []
        self.selected_policy = None
        self.authenticated = False
        self.credentials_provided = False
        self.current_theme = 'crowdstrike'  # Default theme
        self.token_expires_at = None  # Track when the token expires
        self.token_duration = 30 * 60  # CrowdStrike tokens typically last 30 minutes
        self.selected_base_url = None  # Track selected base URL

        # Check for credentials and prompt if needed
        self.check_and_get_credentials()

    def check_and_get_credentials(self):
        """Check for credentials and show dialog if needed"""
        client_id = os.getenv('FALCON_CLIENT_ID', '')
        client_secret = os.getenv('FALCON_CLIENT_SECRET', '')
        base_url = os.getenv('FALCON_BASE_URL', '')

        # Set base URL from environment variable if available
        if base_url:
            self.selected_base_url = base_url

        if client_id and client_secret:
            self.initialize_toolkit()
        else:
            self.credentials_provided = False
            print("No API credentials found in environment variables")
            print("GUI will prompt for credentials")

    def initialize_toolkit(self):
        """Initialize toolkit and authenticate"""
        try:
            # Pass base URL to toolkit if we have one selected
            if self.selected_base_url:
                self.toolkit = CustomIOMToolkit(base_url=self.selected_base_url)
            else:
                self.toolkit = CustomIOMToolkit()

            self.authenticated = self.toolkit.authenticate()
            if self.authenticated:
                # Set token expiration time (CrowdStrike tokens are typically valid for 30 minutes)
                self.token_expires_at = time.time() + self.token_duration
                print("Authentication successful")
            else:
                self.token_expires_at = None
                print("Authentication failed")
        except Exception as e:
            print(f"Error during authentication: {e}")
            self.authenticated = False
            self.token_expires_at = None

    def is_token_valid(self) -> bool:
        """Check if the current token is still valid"""
        if not self.authenticated or not self.token_expires_at:
            return False

        # Check if token expires in the next 5 minutes (buffer time)
        return time.time() < (self.token_expires_at - 300)

    def ensure_authenticated(self) -> bool:
        """Ensure we have a valid token, re-authenticate if needed"""
        if not self.is_token_valid():
            print("Token expired or invalid, re-authenticating...")
            if self.toolkit:
                success = self.toolkit.authenticate()
                if success:
                    self.authenticated = True
                    self.token_expires_at = time.time() + self.token_duration
                    print("Re-authentication successful")
                    return True
                else:
                    self.authenticated = False
                    self.token_expires_at = None
                    print("Re-authentication failed")
                    return False
            else:
                self.authenticated = False
                self.token_expires_at = None
                return False
        return True

    def handle_api_error(self, response, operation_name: str = "API call") -> bool:
        """Handle API errors and attempt re-authentication for 401 errors"""
        if response.status_code == 401:
            print(f"401 Unauthorized received during {operation_name}, attempting re-authentication...")
            if self.ensure_authenticated():
                print("Re-authentication successful, please retry the operation")
                self.show_info("Session expired. Re-authenticated successfully. Please retry your last action.")
                return True
            else:
                self.show_error("Session expired and re-authentication failed. Please check your credentials.")
                self.authenticated = False
                self.token_expires_at = None
                return False
        return False

    def convert_processed_to_pipe_format(self, processed_text: str) -> str:
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

    def setup_theme(self):
        """Setup theme based on current selection"""
        global THEME
        THEME = THEMES[self.current_theme]

        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, THEME['bg_primary'])
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, THEME['bg_secondary'])
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, THEME['bg_secondary'])
                dpg.add_theme_color(dpg.mvThemeCol_Button, THEME['accent_red'])
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, [min(255, THEME['accent_red'][0] + 20),
                                                                  min(255, THEME['accent_red'][1] + 20),
                                                                  min(255, THEME['accent_red'][2] + 20)])
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [max(0, THEME['accent_red'][0] - 20),
                                                                 max(0, THEME['accent_red'][1] - 20),
                                                                 max(0, THEME['accent_red'][2] - 20)])
                dpg.add_theme_color(dpg.mvThemeCol_Text, THEME['text_primary'])
                dpg.add_theme_color(dpg.mvThemeCol_Header, THEME['accent_red'])
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, [min(255, THEME['accent_red'][0] + 20),
                                                                  min(255, THEME['accent_red'][1] + 20),
                                                                  min(255, THEME['accent_red'][2] + 20)])
                dpg.add_theme_color(dpg.mvThemeCol_TableHeaderBg, THEME['accent_red'])
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, THEME['bg_tertiary'])
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, [min(255, THEME['bg_tertiary'][0] + 10),
                                                                   min(255, THEME['bg_tertiary'][1] + 10),
                                                                   min(255, THEME['bg_tertiary'][2] + 10)])
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, [min(255, THEME['bg_tertiary'][0] + 20),
                                                                  min(255, THEME['bg_tertiary'][1] + 20),
                                                                  min(255, THEME['bg_tertiary'][2] + 20)])
                dpg.add_theme_color(dpg.mvThemeCol_Border, THEME['border'])
        dpg.bind_theme(global_theme)

    def show_theme_selector(self):
        """Show theme selection dialog"""
        if dpg.does_item_exist("theme_window"):
            dpg.delete_item("theme_window")

        with dpg.window(label="Select Theme", modal=True, show=True,
                       width=450, height=400, pos=[375, 200], tag="theme_window"):

            dpg.add_text("Choose Your Theme", color=THEME['accent_orange'])
            dpg.add_separator()
            dpg.add_spacer(height=15)

            # Theme preview and selection
            for theme_key, theme_data in THEMES.items():
                with dpg.group(horizontal=True):
                    # Theme color preview
                    with dpg.drawlist(width=30, height=25):
                        dpg.draw_rectangle((0, 0), (30, 25), fill=theme_data['accent_red'])

                    dpg.add_spacer(width=10)

                    # Theme selection button
                    is_current = theme_key == self.current_theme
                    button_label = f"[ACTIVE] {theme_data['name']}" if is_current else theme_data['name']
                    button_width = 300

                    dpg.add_button(
                        label=button_label,
                        width=button_width,
                        height=30,
                        user_data=theme_key,
                        callback=lambda s, a, theme: self.change_theme(theme)
                    )

                dpg.add_spacer(height=8)

            dpg.add_spacer(height=15)
            dpg.add_separator()
            dpg.add_spacer(height=10)

            dpg.add_button(label="Close", width=100, height=35,
                         callback=lambda: dpg.delete_item("theme_window"))

    def change_theme(self, theme_key):
        """Change the application theme"""
        self.current_theme = theme_key
        dpg.delete_item("theme_window")

        # Reapply theme
        self.setup_theme()

        # Show success message
        theme_name = THEMES[theme_key]['name']
        self.show_success(f"Theme changed to {theme_name}!")

    def show_credentials_dialog(self):
        """Show credentials input dialog"""
        if dpg.does_item_exist("credentials_window"):
            dpg.delete_item("credentials_window")

        with dpg.window(label="CrowdStrike API Credentials", modal=True, show=True,
                       width=800, height=500, pos=[100, 100], tag="credentials_window"):

            dpg.add_text("Enter your CrowdStrike API credentials",
                        color=THEME['accent_orange'])
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Base URL / Cloud Environment Selection
            dpg.add_text("Cloud Environment:", color=THEME['text_primary'])
            dpg.add_spacer(height=5)

            # Get current selection or default
            current_base_url = self.selected_base_url or os.getenv('FALCON_BASE_URL', '')
            if not current_base_url:
                current_base_url = CROWDSTRIKE_CLOUDS['US-1']  # Default to US-1

            # Find which cloud environment matches current URL
            selected_cloud = 'US-1'  # Default
            for cloud_name, cloud_url in CROWDSTRIKE_CLOUDS.items():
                if current_base_url == cloud_url:
                    selected_cloud = cloud_name
                    break

            # Create radio buttons for cloud environments
            dpg.add_text("Select your CrowdStrike cloud environment:", color=THEME['text_secondary'])
            dpg.add_spacer(height=5)

            # Store the cloud environment names for the radio button group
            cloud_names = list(CROWDSTRIKE_CLOUDS.keys())
            selected_index = cloud_names.index(selected_cloud) if selected_cloud in cloud_names else 0

            # Create cloud options with URLs inline
            cloud_options_with_urls = []
            for cloud_name in cloud_names:
                cloud_url = CROWDSTRIKE_CLOUDS[cloud_name]
                cloud_options_with_urls.append(f"{cloud_name} - {cloud_url}")

            # Create a single radio button group that works properly
            dpg.add_radio_button(cloud_options_with_urls, default_value=selected_index,
                                tag="cloud_radio_group",
                                callback=lambda s, a: self.set_cloud_selection_by_index(dpg.get_value("cloud_radio_group")))

            dpg.add_spacer(height=15)
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Credentials
            dpg.add_text("Client ID:", color=THEME['text_primary'])
            dpg.add_input_text(hint="your_client_id", width=550, tag="client_id_input")

            dpg.add_spacer(height=10)
            dpg.add_text("Client Secret:", color=THEME['text_primary'])
            dpg.add_input_text(hint="your_client_secret", width=550,
                              password=True, tag="client_secret_input")

            dpg.add_spacer(height=20)

            with dpg.group(horizontal=True):
                dpg.add_button(label="Connect", width=100, height=35,
                             callback=self.authenticate_with_credentials)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel", width=100, height=35,
                             callback=self.cancel_credentials)

            dpg.add_spacer(height=10)
            dpg.add_separator()
            dpg.add_text("Tip: Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_BASE_URL",
                        color=THEME['text_secondary'])
            dpg.add_text("environment variables to skip this dialog",
                        color=THEME['text_secondary'])

    def set_cloud_selection_by_index(self, index):
        """Set selected cloud environment by index"""
        # Ensure index is an integer
        if isinstance(index, str):
            try:
                index = int(index)
            except (ValueError, TypeError):
                return

        cloud_names = list(CROWDSTRIKE_CLOUDS.keys())
        if 0 <= index < len(cloud_names):
            cloud_name = cloud_names[index]
            self.selected_base_url = CROWDSTRIKE_CLOUDS[cloud_name]

    def set_cloud_selection(self, cloud_name):
        """Set selected cloud environment by name"""
        self.selected_base_url = CROWDSTRIKE_CLOUDS[cloud_name]

    def authenticate_with_credentials(self):
        """Authenticate using provided credentials"""
        client_id = dpg.get_value("client_id_input").strip()
        client_secret = dpg.get_value("client_secret_input").strip()

        if not client_id or not client_secret:
            self.show_error("Please enter both Client ID and Client Secret")
            return

        # Get base URL from selected cloud environment
        if not self.selected_base_url:
            # Default to US-1 if nothing selected
            self.selected_base_url = CROWDSTRIKE_CLOUDS['US-1']

        # Set credentials temporarily for this session
        os.environ['FALCON_CLIENT_ID'] = client_id
        os.environ['FALCON_CLIENT_SECRET'] = client_secret
        if self.selected_base_url:
            os.environ['FALCON_BASE_URL'] = self.selected_base_url

        # Initialize toolkit with new credentials and base URL
        self.initialize_toolkit()

        if self.authenticated:
            dpg.delete_item("credentials_window")
            self.credentials_provided = True
            # Set token expiration time when successfully authenticated
            self.token_expires_at = time.time() + self.token_duration
            self.show_main_menu()

            # Show which cloud we connected to
            cloud_name = self._get_cloud_name_from_url(self.selected_base_url)
            if cloud_name:
                self.show_success(f"Successfully authenticated with CrowdStrike {cloud_name} cloud!")
            else:
                self.show_success(f"Successfully authenticated with CrowdStrike API!")
        else:
            self.show_error("Authentication failed. Please check your credentials and cloud environment.")

    def _get_cloud_name_from_url(self, url: str) -> Optional[str]:
        """Get cloud environment name from URL"""
        for cloud_name, cloud_url in CROWDSTRIKE_CLOUDS.items():
            if url == cloud_url:
                return cloud_name
        return None

    def cancel_credentials(self):
        """Cancel credentials dialog"""
        dpg.delete_item("credentials_window")
        self.show_main_menu()

    def show_main_menu(self):
        """Show main menu - matches CLI functionality exactly"""
        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        with dpg.child_window(parent="main_content", border=False):
            # Header
            dpg.add_text("CrowdStrike Custom IOM Toolkit", color=THEME['accent_red'])
            dpg.add_text("Manage Custom Indicators of Misconfiguration (IOMs)",
                        color=THEME['text_secondary'])
            dpg.add_spacer(height=20)

            # Show credentials button if not authenticated
            if not self.authenticated and not self.credentials_provided:
                dpg.add_text("API credentials required", color=THEME['accent_orange'])
                dpg.add_spacer(height=10)
                dpg.add_button(label="Enter API Credentials", width=300, height=40,
                             callback=self.show_credentials_dialog)
                dpg.add_spacer(height=20)
            else:
                # Main menu options (matching CLI exactly)
                dpg.add_text("What would you like to do?", color=THEME['text_primary'])
                dpg.add_spacer(height=15)

                dpg.add_button(label="1. View Existing Policies", width=300, height=40,
                             callback=self.view_existing_policies)
                dpg.add_spacer(height=8)

                dpg.add_button(label="2. Delete Existing Policy", width=300, height=40,
                             callback=self.delete_existing_policy)
                dpg.add_spacer(height=8)

                dpg.add_button(label="3. Create New Policy", width=300, height=40,
                             callback=self.create_new_policy)
                dpg.add_spacer(height=8)

            dpg.add_spacer(height=20)
            dpg.add_separator()

            # Status and settings
            if self.is_token_valid():
                time_remaining = int((self.token_expires_at - time.time()) / 60) if self.token_expires_at else 0
                cloud_info = ""
                if self.selected_base_url:
                    cloud_name = self._get_cloud_name_from_url(self.selected_base_url)
                    if cloud_name:
                        cloud_info = f" ({cloud_name})"
                    else:
                        cloud_info = f" (Custom: {self.selected_base_url})"

                dpg.add_text(f"Status: Connected to CrowdStrike API{cloud_info} (expires in {time_remaining}min)",
                           color=THEME['success_green'])
                dpg.add_spacer(height=10)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Change Credentials", width=150, height=30,
                                 callback=self.show_credentials_dialog)
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Theme Settings", width=120, height=30,
                                 callback=self.show_theme_selector)
            else:
                dpg.add_text("Status: Not authenticated or session expired", color=THEME['accent_red'])
                dpg.add_spacer(height=10)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Re-authenticate", width=120, height=30,
                                 callback=self.show_credentials_dialog)
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Theme Settings", width=120, height=30,
                                 callback=self.show_theme_selector)

    def view_existing_policies(self):
        """View existing policies - matches CLI list_existing_policies"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        try:
            self.policies = self.toolkit.discover_custom_rules()
            self.show_policy_list()
        except Exception as e:
            self.show_error(f"Failed to load policies: {str(e)}")

    def show_policy_list(self):
        """Show policy list with full details"""
        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        with dpg.child_window(parent="main_content", border=False):
            # Header
            with dpg.group(horizontal=True):
                dpg.add_text("Custom IOM Policies", color=THEME['accent_orange'])
                dpg.add_spacer(width=50)
                dpg.add_button(label="Refresh", callback=self.view_existing_policies)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Back to Main Menu", callback=self.show_main_menu)

            dpg.add_separator()
            dpg.add_spacer(height=10)

            if not self.policies:
                dpg.add_text("No Custom IOM policies found")
                return

            dpg.add_text(f"Found {len(self.policies)} custom policies:")
            dpg.add_spacer(height=10)

            # Detailed policy table
            with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True,
                         borders_innerV=True, scrollY=True, height=500):
                dpg.add_table_column(label="Name", width=200)
                dpg.add_table_column(label="Description", width=300)
                dpg.add_table_column(label="Severity", width=80)
                dpg.add_table_column(label="Resource Type", width=180)
                dpg.add_table_column(label="Created", width=100)
                dpg.add_table_column(label="Actions", width=120)

                for i, policy in enumerate(self.policies):
                    with dpg.table_row():
                        # Name
                        name = policy.get('name', 'Unknown')
                        if len(name) > 25:
                            name = name[:22] + "..."
                        dpg.add_text(name)

                        # Description
                        desc = policy.get('description', 'No description')
                        if len(desc) > 40:
                            desc = desc[:37] + "..."
                        dpg.add_text(desc)

                        # Severity
                        severity = policy.get('severity', 3)
                        severity_text = ["Critical", "High", "Medium", "Low"][min(severity, 3)]
                        severity_colors = [
                            THEME['accent_red'], THEME['accent_orange'],
                            [255, 193, 7], THEME['success_green']
                        ]
                        dpg.add_text(severity_text, color=severity_colors[min(severity, 3)])

                        # Resource Type
                        resource_types = policy.get('resource_types', [])
                        if resource_types and len(resource_types) > 0:
                            resource_type = resource_types[0].get('resource_type', 'Unknown')
                            if len(resource_type) > 20:
                                resource_type = resource_type[:17] + "..."
                        else:
                            resource_type = 'Unknown'
                        dpg.add_text(resource_type)

                        # Created date
                        created = policy.get('created_at', '')
                        if created:
                            created = created[:10]  # Just date part
                        dpg.add_text(created)

                        # Actions
                        with dpg.group(horizontal=True):
                            button_tag = f"view_btn_{i}"
                            dpg.add_button(label="Manage", tag=button_tag, width=80,
                                         user_data=policy,
                                         callback=lambda s, a, u: self.show_policy_management(u))

    def show_policy_management(self, policy):
        """Show policy management options - matches CLI _update_policy_interactive"""
        self.selected_policy = policy

        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        with dpg.child_window(parent="main_content", border=False):
            # Policy header
            severity = policy.get('severity', 3)
            severity_text = ["Critical", "High", "Medium", "Low"][min(severity, 3)]
            severity_colors = [
                THEME['accent_red'], THEME['accent_orange'],
                [255, 193, 7], THEME['success_green']
            ]

            dpg.add_text(f"Managing Policy: {policy.get('name', 'Unknown')}",
                        color=THEME['accent_red'])
            dpg.add_text(f"Severity: {severity_text}",
                        color=severity_colors[min(severity, 3)])
            dpg.add_separator()

            # Policy details
            dpg.add_text("Description:", color=THEME['accent_orange'])
            dpg.add_text(policy.get('description', 'No description'), wrap=600)

            dpg.add_spacer(height=10)
            dpg.add_text(f"UUID: {policy.get('uuid', 'Unknown')}",
                        color=THEME['text_secondary'])

            resource_types = policy.get('resource_types', [])
            if resource_types and len(resource_types) > 0:
                resource_type = resource_types[0].get('resource_type', 'Unknown')
                dpg.add_text(f"Resource Type: {resource_type}",
                           color=THEME['text_secondary'])

            dpg.add_spacer(height=20)
            dpg.add_text("Management Options:", color=THEME['accent_orange'])
            dpg.add_spacer(height=10)

            # Use horizontal layout for buttons and test results
            with dpg.group(horizontal=True):
                # Left side - Management buttons
                with dpg.group():
                    dpg.add_button(label="1. Edit Description", width=280, height=40,
                                 callback=lambda: self.edit_description())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="2. Edit Severity", width=280, height=40,
                                 callback=lambda: self.edit_severity())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="3. Edit Alert Info", width=280, height=40,
                                 callback=lambda: self.edit_alert_info())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="4. Edit Remediation Info", width=280, height=40,
                                 callback=lambda: self.edit_remediation_info())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="5. Update Rego Logic", width=280, height=40,
                                 callback=lambda: self.update_rego_logic())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="6. Test Policy", width=280, height=40,
                                 callback=lambda: self.test_policy_inline())
                    dpg.add_spacer(height=8)

                    dpg.add_button(label="7. Export Sample Asset Data", width=280, height=40,
                                 callback=lambda: self.export_sample_asset_data())
                    dpg.add_spacer(height=8)

                    dpg.add_text("Note: Tests against 3 assets for performance",
                               color=THEME['text_secondary'])
                    dpg.add_spacer(height=8)

                dpg.add_spacer(width=50)

                # Right side - Test Results Area
                with dpg.group():
                    dpg.add_text("Policy Test Results:", color=THEME['accent_blue'])
                    dpg.add_separator()
                    dpg.add_spacer(height=10)

                    # Test results container
                    with dpg.child_window(height=300, width=600, border=True, tag="test_results_area"):
                        dpg.add_text("Click 'Test Policy' to run policy against live resources",
                                   color=THEME['text_secondary'], wrap=580, tag="test_status_text")

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Back to Policy List", width=200, height=40,
                             callback=self.view_existing_policies)
                dpg.add_spacer(width=15)
                dpg.add_button(label="Main Menu", width=200, height=40,
                             callback=self.show_main_menu)

    def edit_description(self):
        """Edit policy description"""
        if not self.selected_policy:
            return

        current_desc = self.selected_policy.get('description', '')

        with dpg.window(label="Edit Description", modal=True, show=True,
                       width=500, height=300, pos=[100, 100], tag="edit_desc_window"):

            dpg.add_text("Enter new description:")
            dpg.add_spacer(height=10)

            dpg.add_input_text(default_value=current_desc, multiline=True,
                              width=460, height=120, tag="desc_input")

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save Changes", callback=self.save_description)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel",
                             callback=lambda: dpg.delete_item("edit_desc_window"))

    def save_description(self):
        """Save description changes"""
        print("DEBUG: save_description called")  # Debug line

        # Check if the input field exists
        if not dpg.does_item_exist("desc_input"):
            print("DEBUG: desc_input field not found!")  # Debug line
            self.show_error("Input field not found")
            return

        new_desc = dpg.get_value("desc_input")
        print(f"DEBUG: Got description value: '{new_desc}'")  # Debug line

        if not new_desc or not new_desc.strip():
            print("DEBUG: Description is empty")  # Debug line
            self.show_error("Description cannot be empty")
            return

        # Ensure we have a valid token before making the API call
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        print("DEBUG: Starting API call...")  # Debug line
        try:
            headers = self.toolkit._get_headers()
            update_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"
            print(f"DEBUG: URL: {update_url}")  # Debug line

            # Use the correct payload format that matches the CLI
            payload = {
                "uuid": self.selected_policy['uuid'],
                "description": new_desc
            }
            print(f"DEBUG: Payload: {payload}")  # Debug line

            response = requests.patch(update_url, headers=headers, json=payload)
            print(f"DEBUG: Response status: {response.status_code}")  # Debug line

            if response.status_code == 200:
                print("DEBUG: Update successful")  # Debug line
                self.selected_policy['description'] = new_desc
                dpg.delete_item("edit_desc_window")
                self.show_success("Description updated successfully!")
                self.show_policy_management(self.selected_policy)
            elif self.handle_api_error(response, "description update"):
                # Token was refreshed, user should retry
                return
            else:
                print(f"DEBUG: API error - Status: {response.status_code}")  # Debug line
                print(f"DEBUG: Response content: {response.text}")  # Debug line
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Update failed: {error_msg}")

        except Exception as e:
            print(f"DEBUG: Exception occurred: {str(e)}")  # Debug line
            import traceback
            traceback.print_exc()  # Print full stack trace
            self.show_error(f"Error updating description: {str(e)}")

    def edit_severity(self):
        """Edit policy severity"""
        if not self.selected_policy:
            return

        # Clean up any existing window first
        if dpg.does_item_exist("edit_severity_window"):
            dpg.delete_item("edit_severity_window")

        current_severity = self.selected_policy.get('severity', 3)

        with dpg.window(label="Edit Severity", modal=True, show=True,
                       width=400, height=450, pos=[150, 150], tag="edit_severity_window"):

            dpg.add_text("Select severity level:", color=THEME['accent_orange'])
            dpg.add_spacer(height=10)

            # Severity options with descriptions (API only accepts 0-3)
            severity_options = [
                (0, "Critical", "Immediate action required", THEME['accent_red']),
                (1, "High", "Important security issue", THEME['accent_orange']),
                (2, "Medium", "Moderate security concern", [255, 193, 7]),
                (3, "Informational", "Minor issue or informational", THEME['success_green'])
            ]

            # Initialize selection state
            self.edit_selected_severity = None  # Track selection state

            # Create individual selectable buttons
            for i, (value, label, description, color) in enumerate(severity_options):
                button_label = f"{label} (Level {value})"

                # Create button that changes appearance when selected
                button_tag = f"edit_severity_button_{i}"
                dpg.add_button(
                    label=button_label,
                    width=280,
                    height=35,
                    tag=button_tag,
                    user_data=value,
                    callback=lambda s, a, severity_val: self.select_edit_severity_button(severity_val)
                )
                dpg.add_spacer(height=5)

            dpg.add_spacer(height=10)
            dpg.add_text(f"Current severity: {severity_options[current_severity][1]} (Level {current_severity})",
                        color=THEME['text_secondary'])
            dpg.add_text("Please select a new severity level above",
                        color=THEME['text_secondary'], tag="edit_severity_instruction_text")

            dpg.add_spacer(height=15)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save Changes", callback=self.save_severity)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel",
                             callback=lambda: dpg.delete_item("edit_severity_window"))

    def select_edit_severity_button(self, severity_value):
        """Handle severity button selection with visual feedback for editing"""
        # Store the selected severity
        self.edit_selected_severity = severity_value

        # Update button appearances - make selected button look pressed/highlighted
        severity_options = [
            (0, "Critical", "Immediate action required", THEME['accent_red']),
            (1, "High", "Important security issue", THEME['accent_orange']),
            (2, "Medium", "Moderate security concern", [255, 193, 7]),
            (3, "Informational", "Minor issue or informational", THEME['success_green'])
        ]

        for i, (value, label, description, color) in enumerate(severity_options):
            button_tag = f"edit_severity_button_{i}"
            if dpg.does_item_exist(button_tag):
                if value == severity_value:
                    # Selected button - change appearance to show selection
                    dpg.configure_item(button_tag, label=f">>> {label} (Level {value}) <<<")
                else:
                    # Unselected button - normal appearance
                    dpg.configure_item(button_tag, label=f"{label} (Level {value})")

        # Update instruction text to show current selection
        if dpg.does_item_exist("edit_severity_instruction_text"):
            selected_name = severity_options[severity_value][1]
            dpg.set_value("edit_severity_instruction_text", f"Selected: {selected_name} (Level {severity_value})")

    def set_severity_selection_by_index(self, index):
        """Set severity selection by index"""
        # Ensure index is an integer
        if isinstance(index, str):
            try:
                index = int(index)
            except (ValueError, TypeError):
                return

        # Index corresponds directly to severity level (0=Critical, 1=High, 2=Medium, 3=Low)
        if 0 <= index <= 3:
            self.selected_severity = index

    def save_severity(self):
        """Save severity changes"""
        # Get severity from the button selection
        if not hasattr(self, 'edit_selected_severity') or self.edit_selected_severity is None:
            self.show_error("Please select a severity level")
            return

        new_severity = self.edit_selected_severity

        if new_severity is None or not (0 <= new_severity <= 3):
            self.show_error("Please select a valid severity level")
            return

        # Ensure we have a valid token before making the API call
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        print("DEBUG: Starting API call...")  # Debug line
        try:
            headers = self.toolkit._get_headers()
            update_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"
            print(f"DEBUG: URL: {update_url}")  # Debug line

            payload = {
                "uuid": self.selected_policy['uuid'],
                "severity": int(new_severity)
            }
            print(f"DEBUG: Payload: {payload}")  # Debug line

            response = requests.patch(update_url, headers=headers, json=payload)
            print(f"DEBUG: Response status: {response.status_code}")  # Debug line

            if response.status_code == 200:
                print("DEBUG: Update successful")  # Debug line
                self.selected_policy['severity'] = int(new_severity)
                dpg.delete_item("edit_severity_window")
                self.show_success("Severity updated successfully!")
                self.show_policy_management(self.selected_policy)
            elif self.handle_api_error(response, "severity update"):
                # Token was refreshed, user should retry
                return
            else:
                print(f"DEBUG: API error - Status: {response.status_code}")  # Debug line
                print(f"DEBUG: Response content: {response.text}")  # Debug line
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Update failed: {error_msg}")

        except Exception as e:
            print(f"DEBUG: Exception occurred: {str(e)}")  # Debug line
            import traceback
            traceback.print_exc()  # Print full stack trace
            self.show_error(f"Error updating severity: {str(e)}")

    def edit_alert_info(self):
        """Edit alert information with pipe format guidance"""
        if not self.selected_policy:
            return

        # Convert API processed format back to pipe format for editing
        current_alert = self.selected_policy.get('alert_info', '')
        if current_alert:
            # Convert from "1. Point 1\n2. Point 2" back to "Point 1|Point 2"
            current_alert = self.convert_processed_to_pipe_format(current_alert)

        with dpg.window(label="Edit Alert Information", modal=True, show=True,
                       width=600, height=400, pos=[100, 100], tag="edit_alert_window"):

            dpg.add_text("Edit Alert Information:", color=THEME['accent_orange'])
            dpg.add_spacer(height=5)
            dpg.add_text("Format: Separate each point with | (pipe character)",
                        color=THEME['text_secondary'])
            dpg.add_text("CrowdStrike will automatically number them as 1. 2. 3. etc.",
                        color=THEME['text_secondary'])
            dpg.add_spacer(height=10)

            dpg.add_input_text(default_value=current_alert, multiline=True,
                              width=560, height=180, tag="alert_input")

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save Changes", callback=self.save_alert_info)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel",
                             callback=lambda: dpg.delete_item("edit_alert_window"))

    def save_alert_info(self):
        """Save alert info changes"""
        new_alert = dpg.get_value("alert_input")

        try:
            headers = self.toolkit._get_headers()
            update_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"

            payload = {
                "uuid": self.selected_policy['uuid'],
                "alert_info": new_alert
            }

            response = requests.patch(update_url, headers=headers, json=payload)
            if response.status_code == 200:
                self.selected_policy['alert_info'] = new_alert
                dpg.delete_item("edit_alert_window")
                self.show_success("Alert information updated successfully!")
                self.show_policy_management(self.selected_policy)
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Update failed: {error_msg}")

        except Exception as e:
            self.show_error(f"Error updating alert info: {str(e)}")

    def edit_remediation_info(self):
        """Edit remediation information with pipe format guidance"""
        if not self.selected_policy:
            return

        # Get current remediation from rule_logic_list and convert to pipe format
        current_remediation = ""
        rule_logic_list = self.selected_policy.get('rule_logic_list', [])
        if rule_logic_list and len(rule_logic_list) > 0:
            current_remediation = rule_logic_list[0].get('remediation_info', '')
            if current_remediation:
                # Convert from "1. Step 1\n2. Step 2" back to "Step 1|Step 2"
                current_remediation = self.convert_processed_to_pipe_format(current_remediation)

        with dpg.window(label="Edit Remediation Steps", modal=True, show=True,
                       width=600, height=400, pos=[100, 100], tag="edit_remediation_window"):

            dpg.add_text("Edit Remediation Steps:", color=THEME['accent_orange'])
            dpg.add_spacer(height=5)
            dpg.add_text("Format: Separate each step with | (pipe character)",
                        color=THEME['text_secondary'])
            dpg.add_text("CrowdStrike will automatically number them as Step 1. Step 2. etc.",
                        color=THEME['text_secondary'])
            dpg.add_spacer(height=10)

            dpg.add_input_text(default_value=current_remediation, multiline=True,
                              width=560, height=180, tag="remediation_input")

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save Changes", callback=self.save_remediation_info)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel",
                             callback=lambda: dpg.delete_item("edit_remediation_window"))

    def save_remediation_info(self):
        """Save remediation info changes"""
        new_remediation = dpg.get_value("remediation_input")

        try:
            # Get current Rego logic to preserve it
            current_logic = ""
            rule_logic_list = self.selected_policy.get('rule_logic_list', [])
            if rule_logic_list and len(rule_logic_list) > 0:
                current_logic = rule_logic_list[0].get('logic', '')

            if current_logic:
                headers = self.toolkit._get_headers()
                update_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"

                # Get resource type for dynamic provider detection
                resource_type = "Unknown"
                if self.selected_policy.get('resource_types') and len(self.selected_policy['resource_types']) > 0:
                    resource_type = self.selected_policy['resource_types'][0].get('resource_type', 'Unknown')

                cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
                payload = {
                    "uuid": self.selected_policy['uuid'],
                    "rule_logic_list": [{
                        "logic": current_logic,
                        "platform": cloud_provider["platform"],
                        "remediation_info": new_remediation
                    }]
                }

                response = requests.patch(update_url, headers=headers, json=payload)
                if response.status_code == 200:
                    if 'rule_logic_list' not in self.selected_policy:
                        self.selected_policy['rule_logic_list'] = [{}]
                    self.selected_policy['rule_logic_list'][0]['remediation_info'] = new_remediation

                    dpg.delete_item("edit_remediation_window")
                    self.show_success("Remediation steps updated successfully!")
                    self.show_policy_management(self.selected_policy)
                else:
                    error_data = response.json() if response.content else {}
                    error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                    self.show_error(f"Update failed: {error_msg}")
            else:
                self.show_error("No Rego logic found. Please add Rego logic first.")

        except Exception as e:
            self.show_error(f"Error updating remediation info: {str(e)}")

    def update_rego_logic(self):
        """Update Rego logic using in-GUI editor"""
        if not self.selected_policy:
            return

        # Get current logic
        current_logic = ""
        rule_logic_list = self.selected_policy.get('rule_logic_list', [])
        if rule_logic_list and len(rule_logic_list) > 0:
            current_logic = rule_logic_list[0].get('logic', '')

        if not current_logic:
            current_logic = "package crowdstrike\n\ndefault result := \"pass\"\n\n# Add your Rego logic here\n"

        self.show_rego_editor(current_logic)

    def insert_rego_template(self):
        """Insert a basic Rego template at cursor position"""
        if not dpg.does_item_exist("rego_code_input"):
            return

        current_text = dpg.get_value("rego_code_input")
        template = """
# Basic Rego policy template
default result = "pass"

# Policy fails if conditions are met
result = "fail" if {
    # Add your violation conditions here
    # Example: input.configuration.some_field != "required_value"
}
"""

        # If editor is empty, replace with template, otherwise append
        if not current_text.strip():
            dpg.set_value("rego_code_input", template.strip())
        else:
            dpg.set_value("rego_code_input", current_text + template)

    def format_rego_code(self):
        """Basic Rego code formatting - fix indentation"""
        # Check for both possible input field tags (existing policy editor and new policy creation)
        input_tag = None
        if dpg.does_item_exist("rego_code_input"):
            input_tag = "rego_code_input"
        elif dpg.does_item_exist("rego_logic_input"):
            input_tag = "rego_logic_input"

        if not input_tag:
            return

        current_text = dpg.get_value(input_tag)
        if not current_text.strip():
            return

        # Basic formatting - fix indentation
        lines = current_text.split('\n')
        formatted_lines = []
        indent_level = 0

        for line in lines:
            stripped = line.strip()

            # Decrease indent for closing braces
            if stripped.startswith('}'):
                indent_level = max(0, indent_level - 1)

            # Add proper indentation
            if stripped:
                formatted_lines.append('    ' * indent_level + stripped)
            else:
                formatted_lines.append('')

            # Increase indent for opening braces
            if stripped.endswith('{'):
                indent_level += 1

        formatted_text = '\n'.join(formatted_lines)
        dpg.set_value(input_tag, formatted_text)

    def show_rego_editor(self, current_logic: str):
        """Show in-GUI Rego editor"""
        # Delete existing window if it exists to prevent "Alias already exists" error
        if dpg.does_item_exist("rego_editor_window"):
            dpg.delete_item("rego_editor_window")

        # Also ensure the input field tag is cleared if it exists independently
        if dpg.does_item_exist("rego_code_input"):
            dpg.delete_item("rego_code_input")

        with dpg.window(label="Edit Rego Logic", modal=True, show=True,
                       width=1000, height=700, pos=[100, 50], tag="rego_editor_window"):

            dpg.add_text("Rego Policy Editor", color=THEME['accent_orange'])
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Add helpful tips
            dpg.add_text("Enhanced Rego Code Editor", color=THEME['text_secondary'])
            dpg.add_text("Tips: Use Tab for indentation • Ctrl+A to select all • Supports multi-line editing",
                        color=THEME['text_secondary'])
            dpg.add_spacer(height=15)

            # Rego code editor with enhanced settings
            dpg.add_input_text(
                default_value=current_logic,
                multiline=True,
                width=960,  # Increased width
                height=480,  # Increased height
                tag="rego_code_input",
                tab_input=True,  # Enable tab input for indentation
                no_horizontal_scroll=False,  # Allow horizontal scroll for long lines
                hint="Enter your Rego policy logic here..."
            )

            dpg.add_spacer(height=20)

            # All buttons in a single row at the bottom
            with dpg.group(horizontal=True):
                dpg.add_button(label="Add Template", width=120, height=35,
                             callback=lambda: self.insert_rego_template())
                dpg.add_spacer(width=10)
                dpg.add_button(label="Format Code", width=120, height=35,
                             callback=lambda: self.format_rego_code())
                dpg.add_spacer(width=10)
                dpg.add_button(label="Rego Playground", width=140, height=35,
                             callback=self.open_rego_playground)
                dpg.add_spacer(width=30)  # Larger spacer to separate action buttons
                dpg.add_button(label="Save Changes", width=150, height=35,
                             callback=lambda: self.save_rego_from_editor())
                dpg.add_spacer(width=10)
                dpg.add_button(label="Cancel", width=100, height=35,
                             callback=lambda: dpg.delete_item("rego_editor_window"))

    def open_rego_playground(self):
        """Open Rego playground in web browser"""
        import webbrowser
        try:
            webbrowser.open("https://play.openpolicyagent.org/")
            self.show_info("Rego Playground opened in your web browser!")
        except Exception as e:
            self.show_error(f"Could not open web browser: {str(e)}")

    def show_rego_help(self):
        """Show Rego language help"""
        help_text = """Common Rego Patterns:

• Basic Structure:
  package crowdstrike
  default result := "pass"

• Fail Conditions:
  result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    input.public_access_block.block_public_policy == false
  }

• Multiple Conditions (AND):
  result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    input.state.name == "running"
    input.security_groups[_].group_name == "default"
  }

• Array Checking:
  result = "fail" if {
    tag := input.tags[_]
    tag.key == "Environment"
    not tag.value in ["prod", "dev", "test"]
  }"""

        with dpg.window(label="Rego Help", modal=True, show=True,
                       width=600, height=500, pos=[300, 150], tag="rego_help_window"):
            dpg.add_text("Rego Language Quick Reference", color=THEME['accent_orange'])
            dpg.add_separator()
            dpg.add_spacer(height=10)
            dpg.add_text(help_text, wrap=580)
            dpg.add_spacer(height=20)
            dpg.add_button(label="Close", callback=lambda: dpg.delete_item("rego_help_window"))

    def test_current_rego_editor(self):
        """Test Rego logic from editor against live resources - SIMPLIFIED VERSION"""
        print("DEBUG: test_current_rego_editor called")

        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Check if the rego input exists
        if not dpg.does_item_exist("rego_code_input"):
            print("DEBUG: rego_code_input field not found!")
            self.show_error("Rego code input field not found")
            return

        new_logic = dpg.get_value("rego_code_input")
        print(f"DEBUG: Got Rego logic (first 100 chars): {new_logic[:100]}...")

        if not new_logic or not new_logic.strip():
            self.show_error("Please enter Rego logic to test")
            return

        # Show progress window
        self.show_testing_progress_window()
        self.update_testing_progress("Testing Rego editor content against live resources...", 0.5)

        try:
            resource_types = self.selected_policy.get('resource_types', [])
            if resource_types and len(resource_types) > 0:
                resource_type = resource_types[0].get('resource_type')
                print(f"DEBUG: Testing against resource type: {resource_type}")

                # Call toolkit directly
                print("DEBUG: Calling toolkit.test_policy_logic directly for rego editor")
                test_success, detailed_results = self.toolkit.test_policy_logic(new_logic, resource_type, num_assets=3)

                # Close progress window
                print("DEBUG: Closing progress window")
                self.close_testing_progress()

                # Show results immediately
                print("DEBUG: Showing rego editor results directly")
                self.show_simple_test_results(test_success, detailed_results, "existing")

            else:
                self.close_testing_progress()
                self.show_error("No resource type found for testing")

        except Exception as e:
            print(f"DEBUG: Exception in test_current_rego_editor: {str(e)}")
            import traceback
            traceback.print_exc()
            self.close_testing_progress()
            self.show_error(f"Error testing Rego editor content: {str(e)}")
        """Test Rego logic from editor against live resources"""
        print("DEBUG: test_current_rego_editor called")

        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Check if the rego input exists
        if not dpg.does_item_exist("rego_code_input"):
            print("DEBUG: rego_code_input field not found!")
            self.show_error("Rego code input field not found")
            return

        new_logic = dpg.get_value("rego_code_input")
        print(f"DEBUG: Got Rego logic (first 100 chars): {new_logic[:100]}...")

        if not new_logic or not new_logic.strip():
            self.show_error("Please enter Rego logic to test")
            return

        # Show testing progress window
        print("DEBUG: Showing testing progress window")
        self.show_testing_progress_window()

        # Use a safer approach - schedule the actual testing to happen in the next frame
        # This prevents segfaults from immediate frame rendering
        import threading
        import time

        def run_test():
            try:
                # Small delay to let GUI update
                time.sleep(0.1)

                resource_types = self.selected_policy.get('resource_types', [])
                if resource_types and len(resource_types) > 0:
                    resource_type = resource_types[0].get('resource_type')
                    print(f"DEBUG: Testing against resource type: {resource_type}")

                    print("DEBUG: Updating progress - Discovering resources")
                    self.update_testing_progress("Discovering resources for testing...", 0.2)

                    headers = self.toolkit._get_headers()

                    # Get some resources to test against - try multiple approaches
                    resources_url = f"{self.toolkit.base_url}/cloud-security-assets/queries/resources/v1"

                    # Try different filter approaches
                    filter_attempts = [
                        f"resource_type:'{resource_type}'",
                        f"active:'true'"  # Fallback: get any active resources
                    ]

                    resource_ids = []
                    for filter_expr in filter_attempts:
                        params = {"filter": filter_expr, "limit": 10}
                        print(f"DEBUG: Trying filter: {filter_expr}")

                        resources_response = requests.get(resources_url, headers=headers, params=params, timeout=30)
                        print(f"DEBUG: Resource discovery response status: {resources_response.status_code}")

                        if resources_response.status_code == 200:
                            found_ids = resources_response.json().get('resources', [])
                            if found_ids:
                                resource_ids = found_ids[:3]  # Limit to 3 for testing
                                print(f"DEBUG: Found {len(resource_ids)} resources with filter '{filter_expr}'")
                                break
                            else:
                                print(f"DEBUG: No resources found with filter '{filter_expr}'")
                        else:
                            print(f"DEBUG: Filter '{filter_expr}' failed with status {resources_response.status_code}")

                    if resource_ids:
                        print("DEBUG: Updating progress - Running evaluation")
                        self.update_testing_progress(f"Found {len(resource_ids)} resources. Running policy evaluation...", 0.6)

                        # Use the CLI toolkit's test_policy_logic method which handles this properly
                        print("DEBUG: Using toolkit.test_policy_logic for testing")
                        test_success, detailed_results = self.toolkit.test_policy_logic(new_logic, resource_type, num_assets=min(3, len(resource_ids)))

                        # Store results for main thread display
                        self.pending_test_results = {
                            'success': test_success,
                            'detailed_results': detailed_results,
                            'policy_type': 'existing'
                        }

                        # Close progress window and schedule results display on main thread
                        print("DEBUG: Closing progress window and scheduling results display")
                        self.close_testing_progress()

                        # Schedule GUI update on main thread
                        def show_results_callback():
                            if hasattr(self, 'pending_test_results') and self.pending_test_results:
                                print("DEBUG: Displaying rego editor results from main thread")
                                results = self.pending_test_results
                                self.pending_test_results = None
                                self.show_detailed_test_results(
                                    results['success'],
                                    results['detailed_results'],
                                    results['policy_type']
                                )

                        start_time = time.time()

                        def check_and_display():
                            if time.time() - start_time > 0.1:
                                show_results_callback()
                                return False
                            return True

                        dpg.set_frame_callback(3, check_and_display)
                    else:
                        print("DEBUG: No resources found - trying syntax validation")
                        self.update_testing_progress("No resources found. Attempting syntax validation...", 0.8)

                        # Try alternative: Use a simplified evaluation approach
                        print("DEBUG: Attempting alternative evaluation without resource discovery")
                        try:
                            evaluation_url = f"{self.toolkit.base_url}/cloud-policies/entities/evaluation/v1"

                            # Create a minimal test payload
                            test_payload = {
                                "logic": new_logic,
                                "cloud_provider": "aws",  # Default to AWS
                                "resource_type": resource_type
                            }

                            print(f"DEBUG: Attempting evaluation with minimal payload")
                            eval_response = requests.post(evaluation_url, headers=headers, json=test_payload, timeout=30)
                            print(f"DEBUG: Evaluation response status: {eval_response.status_code}")

                            self.close_testing_progress()

                            if eval_response.status_code == 200:
                                print("DEBUG: Rego logic syntax validation successful")
                                self.show_testing_results("Rego syntax validation successful!",
                                                        f"Rego logic syntax appears valid for {resource_type}\n\n" +
                                                        "No live resources were available for full testing.\n\n" +
                                                        "The policy logic compiled successfully but couldn't be tested against actual assets.", "info")
                            else:
                                print(f"DEBUG: Evaluation response: {eval_response.text}")
                                try:
                                    error_data = eval_response.json()
                                    error_msg = error_data.get('errors', [{}])[0].get('message', 'Unknown error')
                                except:
                                    error_msg = f"HTTP {eval_response.status_code}"
                                self.show_testing_results("Rego logic validation failed",
                                                        f"Rego logic validation failed:\n\n{error_msg}\n\n" +
                                                        "Please check your Rego syntax and policy structure.", "error")

                        except Exception as alt_e:
                            print(f"DEBUG: Alternative evaluation also failed: {str(alt_e)}")
                            self.close_testing_progress()
                            self.show_testing_results("No resources available for testing",
                                                    f"No resources available for testing.\n\n" +
                                                    "No {resource_type} resources were found in your environment, " +
                                                    "and syntax validation also failed.\n\n" +
                                                    "You can save your policy and test it manually in the CrowdStrike console.", "warning")

                else:
                    print("DEBUG: No resource type found in policy")
                    self.close_testing_progress()
                    self.show_error("No resource type found for testing")

            except Exception as e:
                print(f"DEBUG: Exception in test thread: {str(e)}")
                import traceback
                traceback.print_exc()
                self.close_testing_progress()
                self.show_error(f"Error testing policy: {str(e)}")

        # Run the test in a separate thread to avoid blocking the GUI
        test_thread = threading.Thread(target=run_test, daemon=True)
        test_thread.start()

    def show_testing_progress_window(self):
        """Show testing progress window"""
        if dpg.does_item_exist("testing_progress_window"):
            dpg.delete_item("testing_progress_window")

        with dpg.window(label="Testing Policy", modal=True, show=True,
                       width=500, height=200, pos=[300, 250], tag="testing_progress_window"):
            dpg.add_text("Testing Policy Against Live Resources", color=THEME['accent_blue'])
            dpg.add_separator()
            dpg.add_spacer(height=15)
            dpg.add_text("Initializing policy test...", tag="testing_status_text")
            dpg.add_spacer(height=15)
            dpg.add_progress_bar(default_value=0.1, width=450, tag="testing_progress_bar")
            dpg.add_spacer(height=15)
            dpg.add_text("This may take a few seconds...", color=THEME['text_secondary'])

    def update_testing_progress(self, message, progress=0.5):
        """Update testing progress message"""
        if dpg.does_item_exist("testing_status_text"):
            dpg.set_value("testing_status_text", message)
        if dpg.does_item_exist("testing_progress_bar"):
            dpg.set_value("testing_progress_bar", progress)

    def close_testing_progress(self):
        """Close testing progress window"""
        if dpg.does_item_exist("testing_progress_window"):
            dpg.delete_item("testing_progress_window")

    def show_detailed_test_results(self, success: bool, detailed_results: dict, policy_type: str):
        """Show detailed test results with actual pass/fail data"""
        print(f"DEBUG: show_detailed_test_results called with success={success}, policy_type={policy_type}")
        print(f"DEBUG: detailed_results type: {type(detailed_results)}, content: {detailed_results}")

        if dpg.does_item_exist("detailed_results_window"):
            print("DEBUG: Deleting existing detailed_results_window")
            dpg.delete_item("detailed_results_window")

        # Determine title and colors based on results
        policy_name = ""
        if policy_type == "existing" and self.selected_policy:
            policy_name = self.selected_policy.get('name', 'Policy')
        elif policy_type == "new":
            policy_name = self.new_policy_data.get('name', 'New Policy')

        total_assets = detailed_results.get('total_assets', 0)
        resource_type = detailed_results.get('resource_type', 'Unknown')
        pass_count = detailed_results.get('pass_count', 0)
        fail_count = detailed_results.get('fail_count', 0)
        error_count = detailed_results.get('error_count', 0)
        interpretation = detailed_results.get('interpretation', '')

        # Determine result type for colors
        if success and fail_count == 0:
            result_type = "success"
            title = f"Policy '{policy_name}' - All Tests Passed"
        elif success and fail_count > 0:
            result_type = "warning"
            title = f"Policy '{policy_name}' - Mixed Results"
        else:
            result_type = "error"
            title = f"Policy '{policy_name}' - Test Issues"

        # Choose colors
        title_color = THEME['success_green'] if result_type == "success" else \
                     THEME['accent_orange'] if result_type == "warning" else \
                     THEME['accent_red']

        with dpg.window(label="Policy Test Results", modal=True, show=True,
                       width=700, height=600, pos=[250, 100], tag="detailed_results_window"):

            print("DEBUG: Created detailed_results_window")

            # Title
            dpg.add_text(title, color=title_color)
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Summary stats
            dpg.add_text(f"Test Summary for {total_assets} {resource_type} assets:", color=THEME['accent_blue'])
            dpg.add_spacer(height=10)

            # Statistics with colors
            if total_assets > 0:
                pass_pct = (pass_count / total_assets) * 100
                fail_pct = (fail_count / total_assets) * 100

                with dpg.group(horizontal=True):
                    dpg.add_text("Passed:", color=THEME['success_green'])
                    dpg.add_text(f"{pass_count}/{total_assets} ({pass_pct:.1f}%)")

                with dpg.group(horizontal=True):
                    dpg.add_text("Failed:", color=THEME['accent_red'])
                    dpg.add_text(f"{fail_count}/{total_assets} ({fail_pct:.1f}%)")

                if error_count > 0:
                    error_pct = (error_count / total_assets) * 100
                    with dpg.group(horizontal=True):
                        dpg.add_text("Errors:", color=THEME['accent_orange'])
                        dpg.add_text(f"{error_count}/{total_assets} ({error_pct:.1f}%)")

                dpg.add_spacer(height=15)
                dpg.add_separator()
                dpg.add_spacer(height=10)

                # Individual asset results
                dpg.add_text("Individual Asset Results:", color=THEME['accent_blue'])
                dpg.add_spacer(height=10)

                # Asset results table
                test_results = detailed_results.get('test_results', [])
                if test_results:
                    with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True,
                                 borders_innerV=True, scrollY=True, height=200):
                        dpg.add_table_column(label="Asset", width=200)
                        dpg.add_table_column(label="Result", width=100)
                        dpg.add_table_column(label="Details", width=350)

                        for i, result in enumerate(test_results, 1):
                            with dpg.table_row():
                                # Asset ID (truncated)
                                asset_id = result.get('asset_id', 'Unknown')
                                display_id = asset_id[-30:] if len(asset_id) > 30 else asset_id
                                dpg.add_text(f"Asset {i}: {display_id}")

                                # Result with color
                                test_result = result.get('result', 'unknown')
                                if test_result == 'pass':
                                    dpg.add_text("PASS", color=THEME['success_green'])
                                    dpg.add_text("Policy conditions satisfied")
                                elif test_result == 'fail':
                                    dpg.add_text("FAIL", color=THEME['accent_red'])
                                    # Show failure details if available
                                    details = result.get('details', {})
                                    violations = details.get('violations', [])
                                    if violations:
                                        violation_text = violations[0].get('message', 'Policy violation detected')[:50] + "..."
                                        dpg.add_text(violation_text)
                                    else:
                                        dpg.add_text("Policy conditions not met")
                                else:
                                    dpg.add_text("ERROR", color=THEME['accent_orange'])
                                    error_msg = result.get('error', 'Evaluation error')[:50] + "..."
                                    dpg.add_text(error_msg)

                dpg.add_spacer(height=15)
                dpg.add_separator()
                dpg.add_spacer(height=10)

                # Interpretation
                dpg.add_text("Interpretation:", color=THEME['accent_blue'])
                dpg.add_text(interpretation, wrap=650, color=THEME['text_secondary'])

                dpg.add_spacer(height=15)
                dpg.add_separator()
                dpg.add_spacer(height=10)

                # Next steps based on results
                dpg.add_text("Next Steps:", color=THEME['accent_blue'])
                if pass_count == total_assets:
                    dpg.add_text("• All assets passed - policy is working correctly", color=THEME['success_green'])
                    if policy_type == "new":
                        dpg.add_text("• You can proceed to create this policy", color=THEME['success_green'])
                elif fail_count > 0 and error_count == 0:
                    dpg.add_text("• Policy detected compliance issues as expected", color=THEME['accent_blue'])
                    dpg.add_text("• Review individual failures to ensure policy logic is correct", color=THEME['accent_blue'])
                elif error_count > 0:
                    dpg.add_text("• Some assets had evaluation errors", color=THEME['accent_orange'])
                    dpg.add_text("• Check your Rego syntax and policy logic", color=THEME['accent_orange'])

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="View Console Details", width=150, height=35,
                             callback=lambda: self.show_console_tip())
                dpg.add_spacer(width=10)
                dpg.add_button(label="Close", width=100, height=35,
                             callback=lambda: dpg.delete_item("detailed_results_window"))

    def show_testing_results(self, title, message, result_type="info"):
        """Show detailed testing results window"""
        if dpg.does_item_exist("testing_results_window"):
            dpg.delete_item("testing_results_window")

        # Choose colors based on result type
        title_color = THEME['success_green'] if result_type == "success" else \
                     THEME['accent_orange'] if result_type == "warning" else \
                     THEME['accent_red'] if result_type == "error" else \
                     THEME['accent_blue']

        with dpg.window(label="Policy Test Results", modal=True, show=True,
                       width=600, height=400, pos=[250, 150], tag="testing_results_window"):
            dpg.add_text(title, color=title_color)
            dpg.add_separator()
            dpg.add_spacer(height=15)
            dpg.add_text(message, wrap=560)
            dpg.add_spacer(height=20)

            with dpg.group(horizontal=True):
                dpg.add_button(label="View Console Output", width=150, height=35,
                             callback=lambda: self.show_console_tip())
                dpg.add_spacer(width=10)
                dpg.add_button(label="Close", width=100, height=35,
                             callback=lambda: dpg.delete_item("testing_results_window"))

    def show_console_tip(self):
        """Show console tip dialog"""
        if dpg.does_item_exist("console_tip_window"):
            dpg.delete_item("console_tip_window")

        with dpg.window(label="View Detailed Results", modal=True, show=True,
                       width=500, height=250, pos=[300, 200], tag="console_tip_window"):
            dpg.add_text("Detailed Test Results", color=THEME['accent_blue'])
            dpg.add_separator()
            dpg.add_spacer(height=15)
            dpg.add_text("The detailed policy test results are displayed in the console/terminal window where you launched this GUI.")
            dpg.add_spacer(height=10)
            dpg.add_text("Look for colorful output showing:")
            dpg.add_text("• Individual asset test results (pass / fail)")
            dpg.add_text("• Compliance statistics and percentages")
            dpg.add_text("• Policy behavior interpretation")
            dpg.add_spacer(height=15)
            dpg.add_button(label="Got it!", width=100, height=35,
                         callback=lambda: dpg.delete_item("console_tip_window"))

    def save_rego_from_editor(self):
        """Save Rego logic from in-GUI editor"""
        new_logic = dpg.get_value("rego_code_input")

        if not new_logic.strip():
            self.show_error("Rego logic cannot be empty")
            return

        # Close editor window and save
        dpg.delete_item("rego_editor_window")
        self.save_rego_logic(new_logic)

    def show_rego_save_dialog(self, new_logic: str):
        """Show dialog for saving Rego logic with test option"""
        with dpg.window(label="Save Rego Logic", modal=True, show=True,
                       width=500, height=300, pos=[150, 150], tag="rego_save_window"):

            dpg.add_text("Rego logic updated. What would you like to do?",
                        color=THEME['accent_orange'])
            dpg.add_spacer(height=20)

            dpg.add_button(label="Test Logic Against Live Resources", width=300, height=40,
                         user_data=new_logic,
                         callback=lambda s, a, u: self.test_rego_logic(u))

            dpg.add_spacer(height=10)
            dpg.add_button(label="Save Without Testing", width=300, height=40,
                         user_data=new_logic,
                         callback=lambda s, a, u: self.save_rego_logic(u))

            dpg.add_spacer(height=10)
            dpg.add_button(label="Cancel (Discard Changes)", width=300, height=40,
                         callback=lambda: dpg.delete_item("rego_save_window"))

    def test_rego_logic(self, new_logic: str):
        """Test Rego logic against live resources"""
        dpg.delete_item("rego_save_window")

        try:
            resource_types = self.selected_policy.get('resource_types', [])
            if resource_types and len(resource_types) > 0:
                resource_type = resource_types[0].get('resource_type')

                self.show_info("Testing policy against live resources...")

                # Use toolkit's evaluation endpoint (matching CLI logic)
                headers = self.toolkit._get_headers()
                evaluation_url = f"{self.toolkit.base_url}/cloud-policies/entities/evaluation/v1"

                # First get some resources to test against
                resources_url = f"{self.toolkit.base_url}/cloud-security-assets/queries/resources/v1"
                params = {"filter": f"resource_type:'{resource_type}'", "limit": 5}
                resources_response = requests.get(resources_url, headers=headers, params=params)

                if resources_response.status_code == 200:
                    resource_ids = resources_response.json().get('resources', [])
                    if resource_ids:
                        # Test the logic
                        test_payload = {
                            "rego_logic": new_logic,
                            "resource_ids": resource_ids[:1]  # Test with one resource
                        }

                        eval_response = requests.post(evaluation_url, headers=headers, json=test_payload)
                        if eval_response.status_code == 200:
                            self.show_test_success_dialog(new_logic)
                        else:
                            self.show_error("Policy test failed. Please check your Rego logic.")
                    else:
                        self.show_error("No resources found for testing")
                else:
                    self.show_error("Failed to discover resources for testing")
            else:
                self.show_error("No resource type found for testing")

        except Exception as e:
            self.show_error(f"Error testing policy: {str(e)}")

    def show_test_success_dialog(self, new_logic: str):
        """Show success dialog after testing"""
        with dpg.window(label="Test Successful", modal=True, show=True,
                       width=400, height=250, pos=[200, 200], tag="test_success_window"):

            dpg.add_text("Policy test successful!", color=THEME['success_green'])
            dpg.add_spacer(height=10)
            dpg.add_text("What would you like to do next?")
            dpg.add_spacer(height=20)

            dpg.add_button(label="Save Changes", width=200, height=35,
                         user_data=new_logic,
                         callback=lambda s, a, u: self.save_rego_logic(u))

            dpg.add_spacer(height=10)
            dpg.add_button(label="Edit Logic Again", width=200, height=35,
                         callback=lambda: self.edit_logic_again())

            dpg.add_spacer(height=10)
            dpg.add_button(label="Cancel", width=200, height=35,
                         callback=lambda: dpg.delete_item("test_success_window"))

    def save_rego_logic(self, new_logic: str):
        """Save Rego logic changes"""
        try:
            # Preserve existing remediation info
            existing_remediation = ""
            rule_logic_list = self.selected_policy.get('rule_logic_list', [])
            if rule_logic_list and len(rule_logic_list) > 0:
                existing_remediation = rule_logic_list[0].get('remediation_info', '')

            # Get resource type for dynamic provider detection
            resource_type = "Unknown"
            if self.selected_policy.get('resource_types') and len(self.selected_policy['resource_types']) > 0:
                resource_type = self.selected_policy['resource_types'][0].get('resource_type', 'Unknown')

            cloud_provider = determine_cloud_provider_from_resource_type(resource_type)
            logic_item = {"logic": new_logic, "platform": cloud_provider["platform"]}
            if existing_remediation:
                logic_item["remediation_info"] = existing_remediation

            headers = self.toolkit._get_headers()
            update_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"

            payload = {
                "uuid": self.selected_policy['uuid'],
                "rule_logic_list": [logic_item]
            }

            response = requests.patch(update_url, headers=headers, json=payload)
            if response.status_code == 200:
                # Update local copy
                self.selected_policy['rule_logic_list'] = [logic_item]

                # Close any open dialogs
                for window in ["rego_save_window", "test_success_window", "rego_editor_window"]:
                    if dpg.does_item_exist(window):
                        dpg.delete_item(window)

                self.show_success("Rego logic updated successfully!")
                self.show_policy_management(self.selected_policy)
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Update failed: {error_msg}")

        except Exception as e:
            self.show_error(f"Error updating Rego logic: {str(e)}")

    def edit_logic_again(self):
        """Edit Rego logic again"""
        if dpg.does_item_exist("test_success_window"):
            dpg.delete_item("test_success_window")
        self.update_rego_logic()

    def test_policy_inline(self):
        """Test current policy against live resources - INLINE RESULTS"""
        if not self.selected_policy:
            return

        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Get current logic
        current_logic = ""
        rule_logic_list = self.selected_policy.get('rule_logic_list', [])
        if rule_logic_list and len(rule_logic_list) > 0:
            current_logic = rule_logic_list[0].get('logic', '')

        if not current_logic:
            self.show_error("No Rego logic found in this policy")
            return

        # Get resource type
        resource_types = self.selected_policy.get('resource_types', [])
        if not resource_types or len(resource_types) == 0:
            self.show_error("No resource type found for testing")
            return

        resource_type = resource_types[0].get('resource_type')
        if not resource_type:
            self.show_error("No resource type found for testing")
            return

        print("DEBUG: Starting inline test_policy")

        # Update the test results area to show "Testing..."
        self.update_test_results_display("testing")

        try:
            # Call toolkit directly
            print("DEBUG: Calling toolkit.test_policy_logic directly")
            test_success, detailed_results = self.toolkit.test_policy_logic(current_logic, resource_type, num_assets=3)

            # Show results in the inline area
            print("DEBUG: Displaying results inline")
            self.update_test_results_display("results", detailed_results)

        except Exception as e:
            print(f"DEBUG: Exception in test_policy_inline: {str(e)}")
            import traceback
            traceback.print_exc()
            self.update_test_results_display("error", str(e))

    def clear_test_results(self):
        """Clear test results and reset to initial state"""
        if not dpg.does_item_exist("test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("test_results_area", children_only=True)

        # Reset to initial state
        with dpg.child_window(parent="test_results_area", border=False):
            dpg.add_text("Click 'Test Policy' to run policy against live resources",
                       color=THEME['text_secondary'], wrap=580, tag="test_status_text")

    def update_test_results_display(self, status, data=None):
        """Update the inline test results display"""
        if not dpg.does_item_exist("test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("test_results_area", children_only=True)

        with dpg.child_window(parent="test_results_area", border=False):
            if status == "testing":
                dpg.add_text("Testing Policy...", color=THEME['accent_blue'])
                dpg.add_spacer(height=10)
                dpg.add_text("Running policy against live resources", color=THEME['text_secondary'])
                dpg.add_spacer(height=10)
                dpg.add_text("This may take a few seconds...", color=THEME['text_secondary'])

            elif status == "results" and data:
                # Display actual test results
                total_assets = data.get('total_assets', 0)
                resource_type = data.get('resource_type', 'Unknown')
                pass_count = data.get('pass_count', 0)
                fail_count = data.get('fail_count', 0)
                error_count = data.get('error_count', 0)
                interpretation = data.get('interpretation', '')

                dpg.add_text("Test Complete", color=THEME['success_green'])
                dpg.add_spacer(height=10)

                dpg.add_text(f"Test Summary for {total_assets} {resource_type} assets:", color=THEME['accent_blue'])
                dpg.add_spacer(height=5)

                if total_assets > 0:
                    dpg.add_text(f"Passed: {pass_count}/{total_assets}", color=THEME['success_green'])
                    dpg.add_text(f"Failed: {fail_count}/{total_assets}", color=THEME['accent_red'])
                    if error_count > 0:
                        dpg.add_text(f"Errors: {error_count}/{total_assets}", color=THEME['accent_orange'])
                else:
                    dpg.add_text("No assets found for testing", color=THEME['accent_orange'])

                dpg.add_spacer(height=10)
                dpg.add_text("Analysis:", color=THEME['accent_blue'])
                dpg.add_text(interpretation, wrap=530, color=THEME['text_secondary'])

                dpg.add_spacer(height=10)

                # Show individual asset results if available
                test_results = data.get('test_results', [])
                if test_results:
                    dpg.add_text("Asset Results:", color=THEME['accent_blue'])
                    dpg.add_spacer(height=5)

                    for i, result in enumerate(test_results[:3], 1):  # Show max 3 results
                        asset_id = result.get('asset_id', 'Unknown')
                        short_id = asset_id.split('|')[-1] if '|' in asset_id else asset_id[-10:]
                        test_result = result.get('result', 'unknown')

                        if test_result == 'pass':
                            status_color = THEME['success_green']
                            status_text = "PASS"
                        elif test_result == 'fail':
                            status_color = THEME['accent_red']
                            status_text = "FAIL"
                        else:
                            status_color = THEME['accent_orange']
                            status_text = "ERROR"

                        with dpg.group(horizontal=True):
                            dpg.add_text(f"{i}.")
                            dpg.add_text(short_id, color=THEME['text_secondary'])
                            dpg.add_text("->")
                            dpg.add_text(status_text, color=status_color)

                dpg.add_spacer(height=15)
                dpg.add_text("See console for full details", color=THEME['text_secondary'], wrap=530)

                # Add Clear Results button
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_test_results)

            elif status == "error":
                dpg.add_text("Test Failed", color=THEME['accent_red'])
                dpg.add_spacer(height=10)
                dpg.add_text("Error occurred during testing:", color=THEME['text_secondary'])
                dpg.add_spacer(height=5)
                dpg.add_text(str(data)[:200] + "..." if len(str(data)) > 200 else str(data),
                           wrap=530, color=THEME['accent_red'])

                # Add Clear Results button
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_test_results)

    def test_policy(self):
        """Test current policy against live resources - SIMPLIFIED VERSION"""
        if not self.selected_policy:
            return

        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Get current logic
        current_logic = ""
        rule_logic_list = self.selected_policy.get('rule_logic_list', [])
        if rule_logic_list and len(rule_logic_list) > 0:
            current_logic = rule_logic_list[0].get('logic', '')

        if not current_logic:
            self.show_error("No Rego logic found in this policy")
            return

        # Get resource type
        resource_types = self.selected_policy.get('resource_types', [])
        if not resource_types or len(resource_types) == 0:
            self.show_error("No resource type found for testing")
            return

        resource_type = resource_types[0].get('resource_type')
        if not resource_type:
            self.show_error("No resource type found for testing")
            return

        print("DEBUG: Starting simplified test_policy")

        # Show progress window
        self.show_testing_progress_window()
        self.update_testing_progress("Testing policy against live resources...", 0.5)

        try:
            # Call toolkit directly (yes, this will block the GUI briefly - that's fine!)
            print("DEBUG: Calling toolkit.test_policy_logic directly")
            test_success, detailed_results = self.toolkit.test_policy_logic(current_logic, resource_type, num_assets=3)

            # Close progress window
            print("DEBUG: Closing progress window")
            self.close_testing_progress()

            # Show results immediately
            print("DEBUG: Showing detailed results directly")
            self.show_simple_test_results(test_success, detailed_results, "existing")

        except Exception as e:
            print(f"DEBUG: Exception in test_policy: {str(e)}")
            import traceback
            traceback.print_exc()
            self.close_testing_progress()
            self.show_error(f"Error testing policy: {str(e)}")

    def show_simple_test_results(self, success: bool, detailed_results: dict, policy_type: str):
        """Show simple, reliable test results dialog"""
        print(f"DEBUG: show_simple_test_results called - success={success}")

        if dpg.does_item_exist("simple_test_results"):
            dpg.delete_item("simple_test_results")

        # Get basic info
        policy_name = ""
        if policy_type == "existing" and self.selected_policy:
            policy_name = self.selected_policy.get('name', 'Policy')
        elif policy_type == "new":
            policy_name = self.new_policy_data.get('name', 'New Policy')

        total_assets = detailed_results.get('total_assets', 0)
        resource_type = detailed_results.get('resource_type', 'Unknown')
        pass_count = detailed_results.get('pass_count', 0)
        fail_count = detailed_results.get('fail_count', 0)
        error_count = detailed_results.get('error_count', 0)
        interpretation = detailed_results.get('interpretation', '')

        # Create simple results window
        with dpg.window(label="Policy Test Results", modal=True, show=True,
                       width=600, height=500, pos=[200, 150], tag="simple_test_results"):

            print("DEBUG: Creating simple test results window")

            # Title
            title_text = f"Policy Test Results: {policy_name}"
            dpg.add_text(title_text, color=THEME['accent_blue'])
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Simple summary
            dpg.add_text(f"Tested against {total_assets} {resource_type} assets", color=THEME['text_primary'])
            dpg.add_spacer(height=10)

            # Results
            if total_assets > 0:
                dpg.add_text(f"Passed: {pass_count}/{total_assets}", color=THEME['success_green'])
                dpg.add_text(f"Failed: {fail_count}/{total_assets}", color=THEME['accent_red'])
                if error_count > 0:
                    dpg.add_text(f"Errors: {error_count}/{total_assets}", color=THEME['accent_orange'])
            else:
                dpg.add_text("No assets found for testing", color=THEME['accent_orange'])

            dpg.add_spacer(height=15)
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Interpretation
            dpg.add_text("Interpretation:", color=THEME['accent_blue'])
            dpg.add_text(interpretation, wrap=550, color=THEME['text_secondary'])

            dpg.add_spacer(height=15)
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Show individual results if available
            test_results = detailed_results.get('test_results', [])
            if test_results:
                dpg.add_text("Asset Details:", color=THEME['accent_blue'])
                dpg.add_spacer(height=5)

                for i, result in enumerate(test_results[:5], 1):  # Show max 5 results
                    asset_id = result.get('asset_id', 'Unknown')
                    short_id = asset_id.split('|')[-1] if '|' in asset_id else asset_id[-15:]
                    test_result = result.get('result', 'unknown')

                    if test_result == 'pass':
                        status_color = THEME['success_green']
                        status_text = "PASS"
                    elif test_result == 'fail':
                        status_color = THEME['accent_red']
                        status_text = "FAIL"
                    else:
                        status_color = THEME['accent_orange']
                        status_text = "ERROR"

                    with dpg.group(horizontal=True):
                        dpg.add_text(f"Asset {i}:", color=THEME['text_primary'])
                        dpg.add_text(short_id, color=THEME['text_secondary'])
                        dpg.add_text("→")
                        dpg.add_text(status_text, color=status_color)

            dpg.add_spacer(height=20)

            # Buttons
            with dpg.group(horizontal=True):
                dpg.add_button(label="Close", width=100, height=35,
                             callback=lambda: dpg.delete_item("simple_test_results"))
                dpg.add_spacer(width=10)
                dpg.add_text("See console above for detailed output", color=THEME['text_secondary'])

    def delete_existing_policy(self):
        """Delete existing policy - shows policy selection for deletion"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        try:
            # Load policies for deletion
            self.policies = self.toolkit.discover_custom_rules()
            self.show_delete_policy_list()
        except Exception as e:
            self.show_error(f"Failed to load policies: {str(e)}")

    def show_delete_policy_list(self):
        """Show policy list for deletion with confirmation"""
        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        with dpg.child_window(parent="main_content", border=False):
            # Header
            dpg.add_text("Delete Custom IOM Policy", color=THEME['accent_red'])
            dpg.add_text("WARNING: This action cannot be undone!", color=THEME['accent_red'])
            dpg.add_separator()
            dpg.add_spacer(height=20)

            if not self.policies:
                dpg.add_text("No Custom IOM policies found")
                dpg.add_spacer(height=20)
                dpg.add_button(label="Back to Main Menu", callback=self.show_main_menu)
                return

            dpg.add_text(f"Select policy to delete ({len(self.policies)} policies found):")
            dpg.add_spacer(height=15)

            # Policy deletion table
            with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True,
                         borders_innerV=True, scrollY=True, height=400):
                dpg.add_table_column(label="Name", width=250)
                dpg.add_table_column(label="Description", width=300)
                dpg.add_table_column(label="Severity", width=100)
                dpg.add_table_column(label="Actions", width=120)

                for i, policy in enumerate(self.policies):
                    with dpg.table_row():
                        # Name
                        name = policy.get('name', 'Unknown')
                        if len(name) > 30:
                            name = name[:27] + "..."
                        dpg.add_text(name)

                        # Description
                        desc = policy.get('description', 'No description')
                        if len(desc) > 40:
                            desc = desc[:37] + "..."
                        dpg.add_text(desc)

                        # Severity
                        severity = policy.get('severity', 3)
                        severity_text = ["Critical", "High", "Medium", "Low"][min(severity, 3)]
                        severity_colors = [
                            THEME['accent_red'], THEME['accent_orange'],
                            [255, 193, 7], THEME['success_green']
                        ]
                        dpg.add_text(severity_text, color=severity_colors[min(severity, 3)])

                        # Delete button
                        button_tag = f"delete_btn_{i}"
                        dpg.add_button(label="DELETE", tag=button_tag, width=100,
                                     user_data=policy,
                                     callback=lambda s, a, u: self.confirm_policy_deletion(u))

            dpg.add_spacer(height=20)
            dpg.add_button(label="Back to Main Menu", callback=self.show_main_menu)

    def confirm_policy_deletion(self, policy):
        """Show confirmation dialog for policy deletion"""
        with dpg.window(label="Confirm Deletion", modal=True, show=True,
                       width=500, height=300, pos=[350, 250], tag="delete_confirm_window"):

            dpg.add_text("DELETE POLICY", color=THEME['accent_red'])
            dpg.add_separator()
            dpg.add_spacer(height=15)

            dpg.add_text("Are you sure you want to delete this policy?", color=THEME['text_primary'])
            dpg.add_spacer(height=10)

            dpg.add_text(f"Name: {policy.get('name', 'Unknown')}", color=THEME['accent_orange'])
            dpg.add_text(f"Description: {policy.get('description', 'No description')}", wrap=450)
            dpg.add_spacer(height=10)

            dpg.add_text("This action CANNOT be undone!", color=THEME['accent_red'])
            dpg.add_spacer(height=20)

            with dpg.group(horizontal=True):
                dpg.add_button(label="YES - DELETE POLICY", width=180, height=40,
                             user_data=policy,
                             callback=lambda s, a, u: self.execute_policy_deletion(u))
                dpg.add_spacer(width=20)
                dpg.add_button(label="Cancel", width=120, height=40,
                             callback=lambda: dpg.delete_item("delete_confirm_window"))

    def execute_policy_deletion(self, policy):
        """Execute the actual policy deletion"""
        try:
            policy_uuid = policy.get('uuid')
            if not policy_uuid:
                self.show_error("Policy UUID not found")
                return

            headers = self.toolkit._get_headers()
            delete_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1?ids={policy_uuid}"

            response = requests.delete(delete_url, headers=headers)

            if response.status_code == 200:
                dpg.delete_item("delete_confirm_window")
                policy_name = policy.get('name', 'Unknown')
                self.show_success(f"Policy '{policy_name}' deleted successfully!")

                # Refresh the delete list
                self.delete_existing_policy()
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Failed to delete policy: {error_msg}")

        except Exception as e:
            self.show_error(f"Error deleting policy: {str(e)}")

    def create_new_policy(self):
        """Create new policy - matches CLI functionality"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Initialize policy creation data
        self.new_policy_data = {
            'step': 1,
            'name': '',
            'description': '',
            'resource_type': '',
            'alert_info': '',
            'remediation_info': '',
            'rego_logic': ''
        }

        self.show_policy_creation_step()

    def show_policy_creation_step(self):
        """Show current step of policy creation"""
        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        step = self.new_policy_data['step']

        with dpg.child_window(parent="main_content", border=False):
            dpg.add_text("Create New Custom IOM Policy", color=THEME['accent_orange'])
            dpg.add_text(f"Step {step} of 8", color=THEME['text_secondary'])
            dpg.add_separator()
            dpg.add_spacer(height=20)

            if step == 1:
                self.show_step1_basic_info()
            elif step == 2:
                self.show_step2_resource_type()
            elif step == 3:
                self.show_step3_sample_data()
            elif step == 4:
                self.show_step4_severity()
            elif step == 5:
                self.show_step5_alert_info()
            elif step == 6:
                self.show_step6_remediation()
            elif step == 7:
                self.show_step7_rego_logic()
            elif step == 8:
                self.show_step8_test_and_create()

    def show_step1_basic_info(self):
        """Step 1: Basic policy information"""
        dpg.add_text("Step 1: Basic Information", color=THEME['accent_blue'])
        dpg.add_spacer(height=15)

        dpg.add_text("Policy Name:", color=THEME['text_primary'])
        dpg.add_input_text(hint="Enter a descriptive policy name", width=500,
                          default_value=self.new_policy_data['name'], tag="policy_name_input")

        dpg.add_spacer(height=10)
        dpg.add_text("Description:", color=THEME['text_primary'])
        dpg.add_text("Tip: Press Enter to create new lines for longer descriptions",
                    color=THEME['text_secondary'])
        dpg.add_input_text(hint="Describe what this policy checks for", multiline=True,
                          width=650, height=100, default_value=self.new_policy_data['description'],
                          tag="policy_desc_input")

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step2_resource_type(self):
        """Step 2: Resource type selection"""
        dpg.add_text("Step 2: Target Resource Type", color=THEME['accent_blue'])
        dpg.add_text("Select the type of cloud resource this policy will evaluate",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        # Resource type input field
        dpg.add_text("Resource Type:", color=THEME['accent_orange'])
        dpg.add_text("Enter or select a resource type from the samples below:", color=THEME['text_secondary'])
        dpg.add_spacer(height=5)

        current_value = self.new_policy_data.get('resource_type', '')
        dpg.add_input_text(hint="e.g., AWS::S3::Bucket, AWS::EC2::Instance, etc.", width=500,
                          default_value=current_value, tag="resource_type_input")

        dpg.add_spacer(height=20)
        dpg.add_text("Sample Resource Types:", color=THEME['accent_orange'])
        dpg.add_text("Click 'Choose' to auto-fill the field above", color=THEME['text_secondary'])
        dpg.add_spacer(height=10)

        # Common resource types based on CLI implementation
        common_types = [
            # AWS
            "AWS::EC2::Instance",
            "AWS::S3::Bucket",
            "AWS::IAM::Role",
            "AWS::RDS::DBInstance",
            "AWS::Lambda::Function",
            "AWS::Logs::LogGroup",
            "AWS::Route53::HostedZone",
            # Google Cloud Platform
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Disk",
            "compute.googleapis.com/Firewall",
            "container.googleapis.com/Cluster",
            "iam.googleapis.com/Role",
            "iam.googleapis.com/ServiceAccount",
            # Azure
            "Microsoft.Compute/virtualMachines",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.Authorization/policyAssignments",
            "Microsoft.Resources/subscriptions",
            # Other
            "artifactregistry.googleapis.com/Repository",
            "logging.googleapis.com/LogBucket"
        ]

        # Sample resource types table
        with dpg.child_window(height=250, border=True):
            with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True, scrollY=True):
                dpg.add_table_column(label="Resource Type", width=350)
                dpg.add_table_column(label="Provider", width=100)
                dpg.add_table_column(label="Action", width=100)

                for i, resource_type in enumerate(common_types):
                    with dpg.table_row():
                        # Determine provider
                        if resource_type.startswith('AWS::'):
                            provider = 'AWS'
                            color = THEME['accent_orange']
                        elif 'googleapis.com' in resource_type:
                            provider = 'GCP'
                            color = THEME['success_green']
                        elif resource_type.startswith('Microsoft.'):
                            provider = 'Azure'
                            color = THEME['accent_blue']
                        else:
                            provider = 'Other'
                            color = THEME['text_secondary']

                        # Resource type name
                        dpg.add_text(resource_type)

                        # Provider with color
                        dpg.add_text(provider, color=color)

                        # Choose button - auto-fills the input field
                        dpg.add_button(label="Choose", width=80, height=25,
                                     user_data=resource_type,
                                     callback=self.fill_resource_type_callback)

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Previous", width=140, height=40, callback=self.prev_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step3_sample_data(self):
        """Step 3: Sample Asset Data (Optional)"""
        dpg.add_text("Step 3: Sample Asset Data (Optional)", color=THEME['accent_blue'])
        dpg.add_text("To write effective Rego policies, you need to understand the asset data structure",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        resource_type = self.new_policy_data.get('resource_type', '')
        if resource_type:
            dpg.add_text(f"Resource Type: {resource_type}", color=THEME['accent_orange'])
            dpg.add_spacer(height=10)

            # Check if we already have sample data
            if hasattr(self, 'sample_asset_data') and self.sample_asset_data:
                dpg.add_text("Sample asset data loaded!", color=THEME['success_green'])
                dpg.add_spacer(height=10)

                # Show summary of the data
                field_count = len(self.sample_asset_data.keys())
                dpg.add_text(f"Asset has {field_count} top-level fields", color=THEME['text_secondary'])

                # Show key fields
                key_fields = ["resource_id", "resource_type", "configuration", "tags", "region", "service"]
                available_key_fields = [f for f in key_fields if f in self.sample_asset_data]
                if available_key_fields:
                    dpg.add_text(f"Key fields available: {', '.join(available_key_fields[:5])}", color=THEME['text_secondary'])

                dpg.add_spacer(height=15)

                # Action buttons for loaded data
                with dpg.group(horizontal=True):
                    dpg.add_button(label="View Sample Data", width=150, height=35,
                                 callback=self.view_sample_data_dialog)
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Save to JSON File", width=150, height=35,
                                 callback=self.save_sample_data_to_file)
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Fetch New Sample", width=150, height=35,
                                 callback=self.fetch_sample_asset_data)

            else:
                dpg.add_text("Fetch sample asset data to understand the structure for writing Rego policies",
                           color=THEME['text_secondary'])
                dpg.add_spacer(height=15)

                dpg.add_button(label="Fetch Sample Asset Data", width=250, height=40,
                             callback=self.fetch_sample_asset_data)

                dpg.add_spacer(height=10)
                dpg.add_text("This will help you understand available fields when writing your policy logic",
                           color=THEME['text_secondary'])

        else:
            dpg.add_text("No resource type selected", color=THEME['accent_red'])

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Previous", width=140, height=40, callback=self.prev_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step4_severity(self):
        """Step 4: Severity selection"""
        dpg.add_text("Step 4: Severity Level", color=THEME['accent_blue'])
        dpg.add_text("Choose the severity level for policy violations",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        severity_options = [
            (0, "Critical", "Immediate action required", THEME['accent_red']),
            (1, "High", "Important security issue", THEME['accent_orange']),
            (2, "Medium", "Moderate security concern", [255, 193, 7]),
            (3, "Low", "Minor issue or best practice", THEME['success_green']),
            (4, "Info", "Informational finding", THEME['text_secondary'])
        ]

        # Create severity labels for the radio button group
        severity_labels = []
        for value, label, description, color in severity_options:
            severity_labels.append(f"{label} (Level {value}) - {description}")

        # Create individual selectable buttons instead of radio buttons for better control
        self.selected_severity_index = None  # Track selection state

        for i, (value, label, description, color) in enumerate(severity_options):
            button_label = f"{label} (Level {value})"

            # Create button that changes appearance when selected
            button_tag = f"severity_button_{i}"
            dpg.add_button(
                label=button_label,
                width=200,
                height=35,
                tag=button_tag,
                user_data=value,
                callback=lambda s, a, severity_val: self.select_severity_button(severity_val)
            )
            dpg.add_spacer(height=5)

        dpg.add_spacer(height=10)
        dpg.add_text("Please select a severity level above",
                    color=THEME['text_secondary'], tag="severity_instruction_text")

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Previous", width=140, height=40, callback=self.prev_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step5_alert_info(self):
        """Step 5: Alert information"""
        dpg.add_text("Step 5: Alert Information", color=THEME['accent_blue'])
        dpg.add_text("Define what users see when this policy fails",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=10)
        dpg.add_text("Format: Separate each point with | (pipe character)",
                    color=THEME['text_secondary'])
        dpg.add_text("CrowdStrike will automatically number them as 1. 2. 3. etc.",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        dpg.add_input_text(default_value=self.new_policy_data['alert_info'], multiline=True,
                          width=700, height=120, tag="alert_info_input",
                          hint="Security misconfiguration detected|Resource exposes sensitive data|Violates compliance requirements PCI-DSS 3.2.1")

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Previous", width=140, height=40, callback=self.prev_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step6_remediation(self):
        """Step 6: Remediation information"""
        dpg.add_text("Step 6: Remediation Steps", color=THEME['accent_blue'])
        dpg.add_text("Provide step-by-step instructions to fix violations",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=10)
        dpg.add_text("Format: Separate each step with | (pipe character)",
                    color=THEME['text_secondary'])
        dpg.add_text("CrowdStrike will automatically number them as Step 1. Step 2. etc.",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        dpg.add_input_text(default_value=self.new_policy_data['remediation_info'], multiline=True,
                          width=700, height=120, tag="remediation_info_input",
                          hint="Navigate to AWS Console and open the S3 service|Select the non-compliant bucket|Click Properties tab and configure settings|Enable server-side encryption and save changes")

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Previous", width=140, height=40, callback=self.prev_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Next", width=140, height=40, callback=self.next_step)
            dpg.add_spacer(width=15)
            dpg.add_button(label="Cancel", width=140, height=40, callback=self.show_main_menu)

    def show_step7_rego_logic(self):
        """Step 7: Rego logic input"""
        dpg.add_text("Step 7: Policy Logic (Rego)", color=THEME['accent_blue'])
        dpg.add_text("Write the Rego code that defines when the policy fails",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=15)

        # Policy summary moved to top
        dpg.add_text("Policy Summary:", color=THEME['accent_orange'])
        dpg.add_text(f"Name: {self.new_policy_data['name']}")
        dpg.add_text(f"Resource Type: {self.new_policy_data['resource_type']}")
        severity_labels = ["Critical", "High", "Medium", "Low", "Info"]
        severity = self.new_policy_data.get('severity', 2)  # Default to Medium
        severity_label = severity_labels[severity]
        dpg.add_text(f"Severity: {severity_label}")

        dpg.add_spacer(height=20)
        dpg.add_separator()
        dpg.add_spacer(height=15)

        # Rego editor (no longer in horizontal layout)
        dpg.add_text("Rego Policy Code:", color=THEME['accent_orange'])
        dpg.add_spacer(height=5)

        # Create template if none exists
        if not self.new_policy_data['rego_logic']:
            resource_type = self.new_policy_data['resource_type']
            template = f"""package crowdstrike

# Default result - required by CrowdStrike CSPM
default result = "pass"

# This rule applies to {resource_type} resources
is_applicable if {{
    input.resource_type == "{resource_type}"
}}

# Policy passes if conditions are met
result = "pass" if {{
    is_applicable
    # Add your compliance conditions here
    # Example: input.configuration.some_field == "good_value"
}}

# Policy fails if violation conditions are met
result = "fail" if {{
    is_applicable
    # Add your violation conditions here
    # Example: input.configuration.some_field != "required_value"
}}"""
            self.new_policy_data['rego_logic'] = template

        # Rego editor - now full width
        dpg.add_input_text(default_value=self.new_policy_data['rego_logic'], multiline=True,
                          width=800, height=350, tag="rego_logic_input")

        dpg.add_spacer(height=20)
        with dpg.group(horizontal=True):
            dpg.add_button(label="Format Code", width=120, height=40,
                         callback=lambda: self.format_rego_code())
            dpg.add_spacer(width=10)
            dpg.add_button(label="Rego Playground", width=140, height=40,
                         callback=self.open_rego_playground)
            dpg.add_spacer(width=10)
            dpg.add_button(label="Previous", width=120, height=40, callback=self.prev_step)
            dpg.add_spacer(width=10)
            dpg.add_button(label="Next", width=120, height=40, callback=self.next_step)
            dpg.add_spacer(width=10)
            dpg.add_button(label="Cancel", width=120, height=40, callback=self.show_main_menu)

    def show_step8_test_and_create(self):
        """Step 8: Test policy and create"""
        dpg.add_text("Step 8: Test and Create Policy", color=THEME['accent_blue'])
        dpg.add_text("Test your policy logic against live resources and create the policy",
                    color=THEME['text_secondary'])
        dpg.add_spacer(height=20)

        # Use horizontal layout for test controls and results (with better spacing)
        with dpg.group(horizontal=True):
            # Left side - Test controls and policy creation
            with dpg.group():
                dpg.add_text("Policy Actions:", color=THEME['accent_orange'])
                dpg.add_spacer(height=10)

                dpg.add_button(label="Test Logic Against Live Resources", width=280, height=40,
                             callback=self.test_new_policy_logic_step8)
                dpg.add_spacer(height=15)

                dpg.add_button(label="Create Policy", width=280, height=40,
                             callback=self.create_policy_final_step8)

                dpg.add_spacer(height=20)

                # Navigation buttons
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Previous", width=120, height=35, callback=self.prev_step)
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Cancel", width=120, height=35, callback=self.show_main_menu)

            dpg.add_spacer(width=30)

            # Right side - Test Results Area (proper spacing)
            with dpg.group():
                dpg.add_text("Policy Test Results:", color=THEME['accent_blue'])
                dpg.add_separator()
                dpg.add_spacer(height=10)

                # Test results container
                with dpg.child_window(height=350, width=450, border=True, tag="step8_test_results_area"):
                    dpg.add_text("Click 'Test Logic Against Live Resources' to validate your policy",
                               color=THEME['text_secondary'], wrap=430, tag="step8_test_status_text")

    def fill_resource_type(self, resource_type: str):
        """Fill the resource type input field with selected value"""
        if dpg.does_item_exist("resource_type_input"):
            dpg.set_value("resource_type_input", resource_type)

    def fill_resource_type_callback(self, sender, app_data, user_data):
        """Callback wrapper for filling resource type from button click"""
        self.fill_resource_type(user_data)

    def select_severity_button(self, severity_value):
        """Handle severity button selection with visual feedback"""
        # Store the selected severity
        self.new_policy_data['severity'] = severity_value
        self.selected_severity_index = severity_value

        # Update button appearances - make selected button look pressed/highlighted
        severity_options = [
            (0, "Critical", "Immediate action required", THEME['accent_red']),
            (1, "High", "Important security issue", THEME['accent_orange']),
            (2, "Medium", "Moderate security concern", [255, 193, 7]),
            (3, "Low", "Minor issue or best practice", THEME['success_green']),
            (4, "Info", "Informational finding", THEME['text_secondary'])
        ]

        for i, (value, label, description, color) in enumerate(severity_options):
            button_tag = f"severity_button_{i}"
            if dpg.does_item_exist(button_tag):
                if value == severity_value:
                    # Selected button - change appearance to show selection
                    dpg.configure_item(button_tag, label=f">>> {label} (Level {value}) <<<")
                else:
                    # Unselected button - normal appearance
                    dpg.configure_item(button_tag, label=f"{label} (Level {value})")

        # Update instruction text to show current selection
        if dpg.does_item_exist("severity_instruction_text"):
            selected_name = severity_options[severity_value][1]
            dpg.set_value("severity_instruction_text", f"Selected: {selected_name} (Level {severity_value})")

    def set_new_policy_severity(self, severity_index):
        """Set severity for new policy creation"""
        if isinstance(severity_index, str):
            try:
                severity_index = int(severity_index)
            except (ValueError, TypeError):
                return

        if 0 <= severity_index <= 4:
            self.new_policy_data['severity'] = severity_index

    def set_severity(self, severity: int):
        """Set selected severity"""
        self.new_policy_data['severity'] = severity
        # Update all radio buttons
        for i in range(5):
            if dpg.does_item_exist(f"severity_radio_{i}"):
                dpg.set_value(f"severity_radio_{i}", i == severity)

    def next_step(self):
        """Move to next step in policy creation"""
        step = self.new_policy_data['step']

        # Validate current step
        if step == 1:
            name = dpg.get_value("policy_name_input").strip()
            description = dpg.get_value("policy_desc_input").strip()
            if not name:
                self.show_error("Policy name is required")
                return
            if not description:
                description = f"Custom policy: {name}"
            self.new_policy_data['name'] = name
            self.new_policy_data['description'] = description

        elif step == 2:
            # Get resource type from the input field
            if dpg.does_item_exist("resource_type_input"):
                resource_type = dpg.get_value("resource_type_input").strip()
                if not resource_type:
                    self.show_error("Please enter or select a resource type")
                    return
                self.new_policy_data['resource_type'] = resource_type
            else:
                self.show_error("Resource type input not found")
                return

        elif step == 4:
            # Validate severity selection
            if 'severity' not in self.new_policy_data:
                self.show_error("Please select a severity level")
                return

        elif step == 5:
            alert_info = dpg.get_value("alert_info_input").strip()
            self.new_policy_data['alert_info'] = alert_info

        elif step == 6:
            remediation_info = dpg.get_value("remediation_info_input").strip()
            self.new_policy_data['remediation_info'] = remediation_info

        elif step == 7:
            # Save Rego logic from Step 7 before moving to Step 8
            if dpg.does_item_exist("rego_logic_input"):
                rego_logic = dpg.get_value("rego_logic_input").strip()
                if not rego_logic:
                    self.show_error("Rego logic is required")
                    return
                self.new_policy_data['rego_logic'] = rego_logic
            else:
                self.show_error("Rego logic input not found")
                return

        # Move to next step
        self.new_policy_data['step'] += 1
        self.show_policy_creation_step()

    def prev_step(self):
        """Move to previous step in policy creation"""
        if self.new_policy_data['step'] > 1:
            self.new_policy_data['step'] -= 1
            self.show_policy_creation_step()

    def test_new_policy_logic_inline(self):
        """Test the new policy logic - INLINE RESULTS (matching existing policy behavior)"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        rego_logic = dpg.get_value("rego_logic_input")
        resource_type = self.new_policy_data['resource_type']

        if not rego_logic.strip():
            self.show_error("Please enter Rego logic to test")
            return

        if not resource_type:
            self.show_error("Resource type not specified")
            return

        print("DEBUG: Starting inline new policy logic test")

        # Update the test results area to show "Testing..." (matching existing policy)
        self.update_new_policy_test_results_display("testing")

        try:
            # Call toolkit directly (matching existing policy behavior)
            print("DEBUG: Calling toolkit.test_policy_logic directly for new policy")
            test_success, detailed_results = self.toolkit.test_policy_logic(rego_logic, resource_type, num_assets=3)

            # Show results in the inline area (matching existing policy)
            print("DEBUG: Displaying new policy results inline")
            self.update_new_policy_test_results_display("results", detailed_results)

        except Exception as e:
            print(f"DEBUG: Exception in test_new_policy_logic_inline: {str(e)}")
            import traceback
            traceback.print_exc()
            self.update_new_policy_test_results_display("error", str(e))

    def clear_new_policy_test_results(self):
        """Clear new policy test results and reset to initial state"""
        if not dpg.does_item_exist("new_policy_test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("new_policy_test_results_area", children_only=True)

        # Reset to initial state
        with dpg.child_window(parent="new_policy_test_results_area", border=False):
            dpg.add_text("Click 'Test Logic' to run policy against live resources",
                       color=THEME['text_secondary'], wrap=360, tag="new_policy_test_status_text")

    def update_new_policy_test_results_display(self, status, data=None):
        """Update the inline test results display for new policy (matching existing policy behavior)"""
        if not dpg.does_item_exist("new_policy_test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("new_policy_test_results_area", children_only=True)

        with dpg.child_window(parent="new_policy_test_results_area", border=False):
            if status == "testing":
                dpg.add_text("Testing Policy...", color=THEME['accent_blue'])
                dpg.add_spacer(height=10)
                dpg.add_text("Running policy against live resources", color=THEME['text_secondary'])
                dpg.add_spacer(height=10)
                dpg.add_text("This may take a few seconds...", color=THEME['text_secondary'])

            elif status == "results" and data:
                # Display actual test results (matching existing policy format)
                total_assets = data.get('total_assets', 0)
                resource_type = data.get('resource_type', 'Unknown')
                pass_count = data.get('pass_count', 0)
                fail_count = data.get('fail_count', 0)
                error_count = data.get('error_count', 0)
                interpretation = data.get('interpretation', '')

                dpg.add_text("Test Complete", color=THEME['success_green'])
                dpg.add_spacer(height=10)

                dpg.add_text(f"Test Summary for {total_assets} {resource_type} assets:", color=THEME['accent_blue'])
                dpg.add_text("Note: Limited to 3 assets max for performance", color=THEME['accent_orange'])
                dpg.add_spacer(height=5)

                if total_assets > 0:
                    dpg.add_text(f"Passed: {pass_count}/{total_assets}", color=THEME['success_green'])
                    dpg.add_text(f"Failed: {fail_count}/{total_assets}", color=THEME['accent_red'])
                    if error_count > 0:
                        dpg.add_text(f"Errors: {error_count}/{total_assets}", color=THEME['accent_orange'])
                else:
                    dpg.add_text("No assets found for testing", color=THEME['accent_orange'])

                dpg.add_spacer(height=10)
                dpg.add_text("Analysis:", color=THEME['accent_blue'])
                dpg.add_text(interpretation, wrap=360, color=THEME['text_secondary'])

                dpg.add_spacer(height=10)

                # Show individual asset results if available (matching existing policy format)
                test_results = data.get('test_results', [])
                if test_results:
                    dpg.add_text("Asset Results:", color=THEME['accent_blue'])
                    dpg.add_spacer(height=5)

                    for i, result in enumerate(test_results[:3], 1):  # Show max 3 results
                        asset_id = result.get('asset_id', 'Unknown')
                        short_id = asset_id.split('|')[-1] if '|' in asset_id else asset_id[-10:]
                        test_result = result.get('result', 'unknown')

                        if test_result == 'pass':
                            status_color = THEME['success_green']
                            status_text = "PASS"
                        elif test_result == 'fail':
                            status_color = THEME['accent_red']
                            status_text = "FAIL"
                        else:
                            status_color = THEME['accent_orange']
                            status_text = "ERROR"

                        with dpg.group(horizontal=True):
                            dpg.add_text(f"{i}.")
                            dpg.add_text(short_id, color=THEME['text_secondary'])
                            dpg.add_text("->")
                            dpg.add_text(status_text, color=status_color)

                dpg.add_spacer(height=15)
                dpg.add_text("See console for full details", color=THEME['text_secondary'], wrap=360)

                # Add Clear Results button (matching existing policy)
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_new_policy_test_results)

            elif status == "error":
                dpg.add_text("Test Failed", color=THEME['accent_red'])
                dpg.add_spacer(height=10)
                dpg.add_text("Error occurred during testing:", color=THEME['text_secondary'])
                dpg.add_spacer(height=5)
                dpg.add_text(str(data)[:150] + "..." if len(str(data)) > 150 else str(data),
                           wrap=360, color=THEME['accent_red'])

                # Add Clear Results button
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_new_policy_test_results)

    def test_new_policy_logic(self):
        """Test the new policy logic - SIMPLIFIED VERSION"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        rego_logic = dpg.get_value("rego_logic_input")
        resource_type = self.new_policy_data['resource_type']

        if not rego_logic.strip():
            self.show_error("Please enter Rego logic to test")
            return

        if not resource_type:
            self.show_error("Resource type not specified")
            return

        print("DEBUG: Starting simplified test_new_policy_logic")

        # Show progress window
        self.show_testing_progress_window()
        self.update_testing_progress("Testing new policy logic against live resources...", 0.5)

        try:
            # Call toolkit directly
            print("DEBUG: Calling toolkit.test_policy_logic directly for new policy")
            test_success, detailed_results = self.toolkit.test_policy_logic(rego_logic, resource_type, num_assets=3)

            # Close progress window
            print("DEBUG: Closing progress window")
            self.close_testing_progress()

            # Show results immediately
            print("DEBUG: Showing new policy results directly")
            self.show_simple_test_results(test_success, detailed_results, "new")

        except Exception as e:
            print(f"DEBUG: Exception in test_new_policy_logic: {str(e)}")
            import traceback
            traceback.print_exc()
            self.close_testing_progress()
            self.show_error(f"Error testing new policy: {str(e)}")

    def create_policy_final(self):
        """Create the final policy"""
        # Get final Rego logic
        rego_logic = dpg.get_value("rego_logic_input")
        if not rego_logic.strip():
            self.show_error("Rego logic is required")
            return

        self.new_policy_data['rego_logic'] = rego_logic

        try:
            headers = self.toolkit._get_headers()
            create_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"

            # Use the same payload structure as working CLI implementation
            cloud_provider = determine_cloud_provider_from_resource_type(self.new_policy_data['resource_type'])
            payload = {
                "name": self.new_policy_data['name'],
                "description": self.new_policy_data['description'],
                "logic": self.new_policy_data['rego_logic'],
                "resource_type": self.new_policy_data['resource_type'],
                "severity": self.new_policy_data['severity'],
                "platform": cloud_provider["platform"],
                "provider": cloud_provider["provider"],
                "domain": "CSPM",
                "subdomain": "IOM",
                "alert_info": self.new_policy_data['alert_info'],
                "attack_types": "Misconfiguration"
            }

            # Add remediation info if provided
            if self.new_policy_data['remediation_info']:
                payload["remediation_info"] = self.new_policy_data['remediation_info']

            response = requests.post(create_url, headers=headers, json=payload)
            if response.status_code == 200:
                self.show_success("Policy created successfully!")
                self.show_main_menu()
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Policy creation failed: {error_msg}")

        except Exception as e:
            self.show_error(f"Error creating policy: {str(e)}")

    def test_new_policy_logic_step8(self):
        """Test new policy logic from Step 8 - uses inline display in step8_test_results_area"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        rego_logic = self.new_policy_data.get('rego_logic', '')
        resource_type = self.new_policy_data['resource_type']

        if not rego_logic.strip():
            self.show_error("No Rego logic found. Please go back to Step 7 and enter your policy logic.")
            return

        if not resource_type:
            self.show_error("Resource type not specified")
            return

        print("DEBUG: Starting Step 8 policy test")

        # Update the test results area to show "Testing..."
        self.update_step8_test_results_display("testing")

        try:
            # Call toolkit directly
            print("DEBUG: Calling toolkit.test_policy_logic directly from Step 8")
            test_success, detailed_results = self.toolkit.test_policy_logic(rego_logic, resource_type, num_assets=3)

            # Show results in the inline area
            print("DEBUG: Displaying Step 8 results inline")
            self.update_step8_test_results_display("results", detailed_results)

        except Exception as e:
            print(f"DEBUG: Exception in test_new_policy_logic_step8: {str(e)}")
            import traceback
            traceback.print_exc()
            self.update_step8_test_results_display("error", str(e))

    def create_policy_final_step8(self):
        """Create the final policy from Step 8"""
        # Use saved Rego logic from new_policy_data
        rego_logic = self.new_policy_data.get('rego_logic', '')

        if not rego_logic.strip():
            self.show_error("No Rego logic found. Please go back to Step 7 and enter your policy logic.")
            return

        try:
            headers = self.toolkit._get_headers()
            create_url = f"{self.toolkit.base_url}/cloud-policies/entities/rules/v1"

            # Use the same payload structure as working CLI implementation
            cloud_provider = determine_cloud_provider_from_resource_type(self.new_policy_data['resource_type'])
            payload = {
                "name": self.new_policy_data['name'],
                "description": self.new_policy_data['description'],
                "logic": rego_logic,
                "resource_type": self.new_policy_data['resource_type'],
                "severity": int(self.new_policy_data['severity']),  # Ensure integer like CLI
                "platform": cloud_provider["platform"],
                "provider": cloud_provider["provider"],
                "domain": "CSPM",
                "subdomain": "IOM",
                "alert_info": self.new_policy_data['alert_info'],
                "attack_types": "Misconfiguration"
            }

            # Add remediation info if provided
            if self.new_policy_data['remediation_info']:
                payload["remediation_info"] = self.new_policy_data['remediation_info']

            response = requests.post(create_url, headers=headers, json=payload)
            if response.status_code == 200:
                self.show_success("Policy created successfully!")
                self.show_main_menu()
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('errors', [{}])[0].get('message', f'HTTP {response.status_code}')
                self.show_error(f"Policy creation failed: {error_msg}")

        except Exception as e:
            self.show_error(f"Error creating policy: {str(e)}")

    def clear_step8_test_results(self):
        """Clear Step 8 test results and reset to initial state"""
        if not dpg.does_item_exist("step8_test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("step8_test_results_area", children_only=True)

        # Reset to initial state
        with dpg.child_window(parent="step8_test_results_area", border=False):
            dpg.add_text("Click 'Test Logic Against Live Resources' to validate your policy",
                       color=THEME['text_secondary'], wrap=430, tag="step8_test_status_text")

    def update_step8_test_results_display(self, status, data=None):
        """Update the Step 8 test results display - similar to existing inline results"""
        if not dpg.does_item_exist("step8_test_results_area"):
            return

        # Clear existing content
        dpg.delete_item("step8_test_results_area", children_only=True)

        with dpg.child_window(parent="step8_test_results_area", border=False):
            if status == "testing":
                dpg.add_text("Testing Policy...", color=THEME['accent_blue'])
                dpg.add_spacer(height=10)
                dpg.add_text("Running policy against live resources", color=THEME['text_secondary'])
                dpg.add_spacer(height=10)
                dpg.add_text("This may take a few seconds...", color=THEME['text_secondary'])

            elif status == "results" and data:
                # Display actual test results
                total_assets = data.get('total_assets', 0)
                resource_type = data.get('resource_type', 'Unknown')
                pass_count = data.get('pass_count', 0)
                fail_count = data.get('fail_count', 0)
                error_count = data.get('error_count', 0)
                interpretation = data.get('interpretation', '')

                dpg.add_text("Test Complete", color=THEME['success_green'])
                dpg.add_spacer(height=10)

                dpg.add_text(f"Test Summary for {total_assets} {resource_type} assets:", color=THEME['accent_blue'])
                dpg.add_text("Note: Limited to 3 assets max for performance", color=THEME['accent_orange'])
                dpg.add_spacer(height=5)

                if total_assets > 0:
                    dpg.add_text(f"Passed: {pass_count}/{total_assets}", color=THEME['success_green'])
                    dpg.add_text(f"Failed: {fail_count}/{total_assets}", color=THEME['accent_red'])
                    if error_count > 0:
                        dpg.add_text(f"Errors: {error_count}/{total_assets}", color=THEME['accent_orange'])
                else:
                    dpg.add_text("No assets found for testing", color=THEME['accent_orange'])

                dpg.add_spacer(height=10)
                dpg.add_text("Analysis:", color=THEME['accent_blue'])
                dpg.add_text(interpretation, wrap=430, color=THEME['text_secondary'])

                dpg.add_spacer(height=10)

                # Show individual asset results if available
                test_results = data.get('test_results', [])
                if test_results:
                    dpg.add_text("Asset Results:", color=THEME['accent_blue'])
                    dpg.add_spacer(height=5)

                    for i, result in enumerate(test_results[:3], 1):  # Show max 3 results
                        asset_id = result.get('asset_id', 'Unknown')
                        short_id = asset_id.split('|')[-1] if '|' in asset_id else asset_id[-10:]
                        test_result = result.get('result', 'unknown')

                        if test_result == 'pass':
                            status_color = THEME['success_green']
                            status_text = "PASS"
                        elif test_result == 'fail':
                            status_color = THEME['accent_red']
                            status_text = "FAIL"
                        else:
                            status_color = THEME['accent_orange']
                            status_text = "ERROR"

                        with dpg.group(horizontal=True):
                            dpg.add_text(f"{i}.")
                            dpg.add_text(short_id, color=THEME['text_secondary'])
                            dpg.add_text("->")
                            dpg.add_text(status_text, color=status_color)

                dpg.add_spacer(height=15)
                dpg.add_text("See console for full details", color=THEME['text_secondary'], wrap=430)

                # Add Clear Results button
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_step8_test_results)

            elif status == "error":
                dpg.add_text("Test Failed", color=THEME['accent_red'])
                dpg.add_spacer(height=10)
                dpg.add_text("Error occurred during testing:", color=THEME['text_secondary'])
                dpg.add_spacer(height=5)
                dpg.add_text(str(data)[:200] + "..." if len(str(data)) > 200 else str(data),
                           wrap=430, color=THEME['accent_red'])

                # Add Clear Results button
                dpg.add_spacer(height=10)
                dpg.add_button(label="Clear Results", width=100, height=25,
                             callback=self.clear_step8_test_results)

    def discover_resource_types(self):
        """Discover resource types - shows all available resource types"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        try:
            # Get resource types using the CLI method
            resource_types = self.toolkit.discover_resource_types()
            self.show_resource_types_list(resource_types)
        except Exception as e:
            self.show_error(f"Failed to discover resource types: {str(e)}")

    def show_resource_types_list(self, resource_types):
        """Show resource types discovery results"""
        if dpg.does_item_exist("main_content"):
            dpg.delete_item("main_content", children_only=True)

        with dpg.child_window(parent="main_content", border=False):
            # Header
            dpg.add_text("Debug: Discover Resource Types", color=THEME['accent_blue'])
            dpg.add_text("Available resource types for creating custom policies",
                        color=THEME['text_secondary'])
            dpg.add_separator()
            dpg.add_spacer(height=20)

            if not resource_types:
                dpg.add_text("No resource types found or discovery failed")
                dpg.add_spacer(height=20)
                dpg.add_button(label="Back to Main Menu", callback=self.show_main_menu)
                return

            # Search box
            dpg.add_text("Search resource types:", color=THEME['accent_orange'])
            dpg.add_input_text(hint="Type to filter resource types...", width=400,
                             tag="resource_type_search", callback=self.filter_resource_types)
            dpg.add_spacer(height=15)

            dpg.add_text(f"Found {len(resource_types)} resource types:")
            dpg.add_spacer(height=10)

            # Store original resource types for filtering
            self.all_resource_types = resource_types

            # Resource types table
            self.show_filtered_resource_types(resource_types)

            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Refresh Discovery", width=150, height=35,
                             callback=self.discover_resource_types)
                dpg.add_spacer(width=10)
                dpg.add_button(label="Back to Main Menu", width=150, height=35,
                             callback=self.show_main_menu)

    def show_filtered_resource_types(self, resource_types):
        """Show resource types in a table"""
        # Remove existing table if it exists
        if dpg.does_item_exist("resource_types_table"):
            dpg.delete_item("resource_types_table")

        with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True,
                     borders_innerV=True, scrollY=True, height=500,
                     tag="resource_types_table") as table:
            dpg.add_table_column(label="Resource Type", width=300)
            dpg.add_table_column(label="Cloud Provider", width=100)
            dpg.add_table_column(label="Service", width=150)
            dpg.add_table_column(label="Resource Count", width=120)

            for resource_type in resource_types:
                with dpg.table_row():
                    # Parse resource type
                    rt_name = resource_type.get('resource_type', 'Unknown')
                    resource_count = resource_type.get('count', 0)

                    # Determine cloud provider and service
                    if rt_name.startswith('AWS::'):
                        provider = 'AWS'
                        service = rt_name.split('::')[1] if len(rt_name.split('::')) > 1 else 'Unknown'
                    elif rt_name.startswith('Azure.'):
                        provider = 'Azure'
                        service = rt_name.split('.')[0] if '.' in rt_name else 'Unknown'
                    elif 'googleapis.com' in rt_name:
                        provider = 'GCP'
                        service = rt_name.split('.')[0] if '.' in rt_name else 'Unknown'
                    else:
                        provider = 'Other'
                        service = 'Unknown'

                    # Resource type name (with color coding by provider)
                    provider_colors = {
                        'AWS': THEME['accent_orange'],
                        'Azure': THEME['accent_blue'],
                        'GCP': THEME['success_green'],
                        'Other': THEME['text_secondary']
                    }
                    dpg.add_text(rt_name, color=provider_colors.get(provider, THEME['text_primary']))

                    # Provider
                    dpg.add_text(provider, color=provider_colors.get(provider, THEME['text_primary']))

                    # Service
                    dpg.add_text(service)

                    # Resource count
                    count_color = THEME['success_green'] if resource_count > 0 else THEME['text_secondary']
                    dpg.add_text(str(resource_count), color=count_color)

    def filter_resource_types(self):
        """Filter resource types based on search input"""
        if not hasattr(self, 'all_resource_types'):
            return

        search_term = dpg.get_value("resource_type_search").lower()

        if not search_term:
            filtered_types = self.all_resource_types
        else:
            filtered_types = [
                rt for rt in self.all_resource_types
                if search_term in rt.get('resource_type', '').lower()
            ]

        self.show_filtered_resource_types(filtered_types)

    def show_success(self, message):
        """Show success dialog"""
        with dpg.window(label="Success", modal=True, show=True,
                       width=350, height=150, pos=[325, 250]) as success_window:
            dpg.add_text(f"Success: {message}", color=THEME['success_green'])
            dpg.add_spacer(height=20)
            dpg.add_button(label="OK", callback=lambda: dpg.delete_item(success_window))

    def show_error(self, message):
        """Show error dialog"""
        with dpg.window(label="Error", modal=True, show=True,
                       width=400, height=150, pos=[300, 250]) as error_window:
            dpg.add_text(f"Error: {message}", color=THEME['accent_red'])
            dpg.add_spacer(height=20)
            dpg.add_button(label="OK", callback=lambda: dpg.delete_item(error_window))

    def show_info(self, message):
        """Show info dialog"""
        with dpg.window(label="Information", modal=True, show=True,
                       width=400, height=150, pos=[300, 250]) as info_window:
            dpg.add_text(f"Info: {message}", color=THEME['accent_blue'])
            dpg.add_spacer(height=20)
            dpg.add_button(label="OK", callback=lambda: dpg.delete_item(info_window))

    def fetch_sample_asset_data(self):
        """Fetch sample asset data using CLI method with active status filtering"""
        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        resource_type = self.new_policy_data.get('resource_type', '')
        if not resource_type:
            self.show_error("No resource type specified")
            return

        # Show progress
        self.show_info("Fetching sample asset data... This may take a few seconds.")

        try:
            # Use an enhanced version that prioritizes active resources
            sample_data = self.get_sample_asset_data_enhanced(resource_type)

            if sample_data:
                self.sample_asset_data = sample_data
                self.show_success("Sample asset data loaded successfully!")
                # Refresh the current step to show the loaded data
                self.show_policy_creation_step()
            else:
                self.show_error("Could not fetch sample asset data. No active resources found or API error.")

        except Exception as e:
            self.show_error(f"Error fetching sample data: {str(e)}")

    def get_sample_asset_data_enhanced(self, resource_type: str) -> dict:
        """Enhanced version that uses bulk enriched API call - much more efficient"""
        print(f"Fetching sample {resource_type} data from enriched API...")

        headers = self.toolkit._get_headers()

        # Step 1: Get resources of the specific type first (more targeted approach)
        discover_url = f"{self.toolkit.base_url}/cloud-security-assets/queries/resources/v1"

        # Primary approach: Filter by resource type AND active status to get only active resources
        # This is much more efficient than filtering afterwards
        # Only need 1 sample asset, not 100 - much faster for large environments
        discover_params = {"filter": f"resource_type:'{resource_type}'+active:'true'", "limit": 1}
        print(f"Querying for 1 active {resource_type} resource for sampling...")

        try:
            discover_response = requests.get(discover_url, headers=headers, params=discover_params, timeout=30)
            if discover_response.status_code == 200:
                resource_ids = discover_response.json().get("resources", [])
                if resource_ids:
                    print(f"✓ Found {len(resource_ids)} {resource_type} resources")
                else:
                    print(f"❌ No {resource_type} resources found in your environment")
                    return None
            else:
                print(f"❌ Resource discovery failed: {discover_response.status_code}")
                print(f"Response: {discover_response.text[:200]}")
                return None
        except Exception as e:
            print(f"❌ Exception during resource discovery: {e}")
            return None

        # Step 2: BULK ENRICHED API CALL - much more efficient!
        print(f"Making bulk enriched API call for {len(resource_ids)} {resource_type} resources...")

        enriched_url = f"{self.toolkit.base_url}/cloud-policies/entities/enriched-resources/v1"

        # Use first tenant ID for header (all resources should be in same tenant)
        tenant_id = resource_ids[0].split('|')[0]

        enriched_headers = self.toolkit._get_headers()
        enriched_headers["X-CS-CUSTID"] = tenant_id

        # BULK CALL: Pass up to 100 resource IDs at once
        bulk_ids = resource_ids[:100]
        enriched_params = {"ids": bulk_ids}

        try:
            enriched_response = requests.get(enriched_url, headers=enriched_headers, params=enriched_params, timeout=60)
            if enriched_response.status_code == 200:
                enriched_data = enriched_response.json()
                all_resources = enriched_data.get("resources", [])

                print(f"✓ Enriched API returned data for {len(all_resources)} {resource_type} resources")

                # Since we filtered for active assets in the discovery query,
                # we should primarily get active assets, but let's still prioritize them
                active_assets = []
                other_assets = []

                for resource in all_resources:
                    actual_type = resource.get("resource_type", "unknown")
                    asset_status = resource.get("active", "unknown")
                    asset_id = resource.get("resource_id", "unknown")

                    print(f"Found: {actual_type} (active: {asset_status}) - {asset_id[-20:]}")

                    # Since we filtered by resource_type, all should match, but double-check
                    if resource_type == actual_type:
                        # Handle both boolean True and string "true" for active status
                        if asset_status == True or asset_status == "true":
                            print(f"  ✓ ACTIVE {resource_type}")
                            active_assets.append(resource)
                        else:
                            print(f"  ~ NON-ACTIVE {resource_type} (unexpected - we filtered for active)")
                            other_assets.append(resource)
                    else:
                        print(f"  ? Unexpected type: {actual_type}")

                # Return best available asset: should be active since we filtered for them
                if active_assets:
                    best_asset = active_assets[0]
                    print(f"\n✓✓ USING ACTIVE {resource_type}: {len(best_asset.keys())} fields available")
                    return best_asset
                elif other_assets:
                    best_asset = other_assets[0]
                    print(f"\n⚠ USING NON-ACTIVE {resource_type}: {len(best_asset.keys())} fields available")
                    print("Note: Non-active assets may have limited configuration data")
                    return best_asset
                else:
                    print(f"\n❌ No {resource_type} assets found in enriched data")
                    return None

            else:
                print(f"❌ Bulk enriched API call failed: {enriched_response.status_code}")
                print(f"Response: {enriched_response.text[:200]}")
                return None

        except Exception as e:
            print(f"❌ Exception during bulk enriched API call: {e}")
            return None

    def view_sample_data_dialog(self):
        """Show sample data in a dialog"""
        if not hasattr(self, 'sample_asset_data') or not self.sample_asset_data:
            self.show_error("No sample data available")
            return

        if dpg.does_item_exist("sample_data_window"):
            dpg.delete_item("sample_data_window")

        with dpg.window(label="Sample Asset Data", modal=True, show=True,
                       width=800, height=600, pos=[200, 100], tag="sample_data_window"):

            dpg.add_text("Sample Asset Data Structure", color=THEME['accent_orange'])
            dpg.add_separator()
            dpg.add_spacer(height=10)

            # Show key fields first
            key_fields = ["resource_id", "resource_type", "configuration", "tags", "region", "service"]

            dpg.add_text("Key Fields:", color=THEME['accent_blue'])
            dpg.add_spacer(height=5)

            for field in key_fields:
                if field in self.sample_asset_data:
                    value = self.sample_asset_data[field]
                    if isinstance(value, dict):
                        dpg.add_text(f"{field}: (object with {len(value.keys())} fields)",
                                   color=THEME['success_green'])
                    elif isinstance(value, list):
                        dpg.add_text(f"{field}: (array with {len(value)} items)",
                                   color=THEME['success_green'])
                    else:
                        display_value = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                        dpg.add_text(f"{field}: {display_value}", color=THEME['success_green'])

            dpg.add_spacer(height=15)

            # Show other fields
            other_fields = [k for k in self.sample_asset_data.keys() if k not in key_fields]
            if other_fields:
                dpg.add_text("Other Fields:", color=THEME['accent_blue'])
                dpg.add_spacer(height=5)

                # Show first 15 other fields
                fields_to_show = other_fields[:15]
                for field in fields_to_show:
                    value = self.sample_asset_data[field]
                    if isinstance(value, dict):
                        dpg.add_text(f"{field}: (object)", color=THEME['text_secondary'])
                    elif isinstance(value, list):
                        dpg.add_text(f"{field}: (array)", color=THEME['text_secondary'])
                    else:
                        display_value = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
                        dpg.add_text(f"{field}: {display_value}", color=THEME['text_secondary'])

                if len(other_fields) > 15:
                    dpg.add_text(f"...and {len(other_fields) - 15} more fields", color=THEME['text_secondary'])

            dpg.add_spacer(height=15)
            dpg.add_text("Tip: Use this structure to write your Rego policy logic",
                        color=THEME['accent_orange'])
            dpg.add_text("Example: input.configuration.some_field or input.tags[_].key",
                        color=THEME['text_secondary'])

            dpg.add_spacer(height=20)
            dpg.add_button(label="Close", width=100, height=35,
                         callback=lambda: dpg.delete_item("sample_data_window"))

    def save_sample_data_to_file(self):
        """Save sample data to JSON file"""
        print("DEBUG: save_sample_data_to_file called")  # Debug line

        if not hasattr(self, 'sample_asset_data') or not self.sample_asset_data:
            print("DEBUG: No sample asset data available")  # Debug line
            self.show_error("No sample data to save")
            return

        # Check if we're saving from the sample data dialog window and close it first
        # This ensures the success popup appears in front
        close_sample_dialog = dpg.does_item_exist("sample_data_window")

        try:
            import json
            import os

            # Check if we have new_policy_data context
            if hasattr(self, 'new_policy_data') and self.new_policy_data:
                resource_type = self.new_policy_data.get('resource_type', 'unknown')
                print(f"DEBUG: Using resource_type from new_policy_data: {resource_type}")  # Debug line
            else:
                # Fallback - get resource type from sample data itself
                resource_type = self.sample_asset_data.get('resource_type', 'unknown')
                print(f"DEBUG: Using resource_type from sample_asset_data: {resource_type}")  # Debug line

            filename = f"sample_{resource_type.replace('::', '_').replace('/', '_').lower()}_asset.json"

            # Get absolute path for clarity
            full_path = os.path.abspath(filename)
            print(f"DEBUG: Saving to: {full_path}")  # Debug line

            print(f"DEBUG: Sample data has {len(self.sample_asset_data.keys())} fields")  # Debug line

            with open(filename, 'w') as f:
                json.dump(self.sample_asset_data, f, indent=2)

            print(f"DEBUG: File saved successfully: {filename}")  # Debug line

            # Close the sample data dialog if it exists to ensure success popup appears in front
            if close_sample_dialog:
                print("DEBUG: Closing sample_data_window before showing success")  # Debug line
                dpg.delete_item("sample_data_window")

            self.show_success(f"Sample data saved to:\n{full_path}")

        except Exception as e:
            print(f"DEBUG: Exception occurred: {str(e)}")  # Debug line
            import traceback
            traceback.print_exc()  # Print full stack trace
            self.show_error(f"Failed to save file: {str(e)}")

    def export_sample_asset_data(self):
        """Export sample asset data for the current policy's resource type"""
        if not self.selected_policy:
            self.show_error("No policy selected")
            return

        if not self.ensure_authenticated():
            self.show_error("Authentication failed. Please check your credentials.")
            return

        # Get resource type from the selected policy
        resource_types = self.selected_policy.get('resource_types', [])
        if not resource_types or len(resource_types) == 0:
            self.show_error("No resource type found in this policy")
            return

        resource_type = resource_types[0].get('resource_type')
        if not resource_type:
            self.show_error("No resource type found in this policy")
            return

        # Show progress in console instead of blocking modal dialog
        print(f"DEBUG: Fetching sample asset data for {resource_type}... This may take a few seconds.")

        try:
            # Use the enhanced method to get sample asset data
            sample_data = self.get_sample_asset_data_enhanced(resource_type)

            if sample_data:
                # Save the data using the same logic as save_sample_data_to_file
                import json
                import os

                # Create safe filename
                safe_resource_type = resource_type.replace('::', '_').replace('/', '_').replace('.', '_').lower()
                filename = f"sample_{safe_resource_type}_asset.json"

                # Get absolute path for clarity
                full_path = os.path.abspath(filename)
                print(f"DEBUG: Exporting sample data to: {full_path}")

                print(f"DEBUG: Sample data has {len(sample_data.keys())} fields")

                with open(filename, 'w') as f:
                    json.dump(sample_data, f, indent=2)

                print(f"DEBUG: File saved successfully: {filename}")

                policy_name = self.selected_policy.get('name', 'Policy')
                self.show_success(f"Sample {resource_type} data exported to:\n{full_path}")

            else:
                self.show_error("Could not fetch sample asset data. No active resources found or API error.")

        except Exception as e:
            print(f"DEBUG: Exception in export_sample_asset_data: {str(e)}")
            import traceback
            traceback.print_exc()
            self.show_error(f"Error exporting sample data: {str(e)}")

    def create_main_window(self):
        """Create main window"""
        with dpg.window(label="CrowdStrike Custom IOM Toolkit",
                       width=1200, height=800, no_close=True) as main_window:

            # Header
            dpg.add_text("CrowdStrike Custom IOM Toolkit", color=THEME['accent_red'])
            dpg.add_text("Professional Policy Management Interface",
                        color=THEME['text_secondary'])
            dpg.add_separator()

            # Main content area
            dpg.add_child_window(height=700, tag="main_content")

            # Status bar
            dpg.add_separator()
            dpg.add_text("Ready", color=THEME['success_green'])

        dpg.set_primary_window(main_window, True)
        self.show_main_menu()

    def run(self):
        """Run GUI application"""
        dpg.create_context()
        self.setup_theme()
        self.create_main_window()
        dpg.create_viewport(title="CrowdStrike Custom IOM Toolkit",
                          width=1200, height=800, min_width=800, min_height=600)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

def run_gui():
    """Entry point for GUI"""
    gui = CustomIOMGUI()
    gui.run()

if __name__ == "__main__":
    run_gui()