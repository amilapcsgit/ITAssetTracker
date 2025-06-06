import streamlit as st
import urllib.parse # Added import
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import logging
from datetime import datetime
import os
import subprocess
import re

from asset_parser import AssetParser
from dashboard_components import DashboardComponents

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="IT Asset Management Dashboard",
    page_icon="🖥️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Windows 11 Theme CSS
def apply_windows11_theme():
    """Apply Windows 11 styled CSS"""
    theme_mode = st.session_state.get('theme_mode', 'light')
    
    if theme_mode == 'dark':
        bg_color = "#1e1e1e"
        surface_color = "#2d2d30"
        card_color = "#383838"
        text_color = "#ffffff"
        accent_color = "#0078d4"
        hover_color = "#106ebe"
        border_color = "#484848"
    else:
        bg_color = "#F4F6F8"
        surface_color = "#ffffff"
        card_color = "#fafafa"
        text_color = "#212529"  # Updated text color
        accent_color = "#3C82F6"  # Updated accent color
        hover_color = "#2575F5"  # Updated hover color
        border_color = "#e1dfdd"
    
    st.markdown(f"""
    <style>
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}

    .main-title {{
        font-size: 2.5em; /* Larger font size */
        font-weight: bold; /* Bolder font weight */
        margin-bottom: 0px; /* Reduced bottom margin */
    }}

    .caption-text {{
        font-size: 0.85em; /* Smaller font size */
        color: #6c757d; /* Lighter color */
        padding-top: 0px; /* Reduced top padding */
    }}

    /* Removed .asset-name-button styles */
    
    .asset-bubble {{
        background-color: {card_color}; /* Use card_color for background */
        border-radius: 8px;
        padding: 12px; /* Adjusted padding */
        margin: 8px;
        /* color: white; Removed, will inherit from .stApp */
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        min-height: 140px; /* Keep or adjust as needed */
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        border-left: 5px solid transparent; /* Base for status line */
    }}
    
    .asset-bubble:hover {{
        transform: translateY(-2px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        /* background: linear-gradient(135deg, {hover_color} 0%, {accent_color} 100%); Removed gradient hover */
    }}

    /* Status Indicator Border Colors */
    .status-indicator-online {{ border-left-color: #3C82F6 !important; }}
    .status-indicator-offline {{ border-left-color: #D9534F !important; }}
    .status-indicator-scanning {{ border-left-color: #777777 !important; }}
    .status-indicator-pending {{ border-left-color: #F0AD4E !important; }}
    .status-indicator-failed {{ border-left-color: #D9534F !important; }}

    .asset-bubble-content {{
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        height: 100%;
    }}

    .asset-header {{
        margin-bottom: 8px;
    }}

    .asset-name-link {{
        font-size: 16px;
        font-weight: 600;
        text-decoration: none;
        color: {text_color};
    }}
    .asset-name-link:hover {{
        text-decoration: underline;
        color: {hover_color};
    }}
    
    .asset-ip {{
        font-size: 12px;
        opacity: 0.9;
        margin-bottom: 8px;
    }}
    
    .asset-os {{
        font-size: 11px;
        opacity: 0.8;
        margin-bottom: 4px;
    }}
    
    .asset-ram {{
        font-size: 14px;
        font-weight: 500;
        margin-bottom: 8px;
    }}
    
    .anydesk-link {{
        background-color: rgba(255,255,255,0.2);
        border: 1px solid rgba(255,255,255,0.3);
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 10px;
        text-decoration: none;
        color: {accent_color}; /* Use accent_color for links */
        background-color: transparent; /* Remove specific background */
        border: none; /* Remove specific border */
        padding: 4px 0px; /* Adjust padding if needed */
        display: inline-block;
        transition: all 0.2s ease;
    }}
    
    .anydesk-link:hover {{
        /* background-color: rgba(255,255,255,0.3); Removed */
        /* border-color: rgba(255,255,255,0.5); Removed */
        color: {hover_color}; /* Darken or change link color on hover */
        text-decoration: underline;
    }}
    
    .asset-storage {{
        font-size: 11px;
        opacity: 0.8;
        margin-bottom: 4px;
    }}
    
    .low-storage {{
        /* This class is applied to asset-bubble, so it might conflict with status indicators if it also changes border-left. */
        /* For now, keep its distinct background, but ensure it doesn't override the status border. */
        background-color: #FFF3CD !important; /* A light yellow, distinct from card_color but less aggressive than gradient */
        /* border: 2px solid #F0AD4E !important; /* This might be too much with border-left */
        /* Consider a more subtle low storage indication if using border-left for status */
    }}
    
    .low-storage:hover {{
        background-color: #FFF3CD !important; /* Keep consistent on hover, or slightly darker shade of yellow */
    }}

    /* Status Text Colors */
    .status-online {{ color: #3C82F6; font-size: 12px; }}
    .status-offline {{ color: #D9534F; font-size: 12px; }}
    .status-scanning {{ color: #777777; font-size: 12px; }}
    .status-pending {{ color: #F0AD4E; font-size: 12px; }}
    .status-failed {{ color: #D9534F; font-size: 12px; }}
    
    .filter-section {{
        background-color: {surface_color};
        border: 1px solid {border_color};
        border-radius: 8px;
        padding: 16px;
        margin: 8px 0;
    }}
    
    .metric-card {{
        background-color: {card_color};
        border: 1px solid {border_color};
        border-radius: 8px;
        padding: 16px;
        margin: 8px 0;
    }}

    .filter-pill-container {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px; /* Space between pills */
        padding-bottom: 16px; /* Space below the pill container */
        align-items: center; /* Align items vertically */
    }}

    .filter-pill {{
        background-color: #e9ecef;
        color: #495057;
        padding: 5px 8px 5px 12px; /* Top Right Bottom Left */
        border-radius: 16px;
        font-size: 0.875em;
        display: flex; /* Use flex to align text and button */
        align-items: center;
        gap: 5px; /* Space between text and button */
        border: 1px solid #ced4da;
    }}

    .filter-pill-text {{
        /* No specific styling needed if it's just text, but can add if required */
    }}

    /* Styling for the dismiss button itself (Streamlit's default button is hard to override perfectly) */
    /* We target the button within the specific structure Streamlit creates */
    .filter-pill .stButton button {{
        background-color: transparent !important;
        color: #6c757d !important; /* Muted color for 'x' */
        border: none !important;
        padding: 0px 3px !important; /* Minimal padding */
        margin: 0 !important;
        line-height: 1 !important; /* Align 'x' better */
        font-size: 1.2em !important; /* Make 'x' slightly larger */
        font-weight: bold !important;
        box-shadow: none !important;
    }}
    .filter-pill .stButton button:hover {{
        color: #343a40 !important; /* Darker on hover */
        background-color: transparent !important;
    }}
    .filter-pill .stButton button:focus {{
        outline: none !important;
        box-shadow: none !important;
    }}

    .asset-details-group {{
        margin-bottom: 8px;
    }}

    .asset-footer-group {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 12px;
    }}

    .asset-account, .asset-user-email {{
        font-size: 11px;
        opacity: 0.8;
        margin-bottom: 4px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}

    .summary-charts-container {{
        padding: 10px;
        /* background-color: #f8f9fa; /* Optional: slight background for the charts area */
        /* border: 1px solid #dee2e6;    /* Optional: border for the charts area */
        border-radius: 8px;
        margin-bottom: 16px; /* Space below the charts container */
    }}
    </style>
    """, unsafe_allow_html=True)

class ITAssetDashboard:
    def __init__(self):
        self.asset_parser = AssetParser()
        self.dashboard_components = DashboardComponents()
        self.assets_folder = Path("assets")
        
        # Initialize session state
        if 'assets_data' not in st.session_state:
            st.session_state.assets_data = {}
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = None
        if 'selected_assets' not in st.session_state:
            st.session_state.selected_assets = []
        if 'theme_mode' not in st.session_state:
            st.session_state.theme_mode = 'light'
        if 'show_asset_details' not in st.session_state:
            st.session_state.show_asset_details = False
        if 'selected_asset_for_details' not in st.session_state:
            st.session_state.selected_asset_for_details = None
        if 'show_low_storage_only' not in st.session_state:
            st.session_state.show_low_storage_only = False
        if 'nmap_enabled' not in st.session_state:
            st.session_state.nmap_enabled = False # Effectively controlled by nmap_scan_type now
        if 'nmap_path' not in st.session_state:
            st.session_state.nmap_path = "nmap"
        if 'nmap_scan_type' not in st.session_state:
            st.session_state.nmap_scan_type = "Disabled"
        if 'nmap_scan_queue' not in st.session_state:
            st.session_state.nmap_scan_queue = []
        if 'nmap_currently_scanning' not in st.session_state:
            st.session_state.nmap_currently_scanning = None # Stores asset name being scanned

        # --- Filter-related session state initialization ---
        if 'selected_os_filter' not in st.session_state:
            st.session_state.selected_os_filter = []
        if 'selected_manufacturers_filter' not in st.session_state:
            st.session_state.selected_manufacturers_filter = []
        if 'ram_range_filter' not in st.session_state: # Tuple: (min_ram, max_ram) or None
            st.session_state.ram_range_filter = None
        if 'storage_range_filter' not in st.session_state: # Tuple: (min_storage, max_storage) or None
            st.session_state.storage_range_filter = None
        # show_low_storage_only is already initialized
        if 'anydesk_search_filter' not in st.session_state:
            st.session_state.anydesk_search_filter = ""
        if 'search_term_filter' not in st.session_state:
            st.session_state.search_term_filter = ""
        # selected_assets_filter is removed

        # UI Customization Settings
        if 'show_summary_section' not in st.session_state:
            st.session_state.show_summary_section = True
        if 'show_bubbles_section' not in st.session_state:
            st.session_state.show_bubbles_section = True
        if 'show_details_table_section' not in st.session_state:
            st.session_state.show_details_table_section = True


    def _run_nmap_scan(self, ip_address: str, nmap_executable_path: str = "nmap", scan_type: str = "Full Scan") -> dict:
        """Run nmap scan on a given IP address and parse results based on scan type."""
        result = {
            "status": "unknown",
            "mac_address": None,
            "nmap_output": "",
            "error_message": None
        }
        logger.info(f"Starting nmap scan for IP: {ip_address}")
        try:
            # -Pn: Treat host as online (skip host discovery)
            # -T4: Aggressive timing
            # -A: Enable OS detection, version detection, script scanning, and traceroute
            # -v: Verbose
            # -sn: Ping Scan - disable port scan. Used for Quick Scan.

            command = []
            if scan_type == "Quick Scan":
                command = [nmap_executable_path, "-sn", "-T4", ip_address]
                logger.info(f"Executing Nmap Quick Scan for {ip_address}: {' '.join(command)}")
            elif scan_type == "Full Scan":
                command = [nmap_executable_path, "-T4", "-A", "-v", "-Pn", ip_address]
                logger.info(f"Executing Nmap Full Scan for {ip_address}: {' '.join(command)}")
            else:
                result["status"] = "error"
                result["error_message"] = f"Invalid scan type: {scan_type}"
                logger.error(f"Invalid nmap scan type '{scan_type}' for IP {ip_address}")
                return result

            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120  # 120 seconds timeout
            )
            result["nmap_output"] = process.stdout

            if process.returncode == 0:
                logger.info(f"Nmap {scan_type} for {ip_address} command executed successfully (returncode 0). Output:\n{process.stdout[:500]}...") # Log part of output

                if "Host seems down" in process.stdout:
                    result["status"] = "offline"
                elif "Host is up" in process.stdout: # This is the primary indicator for both scan types
                    result["status"] = "online"
                # For Full Scan, open ports can also indicate 'online' if -Pn was used and Host is up/down is ambiguous
                elif scan_type == "Full Scan" and re.search(r"\d+/open/", process.stdout):
                    result["status"] = "online"
                else: # Default to offline if no clear "up" signal, or if quick scan output is minimal
                    result["status"] = "offline"

                logger.info(f"Nmap {scan_type} for {ip_address}: Parsed status: {result['status']}.")

                if scan_type == "Full Scan":
                    mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", process.stdout, re.IGNORECASE)
                    if mac_match:
                        result["mac_address"] = mac_match.group(1).upper()
                        logger.info(f"Nmap Full Scan for {ip_address}: MAC Address found: {result['mac_address']}")
                    else:
                        # Attempt to find MAC in other formats for some OSes (e.g., Linux `nmap localhost`)
                        mac_alt_match = re.search(r"Station MAC: ([0-9A-Fa-f:]{17})", process.stdout, re.IGNORECASE) # Common in -A for local machine
                        if mac_alt_match:
                            result["mac_address"] = mac_alt_match.group(1).upper()
                            logger.info(f"Nmap Full Scan for {ip_address}: Alternate MAC Address found: {result['mac_address']}")
                        else:
                            logger.info(f"Nmap Full Scan for {ip_address}: MAC Address not found in output.")
                # For Quick Scan, result["mac_address"] remains None
            else:
                result["status"] = "error"
                result["error_message"] = f"Nmap {scan_type} for {ip_address} failed with return code {process.returncode}. Error: {process.stderr}"
                logger.error(f"Nmap scan for {ip_address} failed. STDERR: {process.stderr}")

        except FileNotFoundError:
            result["status"] = "error"
            result["error_message"] = f"Nmap command not found at '{nmap_executable_path}'. Please ensure nmap is installed and the path is correct."
            logger.error(f"Nmap command not found at '{nmap_executable_path}' during scan attempt.")
        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["error_message"] = f"Nmap scan for {ip_address} timed out."
            logger.error(f"Nmap scan for {ip_address} timed out.")
        except Exception as e:
            result["status"] = "error"
            result["error_message"] = f"An unexpected error occurred during nmap scan: {str(e)}"
            logger.error(f"Unexpected error during nmap scan for {ip_address}: {str(e)}")

        return result

    def load_assets_data(self):
        """Load and parse all asset files from the assets folder"""
        try:
            if not self.assets_folder.exists():
                self.assets_folder.mkdir(exist_ok=True)
                logger.warning(f"Assets folder created at {self.assets_folder}")
                return {}

            asset_files = list(self.assets_folder.glob("*.txt"))
            
            if not asset_files:
                logger.info("No asset files found in assets folder")
                return {}

            assets_data = {}
            for file_path in asset_files:
                try:
                    asset_data = self.asset_parser.parse_asset_file(file_path)
                    if asset_data:
                        # Initialize network_info if not present
                        if 'network_info' not in asset_data:
                            asset_data['network_info'] = {}

                        # Set initial nmap_scan_status and default status from parser
                        asset_data['network_info']['nmap_scan_status'] = 'pending' # Default for potential scan
                        if 'status' not in asset_data['network_info']: # if parser didn't set one
                             asset_data['network_info']['status'] = 'unknown'


                        asset_name = asset_data.get('computer_name', file_path.stem)
                        ip_address = asset_data.get('network_info', {}).get('ip_address')
                        current_scan_type = st.session_state.nmap_scan_type

                        if current_scan_type != "Disabled" and ip_address and ip_address != 'N/A':
                            # Add to queue if not already processed or queued
                            # Note: A more robust check for "already processed" might involve looking at nmap_scan_status
                            if asset_name not in st.session_state.nmap_scan_queue and \
                               asset_name != st.session_state.nmap_currently_scanning and \
                               asset_data['network_info'].get('nmap_scan_status') != 'completed' and \
                               asset_data['network_info'].get('nmap_scan_status') != 'failed': # Avoid re-queueing completed/failed
                                st.session_state.nmap_scan_queue.append(asset_name)
                                logger.info(f"Asset {asset_name} added to Nmap scan queue.")
                            else:
                                # If already processed (e.g. from a previous partial scan run), ensure status is not 'pending'
                                if asset_data['network_info'].get('nmap_scan_status') == 'pending':
                                     asset_data['network_info']['nmap_scan_status'] = 'unknown' # reset if it was pending but not queued
                        else:
                            asset_data['network_info']['nmap_scan_status'] = 'disabled' # Explicitly mark as disabled or no IP

                        assets_data[asset_name] = asset_data
                        logger.info(f"Successfully processed {file_path.name} (including nmap if applicable).")
                    else:
                        logger.warning(f"No data extracted from {file_path.name}")
                except Exception as e:
                    logger.error(f"Error processing file {file_path.name} in load_assets_data: {str(e)}")
                    continue

            st.session_state.last_refresh = datetime.now()
            return assets_data

        except Exception as e:
            logger.error(f"Error loading assets data: {str(e)}")
            st.error(f"Error loading assets data: {str(e)}")
            return {}

    def normalize_os_version(self, os_string):
        """Normalize OS version for better filtering"""
        if not os_string:
            return "Unknown"
        
        os_lower = os_string.lower()
        if "windows 11" in os_lower:
            return "Windows 11"
        elif "windows 10" in os_lower:
            return "Windows 10"
        elif "windows 8" in os_lower:
            return "Windows 8"
        elif "windows 7" in os_lower:
            return "Windows 7"
        elif "windows server 2022" in os_lower:
            return "Windows Server 2022"
        elif "windows server 2019" in os_lower:
            return "Windows Server 2019"
        elif "windows server 2016" in os_lower:
            return "Windows Server 2016"
        elif "windows server" in os_lower:
            return "Windows Server"
        else:
            return os_string

    def get_c_drive_free_space(self, asset):
        """Extract C drive free space from asset data"""
        try:
            storage_devices = asset.get('hardware_info', {}).get('storage', [])
            for device in storage_devices:
                device_name = device.get('name', '').upper()
                if 'C:' in device_name or 'C Drive' in device_name:
                    return device.get('free_space_gb', None)
            
            # Try to parse from raw content
            raw_content = asset.get('raw_content', '')
            if raw_content:
                # Look for C drive free space patterns
                import re
                patterns = [
                    r'C:.*?(\d+\.?\d*)\s*GB.*?free',
                    r'Free Space.*?C.*?(\d+\.?\d*)\s*GB',
                    r'C Drive.*?Free.*?(\d+\.?\d*)\s*GB'
                ]
                for pattern in patterns:
                    match = re.search(pattern, raw_content, re.IGNORECASE)
                    if match:
                        return float(match.group(1))
            
            return None
        except Exception:
            return None

    def check_and_install_dependencies(self):
        """Check and install required dependencies"""
        required_packages = ['streamlit', 'pandas', 'plotly']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            st.warning(f"Installing missing packages: {', '.join(missing_packages)}")
            import subprocess
            import sys
            for package in missing_packages:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            st.success("Dependencies installed successfully! Please refresh the page.")
            st.stop()

    def render_header(self):
        """Render the main header with title and refresh button"""
        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
        
        with col1:
            st.markdown('<p class="main-title">🖥️ IT Asset Management Dashboard</p>', unsafe_allow_html=True)
            if st.session_state.last_refresh:
                st.markdown(f'<p class="caption-text">Last updated: {st.session_state.last_refresh.strftime("%Y-%m-%d %H:%M:%S")}</p>', unsafe_allow_html=True)
        
        with col2:
            # Theme toggle
            if st.button("🌓 Toggle Theme"):
                st.session_state.theme_mode = 'dark' if st.session_state.theme_mode == 'light' else 'light'
                st.rerun()
        
        with col3:
            if st.button("🔄 Refresh Data", type="primary"):
                with st.spinner("Refreshing asset data..."):
                    st.session_state.assets_data = self.load_assets_data()
                st.rerun()
        
        with col4:
            asset_count = len(st.session_state.assets_data)
            st.metric("Total Assets", asset_count)

    def render_sidebar_filters(self):
        """Render sidebar with filtering options"""
        st.sidebar.header("Filters & Options")
        
        if not st.session_state.assets_data:
            st.sidebar.info("No asset data available. Please ensure asset files are in the 'assets' folder.")
            return {}

        # Asset selection (Removed)

        # OS filter with normalized versions
        all_os_versions_set = set()
        all_manufacturers_set = set()
        all_ram_values_list = []
        all_storage_values_list = []

        for asset in st.session_state.assets_data.values():
            if 'os_info' in asset and asset['os_info'].get('version'):
                all_os_versions_set.add(self.normalize_os_version(asset['os_info']['version']))
            if 'system_info' in asset and asset['system_info'].get('manufacturer'):
                all_manufacturers_set.add(asset['system_info']['manufacturer'])
            memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
            if memory_gb:
                all_ram_values_list.append(int(memory_gb))
            c_drive_free = self.get_c_drive_free_space(asset)
            if c_drive_free is not None:
                all_storage_values_list.append(c_drive_free)

        sorted_os_options = sorted(list(all_os_versions_set))
        sorted_manufacturer_options = sorted(list(all_manufacturers_set))

        # Initialize OS filter state if empty (first run or cleared)
        if not st.session_state.selected_os_filter and sorted_os_options:
            st.session_state.selected_os_filter = sorted_os_options.copy()

        selected_os = st.sidebar.multiselect(
            "Operating System",
            options=sorted_os_options,
            default=st.session_state.selected_os_filter,
            key="selected_os_multiselect",
            on_change=lambda: setattr(st.session_state, 'selected_os_filter', st.session_state.selected_os_multiselect),
            help="Filter by operating system"
        )
        st.session_state.selected_os_filter = selected_os

        # Initialize Manufacturer filter state if empty
        if not st.session_state.selected_manufacturers_filter and sorted_manufacturer_options:
            st.session_state.selected_manufacturers_filter = sorted_manufacturer_options.copy()

        selected_manufacturers = st.sidebar.multiselect(
            "Manufacturer",
            options=sorted_manufacturer_options,
            default=st.session_state.selected_manufacturers_filter,
            key="selected_manufacturers_multiselect",
            on_change=lambda: setattr(st.session_state, 'selected_manufacturers_filter', st.session_state.selected_manufacturers_multiselect),
            help="Filter by computer manufacturer"
        )
        st.session_state.selected_manufacturers_filter = selected_manufacturers

        # RAM range filter
        st.sidebar.subheader("Hardware Filters")
        actual_min_ram = min(all_ram_values_list) if all_ram_values_list else 0
        actual_max_ram = max(all_ram_values_list) if all_ram_values_list else 128 # Default max if no data
        
        current_ram_filter = st.session_state.ram_range_filter
        if current_ram_filter is None: # Not set by user/dismissal yet
            current_ram_filter = (actual_min_ram, actual_max_ram)

        min_ram, max_ram = st.sidebar.slider(
            "RAM Range (GB)",
            min_value=actual_min_ram,
            max_value=actual_max_ram,
            value=current_ram_filter,
            key="ram_slider",
            on_change=lambda: setattr(st.session_state, 'ram_range_filter', st.session_state.ram_slider),
            help="Filter by RAM amount"
        )
        st.session_state.ram_range_filter = (min_ram, max_ram)


        # HDD space filter
        actual_min_storage = 0.0
        actual_max_storage = max(all_storage_values_list) if all_storage_values_list else 500.0 # Default max if no data

        current_storage_filter = st.session_state.storage_range_filter
        if current_storage_filter is None:
            current_storage_filter = (actual_min_storage, actual_max_storage)
        
        min_storage, max_storage = st.sidebar.slider(
            "C Drive Free Space (GB)",
            min_value=actual_min_storage,
            max_value=actual_max_storage,
            value=current_storage_filter,
            key="storage_slider",
            on_change=lambda: setattr(st.session_state, 'storage_range_filter', st.session_state.storage_slider),
            help="Filter by available C drive space"
        )
        st.session_state.storage_range_filter = (min_storage, max_storage)

        # Quick filters
        st.sidebar.subheader("Quick Filters")
        # show_low_storage_only is already correctly bound to st.session_state.show_low_storage_only
        show_low_storage = st.sidebar.checkbox(
            "🔴 Show Low Storage Assets Only (<10GB)",
            value=st.session_state.show_low_storage_only, # Directly use the session state var
            key="show_low_storage_checkbox",
            on_change=lambda: setattr(st.session_state, 'show_low_storage_only', st.session_state.show_low_storage_checkbox),
            help="Show only assets with less than 10GB free space on C drive"
        )
        # No need for the if show_low_storage != ... block anymore if using on_change

        # AnyDesk ID filter
        anydesk_search = st.sidebar.text_input(
            "AnyDesk ID",
            value=st.session_state.anydesk_search_filter,
            key="anydesk_search_input",
            on_change=lambda: setattr(st.session_state, 'anydesk_search_filter', st.session_state.anydesk_search_input),
            placeholder="Search by AnyDesk ID",
            help="Filter by specific AnyDesk ID"
        )
        st.session_state.anydesk_search_filter = anydesk_search

        # Search functionality
        search_term = st.sidebar.text_input(
            "General Search",
            value=st.session_state.search_term_filter,
            key="search_term_input",
            on_change=lambda: setattr(st.session_state, 'search_term_filter', st.session_state.search_term_input),
            placeholder="Search by computer name, IP, etc.",
            help="Search across all asset properties"
        )
        st.session_state.search_term_filter = search_term

        # Nmap Settings
        st.sidebar.subheader("Network Scanning") # Simplified header

        scan_type_options = ["Disabled", "Quick Scan", "Full Scan"]
        # Ensure st.session_state.nmap_scan_type is valid, otherwise default to "Disabled"
        try:
            current_scan_type_index = scan_type_options.index(st.session_state.nmap_scan_type)
        except ValueError:
            st.session_state.nmap_scan_type = "Disabled"
            current_scan_type_index = 0 # Default to "Disabled"

        nmap_scan_type_ui = st.sidebar.selectbox(
            "Nmap Scan Type",
            options=scan_type_options,
            index=current_scan_type_index,
            key="nmap_scan_type_selector", # Added key for robustness
            help="Select Nmap scan intensity. 'Disabled' turns off scanning. 'Quick Scan' only checks online status (-sn). 'Full Scan' provides more details (-A -v -Pn)."
        )
        if nmap_scan_type_ui != st.session_state.nmap_scan_type:
            st.session_state.nmap_scan_type = nmap_scan_type_ui
            # Update the old nmap_enabled for any part of code that might still (erroneously) use it
            st.session_state.nmap_enabled = (nmap_scan_type_ui != "Disabled")
            # st.rerun() # Could be useful if other parts of UI depend on this immediately

        nmap_path_ui = st.sidebar.text_input(
            "Nmap Executable Path",  # More descriptive label
            value=st.session_state.nmap_path,
            help="Path to nmap executable (e.g., '/usr/bin/nmap' or 'C:\\Program Files (x86)\\Nmap\\nmap.exe'). Default is 'nmap' (assumes it's in system PATH)."
        )
        if nmap_path_ui != st.session_state.nmap_path:
            st.session_state.nmap_path = nmap_path_ui

        return {
            # 'selected_assets': selected_assets, # Removed
            'selected_os': selected_os,
            'selected_manufacturers': selected_manufacturers,
            'min_ram': min_ram,
            'max_ram': max_ram,
            'min_storage': min_storage,
            'max_storage': max_storage,
            'show_low_storage': show_low_storage,
            'anydesk_search': anydesk_search,
            'search_term': search_term,
            # 'nmap_enabled' is now implicitly handled by nmap_scan_type
            'nmap_scan_type': st.session_state.nmap_scan_type, # This is nmap setting, not a typical data filter pill
            'nmap_path': st.session_state.nmap_path # Same as above
        }

        # --- View Customization Expander ---
        with st.sidebar.expander("⚙️ View Customization", expanded=False):
            st.session_state.show_summary_section = st.checkbox(
                "Show Summary & Charts",
                value=st.session_state.get('show_summary_section', True)
                # key="show_summary_cb" # Key not strictly needed if direct assignment to session_state
            )
            st.session_state.show_bubbles_section = st.checkbox(
                "Show Asset Bubbles",
                value=st.session_state.get('show_bubbles_section', True)
                # key="show_bubbles_cb"
            )
            st.session_state.show_details_table_section = st.checkbox(
                "Show Asset Details Table",
                value=st.session_state.get('show_details_table_section', True)
                # key="show_details_table_cb"
            )
        return filters # Return original filters dictionary, session state handles customization

    def filter_assets(self, filters):
        """Apply filters to the assets data"""
        filtered_assets = {}
        
        for name, asset in st.session_state.assets_data.items():
            # Asset name filter (Removed)
            
            # OS filter with normalized comparison
            if filters['selected_os']:
                asset_os = asset.get('os_info', {}).get('version', '')
                normalized_asset_os = self.normalize_os_version(asset_os)
                if normalized_asset_os not in filters['selected_os']:
                    continue
            
            # Manufacturer filter
            if filters['selected_manufacturers']:
                asset_manufacturer = asset.get('system_info', {}).get('manufacturer', '')
                if asset_manufacturer not in filters['selected_manufacturers']:
                    continue
            
            # RAM filter
            memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
            if memory_gb and (memory_gb < filters['min_ram'] or memory_gb > filters['max_ram']):
                continue
            
            # Storage filter
            c_drive_free = self.get_c_drive_free_space(asset)
            if c_drive_free is not None:
                if c_drive_free < filters['min_storage'] or c_drive_free > filters['max_storage']:
                    continue
            
            # Low storage filter
            if filters['show_low_storage']:
                if c_drive_free is None or c_drive_free >= 10:
                    continue
            
            # AnyDesk ID filter
            if filters['anydesk_search']:
                anydesk_id = asset.get('anydesk_id', '')
                if filters['anydesk_search'].lower() not in anydesk_id.lower():
                    continue
            
            # General search filter
            if filters['search_term']:
                search_term = filters['search_term'].lower()
                asset_str = json.dumps(asset).lower()
                if search_term not in asset_str:
                    continue
            
            filtered_assets[name] = asset
        
        return filtered_assets

    def render_asset_bubbles(self, assets):
        """Render asset bubbles in a grid layout"""
        if not assets:
            st.warning("No assets match the current filters.")
            return

        st.subheader("Assets Overview")
        
        # Create grid layout (5 columns)
        assets_list = list(assets.items())
        cols_per_row = 5
        
        for i in range(0, len(assets_list), cols_per_row):
            cols = st.columns(cols_per_row)
            row_assets = assets_list[i:i + cols_per_row]
            
            for j, (name, asset) in enumerate(row_assets):
                with cols[j]:
                    self.render_single_asset_bubble(name, asset)
    
    def render_single_asset_bubble(self, name, asset):
        """Render a single asset bubble with new HTML structure and link-based navigation."""
        ip_address = asset.get('network_info', {}).get('ip_address', 'No IP')
        os_version = self.normalize_os_version(asset.get('os_info', {}).get('version', 'Unknown OS'))
        memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
        memory_display = f"{int(memory_gb)} GB" if memory_gb else "N/A"
        anydesk_id = asset.get('anydesk_id', '')
        if anydesk_id == "ID": anydesk_id = ""

        network_info = asset.get('network_info', {})
        status = network_info.get('status', 'unknown')
        nmap_scan_status = network_info.get('nmap_scan_status', 'unknown')
        
        c_drive_free_gb = self.get_c_drive_free_space(asset)
        c_drive_display = f"{c_drive_free_gb:.1f} GB free" if c_drive_free_gb is not None else "N/A"
        low_storage = c_drive_free_gb is not None and c_drive_free_gb < 10

        anydesk_html_link = ""
        if anydesk_id:
            anydesk_html_link = f'<a href="anydesk:{anydesk_id}" class="anydesk-link" target="_blank">AnyDesk: {anydesk_id}</a>'

        status_indicator_class = ""
        status_text_class = ""
        plain_status_text = ""

        if nmap_scan_status == 'scanning':
            plain_status_text = "Scanning"
            status_indicator_class = "status-indicator-scanning"
            status_text_class = "status-scanning"
        elif nmap_scan_status == 'pending':
            plain_status_text = "Scan pending"
            status_indicator_class = "status-indicator-pending"
            status_text_class = "status-pending"
        elif nmap_scan_status == 'failed':
            plain_status_text = "Scan failed"
            status_indicator_class = "status-indicator-failed"
            status_text_class = "status-failed"
        elif status == 'online':
            plain_status_text = "Online"
            status_indicator_class = "status-indicator-online"
            status_text_class = "status-online"
        else:
            plain_status_text = "Offline"
            status_indicator_class = "status-indicator-offline"
            status_text_class = "status-offline"
        
        storage_class = "low-storage" if low_storage else ""
        bubble_classes_list = ["asset-bubble", status_indicator_class, storage_class]
        final_bubble_class = " ".join(filter(None, set(bubble_classes_list)))
        
        name_url_encoded = urllib.parse.quote(name)


        # Extract Windows User Account from raw_content
        windows_account_html = ""
        raw_content = asset.get('raw_content', '')
        if raw_content:
            # Try a few regex patterns to find the user account
            patterns = [
                r"Windows account:\s*(?:[^\\]+\\)?([^\r\n]+)", # Domain\User or just User
                r"User Account:\s*([^\r\n]+)",
                r"Current User:\s*([^\r\n]+)"
            ]
            username_found = None
            for pattern in patterns:
                match = re.search(pattern, raw_content, re.IGNORECASE)
                if match:
                    username_found = match.group(1).strip()
                    if username_found and username_found != "N/A": # Ensure it's not 'N/A'
                        break
            if username_found and username_found != "N/A": # Double check after loop
                 windows_account_html = f'<div class="asset-account">👤 {username_found}</div>'
            elif "Windows account: N/A" not in raw_content and "User Account: N/A" not in raw_content: # Avoid showing empty if explicitly N/A
                logger.debug(f"Windows account not found or explicitly N/A for asset {name}.")


        # Extract User Email
        user_email_html = ""
        user_email = asset.get('user_email')
        if user_email and user_email.strip() and user_email.lower() != 'n/a':
            user_email_html = f'<div class="asset-user-email">📧 {user_email}</div>'

        bubble_html = f"""
        <div class="{final_bubble_class}">
            <div class="asset-bubble-content">
                <div class="asset-header">
                    <a class="asset-name-link" href="/?view_asset={name_url_encoded}" target="_self">{name}</a>
                    <div class="asset-ip">{ip_address}</div>
                </div>
                <div class="asset-details-group">
                    <div class="asset-os">🖥️ OS: {os_version}</div>
                    <div class="asset-ram">💾 RAM: {memory_display}</div>
                    <div class="asset-storage">💽 Storage (C:): {c_drive_display}</div>
                    {windows_account_html}
                    {user_email_html}
                </div>
                <div class="asset-footer-group">
                    <span class="{status_text_class}">{plain_status_text}</span>
                    {anydesk_html_link}
                </div>
            </div>
        </div>
        """
        st.markdown(bubble_html, unsafe_allow_html=True)

    def render_status_distribution_chart(self, assets):
        """Render pie chart for asset status distribution."""
        if not assets:
            # st.info("No data to display asset status chart.") # Or just return silently
            return

        st.subheader("Assets by Status")
        status_counts = {}
        for asset_data in assets.values():
            status = asset_data.get('network_info', {}).get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

        if status_counts:
            # Define colors for specific statuses if desired
            # color_map = {'online': '#28a745', 'offline': '#dc3545', 'unknown': '#6c757d', ...}
            fig = px.pie(
                values=list(status_counts.values()),
                names=list(status_counts.keys()),
                title="Asset Status Overview", # Chart specific title
                # color_discrete_map=color_map # Optional: apply custom colors
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No status data available for visualization.")


    def render_asset_details_modal(self, assets):
        """Render asset details in a modal-like container"""
        if not st.session_state.show_asset_details or not st.session_state.selected_asset_for_details:
            return
        
        selected_asset_name = st.session_state.selected_asset_for_details
        if selected_asset_name not in assets:
            st.session_state.show_asset_details = False
            st.session_state.selected_asset_for_details = None
            st.rerun()
            return
        
        asset = assets[selected_asset_name]
        
        # Modal header with close button
        col1, col2 = st.columns([4, 1])
        with col1:
            st.subheader(f"Asset Details: {selected_asset_name}")
        with col2:
            if st.button("✕ Close", key="close_modal"):
                st.session_state.show_asset_details = False
                st.session_state.selected_asset_for_details = None
                st.rerun()
        
        # Asset details in tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["System Info", "Hardware", "Software", "Network", "Raw Data"])
        
        with tab1:
            self.dashboard_components.render_system_info(asset)
        
        with tab2:
            self.dashboard_components.render_hardware_info(asset)
        
        with tab3:
            self.dashboard_components.render_software_info(asset)
        
        with tab4:
            self.dashboard_components.render_network_info(asset)
            
            # AnyDesk connection section
            anydesk_id = asset.get('anydesk_id', '')
            if anydesk_id:
                st.markdown("---")
                st.subheader("Remote Access")
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.write(f"**AnyDesk ID:** {anydesk_id}")
                with col2:
                    anydesk_url = f"anydesk:{anydesk_id}"
                    st.markdown(f'<a href="{anydesk_url}" target="_blank" style="background-color: #0078d4; color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; display: inline-block;">🖥️ Connect via AnyDesk</a>', unsafe_allow_html=True)
        
        with tab5:
            self.dashboard_components.render_raw_data_viewer(asset)

    def render_overview_metrics(self, assets):
        """Render overview metrics cards"""
        if not assets:
            st.warning("No assets match the current filters.")
            return

        st.subheader("Dashboard Metrics") # Added subheader
        col1, col2, col3, col4 = st.columns(4)
        
        # Calculate metrics
        total_assets = len(assets)
        online_assets = sum(1 for asset in assets.values() 
                          if asset.get('network_info', {}).get('status') == 'online')
        
        os_distribution = {}
        ram_total = 0
        storage_total = 0
        
        for asset in assets.values():
            # OS distribution
            os_version = asset.get('os_info', {}).get('version', 'Unknown')
            os_distribution[os_version] = os_distribution.get(os_version, 0) + 1
            
            # RAM total (convert to GB if needed)
            ram_info = asset.get('hardware_info', {}).get('memory', {})
            if isinstance(ram_info, dict) and 'total_gb' in ram_info:
                ram_total += ram_info['total_gb']
            
            # Storage total
            storage_info = asset.get('hardware_info', {}).get('storage', [])
            if isinstance(storage_info, list):
                for drive in storage_info:
                    if isinstance(drive, dict) and 'size_gb' in drive:
                        storage_total += drive['size_gb']

        with col1:
            st.metric("Total Assets", total_assets)
        
        with col2:
            st.metric("Online Assets", online_assets, delta=f"{online_assets}/{total_assets}")
        
        with col3:
            st.metric("Total RAM", f"{ram_total:.1f} GB" if ram_total > 0 else "N/A")
        
        with col4:
            st.metric("Total Storage", f"{storage_total:.1f} GB" if storage_total > 0 else "N/A")

    def render_visualizations(self, assets):
        """Render data visualizations"""
        if not assets:
            return

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Operating System Distribution")
            os_data = {}
            for asset in assets.values():
                os_version = asset.get('os_info', {}).get('version', 'Unknown')
                os_data[os_version] = os_data.get(os_version, 0) + 1
            
            if os_data:
                fig_os = px.pie(
                    values=list(os_data.values()),
                    names=list(os_data.keys()),
                    title="OS Distribution"
                )
                st.plotly_chart(fig_os, use_container_width=True)
            else:
                st.info("No OS data available for visualization")
        
        with col2:
            st.subheader("Manufacturer Distribution")
            manufacturer_data = {}
            for asset in assets.values():
                manufacturer = asset.get('system_info', {}).get('manufacturer', 'Unknown')
                manufacturer_data[manufacturer] = manufacturer_data.get(manufacturer, 0) + 1
            
            if manufacturer_data:
                fig_mfg = px.bar(
                    x=list(manufacturer_data.keys()),
                    y=list(manufacturer_data.values()),
                    title="Assets by Manufacturer"
                )
                fig_mfg.update_layout(xaxis_title="Manufacturer", yaxis_title="Count")
                st.plotly_chart(fig_mfg, use_container_width=True)
            else:
                st.info("No manufacturer data available for visualization")

    def render_asset_details(self, assets):
        """Render detailed asset information in a table"""
        logger.info(f"render_asset_details: Received assets. Count: {len(assets) if assets else 'None or empty'}")

        if not assets:
            logger.warning("render_asset_details: No assets data provided or assets are empty.")
            st.warning("No asset data available to display details.")
            return

        st.subheader("Asset Details")
        
        table_data = []
        try:
            logger.info("render_asset_details: Starting preparation of table_data.")
            for name, asset in assets.items():
                try:
                    row = {
                        'Computer Name': name,
                        'IP Address': asset.get('network_info', {}).get('ip_address', 'N/A'),
                        'OS': asset.get('os_info', {}).get('version', 'N/A'),
                        'Manufacturer': asset.get('system_info', {}).get('manufacturer', 'N/A'),
                        'Model': asset.get('system_info', {}).get('model', 'N/A'),
                        'RAM (GB)': asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 'N/A'),
                        'CPU': asset.get('hardware_info', {}).get('processor', {}).get('name', 'N/A'),
                        'Status': asset.get('network_info', {}).get('status', 'Unknown')
                    }
                    table_data.append(row)
                except Exception as e:
                    logger.error(f"render_asset_details: Error processing asset '{name}': {str(e)}")
                    # Optionally, add a placeholder row or skip
            logger.info(f"render_asset_details: table_data preparation complete. Number of rows: {len(table_data)}")
            if not table_data:
                logger.warning("render_asset_details: table_data is empty after processing assets.")
                st.info("No data could be prepared for the asset details table.")
                return
        except Exception as e:
            logger.error(f"render_asset_details: Error during table_data preparation loop: {str(e)}")
            st.error("An error occurred while preparing asset data for display.")
            return

        try:
            logger.info("render_asset_details: Creating DataFrame from table_data.")
            df = pd.DataFrame(table_data)
            logger.info(f"render_asset_details: DataFrame created. Shape: {df.shape}. Head: {df.head().to_string() if not df.empty else 'Empty DataFrame'}")
        except Exception as e:
            logger.error(f"render_asset_details: Failed to create DataFrame: {str(e)}")
            st.error("Failed to create the data table for asset details.")
            return
        
        if not df.empty:
            try:
                logger.info("render_asset_details: Converting DataFrame to CSV.")
                csv = df.to_csv(index=False)
                logger.info("render_asset_details: CSV conversion successful.")

                logger.info("render_asset_details: Preparing download button.")
                st.download_button(
                    label="📥 Download Asset Report (CSV)",
                    data=csv,
                    file_name=f"asset_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key="download_asset_report_csv" # Added a key for robustness
                )
                logger.info("render_asset_details: Download button prepared.")
            except Exception as e:
                logger.error(f"render_asset_details: Failed to convert DataFrame to CSV or prepare download button: {str(e)}")
                # Still display the table if CSV fails
        else:
            logger.info("render_asset_details: DataFrame is empty, skipping CSV conversion and download button.")
            st.info("No data available in the table to download as CSV.") # Inform user

        try:
            logger.info("render_asset_details: Displaying DataFrame.")
            st.dataframe(df, use_container_width=True)
            logger.info("render_asset_details: DataFrame displayed successfully.")
        except Exception as e:
            logger.error(f"render_asset_details: Failed to display DataFrame: {str(e)}")
            st.error("Failed to display the asset details table.")

    def render_individual_asset_view(self, assets):
        """Render detailed view for individual assets"""
        if not assets:
            return

        st.subheader("Individual Asset Details")
        
        asset_names = list(assets.keys())
        selected_asset = st.selectbox("Select an asset for detailed view:", asset_names)
        
        if selected_asset and selected_asset in assets:
            asset = assets[selected_asset]
            
            # Create tabs for different information categories
            tab1, tab2, tab3, tab4 = st.tabs(["System Info", "Hardware", "Software", "Network"])
            
            with tab1:
                self.dashboard_components.render_system_info(asset)
            
            with tab2:
                self.dashboard_components.render_hardware_info(asset)
            
            with tab3:
                self.dashboard_components.render_software_info(asset)
            
            with tab4:
                self.dashboard_components.render_network_info(asset)

    def run(self):
        """Main application entry point"""
        try:
            # Query param processing for direct asset view
            if 'view_asset' in st.query_params:
                try:
                    # Ensure assets_data is loaded before checking query_params related to it.
                    if not st.session_state.assets_data: # Initial load might be needed
                        with st.spinner("Loading asset data..."):
                             st.session_state.assets_data = self.load_assets_data()

                    asset_name_from_query = urllib.parse.unquote(st.query_params['view_asset'])
                    if asset_name_from_query in st.session_state.assets_data:
                        st.session_state.selected_asset_for_details = asset_name_from_query
                        st.session_state.show_asset_details = True
                        # It's generally better to let Streamlit manage query_params.
                        # Clearing them programmatically can be tricky and might not always behave as expected.
                        # If show_asset_details is True, the modal will show. User interaction will then drive state.
                    else:
                        st.warning(f"Asset '{asset_name_from_query}' specified in URL not found.")
                except Exception as e:
                    logger.error(f"Error processing view_asset query param: {e}")
                    st.error("Failed to process asset view request from URL.")

            # Check and install dependencies first
            self.check_and_install_dependencies()
            
            # Apply Windows 11 theme
            apply_windows11_theme()
            
            # Load data if not already loaded or if refresh is triggered
            # (also handles case where query_param logic didn't load it and it's still empty)
            if not st.session_state.assets_data or 'refresh_trigger' in st.session_state:
                if 'refresh_trigger' in st.session_state:
                    del st.session_state['refresh_trigger'] # consume trigger

                # Reset scan queue and current scan only if it's a full data reload
                # This might need adjustment if we want scans to persist across soft refreshes
                # For now, refresh implies restart of queue logic
                st.session_state.nmap_scan_queue = []
                st.session_state.nmap_currently_scanning = None
                logger.info("Nmap scan queue reset due to data refresh.")

                with st.spinner("Loading asset data..."):
                    st.session_state.assets_data = self.load_assets_data() # This will populate the queue

            # Render header
            self.render_header()

            # Render sidebar filters
            filters = self.render_sidebar_filters()

            # Display active filters as dismissible pills
            if st.session_state.assets_data and filters:
                # Calculate default values for comparison
                # all_asset_names_list = list(st.session_state.assets_data.keys()) # No longer needed for pills
                all_os_versions_set = set()
                all_manufacturers_set = set()
                all_ram_values_list = []
                all_storage_values_list = []

                for asset in st.session_state.assets_data.values():
                    if 'os_info' in asset and asset['os_info'].get('version'):
                        all_os_versions_set.add(self.normalize_os_version(asset['os_info']['version']))
                    if 'system_info' in asset and asset['system_info'].get('manufacturer'):
                        all_manufacturers_set.add(asset['system_info']['manufacturer'])
                    memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
                    if memory_gb:
                        all_ram_values_list.append(int(memory_gb))
                    c_drive_free = self.get_c_drive_free_space(asset)
                    if c_drive_free is not None:
                        all_storage_values_list.append(c_drive_free)

                default_min_ram = min(all_ram_values_list) if all_ram_values_list else 0
                default_max_ram = max(all_ram_values_list) if all_ram_values_list else 128
                default_min_storage = 0.0
                default_max_storage = max(all_storage_values_list) if all_storage_values_list else 500.0

                active_pills_data = [] # Store tuples of (pill_text, dismiss_key, dismiss_action_args)

                # "Selected Assets" pill logic removed.

                # OS Filters (Individual pills for each selected OS if not all are selected)
                if len(st.session_state.selected_os_filter) != len(all_os_versions_set):
                    for os_name in st.session_state.selected_os_filter:
                        active_pills_data.append((f"OS: {os_name}", f"dismiss_os_{os_name}", {"type": "os", "value": os_name}))

                # Manufacturer Filters (Individual pills)
                if len(st.session_state.selected_manufacturers_filter) != len(all_manufacturers_set):
                    for manuf_name in st.session_state.selected_manufacturers_filter:
                        active_pills_data.append((f"Manuf: {manuf_name}", f"dismiss_manuf_{manuf_name}", {"type": "manufacturer", "value": manuf_name}))

                # RAM Range
                current_ram_filter = st.session_state.ram_range_filter
                if current_ram_filter and (current_ram_filter[0] != default_min_ram or current_ram_filter[1] != default_max_ram):
                    active_pills_data.append((f"RAM: {current_ram_filter[0]}-{current_ram_filter[1]} GB", "dismiss_ram", {"type": "ram_range"}))

                # Storage Range
                current_storage_filter = st.session_state.storage_range_filter
                if current_storage_filter and (current_storage_filter[0] != default_min_storage or current_storage_filter[1] != default_max_storage):
                     active_pills_data.append((f"Storage: {current_storage_filter[0]:.1f}-{current_storage_filter[1]:.1f} GB", "dismiss_storage", {"type": "storage_range"}))

                # Low Storage
                if st.session_state.show_low_storage_only:
                    active_pills_data.append(("Status: Low Storage", "dismiss_low_storage", {"type": "show_low_storage"}))

                # AnyDesk ID
                if st.session_state.anydesk_search_filter:
                    active_pills_data.append((f"AnyDesk: {st.session_state.anydesk_search_filter}", "dismiss_anydesk", {"type": "anydesk_search"}))

                # General Search
                if st.session_state.search_term_filter:
                    active_pills_data.append((f"Search: \"{st.session_state.search_term_filter}\"", "dismiss_search", {"type": "search_term"}))

                if active_pills_data:
                    st.markdown('<div class="filter-pill-container">', unsafe_allow_html=True)
                    # Max pills per row roughly
                    pills_per_row_approx = 4
                    num_rows = (len(active_pills_data) + pills_per_row_approx - 1) // pills_per_row_approx

                    for i in range(num_rows):
                        cols = st.columns(pills_per_row_approx)
                        for j in range(pills_per_row_approx):
                            pill_index = i * pills_per_row_approx + j
                            if pill_index < len(active_pills_data):
                                pill_text, dismiss_key, action_args = active_pills_data[pill_index]
                                with cols[j]:
                                    st.markdown(f'<div class="filter-pill"><span>{pill_text}</span>', unsafe_allow_html=True)
                                    if st.button("×", key=dismiss_key, help=f"Remove {pill_text} filter"):
                                        filter_type = action_args["type"]
                                        if filter_type == "os":
                                            st.session_state.selected_os_filter.remove(action_args["value"])
                                            if not st.session_state.selected_os_filter: # If empty, reset to all (or handle as needed)
                                                 st.session_state.selected_os_filter = sorted(list(all_os_versions_set)) if all_os_versions_set else []
                                        elif filter_type == "manufacturer":
                                            st.session_state.selected_manufacturers_filter.remove(action_args["value"])
                                            if not st.session_state.selected_manufacturers_filter:
                                                st.session_state.selected_manufacturers_filter = sorted(list(all_manufacturers_set)) if all_manufacturers_set else []
                                        elif filter_type == "ram_range":
                                            st.session_state.ram_range_filter = None # Will be reset to default in sidebar
                                        elif filter_type == "storage_range":
                                            st.session_state.storage_range_filter = None # Will be reset to default in sidebar
                                        elif filter_type == "show_low_storage":
                                            st.session_state.show_low_storage_only = False
                                        elif filter_type == "anydesk_search":
                                            st.session_state.anydesk_search_filter = ""
                                        elif filter_type == "search_term":
                                            st.session_state.search_term_filter = ""
                                        st.rerun()
                                    st.markdown('</div>', unsafe_allow_html=True) # Close filter-pill div
                    st.markdown('</div>', unsafe_allow_html=True) # Close filter-pill-container

            # Apply filters using the session state values that back the widgets
            current_filters_for_logic = {
                # 'selected_assets': st.session_state.selected_assets_filter, # Removed
                'selected_os': st.session_state.selected_os_filter,
                'selected_manufacturers': st.session_state.selected_manufacturers_filter,
                'min_ram': st.session_state.ram_range_filter[0] if st.session_state.ram_range_filter else default_min_ram,
                'max_ram': st.session_state.ram_range_filter[1] if st.session_state.ram_range_filter else default_max_ram,
                'min_storage': st.session_state.storage_range_filter[0] if st.session_state.storage_range_filter else default_min_storage,
                'max_storage': st.session_state.storage_range_filter[1] if st.session_state.storage_range_filter else default_max_storage,
                'show_low_storage': st.session_state.show_low_storage_only,
                'anydesk_search': st.session_state.anydesk_search_filter,
                'search_term': st.session_state.search_term_filter
            }
            filtered_assets = self.filter_assets(current_filters_for_logic)

            # Render asset details modal if open
            self.render_asset_details_modal(filtered_assets) # Modal can be rendered early

            # --- Summary Metrics and Charts Section (Conditional) ---
            if st.session_state.get('show_summary_section', True):
                st.markdown('<div class="summary-charts-container">', unsafe_allow_html=True)
                self.render_overview_metrics(filtered_assets) # Metrics first
                st.divider()
                self.render_system_statistics(filtered_assets)
                self.render_status_distribution_chart(filtered_assets)
                st.markdown('</div>', unsafe_allow_html=True)
                st.divider()

            # Render main content - Asset Bubbles and Details Table (Conditional)
            if filtered_assets:
                if st.session_state.get('show_bubbles_section', True):
                    self.render_asset_bubbles(filtered_assets)
                    # Show divider only if both bubbles and table are shown, or if bubbles are hidden and table is shown
                    if st.session_state.get('show_details_table_section', True):
                         st.divider()

                if st.session_state.get('show_details_table_section', True):
                    self.render_asset_details(filtered_assets)
            else:
                # This part remains, showing welcome/no assets message
                if st.session_state.assets_data: # Check if assets were loaded but all filtered out
                    st.warning("No assets match the current filter criteria. Please adjust your filters.")
                else:
                    st.info("""
                    **Welcome to the IT Asset Management Dashboard!**
                    
                    To get started:
                    1. Place your Windows PC data files (.txt format) in the 'assets' folder.
                    2. Click the 'Refresh Data' button to load the asset information.
                    3. Use the sidebar filters to explore your IT assets.
                    
                    The system expects .txt files generated by the infopcv3.py script.
                    """)

            # Process one Nmap scan from the queue after rendering UI
            self._process_nmap_scan_queue()

        except Exception as e:
            logger.error(f"Application error: {str(e)}")
            st.error(f"An unhandled error occurred: {str(e)}") # Show generic error to user
            # Potentially log full traceback for debugging
            import traceback
            logger.error(traceback.format_exc())

    def _process_nmap_scan_queue(self):
        """Process one asset from the Nmap scan queue."""
        if st.session_state.nmap_scan_type == "Disabled":
            if st.session_state.nmap_scan_queue: # Clear queue if scans got disabled
                st.session_state.nmap_scan_queue = []
                logger.info("Nmap scans disabled, queue cleared.")
            st.session_state.nmap_currently_scanning = None
            return

        if not st.session_state.nmap_scan_queue:
            if st.session_state.nmap_currently_scanning is None : # Only log if not already finished all
                 logger.info("Nmap scan queue is empty. All scheduled scans completed or no assets to scan.")
            st.session_state.nmap_currently_scanning = None # Ensure it's reset
            return

        if st.session_state.nmap_currently_scanning is not None:
            logger.info(f"Nmap scan for {st.session_state.nmap_currently_scanning} is already in progress (or waiting for rerun). Skipping new scan initiation.")
            return

        asset_name_to_scan = st.session_state.nmap_scan_queue.pop(0)
        st.session_state.nmap_currently_scanning = asset_name_to_scan

        asset_to_scan = st.session_state.assets_data.get(asset_name_to_scan)

        if not asset_to_scan:
            logger.warning(f"Asset {asset_name_to_scan} not found in assets_data for Nmap scan. Removing from queue.")
            st.session_state.nmap_currently_scanning = None
            if st.session_state.nmap_scan_queue : # If queue still has items trigger next one
                st.rerun()
            return

        ip_address = asset_to_scan.get('network_info', {}).get('ip_address')
        if not ip_address or ip_address == 'N/A':
            logger.warning(f"Skipping Nmap scan for {asset_name_to_scan}: No valid IP address.")
            asset_to_scan['network_info']['nmap_scan_status'] = 'failed'
            asset_to_scan['network_info']['nmap_error'] = 'Missing IP Address for scan'
            st.session_state.nmap_currently_scanning = None
            st.rerun() # Rerun to update UI and process next
            return

        logger.info(f"Starting Nmap {st.session_state.nmap_scan_type} for asset: {asset_name_to_scan} ({ip_address})")
        asset_to_scan['network_info']['nmap_scan_status'] = 'scanning'

        # Trigger a rerun to update UI to "scanning..." before scan starts
        # This makes the UI more responsive. The actual scan happens after this rerun.
        # However, for the tool environment, direct call might be better.
        # For now, let's call it directly and then rerun.
        # st.experimental_rerun() # This would be for real Streamlit app

        nmap_result = self._run_nmap_scan(
            ip_address,
            nmap_executable_path=st.session_state.nmap_path,
            scan_type=st.session_state.nmap_scan_type
        )

        # Update asset data in session state
        target_asset = st.session_state.assets_data[asset_name_to_scan]
        if nmap_result.get('status') and nmap_result.get('status') not in ['unknown', 'error']:
            target_asset['network_info']['status'] = nmap_result.get('status')

        if st.session_state.nmap_scan_type == "Full Scan" and nmap_result.get('mac_address'):
            target_asset['network_info']['mac_address'] = nmap_result.get('mac_address')

        target_asset['network_info']['nmap_scan_output'] = nmap_result.get('nmap_output')
        target_asset['network_info']['nmap_error'] = nmap_result.get('error_message')

        if nmap_result.get('error_message') or nmap_result.get('status') == 'error':
            target_asset['network_info']['nmap_scan_status'] = 'failed'
            logger.error(f"Nmap scan failed for {asset_name_to_scan}: {nmap_result.get('error_message')}")
        else:
            target_asset['network_info']['nmap_scan_status'] = 'completed'
            logger.info(f"Nmap scan completed for {asset_name_to_scan}. Status: {target_asset['network_info']['status']}")

        st.session_state.nmap_currently_scanning = None
        st.rerun() # Rerun to update UI and process next in queue


    def render_system_statistics(self, assets):
        """Render system statistics with pie charts"""
        st.subheader("System Statistics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # OS Distribution
            os_data = {}
            for asset in assets.values():
                os_version = self.normalize_os_version(asset.get('os_info', {}).get('version', 'Unknown'))
                os_data[os_version] = os_data.get(os_version, 0) + 1
            
            if os_data:
                fig_os = px.pie(
                    values=list(os_data.values()),
                    names=list(os_data.keys()),
                    title="Operating System Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                fig_os.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_os, use_container_width=True)
        
        with col2:
            # Manufacturer Distribution
            manufacturer_data = {}
            for asset in assets.values():
                manufacturer = asset.get('system_info', {}).get('manufacturer', 'Unknown')
                manufacturer_data[manufacturer] = manufacturer_data.get(manufacturer, 0) + 1
            
            if manufacturer_data:
                fig_mfg = px.pie(
                    values=list(manufacturer_data.values()),
                    names=list(manufacturer_data.keys()),
                    title="System Manufacturer Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set2
                )
                fig_mfg.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_mfg, use_container_width=True)

if __name__ == "__main__":
    app = ITAssetDashboard()
    app.run()
