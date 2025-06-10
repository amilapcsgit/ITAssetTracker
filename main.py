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
import requests # For MAC vendor lookup
from typing import Dict, List, Optional, Any, Tuple # Ensured all are present
import html # For escaping HTML special characters

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

        if 'network_discovery_range' not in st.session_state: # For network discovery
            st.session_state.network_discovery_range = "192.168.1.0/24" # Default, adjust as needed

        if 'show_discovered_only_filter' not in st.session_state: # For discovered assets filter
            st.session_state.show_discovered_only_filter = False

        if 'detailed_assets_data' not in st.session_state: # For storing non-discovered assets
            st.session_state.detailed_assets_data = {}
        if 'discovered_assets_collection' not in st.session_state: # For storing discovered assets
            st.session_state.discovered_assets_collection = {}


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
            # -PR: ARP Ping scan
            # -O: Enable OS detection
            # --osscan-guess: Guess OS more aggressively
            # -sL: List Scan (DNS resolution)

            command = []
            # Mocked OS Scan for a specific IP
            if scan_type == "OS Scan" and ip_address == "192.168.1.250":
                logger.info(f"Returning MOCKED OS Scan result for test IP {ip_address}")
                result["status"] = "online" # Assuming host is up for OS scan to proceed
                result["detected_os_type"] = "Windows"
                result["nmap_output"] = "Mocked Nmap OS Scan Output for 192.168.1.250\nRunning: Microsoft Windows 10"
                return result
            # Mocked ReverseDNS Scan for a specific IP
            if scan_type == "ReverseDNS Scan" and ip_address == "192.168.1.251": # Test IP for rDNS
                logger.info(f"Returning MOCKED ReverseDNS Scan result for test IP {ip_address}")
                result["status"] = "online" # Assumed, as -sL doesn't ping but needs host to be resolvable conceptually
                result["hostname"] = "mocked-hostname.example.com"
                result["nmap_output"] = f"Mocked Nmap ReverseDNS Scan Output for 192.168.1.251\nNmap scan report for mocked-hostname.example.com ({ip_address})"
                return result

            if scan_type == "Quick Scan":
                command = [nmap_executable_path, "-sn", "-T4", ip_address]
                logger.info(f"Executing Nmap Quick Scan for {ip_address}: {' '.join(command)}")
            elif scan_type == "Full Scan":
                command = [nmap_executable_path, "-T4", "-A", "-v", "-Pn", ip_address]
                logger.info(f"Executing Nmap Full Scan for {ip_address}: {' '.join(command)}")
            elif scan_type == "MAC Scan":
                command = [nmap_executable_path, "-sn", "-PR", "-T4", ip_address]
                logger.info(f"Executing Nmap MAC Scan for {ip_address}: {' '.join(command)}")
            elif scan_type == "OS Scan":
                command = [nmap_executable_path, "-O", "--osscan-guess", "-T4", "-Pn", ip_address]
                logger.info(f"Executing Nmap OS Scan for {ip_address}: {' '.join(command)}")
            elif scan_type == "ReverseDNS Scan":
                command = [nmap_executable_path, "-sL", "-Pn", ip_address] # List scan, treat as online
                logger.info(f"Executing Nmap ReverseDNS Scan for {ip_address}: {' '.join(command)}")
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

                # MAC address parsing for Full Scan and MAC Scan
                if scan_type == "Full Scan" or scan_type == "MAC Scan":
                    mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", process.stdout, re.IGNORECASE)
                    if mac_match:
                        result["mac_address"] = mac_match.group(1).upper()
                        logger.info(f"Nmap {scan_type} for {ip_address}: MAC Address found: {result['mac_address']}")
                    else:
                        # Attempt to find MAC in other formats (e.g., for local machine or different Nmap versions/OS)
                        mac_alt_match = re.search(r"Station MAC: ([0-9A-Fa-f:]{17})", process.stdout, re.IGNORECASE)
                        if mac_alt_match:
                            result["mac_address"] = mac_alt_match.group(1).upper()
                            logger.info(f"Nmap {scan_type} for {ip_address}: Alternate MAC Address found: {result['mac_address']}")
                        elif scan_type == "MAC Scan" and result["status"] == "online": # If MAC scan says online but no MAC, explicitly log
                            logger.info(f"Nmap MAC Scan for {ip_address}: Host is online, but MAC Address not found in output.")
                        elif scan_type == "Full Scan": # Only log MAC not found for Full Scan if it was expected
                            logger.info(f"Nmap Full Scan for {ip_address}: MAC Address not found in output.")

                # OS Detection parsing for OS Scan (and potentially Full Scan if -A provides it)
                if scan_type == "OS Scan" or (scan_type == "Full Scan" and "-A" in command): # Full scan with -A also does OS detection
                    result["detected_os_type"] = "Unknown" # Default
                    # Simple keyword-based OS parsing
                    if re.search(r"Running: Microsoft Windows", process.stdout, re.IGNORECASE) or \
                       re.search(r"OS details: Microsoft Windows", process.stdout, re.IGNORECASE) or \
                       re.search(r"OS CPE: cpe:/o:microsoft:windows", process.stdout, re.IGNORECASE):
                        result["detected_os_type"] = "Windows"
                    elif re.search(r"Running: Linux", process.stdout, re.IGNORECASE) or \
                         re.search(r"OS details: Linux", process.stdout, re.IGNORECASE) or \
                         re.search(r"OS CPE: cpe:/o:linux:linux_kernel", process.stdout, re.IGNORECASE):
                        result["detected_os_type"] = "Linux"
                    elif re.search(r"Running: Apple macOS", process.stdout, re.IGNORECASE) or \
                         re.search(r"OS details: Apple macOS", process.stdout, re.IGNORECASE) or \
                         re.search(r"OS CPE: cpe:/o:apple:macos", process.stdout, re.IGNORECASE) or \
                         re.search(r"Darwin", process.stdout, re.IGNORECASE): # Darwin is often in macOS Nmap results
                        result["detected_os_type"] = "macOS"

                    if result["detected_os_type"] != "Unknown":
                        logger.info(f"Nmap {scan_type} for {ip_address}: Detected OS Type: {result['detected_os_type']}")
                    else:
                        logger.info(f"Nmap {scan_type} for {ip_address}: OS Type could not be determined from output.")

                # Hostname parsing for ReverseDNS Scan
                if scan_type == "ReverseDNS Scan":
                    # Example output: "Nmap scan report for hostname.example.com (192.168.1.1)"
                    # Or just "Nmap scan report for 192.168.1.1" if no rDNS
                    hostname_match = re.search(r"Nmap scan report for (\S+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", process.stdout)
                    if hostname_match:
                        potential_hostname = hostname_match.group(1)
                        ip_in_report = hostname_match.group(2)
                        if potential_hostname != ip_in_report: # If hostname is different from IP, it's likely a valid rDNS name
                            result["hostname"] = potential_hostname
                            logger.info(f"Nmap ReverseDNS Scan for {ip_address}: Found hostname: {result['hostname']}")
                        else:
                            logger.info(f"Nmap ReverseDNS Scan for {ip_address}: No distinct hostname found (rDNS likely same as IP).")
                    else: # Fallback if the primary regex doesn't match (e.g., only IP in report)
                        simple_report_match = re.search(r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", process.stdout)
                        if simple_report_match and simple_report_match.group(1) == ip_address:
                             logger.info(f"Nmap ReverseDNS Scan for {ip_address}: No hostname found, report is for IP only.")
                        # else:
                            # logger.info(f"Nmap ReverseDNS Scan for {ip_address}: Could not parse hostname from output: {process.stdout.splitlines()[0] if process.stdout else 'Empty output'}")


                # For Quick Scan, result["mac_address"] remains None (as it doesn't typically fetch it)
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

                        # Initialize os_info if not present (for detected_os_type)
                        if 'os_info' not in asset_data:
                             asset_data['os_info'] = {}
                        asset_data['os_info'].setdefault('detected_os_type', None)


                        # Explicitly set status to 'pending scan' at initial loading
                        asset_data['network_info']['status'] = 'pending scan'

                        # Set initial nmap_scan_status
                        asset_data['network_info']['nmap_scan_status'] = 'pending' # Default for potential scan
                        # Note: The 'status' from asset_parser (like 'online'/'offline') is now overridden
                        # and will be updated by the nmap scan results later.

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

                        asset_data['file_path'] = str(file_path) # Store full file path
                        asset_data['file_name'] = file_path.name # Store file name

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

        st.session_state.show_discovered_only_filter = st.sidebar.checkbox(
            "📡 Show Only Auto-Discovered Assets",
            value=st.session_state.show_discovered_only_filter,
            key="show_discovered_only_checkbox",
            # on_change callback is implicitly handled by Streamlit if we just read from the key,
            # but explicit on_change=lambda: setattr(...) is also fine and sometimes clearer.
            # For direct binding, ensure the key is used in the value param.
            help="Show only assets created via Network Discovery (filename starts with DISCOVERED_)"
        )


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
        st.sidebar.subheader("Network Scanning & Discovery") # Updated header

        # Nmap Live Scans (per asset)
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
            key="nmap_path_input", # Added key
            on_change=lambda: setattr(st.session_state, 'nmap_path', st.session_state.nmap_path_input),
            help="Path to nmap executable (e.g., '/usr/bin/nmap' or 'C:\\Program Files (x86)\\Nmap\\nmap.exe'). Default is 'nmap' (assumes it's in system PATH)."
        )
        # No need for: if nmap_path_ui != st.session_state.nmap_path: ... due to on_change

        st.sidebar.divider() # Visual separator

        # Network Discovery Section
        st.sidebar.subheader("Network Asset Discovery")

        network_range_input = st.sidebar.text_input(
            "Network Range for Discovery (e.g., 192.168.1.0/24)",
            value=st.session_state.network_discovery_range,
            key="network_discovery_range_input",
            on_change=lambda: setattr(st.session_state, 'network_discovery_range', st.session_state.network_discovery_range_input),
            help="Define the network range for Nmap discovery scan."
        )
        # No need for: if network_range_input != st.session_state.network_discovery_range: ...

        if st.sidebar.button("📡 Discover Network Assets", key="discover_assets_button"):
            with st.spinner(f"Discovering assets in {st.session_state.network_discovery_range}... This may take a while."):
                self.discover_network_assets(
                    network_range=st.session_state.network_discovery_range,
                    nmap_executable_path=st.session_state.nmap_path
                )
            st.toast("Network discovery process completed!", icon="✅")
            st.rerun()

        return {
            # 'selected_assets': selected_assets, # Removed
            'selected_os': selected_os, # This is st.session_state.selected_os_filter
            'selected_manufacturers': selected_manufacturers, # This is st.session_state.selected_manufacturers_filter
            'min_ram': min_ram,
            'max_ram': max_ram,
            'min_storage': min_storage,
                'max_storage': max_storage, # This is st.session_state.storage_range_filter[1]
                'show_low_storage': show_low_storage, # This is st.session_state.show_low_storage_only
                'show_discovered_only': st.session_state.show_discovered_only_filter, # Added
                'anydesk_search': anydesk_search, # This is st.session_state.anydesk_search_filter
                'search_term': search_term, # This is st.session_state.search_term_filter
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
        # The filters dictionary returned here is based on st.session_state values, which is fine.
        return filters

    def filter_assets(self, filters: Dict[str, Any], assets_to_filter: Dict[str, Any]) -> Dict[str, Any]:
        """Apply filters to a given dictionary of assets."""
        filtered_assets_dict = {}
        
        for name, asset in assets_to_filter.items():
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
            
            # Show only discovered assets filter
            if filters['show_discovered_only']: # This key comes from current_filters_for_logic
                # This specific filter is to *only* show discovered assets.
                # So, if this flag is true, and the asset is NOT a discovered one, skip it.
                if not asset.get('file_name', '').startswith('DISCOVERED_'):
                    continue
            # If filters['show_discovered_only'] is False, this condition does nothing,
            # and other filters determine inclusion. The separation of detailed vs discovered
            # for display is handled in the run() method by choosing which dict to pass to this func.

            filtered_assets_dict[name] = asset
        
        return filtered_assets_dict

    def render_asset_bubbles(self, assets):
        """Render asset bubbles in a grid layout"""
        # The "no assets" message is now handled in the run() method before calling this.
        # if not assets:
        #     st.warning("No detailed assets match the current filters.") # Specific message
        #     return

        # st.subheader("Assets Overview") # Subheader is now handled in run()
        
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

        detected_os_type = asset.get('os_info', {}).get('detected_os_type')
        os_icon_html = ""
        if detected_os_type:
            icon_char = "❓" # Default unknown
            if detected_os_type == "Windows": icon_char = "🪟" # Using a window emoji as a placeholder
            elif detected_os_type == "Linux": icon_char = "🐧"
            elif detected_os_type == "macOS": icon_char = ""
            os_icon_html = f'<span class="os-icon" title="{detected_os_type}" style="opacity: 0.7; font-size: 0.9em; margin-right: 4px;">{icon_char}</span>'


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

        # Priority for nmap status
        if nmap_scan_status == 'pending':
            plain_status_text = "Pending Scan" # Updated text
            status_indicator_class = "status-indicator-pending"
            status_text_class = "status-pending"
        elif nmap_scan_status == 'scanning':
            plain_status_text = "Scanning..." # Updated text
            status_indicator_class = "status-indicator-scanning"
            status_text_class = "status-scanning"
        elif nmap_scan_status == 'failed':
            plain_status_text = "Scan failed"
            status_indicator_class = "status-indicator-failed"
            status_text_class = "status-failed"
        # Fallback to network_info.status if nmap scan is completed or not actively pending/scanning
        elif nmap_scan_status == 'completed' or nmap_scan_status == 'disabled' or nmap_scan_status == 'unknown':
            if status == 'online':
                plain_status_text = "Online"
                status_indicator_class = "status-indicator-online"
                status_text_class = "status-online"
            elif status == 'offline':
                plain_status_text = "Offline"
                status_indicator_class = "status-indicator-offline"
                status_text_class = "status-offline"
            else: # Default for 'pending scan' (initial load) or other 'unknown' network_info.status
                plain_status_text = "Pending Scan"
                status_indicator_class = "status-indicator-pending"
                status_text_class = "status-pending"
        else: # Should ideally not be reached if nmap_scan_status is one of the above
            plain_status_text = "Unknown"
            status_indicator_class = "status-indicator-offline" # Default to offline visuals
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
                    <div class="asset-os">{os_icon_html}🖥️ OS: {os_version}</div>
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

        metric_label = "Filtered Detailed Assets"
        if st.session_state.show_discovered_only_filter:
            metric_label = "Filtered Discovered Assets"

        with col1:
            st.metric(metric_label, total_assets)
        
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

    def discover_network_assets(self, network_range: str, nmap_executable_path: str):
        """Discovers assets on the network, updates known ones, and logs new ones."""
        logger.info(f"Starting network asset discovery for range: {network_range}")
        live_ips = []

        try:
            # 1. Broad Nmap scan to find live hosts (-sn: Ping Scan, no ports; -T4: Aggressive timing)
            # Use -PR for ARP scan on localnet, -PU for UDP ping to cover more ground.
            # -n for no DNS resolution to speed up.
            # Consider a shorter timeout for this initial discovery scan.
            # command_discover = [nmap_executable_path, "-sn", "-T4", "-PU", "-PR", "-n", network_range]
            command_discover = [nmap_executable_path, "-sn", "-T4", "-n", network_range] # Simpler initial scan
            logger.info(f"Executing network discovery scan: {' '.join(command_discover)}")

            process_discover = subprocess.run(
                command_discover,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout for discovery scan
            )

            if process_discover.returncode == 0:
                # Regex to find IP addresses in "Nmap scan report for <IP_ADDRESS>" lines
                # then check if "Host is up" follows.
                # A more robust way is to parse line by line.
                output_lines = process_discover.stdout.splitlines()
                current_ip = None
                for i, line in enumerate(output_lines):
                    ip_match = re.search(r"Nmap scan report for (\S+)", line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        # Check next few lines for "Host is up"
                        for j in range(i + 1, min(i + 4, len(output_lines))):
                            if "Host is up" in output_lines[j]:
                                if current_ip not in live_ips: # Avoid duplicates if multiple "Host is up"
                                    live_ips.append(current_ip)
                                    logger.info(f"Discovery: Found live host at {current_ip}")
                                break # Found "Host is up", move to next potential IP
                        current_ip = None # Reset for next "Nmap scan report"
                logger.info(f"Discovery: Found {len(live_ips)} live hosts: {live_ips}")
            else:
                logger.error(f"Network discovery scan failed. Nmap stderr: {process_discover.stderr}")
                st.error(f"Network discovery scan failed. Check logs. Error: {process_discover.stderr}")
                return

        except subprocess.TimeoutExpired:
            logger.error(f"Network discovery scan for {network_range} timed out.")
            st.warning(f"Network discovery scan timed out for {network_range}.")
            return # Stop processing if discovery scan times out
        except FileNotFoundError:
            logger.error(f"Nmap command not found at '{nmap_executable_path}' during discovery.")
            st.error(f"Nmap not found at '{nmap_executable_path}'. Cannot perform discovery.")
            return
        except Exception as e:
            logger.error(f"An error occurred during initial network discovery: {str(e)}")
            st.error(f"Discovery error: {str(e)}")
            return

        # 2. For each live IP, get MAC and update/log asset
        for ip_address in live_ips:
            logger.info(f"Processing live IP: {ip_address}")
            mac_scan_result = self._run_nmap_scan(ip_address, nmap_executable_path, "MAC Scan")

            discovered_mac = mac_scan_result.get("mac_address")
            asset_found_by_mac = False
            # asset_found_by_ip = False # Not strictly needed here as MAC takes precedence for file creation
            data_changed_by_discovery_this_iteration = False

            if discovered_mac:
                logger.info(f"Discovery: IP {ip_address} has MAC {discovered_mac}")
                # Check if this MAC already exists
                for asset_name, asset_data_existing in st.session_state.assets_data.items():
                    if asset_data_existing.get('network_info', {}).get('mac_address', '').upper() == discovered_mac:
                        asset_found_by_mac = True
                        logger.info(f"Discovery: MAC {discovered_mac} matches existing asset '{asset_name}'.")
                        old_ip = asset_data_existing['network_info'].get('ip_address')

                        # Update internal data
                        asset_data_existing['network_info']['ip_address'] = ip_address
                        asset_data_existing['network_info']['status'] = 'online'
                        asset_data_existing['network_info']['nmap_scan_status'] = 'completed'
                        asset_data_existing['network_info']['last_seen_via_discovery'] = datetime.now().isoformat()
                        data_changed_by_discovery_this_iteration = True

                        # Update the asset's .txt file
                        original_file_path_str = asset_data_existing.get('file_path')
                        if original_file_path_str:
                            try:
                                original_file_path = Path(original_file_path_str)
                                with open(original_file_path, 'r', encoding='utf-8') as f_read:
                                    content_lines = f_read.readlines()

                                new_content_lines = []
                                ip_updated_in_file = False
                                for line in content_lines:
                                    if line.lower().startswith("ip address:"):
                                        new_content_lines.append(f"IP Address: {ip_address}\n")
                                        ip_updated_in_file = True
                                    else:
                                        new_content_lines.append(line)
                                if not ip_updated_in_file:
                                    new_content_lines.append(f"IP Address: {ip_address}\n")

                                with open(original_file_path, 'w', encoding='utf-8') as f_write:
                                    f_write.writelines(new_content_lines)
                                logger.info(f"Discovery: Updated IP in file {original_file_path}")

                                # Conditional File Renaming (if filename was old IP)
                                if old_ip and old_ip != ip_address and original_file_path.stem == old_ip:
                                    new_file_name_stem = ip_address
                                    new_file_path = original_file_path.with_name(f"{new_file_name_stem}{original_file_path.suffix}")
                                    try:
                                        os.rename(original_file_path, new_file_path)
                                        logger.info(f"Discovery: Renamed asset file from {original_file_path.name} to {new_file_path.name}")
                                        asset_data_existing['file_path'] = str(new_file_path)
                                        asset_data_existing['file_name'] = new_file_path.name
                                    except OSError as e_rename:
                                        logger.error(f"Discovery: Error renaming file {original_file_path} to {new_file_path}: {e_rename}")
                            except IOError as e_io:
                                logger.error(f"Discovery: IOError updating file for asset {asset_name}: {e_io}")
                        else:
                            logger.warning(f"Discovery: File path not found for existing asset {asset_name}. Cannot update file.")
                        break # Found and processed this MAC

                if not asset_found_by_mac:
                    computer_name_to_use = None
                    # Attempt rDNS Lookup first
                    logger.info(f"Discovery: Attempting rDNS lookup for new MAC {discovered_mac} at IP {ip_address}")
                    rdns_result = self._run_nmap_scan(ip_address, nmap_executable_path, "ReverseDNS Scan")
                    if rdns_result and rdns_result.get("hostname"):
                        # Ensure hostname is not just the IP address itself
                        if rdns_result["hostname"] != ip_address:
                            computer_name_to_use = rdns_result["hostname"]
                            logger.info(f"Discovery: Using hostname from rDNS: {computer_name_to_use}")

                    # Fetch vendor details (needed for Vendor field anyway, and for naming if rDNS fails)
                    vendor = self.get_mac_vendor_details(discovered_mac) or 'N/A'

                    if not computer_name_to_use: # If rDNS failed or returned IP
                        if vendor != 'N/A' and vendor != "Unknown Vendor" and vendor != "Unknown Vendor (No vendor field)" and vendor != "Unknown Vendor (JSON Decode Error)" and vendor != "Unknown Vendor (Invalid MAC format for API)":
                            computer_name_to_use = f"{vendor} device ({ip_address})"
                            logger.info(f"Discovery: Using vendor-based name: {computer_name_to_use}")
                        else:
                            computer_name_to_use = f"DISCOVERED_ASSET_{discovered_mac.replace(':', '')}"
                            logger.info(f"Discovery: Using MAC-based fallback name: {computer_name_to_use}")

                    # Final fallback if all else fails (should be rare)
                    if not computer_name_to_use:
                        computer_name_to_use = f"UNKNOWN_DEVICE_{discovered_mac.replace(':', '')}"

                    logger.info(f"Discovery: Final chosen name for new asset: {computer_name_to_use} (IP: {ip_address}, MAC: {discovered_mac})")

                    new_asset_filename = f"DISCOVERED_{discovered_mac.replace(':', '')}.txt" # Filename still MAC-based for uniqueness
                    new_asset_filepath = self.assets_folder / new_asset_filename

                    file_content = (
                        f"Computer Name: {computer_name_to_use}\n"
                        f"IP Address: {ip_address}\n"
                        f"MAC Address: {discovered_mac}\n"
                        f"Vendor: {vendor}\n"
                        f"Status: online\n" # Default status for newly discovered
                        f"DiscoveryDate: {datetime.now().isoformat()}\n"
                        f"Source: Network Discovery\n"
                    )
                    try:
                        with open(new_asset_filepath, 'w', encoding='utf-8') as f:
                            f.write(file_content)
                        logger.info(f"Discovery: Created new asset file: {new_asset_filepath} with Computer Name: {computer_name_to_use}")
                        data_changed_by_discovery_this_iteration = True
                    except IOError as e:
                        logger.error(f"Discovery: Failed to write new asset file {new_asset_filepath}: {e}")

            # If no MAC, but IP is live - try to update existing asset by IP (but don't create new file)
            elif mac_scan_result.get("status") == "online": # MAC not found, but host is up
                logger.info(f"Discovery: MAC address not found for live IP {ip_address}. Will try to match by IP for existing assets.")
                for asset_name, asset_data_existing in st.session_state.assets_data.items():
                    if asset_data_existing.get('network_info', {}).get('ip_address') == ip_address:
                        # Only update status if it's not already reflecting a recent scan by other means
                        # This avoids overwriting a detailed 'online' from full scan with a simple 'online' from discovery
                        if asset_data_existing['network_info'].get('status') != 'online' or \
                           asset_data_existing['network_info'].get('nmap_scan_status') not in ['completed', 'scanning']:
                            logger.info(f"Discovery: Known asset '{asset_name}' found by IP {ip_address} (MAC not identified in this scan). Updating status.")
                            asset_data_existing['network_info']['status'] = 'online'
                            # Do not change nmap_scan_status here to 'completed' unless we are sure this is the primary source of truth now.
                            # Keep it as is, or set to something like 'verified_online_by_discovery' if a new state is desired.
                            # For now, just update 'status' and 'last_seen_via_discovery'.
                            asset_data_existing['network_info']['last_seen_via_discovery'] = datetime.now().isoformat()
                            data_changed_by_discovery_this_iteration = True
                            # Note: We are not updating the IP address line in the file here,
                            # as this block is for when MAC is primary identifier and wasn't found.
                            # Updating IP in file is handled in the MAC-found block.
                        break # Found by IP
                # No 'else' here to create new file, as per requirement (new files created only if MAC is found)

            if data_changed_by_discovery_this_iteration:
                self.data_changed_by_discovery = True # Set the class/instance level flag

        logger.info("Network asset discovery process completed.")
        if self.data_changed_by_discovery:
            logger.info("Reloading all asset data due to changes during discovery.")
            st.session_state.assets_data = self.load_assets_data()
        # Future: Implement logic to mark assets not found as potentially offline.

    def get_mac_vendor_details(self, mac_address: str) -> Optional[str]:
        """
        Looks up the vendor for a given MAC address using an external API.
        Includes a mock for a test MAC address.
        """
        if not mac_address:
            return None

        # Mocked response for testing
        test_mac = "00:00:00:TEST:00" # Example test MAC
        if mac_address.upper() == test_mac:
            logger.info(f"Returning mocked vendor for test MAC: {mac_address}")
            return "Test Vendor Inc."

        # Using api.maclookup.app - no API key needed for basic vendor info
        # Normalizing MAC address format for the API (e.g., removing colons/hyphens if needed by API)
        # This API seems to accept MAC with colons.
        api_url = f"https://api.maclookup.app/v2/macs/{mac_address.upper()}"

        logger.info(f"Querying MAC vendor for: {mac_address} at {api_url}")

        try:
            response = requests.get(api_url, timeout=10) # 10-second timeout

            if response.status_code == 200:
                try:
                    data = response.json()
                    vendor = data.get('vendor')
                    if vendor:
                        logger.info(f"Vendor found for {mac_address}: {vendor}")
                        return vendor
                    else:
                        logger.info(f"Vendor field not found in API response for {mac_address}. Response: {data}")
                        return "Unknown Vendor (No vendor field)"
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode JSON response for {mac_address}. Response text: {response.text}")
                    return "Unknown Vendor (JSON Decode Error)"
            elif response.status_code == 404: # Not Found - MAC prefix not in their database
                logger.info(f"Vendor not found for MAC {mac_address} (404 Error).")
                return "Unknown Vendor"
            elif response.status_code == 400: # Bad Request (e.g. invalid MAC format)
                logger.warning(f"Bad request for MAC vendor lookup ({mac_address}). Status: 400. Response: {response.text}")
                return "Unknown Vendor (Invalid MAC format for API)"
            elif response.status_code == 429: # Too many requests
                logger.warning(f"Too many requests to MAC vendor API for {mac_address}. Status: 429.")
                return None # Indicate rate limiting, perhaps try later or signal unavailability
            else:
                logger.error(f"Error looking up MAC vendor for {mac_address}. Status: {response.status_code}, Response: {response.text}")
                return None # Or "Unknown Vendor (API Error)"

        except requests.exceptions.Timeout:
            logger.error(f"Timeout during MAC vendor lookup for {mac_address} at {api_url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error during MAC vendor lookup for {mac_address} at {api_url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during MAC vendor lookup for {mac_address}: {e}")
            return None

        return None # Default return if other paths don't hit

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

                # Pill for "Show Discovered Only"
                if st.session_state.show_discovered_only_filter:
                    active_pills_data.append(("View: Auto-Discovered", "dismiss_discovered_only", {"type": "show_discovered_only"}))

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
                                        elif filter_type == "show_discovered_only":
                                            st.session_state.show_discovered_only_filter = False
                                        st.rerun()
                                    st.markdown('</div>', unsafe_allow_html=True) # Close filter-pill div
                    st.markdown('</div>', unsafe_allow_html=True) # Close filter-pill-container

            # Split assets into detailed and discovered collections
            # This should happen *before* current_filters_for_logic is fully determined if filters depend on all data,
            # but since render_sidebar_filters already used st.session_state.assets_data, it's fine here.
            if 'assets_data' in st.session_state and st.session_state.assets_data:
                temp_detailed_assets = {}
                temp_discovered_assets = {}
                for name, asset in st.session_state.assets_data.items():
                    if asset.get('file_name', '').startswith('DISCOVERED_'):
                        temp_discovered_assets[name] = asset
                    else:
                        temp_detailed_assets[name] = asset
                st.session_state.detailed_assets_data = temp_detailed_assets
                st.session_state.discovered_assets_collection = temp_discovered_assets
            else: # Ensure these are initialized if assets_data is empty
                st.session_state.detailed_assets_data = {}
                st.session_state.discovered_assets_collection = {}


            current_filters_for_logic = {
                'selected_os': st.session_state.selected_os_filter,
                'selected_manufacturers': st.session_state.selected_manufacturers_filter,
                'min_ram': st.session_state.ram_range_filter[0] if st.session_state.ram_range_filter else default_min_ram,
                'max_ram': st.session_state.ram_range_filter[1] if st.session_state.ram_range_filter else default_max_ram,
                'min_storage': st.session_state.storage_range_filter[0] if st.session_state.storage_range_filter else default_min_storage,
                'max_storage': st.session_state.storage_range_filter[1] if st.session_state.storage_range_filter else default_max_storage,
                'show_low_storage': st.session_state.show_low_storage_only,
                'show_discovered_only': st.session_state.show_discovered_only_filter, # Added for filter_assets
                'anydesk_search': st.session_state.anydesk_search_filter,
                'search_term': st.session_state.search_term_filter
            }

            # Determine which collection of assets to filter and display
            assets_for_main_view = {}
            if st.session_state.show_discovered_only_filter:
                # When showing only discovered assets, use minimal filters, primarily search term
                minimal_filters_for_discovered = current_filters_for_logic.copy()
                minimal_filters_for_discovered['selected_os'] = []
                minimal_filters_for_discovered['selected_manufacturers'] = []
                minimal_filters_for_discovered['min_ram'] = 0
                minimal_filters_for_discovered['max_ram'] = 9999
                minimal_filters_for_discovered['min_storage'] = 0.0
                minimal_filters_for_discovered['max_storage'] = 99999.0
                minimal_filters_for_discovered['show_low_storage'] = False
                minimal_filters_for_discovered['anydesk_search'] = ""
                # 'search_term' and 'show_discovered_only' (which is True) are preserved from current_filters_for_logic

                assets_for_main_view = self.filter_assets(minimal_filters_for_discovered, st.session_state.discovered_assets_collection)
            else:
                # Otherwise, filter the detailed assets collection using all sidebar filters
                assets_for_main_view = self.filter_assets(current_filters_for_logic, st.session_state.detailed_assets_data)


            # Render asset details modal if open (operates on the currently relevant view)
            self.render_asset_details_modal(assets_for_main_view)

            # --- Summary Metrics and Charts Section (Conditional) ---
            if st.session_state.get('show_summary_section', True):
                st.markdown('<div class="summary-charts-container">', unsafe_allow_html=True)
                self.render_overview_metrics(assets_for_main_view)
                st.divider()
                self.render_system_statistics(assets_for_main_view)
                self.render_status_distribution_chart(assets_for_main_view)
                st.markdown('</div>', unsafe_allow_html=True)
                st.divider()

            # Conditional Rendering for Bubbles and Table
            bubbles_rendered_or_message_shown = False
            if st.session_state.get('show_bubbles_section', True):
                if st.session_state.show_discovered_only_filter:
                    st.subheader("Discovered Assets Overview")
                    if not assets_for_main_view:
                        st.info("No discovered assets match the current search term, or no assets have been discovered yet.")
                        bubbles_rendered_or_message_shown = True
                    else:
                        self.render_discovered_asset_bubbles(assets_for_main_view)
                        bubbles_rendered_or_message_shown = True
                else: # Detailed assets view
                    st.subheader("Assets Overview")
                    if not assets_for_main_view:
                        # This message will show if detailed assets are empty after filtering
                        # but before the global "welcome" or "no assets at all" message.
                        st.warning("No detailed assets match the current filter criteria.")
                        bubbles_rendered_or_message_shown = True
                    else:
                        self.render_asset_bubbles(assets_for_main_view)
                        bubbles_rendered_or_message_shown = True

                if assets_for_main_view and st.session_state.get('show_details_table_section', True): # Only add divider if bubbles were shown and table will be shown
                    st.divider()

            if st.session_state.get('show_details_table_section', True):
                # The table rendering function also has its own "no assets to display" if assets_for_main_view is empty
                self.render_asset_details(assets_for_main_view)
                # If bubbles were not shown but table is, and table is empty, render_asset_details shows a warning.
                # If bubbles were shown (even if empty message was printed for bubbles), and table is also empty,
                # render_asset_details will print its own warning. This might be slightly redundant but acceptable.
                # If bubbles were NOT shown, and table is empty, this is the first "no data" message.
                if not assets_for_main_view and not bubbles_rendered_or_message_shown : # if bubbles section was hidden and table is also empty
                     st.warning("No assets to display in the table for the current filters.")


            # Fallback "Welcome" or "No assets loaded at all" message
            # This should only appear if no specific "empty view" message has been shown yet by bubbles or table sections.
            if not st.session_state.assets_data: # Check if any assets were loaded at all, ever.
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


    def render_discovered_asset_bubbles(self, discovered_assets: Dict[str, Any]):
        """Render a simpler view for discovered assets with corrected HTML rendering."""
        assets_list = list(discovered_assets.items())
        cols_per_row = 5

        for i in range(0, len(assets_list), cols_per_row):
            cols = st.columns(cols_per_row)
            row_assets = assets_list[i:i + cols_per_row]

            for j, (name, asset) in enumerate(row_assets):
                with cols[j]:
                    # --- Data Preparation ---
                    ip_address = asset.get('network_info', {}).get('ip_address', 'N/A')
                    mac_address = asset.get('network_info', {}).get('mac_address', 'N/A')
                    vendor = asset.get('vendor', 'Unknown Vendor')
                    vendor_display = (vendor[:20] + '...') if len(vendor) > 23 else vendor

                    discovery_date_str = asset.get('discovery_date', 'N/A')
                    discovery_date_display = "N/A"
                    if discovery_date_str and discovery_date_str != 'N/A':
                        try:
                            # Ensure datetime is imported if not already: from datetime import datetime
                            discovery_date_dt = datetime.fromisoformat(discovery_date_str)
                            discovery_date_display = discovery_date_dt.strftime("%Y-%m-%d")
                        except ValueError:
                            discovery_date_display = discovery_date_str

                    detected_os_type = asset.get('os_info', {}).get('detected_os_type')
                    os_icon_html = ""
                    if detected_os_type:
                        icon_char = "❓"
                        if detected_os_type == "Windows": icon_char = "🪟"
                        elif detected_os_type == "Linux": icon_char = "🐧"
                        elif detected_os_type == "macOS": icon_char = ""
                        os_icon_html = f'<span title="{detected_os_type}" style="opacity: 0.7; font-size: 0.9em;">{icon_char}</span>'

                    # Ensure urllib.parse is imported: import urllib.parse
                    name_url_encoded = urllib.parse.quote(name)

                    # --- HTML String Construction ---
                    bubble_html = f"""
                    <a href="/?view_asset={name_url_encoded}" target="_self" class="asset-bubble-link">
                        <div class="asset-bubble status-indicator-online">
                            <div class="asset-bubble-content">
                                <div class="asset-header">
                                    <span class="asset-name">{os_icon_html} {name}</span>
                                    <div class="asset-ip">{ip_address}</div>
                                </div>
                                <div class="asset-details-group" style="font-size: 0.8em;">
                                    <div>MAC: {mac_address}</div>
                                    <div title="{vendor}">Vendor: {vendor_display}</div>
                                    <div>Seen: {discovery_date_display}</div>
                                </div>
                                <div class="asset-footer-group">
                                    <span class="status-online" style="font-size: 0.85em;">Discovered</span>
                                </div>
                            </div>
                        </div>
                    </a>
                    """

                    st.markdown(bubble_html, unsafe_allow_html=True)

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

        # Store detected_os_type if the scan provides it (e.g. Full Scan with -A, or a future OS Scan type)
        if nmap_result.get('detected_os_type'):
            target_asset.setdefault('os_info', {}).setdefault('detected_os_type', nmap_result.get('detected_os_type'))
            # If 'os_info' was missing, setdefault creates it. Then setdefault for 'detected_os_type'.

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
