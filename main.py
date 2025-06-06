import streamlit as st
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
        bg_color = "#f3f3f3"
        surface_color = "#ffffff"
        card_color = "#fafafa"
        text_color = "#323130"
        accent_color = "#0078d4"
        hover_color = "#106ebe"
        border_color = "#e1dfdd"
    
    st.markdown(f"""
    <style>
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}
    
    .asset-bubble {{
        background: linear-gradient(135deg, {accent_color} 0%, {hover_color} 100%);
        border-radius: 8px;
        padding: 16px;
        margin: 8px;
        color: white;
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        min-height: 140px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }}
    
    .asset-bubble:hover {{
        transform: translateY(-2px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        background: linear-gradient(135deg, {hover_color} 0%, {accent_color} 100%);
    }}
    
    .asset-name {{
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 4px;
        text-overflow: ellipsis;
        overflow: hidden;
        white-space: nowrap;
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
        color: white;
        display: inline-block;
        transition: all 0.2s ease;
    }}
    
    .anydesk-link:hover {{
        background-color: rgba(255,255,255,0.3);
        border-color: rgba(255,255,255,0.5);
        color: white;
        text-decoration: none;
    }}
    
    .asset-storage {{
        font-size: 11px;
        opacity: 0.8;
        margin-bottom: 4px;
    }}
    
    .low-storage {{
        background: linear-gradient(135deg, #dc3545 0%, #c82333 100%) !important;
        border: 2px solid #ff6b6b !important;
    }}
    
    .low-storage:hover {{
        background: linear-gradient(135deg, #c82333 0%, #a71e2a 100%) !important;
    }}
    
    .status-online {{
        color: #10b981;
        font-size: 12px;
    }}
    
    .status-offline {{
        color: #ef4444;
        font-size: 12px;
    }}
    
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
            st.session_state.nmap_enabled = False
        if 'nmap_path' not in st.session_state:
            st.session_state.nmap_path = "nmap"

    def _run_nmap_scan(self, ip_address: str, nmap_executable_path: str = "nmap") -> dict:
        """Run nmap scan on a given IP address and parse results."""
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
            process = subprocess.run(
                [nmap_executable_path, "-T4", "-A", "-v", "-Pn", ip_address],
                capture_output=True,
                text=True,
                timeout=120  # 120 seconds timeout
            )
            result["nmap_output"] = process.stdout

            if process.returncode == 0:
                logger.info(f"Nmap scan for {ip_address} successful.")
                # Check for host status
                if "Host seems down" in process.stdout:
                    result["status"] = "offline"
                    logger.info(f"Nmap scan for {ip_address}: Host seems down.")
                elif "Host is up" in process.stdout:
                    result["status"] = "online"
                    logger.info(f"Nmap scan for {ip_address}: Host is up.")
                else:
                    # Check if any ports are open as an indication of being online
                    if re.search(r"\d+/open/", process.stdout):
                        result["status"] = "online"
                        logger.info(f"Nmap scan for {ip_address}: Host is up (open ports found).")
                    else:
                        result["status"] = "offline" # Default to offline if no clear "up" signal
                        logger.info(f"Nmap scan for {ip_address}: Host status unclear, assuming offline.")


                # Parse MAC address
                mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", process.stdout)
                if mac_match:
                    result["mac_address"] = mac_match.group(1)
                    logger.info(f"Nmap scan for {ip_address}: MAC Address found: {result['mac_address']}")
                else:
                    logger.info(f"Nmap scan for {ip_address}: MAC Address not found in output.")
            else:
                result["status"] = "error"
                result["error_message"] = f"Nmap scan failed with return code {process.returncode}. Error: {process.stderr}"
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
                        # Nmap integration
                        ip_address = asset_data.get('network_info', {}).get('ip_address')

                        if st.session_state.nmap_enabled and ip_address and ip_address != 'N/A':
                            logger.info(f"Attempting nmap scan for asset {asset_data.get('computer_name', file_path.stem)} at IP {ip_address} using nmap path: {st.session_state.nmap_path}")
                            nmap_result = self._run_nmap_scan(ip_address, nmap_executable_path=st.session_state.nmap_path)

                            # Ensure network_info dictionary exists
                            if 'network_info' not in asset_data:
                                asset_data['network_info'] = {}

                            # Merge nmap results, potentially overwriting parser results for status and MAC
                            asset_data['network_info']['status'] = nmap_result.get('status', asset_data['network_info'].get('status', 'unknown'))
                            if nmap_result.get('mac_address'): # Prioritize nmap MAC address
                                asset_data['network_info']['mac_address'] = nmap_result.get('mac_address')
                            asset_data['network_info']['nmap_scan_output'] = nmap_result.get('nmap_output')
                            asset_data['network_info']['nmap_error'] = nmap_result.get('error_message')

                            if nmap_result.get('error_message'):
                                logger.warning(f"Nmap scan for {ip_address} (Asset: {asset_data.get('computer_name', file_path.stem)}) encountered an error: {nmap_result.get('error_message')}")
                            else:
                                logger.info(f"Nmap scan for {ip_address} (Asset: {asset_data.get('computer_name', file_path.stem)}) completed. Status: {nmap_result.get('status')}")
                        elif not ip_address or ip_address == 'N/A':
                            logger.info(f"Skipping nmap scan for asset {asset_data.get('computer_name', file_path.stem)} due to missing IP address.")

                        assets_data[asset_data.get('computer_name', file_path.stem)] = asset_data
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
            st.title("🖥️ IT Asset Management Dashboard")
            if st.session_state.last_refresh:
                st.caption(f"Last updated: {st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S')}")
        
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

        # Asset selection
        asset_names = list(st.session_state.assets_data.keys())
        selected_assets = st.sidebar.multiselect(
            "Select Assets",
            options=asset_names,
            default=asset_names,
            help="Select specific assets to display"
        )

        # OS filter with normalized versions
        os_versions = set()
        manufacturers = set()
        for asset in st.session_state.assets_data.values():
            if 'os_info' in asset and asset['os_info'].get('version'):
                normalized_os = self.normalize_os_version(asset['os_info']['version'])
                os_versions.add(normalized_os)
            if 'system_info' in asset and asset['system_info'].get('manufacturer'):
                manufacturers.add(asset['system_info']['manufacturer'])

        selected_os = st.sidebar.multiselect(
            "Operating System",
            options=sorted(os_versions),
            default=sorted(os_versions),
            help="Filter by operating system"
        )

        selected_manufacturers = st.sidebar.multiselect(
            "Manufacturer",
            options=sorted(manufacturers),
            default=sorted(manufacturers),
            help="Filter by computer manufacturer"
        )

        # RAM range filter
        st.sidebar.subheader("Hardware Filters")
        ram_values = []
        for asset in st.session_state.assets_data.values():
            memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
            if memory_gb:
                ram_values.append(int(memory_gb))
        
        if ram_values:
            min_ram, max_ram = st.sidebar.slider(
                "RAM Range (GB)",
                min_value=min(ram_values),
                max_value=max(ram_values),
                value=(min(ram_values), max(ram_values)),
                help="Filter by RAM amount"
            )
        else:
            min_ram, max_ram = 0, 999

        # HDD space filter
        storage_values = []
        for asset in st.session_state.assets_data.values():
            c_drive_free = self.get_c_drive_free_space(asset)
            if c_drive_free is not None:
                storage_values.append(c_drive_free)
        
        if storage_values:
            min_storage, max_storage = st.sidebar.slider(
                "C Drive Free Space (GB)",
                min_value=0.0,
                max_value=max(storage_values),
                value=(0.0, max(storage_values)),
                help="Filter by available C drive space"
            )
        else:
            min_storage, max_storage = 0, 999

        # Quick filters
        st.sidebar.subheader("Quick Filters")
        show_low_storage = st.sidebar.checkbox(
            "🔴 Show Low Storage Assets Only (<10GB)",
            value=st.session_state.show_low_storage_only,
            help="Show only assets with less than 10GB free space on C drive"
        )
        
        if show_low_storage != st.session_state.show_low_storage_only:
            st.session_state.show_low_storage_only = show_low_storage

        # AnyDesk ID filter
        anydesk_search = st.sidebar.text_input(
            "AnyDesk ID",
            placeholder="Search by AnyDesk ID",
            help="Filter by specific AnyDesk ID"
        )

        # Search functionality
        search_term = st.sidebar.text_input(
            "General Search",
            placeholder="Search by computer name, IP, etc.",
            help="Search across all asset properties"
        )

        # Nmap Settings
        st.sidebar.subheader("Network Scanning (Nmap)")
        nmap_enabled_ui = st.sidebar.checkbox(
            "Enable Nmap Scans",
            value=st.session_state.nmap_enabled,
            help="Scan assets with nmap for live status and MAC address. Can significantly increase data loading times."
        )
        if nmap_enabled_ui != st.session_state.nmap_enabled:
            st.session_state.nmap_enabled = nmap_enabled_ui
            # No rerun needed, will be picked up on next data load or refresh

        nmap_path_ui = st.sidebar.text_input(
            "Nmap Path",
            value=st.session_state.nmap_path,
            help="Path to nmap executable (e.g., '/usr/bin/nmap' or 'C:\\Program Files (x86)\\Nmap\\nmap.exe'). Default is 'nmap' (assumes it's in system PATH)."
        )
        if nmap_path_ui != st.session_state.nmap_path:
            st.session_state.nmap_path = nmap_path_ui

        return {
            'selected_assets': selected_assets,
            'selected_os': selected_os,
            'selected_manufacturers': selected_manufacturers,
            'min_ram': min_ram,
            'max_ram': max_ram,
            'min_storage': min_storage,
            'max_storage': max_storage,
            'show_low_storage': show_low_storage,
            'anydesk_search': anydesk_search,
            'search_term': search_term,
            'nmap_enabled': st.session_state.nmap_enabled, # Pass current state
            'nmap_path': st.session_state.nmap_path         # Pass current state
        }

    def filter_assets(self, filters):
        """Apply filters to the assets data"""
        filtered_assets = {}
        
        for name, asset in st.session_state.assets_data.items():
            # Asset name filter
            if filters['selected_assets'] and name not in filters['selected_assets']:
                continue
            
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
        """Render a single asset bubble"""
        # Extract asset information
        ip_address = asset.get('network_info', {}).get('ip_address', 'No IP')
        os_version = self.normalize_os_version(asset.get('os_info', {}).get('version', 'Unknown'))
        memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
        memory_display = f"{int(memory_gb)} GB" if memory_gb else "N/A"
        anydesk_id = asset.get('anydesk_id', '')
        # If "ID" is an explicitly bad value, treat it as if no ID was found.
        if anydesk_id == "ID":
            anydesk_id = ""
        status = asset.get('network_info', {}).get('status', 'unknown')
        
        # Extract C Drive free space
        c_drive_free_gb = self.get_c_drive_free_space(asset)
        c_drive_display = f"C: {c_drive_free_gb:.1f} GB free" if c_drive_free_gb is not None else "C: N/A"
        low_storage = c_drive_free_gb is not None and c_drive_free_gb < 10
        
        # Create the bubble HTML without problematic onClick
        anydesk_html = ""
        if anydesk_id:
            anydesk_html = f'<a href="anydesk:{anydesk_id}" class="anydesk-link" target="_blank">AnyDesk: {anydesk_id}</a>'
        
        status_class = "status-online" if status == "online" else "status-offline"
        status_text = "● Online" if status == "online" else "● Offline"
        
        storage_class = "low-storage" if low_storage else ""
        bubble_class = f"asset-bubble {storage_class}"
        
        bubble_html = f"""
        <div class="{bubble_class}">
            <div>
                <div class="asset-name">{name}</div>
                <div class="asset-ip">{ip_address}</div>
                <div class="asset-os">{os_version}</div>
                <div class="asset-ram">{memory_display}</div>
                <div class="asset-storage">{c_drive_display}</div>
            </div>
            <div>
                <div class="{status_class}">{status_text}</div>
                {anydesk_html}
            </div>
        </div>
        """
        
        st.markdown(bubble_html, unsafe_allow_html=True)
        
        # Use Streamlit button for click handling
        if st.button(f"📋 {name}", key=f"asset_btn_{name}", help="Click to view details", use_container_width=True):
            st.session_state.selected_asset_for_details = name
            st.session_state.show_asset_details = True
            st.rerun()

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
        
        try:
            logger.info("render_asset_details: Converting DataFrame to CSV.")
            csv = df.to_csv(index=False)
            logger.info("render_asset_details: CSV conversion successful.")

            st.download_button(
                label="📥 Download Asset Report (CSV)",
                data=csv,
                file_name=f"asset_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        except Exception as e:
            logger.error(f"render_asset_details: Failed to convert DataFrame to CSV: {str(e)}")
            st.error("Failed to generate CSV report for download.")
            # Still display the table if CSV fails

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
            # Check and install dependencies first
            self.check_and_install_dependencies()
            
            # Apply Windows 11 theme
            apply_windows11_theme()
            
            # Load data if not already loaded
            if not st.session_state.assets_data:
                with st.spinner("Loading asset data..."):
                    st.session_state.assets_data = self.load_assets_data()

            # Render header
            self.render_header()

            # Render sidebar filters
            filters = self.render_sidebar_filters()

            # Apply filters
            filtered_assets = self.filter_assets(filters)

            # Render asset details modal if open
            self.render_asset_details_modal(filtered_assets)

            # Render main content
            if filtered_assets:
                # Asset bubbles (main view)
                self.render_asset_bubbles(filtered_assets)
                
                st.divider()
                
                # Overview metrics
                self.render_overview_metrics(filtered_assets)
                
                st.divider()
                
                # System Statistics (pie charts)
                self.render_system_statistics(filtered_assets)
                
                st.divider()
                
                # Asset details table
                self.render_asset_details(filtered_assets)
            else:
                if st.session_state.assets_data:
                    st.warning("No assets match the current filter criteria. Please adjust your filters.")
                else:
                    st.info("""
                    **Welcome to the IT Asset Management Dashboard!**
                    
                    To get started:
                    1. Place your Windows PC data files (.txt format) in the 'assets' folder
                    2. Click the 'Refresh Data' button to load the asset information
                    3. Use the sidebar filters to explore your IT assets
                    
                    The system expects .txt files generated by the infopcv3.py script.
                    """)

        except Exception as e:
            logger.error(f"Application error: {str(e)}")
            st.error(f"Application error: {str(e)}")
    
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
