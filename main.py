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
        accent_color = "#0078d4" # Keep original dark theme accent for now
        hover_color = "#106ebe"  # Keep original dark theme hover for now
        border_color = "#484848"
    else:
        bg_color = "#F4F6F8"
        surface_color = "#ffffff"
        card_color = "#fafafa"
        text_color = "#212529"
        accent_color = "#3C82F6"
        hover_color = "#2575F5"
        border_color = "#e1dfdd"
    
    st.markdown(f"""
    <style>
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}

    .main-title {{
        font-size: 2.5em;
        font-weight: bold;
        margin-bottom: 0px;
    }}

    .caption-text {{
        font-size: 0.85em;
        color: #6c757d;
        padding-top: 0px;
    }}
    
    .asset-bubble {{
        background-color: {card_color};
        border-radius: 8px;
        padding: 12px;
        margin: 8px;
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        min-height: 170px; /* Adjusted min-height for new fields */
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        border-left: 5px solid transparent;
    }}
    
    .asset-bubble:hover {{
        transform: translateY(-2px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.2);
    }}

    /* Status Indicator Border Colors */
    .status-indicator-online {{ border-left-color: #3C82F6 !important; }}
    .status-indicator-offline {{ border-left-color: #D9534F !important; }}
    .status-indicator-scanning {{ border-left-color: #777777 !important; }} /* Neutral gray for unknown/scanning */
    .status-indicator-pending {{ border-left-color: #F0AD4E !important; }} /* Orange for pending */
    .status-indicator-failed {{ border-left-color: #D9534F !important; }} /* Red for failed */
    .status-indicator-unknown {{ border-left-color: #777777 !important; }} /* Default for unknown status */


    .asset-bubble-link {{
        text-decoration: none !important;
    }}
    .asset-bubble-link:hover {{
        text-decoration: none !important;
    }}

    .asset-bubble-content {{
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        height: 100%;
    }}

    .asset-header {{
        margin-bottom: 8px;
    }}

    .asset-name {{
       font-size: 16px;
       font-weight: 600;
       color: {text_color};
       display: block;
       white-space: nowrap;
       overflow: hidden;
       text-overflow: ellipsis;
       margin-bottom: 2px; /* Added small margin below name */
    }}
    
    .asset-ip {{
        font-size: 12px;
        opacity: 0.9;
        /* margin-bottom: 8px; Removed, spacing handled by asset-header */
    }}
    
    .asset-details-group div {{ /* Target divs directly inside for consistent styling */
        font-size: 11px;
        opacity: 0.8;
        margin-bottom: 4px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    /* Keep specific class names if some need different styling later */
    .asset-os {{}}
    .asset-ram {{}}
    .asset-storage {{}}
    .asset-account {{}}
    .asset-user-email {{}}
    /* Antivirus specific - if it needs to stand out or have different icon handling */
    /* .asset-antivirus {{}} */
    
    .anydesk-link {{
        font-size: 10px;
        text-decoration: none;
        color: {accent_color};
        background-color: transparent;
        border: none;
        padding: 0; /* Minimal padding for a link */
        display: inline-block;
        transition: all 0.2s ease;
    }}
    
    .anydesk-link:hover {{
        color: {hover_color};
        text-decoration: underline;
    }}

    .low-storage {{
        background-color: #FFF3CD !important;
    }}
    
    .low-storage:hover {{
        background-color: #FFF3CD !important;
    }}

    /* Status Text Colors */
    .status-online {{ color: #3C82F6; font-size: 12px; }}
    .status-offline {{ color: #D9534F; font-size: 12px; }}
    .status-scanning {{ color: #777777; font-size: 12px; }}
    .status-pending {{ color: #F0AD4E; font-size: 12px; }}
    .status-failed {{ color: #D9534F; font-size: 12px; }}
    .status-unknown {{ color: #777777; font-size: 12px;}} /* Default for unknown status text */
    
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
        gap: 8px;
        padding-bottom: 16px;
        align-items: center;
    }}

    .filter-pill {{
        background-color: #e9ecef;
        color: #495057;
        padding: 5px 8px 5px 12px;
        border-radius: 16px;
        font-size: 0.875em;
        display: flex;
        align-items: center;
        gap: 5px;
        border: 1px solid #ced4da;
    }}

    .filter-pill-text {{
    }}

    .filter-pill .stButton button {{
        background-color: transparent !important;
        color: #6c757d !important;
        border: none !important;
        padding: 0px 3px !important;
        margin: 0 !important;
        line-height: 1 !important;
        font-size: 1.2em !important;
        font-weight: bold !important;
        box-shadow: none !important;
    }}
    .filter-pill .stButton button:hover {{
        color: #343a40 !important;
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

    .asset-account, .asset-user-email {{ /* These are now styled by .asset-details-group div */
    }}

    .summary-charts-container {{
        padding: 10px;
        border-radius: 8px;
        margin-bottom: 16px;
    }}
    </style>
    """, unsafe_allow_html=True)

class ITAssetDashboard:
    def __init__(self):
        self.asset_parser = AssetParser()
        self.dashboard_components = DashboardComponents()
        self.assets_folder = Path("assets")
        
        if 'assets_data' not in st.session_state:
            st.session_state.assets_data = {}
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = None
        if 'theme_mode' not in st.session_state:
            st.session_state.theme_mode = 'light'
        if 'show_asset_details' not in st.session_state:
            st.session_state.show_asset_details = False
        if 'selected_asset_for_details' not in st.session_state:
            st.session_state.selected_asset_for_details = None

        if 'nmap_path' not in st.session_state:
            st.session_state.nmap_path = "nmap"
        if 'nmap_scan_type' not in st.session_state:
            st.session_state.nmap_scan_type = "Quick Scan"

        if 'selected_os_filter' not in st.session_state:
            st.session_state.selected_os_filter = []
        if 'selected_manufacturers_filter' not in st.session_state:
            st.session_state.selected_manufacturers_filter = []
        if 'ram_range_filter' not in st.session_state:
            st.session_state.ram_range_filter = None
        if 'storage_range_filter' not in st.session_state:
            st.session_state.storage_range_filter = None
        if 'show_low_storage_only' not in st.session_state:
            st.session_state.show_low_storage_only = False
        if 'anydesk_search_filter' not in st.session_state:
            st.session_state.anydesk_search_filter = ""
        if 'search_term_filter' not in st.session_state:
            st.session_state.search_term_filter = ""

        if 'show_summary_section' not in st.session_state:
            st.session_state.show_summary_section = True
        if 'show_bubbles_section' not in st.session_state:
            st.session_state.show_bubbles_section = True
        if 'show_details_table_section' not in st.session_state:
            st.session_state.show_details_table_section = True


    def _run_nmap_scan(self, ip_address: str, nmap_executable_path: str = "nmap", scan_type: str = "Full Scan") -> dict:
        result = { "status": "unknown", "mac_address": None, "nmap_output": "", "error_message": None }
        logger.info(f"Starting nmap scan for IP: {ip_address}")
        try:
            command = []
            if scan_type == "Quick Scan":
                command = [nmap_executable_path, "-sn", "-T4", ip_address]
            elif scan_type == "Full Scan":
                command = [nmap_executable_path, "-T4", "-A", "-v", "-Pn", ip_address]
            else:
                result["error_message"] = f"Invalid scan type: {scan_type}"
                logger.error(result["error_message"])
                return result

            logger.info(f"Executing Nmap {scan_type} for {ip_address}: {' '.join(command)}")
            process = subprocess.run(command, capture_output=True, text=True, timeout=120)
            result["nmap_output"] = process.stdout

            if process.returncode == 0:
                if "Host seems down" in process.stdout: result["status"] = "offline"
                elif "Host is up" in process.stdout: result["status"] = "online"
                elif scan_type == "Full Scan" and re.search(r"\d+/open/", process.stdout): result["status"] = "online"
                else: result["status"] = "offline"
                logger.info(f"Nmap {scan_type} for {ip_address}: Parsed status: {result['status']}.")
                if scan_type == "Full Scan":
                    mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", process.stdout, re.IGNORECASE)
                    if mac_match: result["mac_address"] = mac_match.group(1).upper()
            else:
                result["error_message"] = f"Nmap scan failed (code {process.returncode}): {process.stderr}"
                logger.error(result["error_message"])
        except FileNotFoundError:
            result["error_message"] = f"Nmap not found at '{nmap_executable_path}'."
            logger.error(result["error_message"])
        except subprocess.TimeoutExpired:
            result["error_message"] = "Nmap scan timed out."
            logger.error(result["error_message"])
        except Exception as e:
            result["error_message"] = f"Nmap scan error: {e}"
            logger.error(result["error_message"], exc_info=True)
        return result

    def load_assets_data(self):
       logger.info("Starting load_assets_data...")
       try:
           if not self.assets_folder.exists():
               self.assets_folder.mkdir(exist_ok=True); return {}
           asset_files = list(self.assets_folder.glob("*.txt"))
           if not asset_files: return {}
           assets_data = {}
           logger.info(f"Found {len(asset_files)} asset files. Processing...")
           for file_path_obj in asset_files:
               file_path_str = str(file_path_obj)
               try:
                   asset_data_item = self.asset_parser.parse_asset_file(file_path_obj)
                   if asset_data_item:
                       asset_name = asset_data_item.get('computer_name', file_path_obj.stem)
                       if 'network_info' not in asset_data_item: asset_data_item['network_info'] = {}
                       asset_data_item['network_info']['nmap_scan_status'] = 'pending_quick_scan'
                       asset_data_item['network_info']['status'] = asset_data_item['network_info'].get('status', 'unknown')
                       ip_address = asset_data_item.get('network_info', {}).get('ip_address')
                       nmap_exe_path = st.session_state.get('nmap_path', 'nmap')
                       if ip_address and ip_address != 'N/A':
                           logger.info(f"Quick Scan for {asset_name} at {ip_address} using Nmap: {nmap_exe_path}")
                           nmap_result = self._run_nmap_scan(ip_address, nmap_executable_path=nmap_exe_path, scan_type="Quick Scan")
                           asset_data_item['network_info']['nmap_scan_status'] = 'completed_quick_scan'
                           if nmap_result.get('status') and nmap_result.get('status') not in ['unknown', 'error']:
                               asset_data_item['network_info']['status'] = nmap_result['status']
                           asset_data_item['network_info']['nmap_quick_scan_output'] = nmap_result.get('nmap_output', '')
                           if nmap_result.get('error_message'):
                               asset_data_item['network_info']['nmap_scan_status'] = 'failed_quick_scan'
                               asset_data_item['network_info']['nmap_error'] = nmap_result['error_message']
                               logger.error(f"Nmap Quick Scan failed for {asset_name}: {nmap_result['error_message']}")
                       else:
                           asset_data_item['network_info']['nmap_scan_status'] = 'skipped_no_ip'
                       assets_data[asset_name] = asset_data_item
               except Exception as e:
                   logger.error(f"Error processing file {file_path_str}: {e}", exc_info=True)
           st.session_state.last_refresh = datetime.now()
           logger.info(f"load_assets_data completed. Loaded {len(assets_data)} assets.")
           return assets_data
       except Exception as e:
           logger.error(f"Major error in load_assets_data: {e}", exc_info=True)
           st.error(f"Error loading assets data: {e}"); return {}

    def normalize_os_version(self, os_string):
        if not os_string: return "Unknown"
        os_lower = os_string.lower()
        if "windows 11" in os_lower: return "Windows 11"
        if "windows 10" in os_lower: return "Windows 10"
        if "windows 8" in os_lower: return "Windows 8"
        if "windows 7" in os_lower: return "Windows 7"
        if "windows server 2022" in os_lower: return "Windows Server 2022"
        if "windows server 2019" in os_lower: return "Windows Server 2019"
        if "windows server 2016" in os_lower: return "Windows Server 2016"
        if "windows server" in os_lower: return "Windows Server"
        return os_string

    def get_c_drive_free_space(self, asset):
        try:
            for device in asset.get('hardware_info', {}).get('storage', []):
                if ('C:' in device.get('name','').upper() or 'C DRIVE' in device.get('name','').upper()):
                    return device.get('free_space_gb')
            raw_content = asset.get('raw_content', '')
            if raw_content:
                for pattern in [r'C:.*?(\d+\.?\d*)\s*GB.*?free', r'Free Space.*?C.*?(\d+\.?\d*)\s*GB']:
                    match = re.search(pattern, raw_content, re.IGNORECASE)
                    if match: return float(match.group(1))
            return None
        except: return None

    def check_and_install_dependencies(self):
        # ... (implementation unchanged) ...
        pass

    def render_header(self):
        # ... (implementation unchanged) ...
        pass

    def render_sidebar_filters(self):
        # ... (implementation unchanged by this subtask, but uses updated session state) ...
        st.sidebar.header("Filters & Options")
        filters = {}
        if not st.session_state.assets_data:
            st.sidebar.info("No asset data available.")
            return {
               'selected_os': [], 'selected_manufacturers': [],
               'min_ram': 0, 'max_ram': 128, 'min_storage': 0.0, 'max_storage': 500.0,
               'show_low_storage': False, 'anydesk_search': "", 'search_term': "",
               'nmap_scan_type': st.session_state.get('nmap_scan_type', "Quick Scan"),
               'nmap_path': st.session_state.get('nmap_path', "nmap")
           }
        all_os_versions_set, all_manufacturers_set, all_ram_values_list, all_storage_values_list = set(), set(), [], []
        for asset in st.session_state.assets_data.values():
            if 'os_info' in asset and asset['os_info'].get('version'): all_os_versions_set.add(self.normalize_os_version(asset['os_info']['version']))
            if 'system_info' in asset and asset['system_info'].get('manufacturer'): all_manufacturers_set.add(asset['system_info']['manufacturer'])
            memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
            if memory_gb: all_ram_values_list.append(int(memory_gb))
            c_drive_free = self.get_c_drive_free_space(asset)
            if c_drive_free is not None: all_storage_values_list.append(c_drive_free)
        sorted_os_options, sorted_manufacturer_options = sorted(list(all_os_versions_set)), sorted(list(all_manufacturers_set))
        if not st.session_state.selected_os_filter and sorted_os_options: st.session_state.selected_os_filter = sorted_os_options.copy()
        filters['selected_os'] = st.sidebar.multiselect("OS", sorted_os_options, default=st.session_state.selected_os_filter, key="selected_os_multiselect", on_change=lambda: setattr(st.session_state, 'selected_os_filter', st.session_state.selected_os_multiselect))
        if not st.session_state.selected_manufacturers_filter and sorted_manufacturer_options: st.session_state.selected_manufacturers_filter = sorted_manufacturer_options.copy()
        filters['selected_manufacturers'] = st.sidebar.multiselect("Manufacturer", sorted_manufacturer_options, default=st.session_state.selected_manufacturers_filter, key="selected_manufacturers_multiselect", on_change=lambda: setattr(st.session_state, 'selected_manufacturers_filter', st.session_state.selected_manufacturers_multiselect))
        st.sidebar.subheader("Hardware")
        actual_min_ram, actual_max_ram = (min(all_ram_values_list) if all_ram_values_list else 0), (max(all_ram_values_list) if all_ram_values_list else 128)
        current_ram_filter = st.session_state.ram_range_filter if st.session_state.ram_range_filter else (actual_min_ram, actual_max_ram)
        filters['min_ram'], filters['max_ram'] = st.sidebar.slider("RAM (GB)", actual_min_ram, actual_max_ram, current_ram_filter, key="ram_slider", on_change=lambda: setattr(st.session_state, 'ram_range_filter', st.session_state.ram_slider))
        actual_min_storage, actual_max_storage = 0.0, (max(all_storage_values_list) if all_storage_values_list else 500.0)
        current_storage_filter = st.session_state.storage_range_filter if st.session_state.storage_range_filter else (actual_min_storage, actual_max_storage)
        filters['min_storage'], filters['max_storage'] = st.sidebar.slider("C: Free Space (GB)", actual_min_storage, actual_max_storage, current_storage_filter, key="storage_slider", on_change=lambda: setattr(st.session_state, 'storage_range_filter', st.session_state.storage_slider))
        st.sidebar.subheader("Quick Filters")
        filters['show_low_storage'] = st.sidebar.checkbox("Low Storage (<10GB)", value=st.session_state.show_low_storage_only, key="show_low_storage_checkbox", on_change=lambda: setattr(st.session_state, 'show_low_storage_only', st.session_state.show_low_storage_checkbox))
        filters['anydesk_search'] = st.sidebar.text_input("AnyDesk ID", value=st.session_state.anydesk_search_filter, key="anydesk_search_input", on_change=lambda: setattr(st.session_state, 'anydesk_search_filter', st.session_state.anydesk_search_input))
        filters['search_term'] = st.sidebar.text_input("General Search", value=st.session_state.search_term_filter, key="search_term_input", on_change=lambda: setattr(st.session_state, 'search_term_filter', st.session_state.search_term_input))
        st.sidebar.subheader("Network Scanning")
        scan_type_options = ["Quick Scan", "Full Scan", "Disabled"]
        try: current_scan_type_index = scan_type_options.index(st.session_state.nmap_scan_type)
        except ValueError: current_scan_type_index = 0; st.session_state.nmap_scan_type = "Quick Scan"
        st.sidebar.selectbox("Nmap Scan Type (info only)", scan_type_options, index=current_scan_type_index, key="nmap_scan_type_selector", help="Quick Scan is auto on load. Others for future use.")
        filters['nmap_scan_type'] = st.session_state.nmap_scan_type
        filters['nmap_path'] = st.sidebar.text_input("Nmap Path", value=st.session_state.nmap_path, key="nmap_path_input", on_change=lambda: setattr(st.session_state, 'nmap_path', st.session_state.nmap_path_input))
        with st.sidebar.expander("⚙️ View Customization", expanded=False):
            st.checkbox("Summary & Charts", value=st.session_state.show_summary_section, key="show_summary_cb", on_change=lambda: setattr(st.session_state, 'show_summary_section', st.session_state.show_summary_cb))
            st.checkbox("Asset Bubbles", value=st.session_state.show_bubbles_section, key="show_bubbles_cb", on_change=lambda: setattr(st.session_state, 'show_bubbles_section', st.session_state.show_bubbles_cb))
            st.checkbox("Asset Details Table", value=st.session_state.show_details_table_section, key="show_details_table_cb", on_change=lambda: setattr(st.session_state, 'show_details_table_section', st.session_state.show_details_table_cb))
        return filters

    def filter_assets(self, filters):
        # ... (implementation unchanged) ...
        filtered_assets = {}
        for name, asset in st.session_state.assets_data.items():
            if filters['selected_os'] and self.normalize_os_version(asset.get('os_info', {}).get('version', '')) not in filters['selected_os']: continue
            if filters['selected_manufacturers'] and asset.get('system_info', {}).get('manufacturer', '') not in filters['selected_manufacturers']: continue
            memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
            if memory_gb and (memory_gb < filters['min_ram'] or memory_gb > filters['max_ram']): continue
            c_drive_free = self.get_c_drive_free_space(asset)
            if c_drive_free is not None and (c_drive_free < filters['min_storage'] or c_drive_free > filters['max_storage']): continue
            if filters['show_low_storage'] and (c_drive_free is None or c_drive_free >= 10): continue
            if filters['anydesk_search'] and filters['anydesk_search'].lower() not in asset.get('anydesk_id', '').lower(): continue
            if filters['search_term'] and filters['search_term'].lower() not in json.dumps(asset).lower(): continue
            filtered_assets[name] = asset
        return filtered_assets


    def render_asset_bubbles(self, assets):
        # ... (implementation unchanged) ...
        if not assets: st.warning("No assets match filters."); return
        st.subheader("Assets Overview")
        assets_list = list(assets.items()); cols_per_row = 5
        for i in range(0, len(assets_list), cols_per_row):
            cols = st.columns(cols_per_row)
            for j, (name, asset) in enumerate(assets_list[i:i + cols_per_row]):
                with cols[j]: self.render_single_asset_bubble(name, asset)
    
    def render_single_asset_bubble(self, name, asset):
       # --- Data Extraction ---
       ip_address = asset.get('network_info', {}).get('ip_address', 'No IP')
       os_version = self.normalize_os_version(asset.get('os_info', {}).get('version', 'Unknown OS'))
       memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
       memory_display = f"{int(memory_gb)} GB" if memory_gb else "N/A"
       c_drive_free_gb = self.get_c_drive_free_space(asset)
       c_drive_display = f"{c_drive_free_gb:.1f} GB free" if c_drive_free_gb is not None else "N/A"

       antivirus_raw = asset.get('software_info', {}).get('antivirus', '')
       if not antivirus_raw or str(antivirus_raw).strip().lower() == 'n/a' or str(antivirus_raw).strip() == "":
           antivirus_html = ""
       else:
           antivirus_html = f"<div>🛡️ AV: {str(antivirus_raw)}</div>"

       # --- Status Logic ---
       raw_status = asset.get('network_info', {}).get('status', 'unknown')
       if not isinstance(raw_status, str):
           raw_status = 'unknown' # Ensure status is a string

       status_for_class = raw_status.lower()
       # Default to 'unknown' (maps to gray/scanning styles) if status string is not one of the explicit CSS classes
       valid_status_css_classes = ["online", "offline", "scanning", "pending", "failed"]
       if status_for_class not in valid_status_css_classes:
            nmap_scan_status_msg = asset.get('network_info', {}).get('nmap_scan_status', '').lower()
            if "failed" in nmap_scan_status_msg: status_for_class = "failed"
            elif "pending" in nmap_scan_status_msg: status_for_class = "pending"
            elif "skipped" in nmap_scan_status_msg: status_for_class = "scanning" # Treat skipped as neutral/scanning
            else: status_for_class = "unknown" # Fallback to unknown for styling

       status_indicator_class = f"status-indicator-{status_for_class}"
       status_text_class = f"status-{status_for_class}"

       # Refine plain_status_text based on the final status_for_class
       if status_for_class == "failed": plain_status_text = "Scan Failed"
       elif status_for_class == "pending": plain_status_text = "Scan Pending"
       elif status_for_class == "scanning" and raw_status == "unknown": plain_status_text = "Unknown"
       elif status_for_class == "scanning" and "skipped" in asset.get('network_info', {}).get('nmap_scan_status', '').lower(): plain_status_text = "Scan Skipped"
       else: plain_status_text = raw_status.capitalize()


       # --- CSS Classes ---
       low_storage = c_drive_free_gb is not None and c_drive_free_gb < 10
       storage_class = "low-storage" if low_storage else ""
       final_bubble_class = f"asset-bubble {status_indicator_class} {storage_class}".strip() # Add strip for cleaner class string

       # --- HTML Construction ---
       name_url_encoded = urllib.parse.quote(name)

       windows_account_html = ""
       raw_content = asset.get('raw_content', '')
       if raw_content:
           username_found = None
           for line in raw_content.splitlines():
               line_lower = line.lower()
               if "windows account:" in line_lower:
                   username_val = line.split(':', 1)[-1].strip()
                   if '\\' in username_val: username_val = username_val.split('\\', 1)[-1]
                   elif '/' in username_val: username_val = username_val.split('/',1)[-1]
                   if username_val and username_val.lower() != "n/a" and username_val.strip() != "":
                       username_found = username_val; break
               elif "user account:" in line_lower or "current user:" in line_lower:
                   username_val = line.split(':', 1)[-1].strip()
                   if username_val and username_val.lower() != "n/a" and username_val.strip() != "":
                       username_found = username_val; break
           if username_found:
               windows_account_html = f'<div>👤 {username_found}</div>'

       user_email_html = ""
       user_email_raw = asset.get('user_email', '')
       if user_email_raw and str(user_email_raw).strip() and str(user_email_raw).strip().lower() != 'n/a':
           user_email_html = f'<div>📧 {str(user_email_raw)}</div>'

       anydesk_id_val = asset.get('anydesk_id', '')
       anydesk_html = ""
       if anydesk_id_val and str(anydesk_id_val).strip() and str(anydesk_id_val).strip().lower() != 'n/a':
            anydesk_html = f'<a href="anydesk:{str(anydesk_id_val)}" class="anydesk-link" target="_blank">AnyDesk</a>'

       bubble_html = f"""
       <a href="/?view_asset={name_url_encoded}" target="_self" class="asset-bubble-link">
           <div class="{final_bubble_class}">
               <div class="asset-bubble-content">
                   <div class="asset-header">
                       <span class="asset-name">{name}</span>
                       <span class="asset-ip">{ip_address}</span>
                   </div>
                   <div class="asset-details-group">
                       <div>🖥️ OS: {os_version}</div>
                       <div>💾 RAM: {memory_display}</div>
                       <div>💽 C: {c_drive_display}</div>
                       {antivirus_html}
                       {windows_account_html}
                       {user_email_html}
                   </div>
                   <div class="asset-footer-group">
                       <span class="{status_text_class}">{plain_status_text}</span>
                       {anydesk_html}
                   </div>
               </div>
           </div>
       </a>
       """
       st.markdown(bubble_html, unsafe_allow_html=True)

    def render_status_distribution_chart(self, assets):
        # ... (implementation unchanged) ...
        if not assets: return
        st.subheader("Assets by Status"); status_counts = {}
        for asset_data in assets.values(): status = asset_data.get('network_info', {}).get('status', 'unknown'); status_counts[status] = status_counts.get(status, 0) + 1
        if status_counts:
            fig = px.pie(values=list(status_counts.values()), names=list(status_counts.keys()), title="Asset Status Overview")
            fig.update_traces(textposition='inside', textinfo='percent+label'); st.plotly_chart(fig, use_container_width=True)
        else: st.info("No status data for visualization.")

    def render_asset_details_modal(self, assets):
        # ... (implementation unchanged) ...
        pass # Placeholder for brevity

    def render_overview_metrics(self, assets):
        # ... (implementation unchanged) ...
        pass # Placeholder for brevity

    def render_asset_details(self, assets):
        # ... (implementation unchanged) ...
        pass # Placeholder for brevity

    def render_system_statistics(self, assets):
        # ... (implementation unchanged) ...
        pass # Placeholder for brevity

    def run(self):
        """Main application entry point"""
        try:
            if 'view_asset' in st.query_params:
                try:
                    if not st.session_state.assets_data:
                        with st.spinner("Loading asset data..."):
                             st.session_state.assets_data = self.load_assets_data()
                    asset_name_from_query = urllib.parse.unquote(st.query_params['view_asset'])
                    if asset_name_from_query and asset_name_from_query in st.session_state.assets_data:
                        st.session_state.selected_asset_for_details = asset_name_from_query
                        st.session_state.show_asset_details = True
                    elif asset_name_from_query:
                        st.warning(f"Asset '{asset_name_from_query}' specified in URL not found.")
                    st.query_params.clear()
                except Exception as e:
                    logger.error(f"Error processing view_asset query param: {e}", exc_info=True)
                    st.error("Failed to process asset view request from URL.")
                    if 'view_asset' in st.query_params:
                        try: st.query_params.clear()
                        except Exception as e_clear: logger.error(f"Failed to clear query_params on error: {e_clear}")
            
            self.check_and_install_dependencies()
            apply_windows11_theme()
            
            if not st.session_state.assets_data or 'refresh_trigger' in st.session_state:
                if 'refresh_trigger' in st.session_state: del st.session_state['refresh_trigger']
                logger.info("No Nmap queue to reset.") # Nmap queue was removed
                with st.spinner("Loading asset data (including Nmap Quick Scans)..."):
                    st.session_state.assets_data = self.load_assets_data()

            self.render_header()
            filters = self.render_sidebar_filters() # This now returns a dict of actual filter values

            # This block for active pills display logic is kept from previous state,
            # ensure it correctly uses session state for filter values.
            if st.session_state.assets_data and filters:
                all_os_versions_set, all_manufacturers_set, all_ram_values_list, all_storage_values_list = set(), set(), [], []
                for asset in st.session_state.assets_data.values():
                    if asset.get('os_info', {}).get('version'): all_os_versions_set.add(self.normalize_os_version(asset['os_info']['version']))
                    if asset.get('system_info', {}).get('manufacturer'): all_manufacturers_set.add(asset['system_info']['manufacturer'])
                    memory_gb = asset.get('hardware_info', {}).get('memory', {}).get('total_gb', 0)
                    if memory_gb: all_ram_values_list.append(int(memory_gb))
                    c_drive_free = self.get_c_drive_free_space(asset)
                    if c_drive_free is not None: all_storage_values_list.append(c_drive_free)

                default_min_ram = min(all_ram_values_list) if all_ram_values_list else 0
                default_max_ram = max(all_ram_values_list) if all_ram_values_list else 128
                default_min_storage = 0.0
                default_max_storage = max(all_storage_values_list) if all_storage_values_list else 500.0

                active_pills_data = []
                if len(st.session_state.selected_os_filter) != len(all_os_versions_set):
                    for os_name in st.session_state.selected_os_filter: active_pills_data.append((f"OS: {os_name}", f"dismiss_os_{os_name}", {"type": "os", "value": os_name}))
                if len(st.session_state.selected_manufacturers_filter) != len(all_manufacturers_set):
                    for manuf_name in st.session_state.selected_manufacturers_filter: active_pills_data.append((f"Manuf: {manuf_name}", f"dismiss_manuf_{manuf_name}", {"type": "manufacturer", "value": manuf_name}))
                current_ram_filter = st.session_state.ram_range_filter
                if current_ram_filter and (current_ram_filter[0] != default_min_ram or current_ram_filter[1] != default_max_ram): active_pills_data.append((f"RAM: {current_ram_filter[0]}-{current_ram_filter[1]} GB", "dismiss_ram", {"type": "ram_range"}))
                current_storage_filter = st.session_state.storage_range_filter
                if current_storage_filter and (current_storage_filter[0] != default_min_storage or current_storage_filter[1] != default_max_storage): active_pills_data.append((f"Storage: {current_storage_filter[0]:.1f}-{current_storage_filter[1]:.1f} GB", "dismiss_storage", {"type": "storage_range"}))
                if st.session_state.show_low_storage_only: active_pills_data.append(("Status: Low Storage", "dismiss_low_storage", {"type": "show_low_storage"}))
                if st.session_state.anydesk_search_filter: active_pills_data.append((f"AnyDesk: {st.session_state.anydesk_search_filter}", "dismiss_anydesk", {"type": "anydesk_search"}))
                if st.session_state.search_term_filter: active_pills_data.append((f"Search: \"{st.session_state.search_term_filter}\"", "dismiss_search", {"type": "search_term"}))

                if active_pills_data:
                    st.markdown('<div class="filter-pill-container">', unsafe_allow_html=True)
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
                                        if filter_type == "os": st.session_state.selected_os_filter.remove(action_args["value"]); st.session_state.selected_os_filter = st.session_state.selected_os_filter or (sorted(list(all_os_versions_set)) if all_os_versions_set else [])
                                        elif filter_type == "manufacturer": st.session_state.selected_manufacturers_filter.remove(action_args["value"]); st.session_state.selected_manufacturers_filter = st.session_state.selected_manufacturers_filter or (sorted(list(all_manufacturers_set)) if all_manufacturers_set else [])
                                        elif filter_type == "ram_range": st.session_state.ram_range_filter = None
                                        elif filter_type == "storage_range": st.session_state.storage_range_filter = None
                                        elif filter_type == "show_low_storage": st.session_state.show_low_storage_only = False
                                        elif filter_type == "anydesk_search": st.session_state.anydesk_search_filter = ""
                                        elif filter_type == "search_term": st.session_state.search_term_filter = ""
                                        st.rerun()
                                    st.markdown('</div>', unsafe_allow_html=True)
                    st.markdown('</div>', unsafe_allow_html=True)

            # Use the 'filters' dict returned by render_sidebar_filters for filtering logic
            # This dict should reflect the latest state from session_state due to on_change callbacks
            filtered_assets = self.filter_assets(filters)
            self.render_asset_details_modal(filtered_assets)

            if st.session_state.get('show_summary_section', True):
                st.markdown('<div class="summary-charts-container">', unsafe_allow_html=True)
                self.render_overview_metrics(filtered_assets)
                st.divider()
                self.render_system_statistics(filtered_assets)
                self.render_status_distribution_chart(filtered_assets)
                st.markdown('</div>', unsafe_allow_html=True)
                st.divider()

            if filtered_assets:
                if st.session_state.get('show_bubbles_section', True):
                    self.render_asset_bubbles(filtered_assets)
                    if st.session_state.get('show_details_table_section', True): st.divider()
                if st.session_state.get('show_details_table_section', True):
                    self.render_asset_details(filtered_assets)
            else:
                if st.session_state.assets_data: st.warning("No assets match filters.")
                else: st.info("Welcome! Place asset files in 'assets' and refresh.")
        except Exception as e:
            logger.error(f"Application error: {str(e)}", exc_info=True)
            st.error(f"An unhandled error occurred: {str(e)}")

if __name__ == "__main__":
    app = ITAssetDashboard()
    app.run()
