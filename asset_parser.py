import re
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

class AssetParser:
    """Parser for Windows PC asset data files"""
    
    def __init__(self):
        self.patterns = {
            'computer_name': [
                r'Computer Name[:\s]+([^\n]+)',
                r'System Name[:\s]+([^\n]+)',
                r'Hostname[:\s]+([^\n]+)'
            ],
            'ip_address': [
                r'IP Address[:\s]+(\d+\.\d+\.\d+\.\d+)',
                r'IPv4 Address[:\s]+(\d+\.\d+\.\d+\.\d+)',
                r'Network Address[:\s]+(\d+\.\d+\.\d+\.\d+)'
            ],
            'os_version': [
                r'OS Version[:\s]+([^\n]+)',
                r'Operating System[:\s]+([^\n]+)',
                r'Windows Version[:\s]+([^\n]+)'
            ],
            'manufacturer': [
                r'Manufacturer[:\s]+([^\n]+)',
                r'System Manufacturer[:\s]+([^\n]+)',
                r'Computer Manufacturer[:\s]+([^\n]+)'
            ],
            'model': [
                r'Model[:\s]+([^\n]+)',
                r'System Model[:\s]+([^\n]+)',
                r'Computer Model[:\s]+([^\n]+)'
            ],
            'processor': [
                r'Processor[:\s]+([^\n]+)',
                r'CPU[:\s]+([^\n]+)',
                r'Central Processor[:\s]+([^\n]+)'
            ],
            'memory': [
                r'Total Physical Memory[:\s]+([^\n]+)',
                r'RAM[:\s]+([^\n]+)',
                r'Memory[:\s]+([^\n]+)'
            ],
            'anydesk_id': [
                r'AnyDesk ID[:\s]+(\d+)',
                r'AnyDesk[:\s]+(\d+)',
                r'Remote ID[:\s]+(\d+)'
            ],
            'user_email': [
                r'User Email\(s\)[:\s]+([^\n]+)',
                r'Email[:\s]+([^\n]+)',
                r'User Account[:\s]+([^\n]+)'
            ],
            'gpu': [
                r'GPU[:\s]+([^\n]+)',
                r'Graphics[:\s]+([^\n]+)',
                r'Video Card[:\s]+([^\n]+)'
            ],
            'bios_version': [
                r'BIOS Version[:\s]+([^\n]+)',
                r'BIOS[:\s]+([^\n]+)'
            ],
            'windows_language': [
                r'Windows Language[:\s]+([^\n]+)',
                r'Language[:\s]+([^\n]+)'
            ],
            'antivirus': [
                r'Antivirus[:\s]+([^\n]+)',
                r'Anti-virus[:\s]+([^\n]+)'
            ],
            'office_version': [
                r'Office Version[:\s]+([^\n]+)',
                r'Microsoft Office[:\s]+([^\n]+)'
            ],
            'os_activation': [
                r'OS Activation[:\s]+([^\n]+)',
                r'Windows Activation[:\s]+([^\n]+)',
                r'Licensed[:\s]*\n'
            ],
            'network_mode': [
                r'Network Mode[:\s]+([^\n]+)',
                r'DHCP[:\s]+([^\n]+)',
                r'IP Configuration[:\s]+([^\n]+)'
            ],
            'vendor': [r'Vendor[:\s]+([^\n]+)'],
            'discovery_date': [r'DiscoveryDate[:\s]+([^\n]+)'],
            'source': [r'Source[:\s]+([^\n]+)'],
            # --- ADDED NEW PATTERNS HERE ---
            'detected_os': [
                r'Detected OS[:\s]+([^\n]+)'
            ],
            'nmap_output': [
                r'=== Nmap Discovery Output ===\n(.*?)(?=\n===|\Z)'
            ]
        }

    def extract_field(self, content: str, field_name: str) -> Optional[str]:
        """Extract a specific field from the content using regex patterns."""
        patterns = self.patterns.get(field_name, [])

        for pattern in patterns:
            # --- MODIFICATION ---
            # Added the re.DOTALL flag to allow '.' to match newlines.
            # This is critical for capturing multi-line Nmap output.
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if match:
                return match.group(1).strip()

        return None

    def parse_memory_size(self, memory_str: str) -> Optional[float]:
        """Parse memory string and convert to GB"""
        if not memory_str:
            return None
        
        # Handle Italian decimal notation (comma as decimal separator)
        memory_str = memory_str.replace(',', '.').strip()
        
        # Look for patterns like "8.00 GB", "8192 MB", "8388608 KB"
        gb_match = re.search(r'(\d+\.?\d*)\s*GB', memory_str, re.IGNORECASE)
        if gb_match:
            value = float(gb_match.group(1))
            # Round to nearest GB for display
            return round(value)
        
        mb_match = re.search(r'(\d+\.?\d*)\s*MB', memory_str, re.IGNORECASE)
        if mb_match:
            value = float(mb_match.group(1)) / 1024
            return round(value)
        
        kb_match = re.search(r'(\d+\.?\d*)\s*KB', memory_str, re.IGNORECASE)
        if kb_match:
            value = float(kb_match.group(1)) / (1024 * 1024)
            return round(value)
        
        # Try to extract just numbers and assume MB if no unit
        number_match = re.search(r'(\d+\.?\d*)', memory_str)
        if number_match:
            value = float(number_match.group(1))
            # If the value is very large, assume it's in bytes
            if value > 1000000:
                return round(value / (1024 * 1024 * 1024))
            # If moderate, assume MB
            elif value > 1000:
                return round(value / 1024)
            # If small, assume GB
            else:
                return round(value)
        
        return None

    def parse_storage_info(self, content: str) -> List[Dict[str, Any]]:
        """Parse storage/disk information from content including Italian format"""
        storage_devices = []
        
        # Look for Local Disks section in the content
        local_disks_pattern = r'=== Local Disks \(in MB\) ===(.*?)(?=\n\n|\n===|\Z)'
        disks_match = re.search(local_disks_pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        
        if disks_match:
            disks_section = disks_match.group(1)
            # Parse each disk line: C:  Total: 485637 MB, Free: 412269.2 MB
            disk_lines = disks_section.strip().split('\n')
            
            for line in disk_lines:
                line = line.strip()
                if ':' in line and 'Total:' in line and 'Free:' in line:
                    # Extract drive letter
                    drive_match = re.match(r'([A-Z]):.*?Total:\s*(\d+\.?\d*)\s*MB.*?Free:\s*(\d+\.?\d*)\s*MB', line, re.IGNORECASE)
                    if drive_match:
                        drive_letter = drive_match.group(1)
                        total_mb = float(drive_match.group(2).replace(',', '.'))
                        free_mb = float(drive_match.group(3).replace(',', '.'))
                        
                        # Convert MB to GB
                        total_gb = total_mb / 1024
                        free_gb = free_mb / 1024
                        
                        storage_devices.append({
                            'name': f"{drive_letter}: Drive ({total_gb:.1f} GB)",
                            'size_gb': total_gb,
                            'free_space_gb': free_gb,
                            'drive_letter': drive_letter
                        })
        
        # Fallback: Look for older disk drive patterns
        if not storage_devices:
            disk_patterns = [
                r'Disk Drive[:\s]+([^\n\r]+)',
                r'Hard Disk[:\s]+([^\n\r]+)',
                r'Storage Device[:\s]+([^\n\r]+)'
            ]
            
            for pattern in disk_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    disk_info = match.group(1).strip()
                    
                    # Try to extract size information
                    size_gb = None
                    size_match = re.search(r'(\d+\.?\d*)\s*(GB|TB|MB)', disk_info, re.IGNORECASE)
                    if size_match:
                        size_value = float(size_match.group(1).replace(',', '.'))
                        unit = size_match.group(2).upper()
                        
                        if unit == 'TB':
                            size_gb = size_value * 1024
                        elif unit == 'GB':
                            size_gb = size_value
                        elif unit == 'MB':
                            size_gb = size_value / 1024
                    
                    storage_devices.append({
                        'name': disk_info,
                        'size_gb': size_gb,
                        'free_space_gb': None
                    })
        
        return storage_devices

    def parse_software_list(self, content: str) -> List[str]:
        """Parse installed software list from content"""
        software_list = []
        
        # Look for software/program sections
        software_patterns = [
            r'Installed Programs?[:\s]*\n(.*?)(?=\n\n|\Z)',
            r'Software[:\s]*\n(.*?)(?=\n\n|\Z)',
            r'Applications?[:\s]*\n(.*?)(?=\n\n|\Z)'
        ]
        
        for pattern in software_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if match:
                software_section = match.group(1)
                # Split by lines and clean up
                lines = software_section.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('-') and len(line) > 3:
                        software_list.append(line)
                break
        
        return software_list

    def parse_shared_folders(self, content: str) -> List[str]:
        """Parse shared folders information"""
        shared_folders = []
        
        # Look for shared folders section
        shared_pattern = r'Shared Folders[:\s]*\n(.*?)(?=\n\n|\Z)'
        match = re.search(shared_pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        
        if match:
            shared_section = match.group(1)
            lines = shared_section.split('\n')
            for line in lines:
                line = line.strip()
                if line and '->' in line:
                    shared_folders.append(line)
        
        return shared_folders

    def parse_stored_credentials(self, content: str) -> List[str]:
        """Parse stored network credentials"""
        credentials = []
        
        # Look for stored credentials section
        cred_patterns = [
            r'Stored Network Credentials[:\s]*\n(.*?)(?=\n\n|\Z)',
            r'Network Credentials[:\s]*\n(.*?)(?=\n\n|\Z)'
        ]
        
        for pattern in cred_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if match:
                cred_section = match.group(1)
                lines = cred_section.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.lower().startswith('no') and len(line) > 3:
                        credentials.append(line)
                break
        
        return credentials

    def parse_adobe_autodesk(self, content: str) -> List[str]:
        """Parse Adobe/Autodesk software information"""
        software_list = []
        
        # Look for Adobe/Autodesk section
        adobe_pattern = r'Adobe/Autodesk[:\s]*\n?(.*?)(?=\n\n|\n===|\Z)'
        match = re.search(adobe_pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        
        if match:
            adobe_section = match.group(1)
            # Split by semicolons and clean up
            items = adobe_section.split(';')
            for item in items:
                item = item.strip()
                if item and len(item) > 3:
                    software_list.append(item)
        
        return software_list

    def parse_network_info(self, content: str) -> Dict[str, Any]:
        """Parse network configuration information"""
        network_info = {}
        
        # IP Address
        ip_address = self.extract_field(content, 'ip_address')
        if ip_address:
            network_info['ip_address'] = ip_address
        
        # Look for additional network information
        mac_pattern = r'MAC Address[:\s]+([A-Fa-f0-9:-]{17})'
        mac_match = re.search(mac_pattern, content, re.IGNORECASE)
        if mac_match:
            network_info['mac_address'] = mac_match.group(1)
        
        # Network adapter information
        adapter_pattern = r'Network Adapter[:\s]+([^\n\r]+)'
        adapter_matches = re.finditer(adapter_pattern, content, re.IGNORECASE | re.MULTILINE)
        adapters = [match.group(1).strip() for match in adapter_matches]
        if adapters:
            network_info['adapters'] = adapters
        
        # Determine status (basic heuristic)
        if ip_address and not ip_address.startswith('169.254'):
            network_info['status'] = 'online'
        else:
            network_info['status'] = 'offline'
        
        return network_info

    def parse_asset_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a single asset file and return structured data"""
        try:
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return None

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(file_path, 'r', encoding='cp1252') as f:
                    content = f.read()

            if not content.strip():
                logger.warning(f"Empty file: {file_path}")
                return None

            asset_data = {
                'file_name': file_path.name,
                'file_path': str(file_path),
                'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                'computer_name': self.extract_field(content, 'computer_name') or file_path.stem,
                'vendor': self.extract_field(content, 'vendor'), # Added vendor parsing
                'discovery_date': self.extract_field(content, 'discovery_date'), # Added discovery date parsing
                'anydesk_id': self.extract_field(content, 'anydesk_id'),
                'user_email': self.extract_field(content, 'user_email'),
                'system_info': {
                    'manufacturer': self.extract_field(content, 'manufacturer'),
                    'model': self.extract_field(content, 'model'),
                    'bios_version': self.extract_field(content, 'bios_version')
                },
                'os_info': {
                    'version': self.extract_field(content, 'os_version'),
                    'activation': self.extract_field(content, 'os_activation'),
                    'language': self.extract_field(content, 'windows_language'),
                    'detected_os': self.extract_field(content, 'detected_os') # --- ADDED THIS ---
                },
                'hardware_info': { 'processor': { 'name': self.extract_field(content, 'processor') }, 'gpu': self.extract_field(content, 'gpu'), 'memory': {}, 'storage': [] },
                'network_info': { 'mode': self.extract_field(content, 'network_mode') },
                'software_info': { 'office_version': self.extract_field(content, 'office_version'), 'antivirus': self.extract_field(content, 'antivirus'), 'adobe_autodesk': [], 'installed_programs': [] },
                'shared_folders': [],
                'stored_credentials': [],
                'raw_content': content
            }

            # --- ADDED NMAP OUTPUT PARSING ---
            # Note: The user's new `__init__` defines a pattern for 'nmap_output'.
            # The `extract_field` method should be used here for consistency if it handles re.DOTALL implicitly or if the pattern is adapted.
            # However, the previous explicit `re.search` with `re.DOTALL` was more robust for multiline.
            # For now, strictly follow user's code which uses extract_field.
            # If `extract_field` doesn't use DOTALL, the nmap_output pattern in __init__ might need `(?s)` prefix or similar.
            # This version from user uses self.extract_field:
            asset_data['network_info']['nmap_discovery_output'] = self.extract_field(content, 'nmap_output')


            # Parse memory, storage, network, software, etc.
            memory_str = self.extract_field(content, 'memory')
            if memory_str:
                asset_data['hardware_info']['memory'] = { 'raw': memory_str, 'total_gb': self.parse_memory_size(memory_str) }

            asset_data['hardware_info']['storage'] = self.parse_storage_info(content)

            # Combine parsed network info with existing dictionary
            # It's important that parse_network_info() doesn't overwrite nmap_discovery_output if it's already set
            # Or, nmap_discovery_output should be added *after* parse_network_info() populates other network details.
            # Let's ensure nmap_discovery_output is preserved if parse_network_info also writes to asset_data['network_info']
            
            # Store nmap_output before calling parse_network_info, then restore if necessary,
            # or ensure parse_network_info is additive.
            # The user's code places nmap_output parsing *before* parse_network_info.
            # parse_network_info in the original code did: `network_info['mac_address'] = ...`, `network_info['ip_address'] = ...`
            # It did not clear the dict. So this order should be fine.

            parsed_network_info = self.parse_network_info(content) # This method returns a dict
            if 'network_info' not in asset_data: asset_data['network_info'] = {} # Ensure it exists
            asset_data['network_info'].update(parsed_network_info) # Update with general IP/MAC etc.
            # Re-assign nmap_discovery_output here if there's a risk parse_network_info overwrote the whole dict,
            # but .update() should merge. The current user code puts nmap_output parsing separately.
            # The provided code is:
            # asset_data['network_info']['nmap_discovery_output'] = self.extract_field(content, 'nmap_output')
            # ... (memory, storage) ...
            # parsed_network_info = self.parse_network_info(content)
            # asset_data['network_info'].update(parsed_network_info)
            # This means nmap_discovery_output would be set, then other network info updated. This is fine.

            asset_data['software_info']['installed_programs'] = self.parse_software_list(content)
            asset_data['software_info']['adobe_autodesk'] = self.parse_adobe_autodesk(content)
            asset_data['shared_folders'] = self.parse_shared_folders(content)
            asset_data['stored_credentials'] = self.parse_stored_credentials(content)

            # Ensure datetime is imported
            # from datetime import datetime (should be at the top of the file)
            
            logger.info(f"Successfully parsed asset file: {file_path.name}")
            return asset_data

        except Exception as e:
            logger.error(f"Error parsing asset file {file_path}: {str(e)}")
            return None

    def validate_asset_data(self, asset_data: Dict[str, Any]) -> bool:
        """Validate that asset data contains minimum required information"""
        required_fields = ['computer_name']
        
        for field in required_fields:
            if not asset_data.get(field):
                return False
        
        return True
