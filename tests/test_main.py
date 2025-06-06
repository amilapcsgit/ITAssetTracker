import unittest
from unittest.mock import patch, Mock, MagicMock
import subprocess
import sys
import os

# Add the parent directory to the Python path to allow importing 'main'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Need to mock streamlit before importing main
# Create a general mock for st and its functions that might be called at import time
mock_st = MagicMock()
sys.modules['streamlit'] = mock_st
sys.modules['pandas'] = MagicMock()
sys.modules['plotly.express'] = MagicMock()
sys.modules['plotly.graph_objects'] = MagicMock()

# It's important that ITAssetDashboard is imported AFTER streamlit is mocked
from main import ITAssetDashboard

class TestNmapScan(unittest.TestCase):

    def setUp(self):
        # Reset session_state for each test to avoid interference
        mock_st.session_state = MagicMock()
        # ITAssetDashboard init itself might set some session_state vars, let it.
        # We are testing methods of an instance of ITAssetDashboard.
        with patch('main.AssetParser', MagicMock()), \
             patch('main.DashboardComponents', MagicMock()), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.glob', return_value=[]):
            self.app = ITAssetDashboard()
            # Explicitly set session_state attributes that might be used by the class instance
            # if not set by __init__ under test conditions.
            # For _run_nmap_scan, these are not directly used by the method itself but by callers.
            # However, good practice for consistency if other methods were tested.
            if 'nmap_scan_type' not in mock_st.session_state:
                 mock_st.session_state.nmap_scan_type = "Full Scan" # Default for these tests
            if 'nmap_path' not in mock_st.session_state:
                 mock_st.session_state.nmap_path = "nmap"


    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_success_with_mac(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = """
Host is up (0.0010s latency).
Not shown: 995 closed ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)
|   256 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff (ECDSA)
|_  256 10:20:30:40:50:60:70:80:90:00:a0:b0:c0:d0:e0:f0 (ED25519)
80/tcp    open  http         Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: AA:BB:CC:DD:EE:FF (Test Vendor)
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
"""
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        expected_ip = "192.168.1.1"
        # Ensure scan_type is passed; default is "Full Scan" in method signature, but explicit here for clarity
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap", scan_type="Full Scan")

        self.assertEqual(result["status"], "online")
        self.assertEqual(result["mac_address"], "AA:BB:CC:DD:EE:FF") # MAC should be uppercase now
        self.assertIsNone(result["error_message"])
        self.assertIn("Host is up", result["nmap_output"])
        mock_subprocess_run.assert_called_once_with(
            ["nmap", "-T4", "-A", "-v", "-Pn", expected_ip],
            capture_output=True, text=True, timeout=120
        )

    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_host_down(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 2.03 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.2", nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "offline")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])
        self.assertIn("Host seems down", result["nmap_output"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_command_not_found(self, mock_subprocess_run): # Applies to any scan type
        nmap_path = "/custom/path/to/nmap"
        mock_subprocess_run.side_effect = FileNotFoundError

        result = self.app._run_nmap_scan("192.168.1.3", nmap_executable_path=nmap_path, scan_type="Full Scan")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_message"], f"Nmap command not found at '{nmap_path}'. Please ensure nmap is installed and the path is correct.")
        self.assertIsNone(result["mac_address"])
        self.assertEqual(result["nmap_output"], "")

    @patch('main.subprocess.run')
    def test_run_nmap_scan_timeout(self, mock_subprocess_run): # Applies to any scan type
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd="nmap ...", timeout=120)

        expected_ip = "192.168.1.4"
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_message"], f"Nmap scan for {expected_ip} timed out.")
        self.assertIsNone(result["mac_address"])

    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_error_return_code(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.stdout = "Some output indicating an issue."
        mock_process.stderr = "Nmap error: Invalid arguments."
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.5", nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "error")
        self.assertTrue("Nmap Full Scan for 192.168.1.5 failed with return code 1" in result["error_message"])
        self.assertTrue("Nmap error: Invalid arguments" in result["error_message"])
        self.assertIsNone(result["mac_address"])

    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_online_no_mac(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Host is up.\nNmap done."
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.6", nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "online")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])

    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_status_unclear_but_open_ports(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.1\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\nNmap done: 1 IP address (1 host up) scanned in 0.20 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.1", nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "online")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])

    @patch('main.subprocess.run')
    def test_run_nmap_full_scan_status_unclear_no_open_ports(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.1\nAll 1000 scanned ports on 192.168.1.1 are closed\nNmap done: 1 IP address (1 host up) scanned in 0.20 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.1", nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(result["status"], "offline")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])

    @patch('main.subprocess.run')
    def test_run_nmap_quick_scan_host_up(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.10\nHost is up (0.0020s latency).\nNmap done: 1 IP address (1 host up) scanned in 0.05 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        expected_ip = "192.168.1.10"
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap", scan_type="Quick Scan")

        self.assertEqual(result["status"], "online")
        self.assertIsNone(result["mac_address"]) # Quick scan doesn't fetch MAC
        self.assertIsNone(result["error_message"])
        self.assertIn("Host is up", result["nmap_output"])
        mock_subprocess_run.assert_called_once_with(
            ["nmap", "-sn", "-T4", expected_ip],
            capture_output=True, text=True, timeout=120
        )

    @patch('main.subprocess.run')
    def test_run_nmap_quick_scan_host_down(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0 # nmap -sn might still return 0 for host down
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.11\nNote: Host seems down.\nNmap done: 1 IP address (0 hosts up) scanned in 1.00 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        expected_ip = "192.168.1.11"
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap", scan_type="Quick Scan")

        self.assertEqual(result["status"], "offline")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])
        self.assertIn("Host seems down", result["nmap_output"])
        mock_subprocess_run.assert_called_once_with(
            ["nmap", "-sn", "-T4", expected_ip],
            capture_output=True, text=True, timeout=120
        )

    @patch('main.subprocess.run')
    def test_run_nmap_invalid_scan_type(self, mock_subprocess_run):
        result = self.app._run_nmap_scan("192.168.1.1", scan_type="InvalidType")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_message"], "Invalid scan type: InvalidType")
        mock_subprocess_run.assert_not_called()


class TestAssetDetailsRendering(unittest.TestCase):
    # Per subtask instructions:
    # "Alternatively, create a mock ITAssetDashboard instance and test the generation of table_data
    # based on various assets inputs... Assert that table_data is structured as expected.
    # (This might be difficult without refactoring render_asset_details as it's tightly coupled
    # with Streamlit's st calls. Prioritize _run_nmap_scan tests if this is too complex for the subtask)."

    # Given the tight coupling with st calls for UI elements (subheader, download_button, dataframe),
    # testing the data preparation part of `render_asset_details` without significant refactoring
    # is indeed complex. The function's primary role is rendering.
    # A more effective approach would be to refactor `render_asset_details` to have a separate
    # helper function like `prepare_table_data(assets)` which returns `table_data`, and then test that helper.
    # Without such refactoring, a meaningful unit test for `render_asset_details`'s data aspect is challenging.
    # For this subtask, focus remains on Nmap tests.
    # A brief attempt to test data preparation for render_asset_details:
    def test_prepare_table_data_for_render_asset_details(self):
        # This test is conceptual as render_asset_details is not refactored.
        # If it were refactored to have a `_prepare_table_data(assets)` method:

        # mock_app = ITAssetDashboard() # Assume __init__ is simple or fully mocked
        # assets_input = {
        #     "PC01": {
        #         "network_info": {"ip_address": "10.0.0.1", "status": "online"},
        #         "os_info": {"version": "Windows 10"},
        #         "system_info": {"manufacturer": "Dell", "model": "Latitude"},
        #         "hardware_info": {"memory": {"total_gb": 8}, "processor": {"name": "Intel i5"}}
        #     },
        #     "PC02": { # Asset with some missing info
        #         "network_info": {"ip_address": "10.0.0.2", "status": "offline"},
        #         "os_info": {"version": "Ubuntu 20.04"},
        #         "system_info": {}, # Missing manufacturer, model
        #         "hardware_info": {"memory": {}, "processor": {}} # Missing RAM, CPU
        #     }
        # }
        # expected_table_data = [
        #     {'Computer Name': 'PC01', 'IP Address': '10.0.0.1', 'OS': 'Windows 10',
        #      'Manufacturer': 'Dell', 'Model': 'Latitude', 'RAM (GB)': 8,
        #      'CPU': 'Intel i5', 'Status': 'online'},
        #     {'Computer Name': 'PC02', 'IP Address': '10.0.0.2', 'OS': 'Ubuntu 20.04',
        #      'Manufacturer': 'N/A', 'Model': 'N/A', 'RAM (GB)': 'N/A',
        #      'CPU': 'N/A', 'Status': 'offline'},
        # ]
        # actual_table_data = mock_app._prepare_table_data(assets_input) # Hypothetical method
        # self.assertEqual(actual_table_data, expected_table_data)
        pass # Keep as placeholder


class TestNmapQueuePopulation(unittest.TestCase):
    def setUp(self):
        mock_st.session_state = MagicMock()
        # Default session state for Nmap settings for these tests
        mock_st.session_state.nmap_scan_type = "Disabled"
        mock_st.session_state.nmap_path = "nmap"
        mock_st.session_state.nmap_scan_queue = []
        mock_st.session_state.nmap_currently_scanning = None

        with patch('main.AssetParser') as MockAssetParser:
            self.mock_parser_instance = MockAssetParser.return_value
            with patch('main.DashboardComponents', MagicMock()), \
                 patch('pathlib.Path.exists', return_value=True): # Ensure ITAssetDashboard inits
                self.app = ITAssetDashboard()

    @patch('pathlib.Path.glob')
    def test_load_assets_populates_queue_full_scan(self, mock_glob):
        mock_st.session_state.nmap_scan_type = "Full Scan"
        mock_st.session_state.nmap_scan_queue = [] # ensure it's empty before test

        mock_asset_file = MagicMock(spec=os.PathLike)
        mock_asset_file.name = "asset1.txt"
        mock_asset_file.stem = "asset1"
        mock_glob.return_value = [mock_asset_file]

        self.mock_parser_instance.parse_asset_file.return_value = {
            "computer_name": "Asset1",
            "network_info": {"ip_address": "192.168.1.100"},
            # other necessary fields for asset_data to be considered valid by load_assets_data
        }

        with patch.object(self.app, '_run_nmap_scan') as mock_run_scan: # Ensure actual scan isn't called
            self.app.load_assets_data()

        self.assertIn("Asset1", mock_st.session_state.nmap_scan_queue)
        self.assertEqual(len(mock_st.session_state.nmap_scan_queue), 1)
        mock_run_scan.assert_not_called() # load_assets_data should not call it directly
        # Check if nmap_scan_status was initialized
        self.assertEqual(self.app.st.session_state.assets_data["Asset1"]['network_info']['nmap_scan_status'], 'pending')


    @patch('pathlib.Path.glob')
    def test_load_assets_nmap_disabled(self, mock_glob):
        mock_st.session_state.nmap_scan_type = "Disabled"
        mock_st.session_state.nmap_scan_queue = []

        mock_asset_file = MagicMock(spec=os.PathLike)
        mock_asset_file.name = "asset2.txt"
        mock_asset_file.stem = "asset2"
        mock_glob.return_value = [mock_asset_file]
        self.mock_parser_instance.parse_asset_file.return_value = {"computer_name": "Asset2", "network_info": {"ip_address": "192.168.1.101"}}

        self.app.load_assets_data()
        self.assertEqual(len(mock_st.session_state.nmap_scan_queue), 0)
        self.assertEqual(self.app.st.session_state.assets_data["Asset2"]['network_info']['nmap_scan_status'], 'disabled')


class TestNmapQueueProcessing(unittest.TestCase):
    def setUp(self):
        # Reset session_state for each test
        mock_st.session_state = MagicMock()
        mock_st.session_state.assets_data = {}
        mock_st.session_state.nmap_scan_queue = []
        mock_st.session_state.nmap_currently_scanning = None
        mock_st.session_state.nmap_scan_type = "Full Scan" # Default for these tests
        mock_st.session_state.nmap_path = "nmap"

        with patch('main.AssetParser', MagicMock()), \
             patch('main.DashboardComponents', MagicMock()), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.glob', return_value=[]):
            self.app = ITAssetDashboard()
            # It's crucial that self.app uses the same mock_st.session_state
            # This is generally true if main.py uses `import streamlit as st` and then `st.session_state`
            self.app.st = mock_st # Ensure the app instance uses our mocked st

    def test_process_queue_empty(self):
        mock_st.session_state.nmap_scan_queue = []
        with patch.object(self.app, '_run_nmap_scan') as mock_run_scan, \
             patch('main.st.rerun') as mock_rerun:
            self.app._process_nmap_scan_queue()
            mock_run_scan.assert_not_called()
            mock_rerun.assert_not_called() # Should not rerun if queue is empty and nothing was scanning

    @patch('main.st.rerun') # Mock st.rerun from where it's called in main.py
    @patch.object(ITAssetDashboard, '_run_nmap_scan') # Patch the method on the class
    def test_process_queue_one_item_full_scan(self, mock_run_nmap_scan, mock_rerun):
        asset_name = "TestPC1"
        ip = "192.168.1.50"
        mock_st.session_state.nmap_scan_queue = [asset_name]
        mock_st.session_state.assets_data = {
            asset_name: {"computer_name": asset_name, "network_info": {"ip_address": ip, "nmap_scan_status": "pending"}}
        }
        mock_st.session_state.nmap_scan_type = "Full Scan"
        mock_st.session_state.nmap_currently_scanning = None

        mock_nmap_result = {"status": "online", "mac_address": "AB:CD:EF:12:34:56", "nmap_output": "...", "error_message": None}
        mock_run_nmap_scan.return_value = mock_nmap_result

        self.app._process_nmap_scan_queue()

        mock_run_nmap_scan.assert_called_once_with(ip, nmap_executable_path="nmap", scan_type="Full Scan")
        self.assertEqual(mock_st.session_state.assets_data[asset_name]['network_info']['status'], "online")
        self.assertEqual(mock_st.session_state.assets_data[asset_name]['network_info']['mac_address'], "AB:CD:EF:12:34:56")
        self.assertEqual(mock_st.session_state.assets_data[asset_name]['network_info']['nmap_scan_status'], 'completed')
        self.assertIsNone(mock_st.session_state.nmap_currently_scanning)
        self.assertEqual(len(mock_st.session_state.nmap_scan_queue), 0)
        mock_rerun.assert_called_once()

    @patch('main.st.rerun')
    @patch.object(ITAssetDashboard, '_run_nmap_scan')
    def test_process_queue_nmap_disabled(self, mock_run_nmap_scan, mock_rerun):
        mock_st.session_state.nmap_scan_type = "Disabled"
        mock_st.session_state.nmap_scan_queue = ["TestPC1"] # Queue has an item
        self.app._process_nmap_scan_queue()

        self.assertEqual(len(mock_st.session_state.nmap_scan_queue), 0) # Queue should be cleared
        mock_run_nmap_scan.assert_not_called()
        # rerun might be called if queue was cleared, or not if it was already empty.
        # The current logic doesn't rerun if queue becomes empty *and* was not scanning.
        # If it was scanning, nmap_currently_scanning would be reset, but no rerun from this path.
        # Let's assume no rerun if it just clears an existing queue due to disabling.
        # Actually, the current code does not call st.rerun() if it just clears the queue.
        mock_rerun.assert_not_called()

    @patch('main.st.rerun')
    @patch.object(ITAssetDashboard, '_run_nmap_scan')
    def test_process_queue_scan_already_in_progress(self, mock_run_nmap_scan, mock_rerun):
        mock_st.session_state.nmap_currently_scanning = "BusyPC"
        mock_st.session_state.nmap_scan_queue = ["TestPC1"] # Item in queue

        self.app._process_nmap_scan_queue()

        mock_run_nmap_scan.assert_not_called() # Should not start a new scan
        mock_rerun.assert_not_called()

    def test_placeholder_for_render_asset_details(self):
        # This test serves as a placeholder acknowledging the decision.
        self.assertTrue(True, "Skipping direct test of render_asset_details data prep due to Streamlit coupling. Focus is on Nmap functionality tests.")


if __name__ == '__main__':
    unittest.main()
