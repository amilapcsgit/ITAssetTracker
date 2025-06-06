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

from main import ITAssetDashboard # Should be importable now

class TestNmapScan(unittest.TestCase):

    def setUp(self):
        # We need a dummy app instance to call _run_nmap_scan
        # Mocking __init__ dependencies if they are complex or not needed for this test
        with patch('main.AssetParser', MagicMock()), \
             patch('main.DashboardComponents', MagicMock()), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.glob', return_value=[]): # Ensure asset loading doesn't run
            self.app = ITAssetDashboard()

    @patch('main.subprocess.run')
    def test_run_nmap_scan_success_with_mac(self, mock_subprocess_run):
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
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap")

        self.assertEqual(result["status"], "online")
        self.assertEqual(result["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(result["error_message"])
        self.assertIn("Host is up", result["nmap_output"])
        mock_subprocess_run.assert_called_once_with(
            ["nmap", "-T4", "-A", "-v", "-Pn", expected_ip],
            capture_output=True, text=True, timeout=120
        )

    @patch('main.subprocess.run')
    def test_run_nmap_scan_host_down(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0 # Nmap can return 0 even if host is down, output parsing is key
        mock_process.stdout = "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 2.03 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.2", nmap_executable_path="nmap")
        self.assertEqual(result["status"], "offline")
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])
        self.assertIn("Host seems down", result["nmap_output"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_command_not_found(self, mock_subprocess_run):
        nmap_path = "/custom/path/to/nmap"
        mock_subprocess_run.side_effect = FileNotFoundError

        result = self.app._run_nmap_scan("192.168.1.3", nmap_executable_path=nmap_path)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_message"], f"Nmap command not found at '{nmap_path}'. Please ensure nmap is installed and the path is correct.")
        self.assertIsNone(result["mac_address"])
        self.assertEqual(result["nmap_output"], "")

    @patch('main.subprocess.run')
    def test_run_nmap_scan_timeout(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd="nmap ...", timeout=120)

        expected_ip = "192.168.1.4"
        result = self.app._run_nmap_scan(expected_ip, nmap_executable_path="nmap")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_message"], f"Nmap scan for {expected_ip} timed out.")
        self.assertIsNone(result["mac_address"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_error_return_code(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.stdout = "Some output indicating an issue."
        mock_process.stderr = "Nmap error: Invalid arguments."
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.5", nmap_executable_path="nmap")
        self.assertEqual(result["status"], "error")
        self.assertTrue("Nmap scan failed with return code 1" in result["error_message"])
        self.assertTrue("Nmap error: Invalid arguments" in result["error_message"])
        self.assertIsNone(result["mac_address"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_online_no_mac(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Host is up.\nNmap done." # No MAC address line
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.6", nmap_executable_path="nmap")
        self.assertEqual(result["status"], "online")
        self.assertIsNone(result["mac_address"]) # Expect None if MAC not found
        self.assertIsNone(result["error_message"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_status_unclear_but_open_ports(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        # No "Host is up" or "Host seems down", but open ports are listed
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.1\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\nNmap done: 1 IP address (1 host up) scanned in 0.20 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.1", nmap_executable_path="nmap")
        self.assertEqual(result["status"], "online") # Should be considered online due to open ports
        self.assertIsNone(result["mac_address"]) # Assuming no MAC in this minimal output
        self.assertIsNone(result["error_message"])

    @patch('main.subprocess.run')
    def test_run_nmap_scan_status_unclear_no_open_ports(self, mock_subprocess_run):
        mock_process = Mock()
        mock_process.returncode = 0
        # No "Host is up", "Host seems down", and no open ports
        mock_process.stdout = "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for 192.168.1.1\nAll 1000 scanned ports on 192.168.1.1 are closed\nNmap done: 1 IP address (1 host up) scanned in 0.20 seconds"
        mock_process.stderr = ""
        mock_subprocess_run.return_value = mock_process

        result = self.app._run_nmap_scan("192.168.1.1", nmap_executable_path="nmap")
        self.assertEqual(result["status"], "offline") # Should be considered offline
        self.assertIsNone(result["mac_address"])
        self.assertIsNone(result["error_message"])


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
    # For this subtask, I will focus on the `_run_nmap_scan` tests as prioritized.

    # If a refactor were done, tests would look something like this:
    # def test_prepare_table_data_normal(self):
    #     app = ITAssetDashboard() # Assuming a suitably mocked/simple init
    #     assets = {
    #         "Asset1": {'network_info': {'ip_address': '1.1.1.1', 'status': 'online'},
    #                    'os_info': {'version': 'Win10'},
    #                    'system_info': {'manufacturer': 'Dell', 'model': 'XPS'},
    #                    'hardware_info': {'memory': {'total_gb': 16}, 'processor': {'name': 'i7'}}}
    #     }
    #     # Assuming a hypothetical prepare_table_data method
    #     # table_data = app.prepare_table_data(assets)
    #     # self.assertEqual(len(table_data), 1)
    #     # self.assertEqual(table_data[0]['Computer Name'], "Asset1")
    #     pass

    def test_placeholder_for_render_asset_details(self):
        # This test serves as a placeholder acknowledging the decision.
        self.assertTrue(True, "Skipping direct test of render_asset_details data prep due to Streamlit coupling. Focus is on _run_nmap_scan.")


if __name__ == '__main__':
    # This is to allow running tests directly
    # However, typically you'd run with `python -m unittest discover tests`
    unittest.main()
