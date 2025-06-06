import unittest
from pathlib import Path
import sys
import os

# Add the parent directory to the Python path to allow importing 'asset_parser'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from asset_parser import AssetParser

class TestAssetParser(unittest.TestCase):

    def setUp(self):
        self.parser = AssetParser()

    def test_extract_field_anydesk_id(self):
        content_standard = "Some text before\nAnyDesk ID: 123456789\nSome text after"
        self.assertEqual(self.parser.extract_field(content_standard, 'anydesk_id'), "123456789")

        content_alternative = "Blah blah\nAnyDesk: 987654321\nEnd"
        self.assertEqual(self.parser.extract_field(content_alternative, 'anydesk_id'), "987654321")

        content_remote_id = "Remote ID: 111222333"
        self.assertEqual(self.parser.extract_field(content_remote_id, 'anydesk_id'), "111222333")

        # Test case based on previous discussions: if "ID" is present, it should not match \d+
        # The regexes r'AnyDesk ID[:\s]+(\d+)', r'AnyDesk[:\s]+(\d+)', r'Remote ID[:\s]+(\d+)'
        # are designed to capture only digits. So, "ID" should not be extracted.
        content_literal_id = "AnyDesk ID: ID"
        self.assertIsNone(self.parser.extract_field(content_literal_id, 'anydesk_id'))

        content_no_id = "This content has no AnyDesk ID."
        self.assertIsNone(self.parser.extract_field(content_no_id, 'anydesk_id'))

        content_mixed_case = "anydesk id: 777888999"
        self.assertEqual(self.parser.extract_field(content_mixed_case, 'anydesk_id'), "777888999")

        content_with_label_only = "AnyDesk ID:"
        self.assertIsNone(self.parser.extract_field(content_with_label_only, 'anydesk_id'))

        content_numbers_elsewhere = "My ID is 123, but AnyDesk is not here."
        self.assertIsNone(self.parser.extract_field(content_numbers_elsewhere, 'anydesk_id'))

    def test_parse_memory_size(self):
        self.assertEqual(self.parser.parse_memory_size("8 GB"), 8.0)
        self.assertEqual(self.parser.parse_memory_size("16000 MB"), 16.0) # 16000/1024 roughly 15.625, rounded to 16
        self.assertEqual(self.parser.parse_memory_size("16384 MB"), 16.0)
        self.assertEqual(self.parser.parse_memory_size("8,00 GB"), 8.0) # Italian format
        self.assertEqual(self.parser.parse_memory_size("15.6 GB"), 16.0) # Test rounding
        self.assertEqual(self.parser.parse_memory_size("7.4 GB"), 7.0)   # Test rounding
        self.assertEqual(self.parser.parse_memory_size("Total Physical Memory: 32 GB"), 32.0)
        self.assertEqual(self.parser.parse_memory_size("RAM: 16GB"), 16.0)
        self.assertIsNone(self.parser.parse_memory_size("Unknown memory"))
        self.assertIsNone(self.parser.parse_memory_size(""))
        self.assertEqual(self.parser.parse_memory_size("4096 KB"), 0.0) # 4MB, rounds to 0 GB
        # Test rounding for values that would be < 1 GB after conversion
        self.assertEqual(self.parser.parse_memory_size("512 MB"), 1.0) # 0.5 GB, rounds to 1 GB
        self.assertEqual(self.parser.parse_memory_size("1023 MB"), 1.0) # almost 1GB, rounds to 1GB

if __name__ == '__main__':
    unittest.main()
