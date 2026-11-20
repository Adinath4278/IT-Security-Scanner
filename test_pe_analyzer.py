import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pe_analyzer import analyze_pe


class PeAnalyzerTests(unittest.TestCase):
    def test_pe_resource_is_closed_when_analysis_fails(self):
        section = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            get_entropy=Mock(side_effect=ValueError("malformed section"))
        )
        pe = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
            sections=[section],
            close=Mock()
        )

        with patch("pe_analyzer.pefile.PE", return_value=pe):
            result = analyze_pe("sample.exe")

        self.assertTrue(result["is_pe"])
        self.assertIn("malformed section", result["errors"][0])
        pe.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
