
import unittest

from core.url_scanner import scan_url


class TestURLScanner(unittest.TestCase):

    def test_normal_https_url(self):
        result = scan_url("https://example.com")
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["hostname"], "example.com")

    def test_brand_lookalike(self):
        result = scan_url("https://g00gle.com")
        self.assertGreaterEqual(result["score"], 30)
        self.assertTrue(
            any("resembles 'google'" in item for item in result["findings"])
        )

    def test_misleading_at_symbol(self):
        result = scan_url("https://paypal.com@evil.example")
        self.assertEqual(result["hostname"], "evil.example")
        self.assertTrue(
            any("actual hostname" in item for item in result["findings"])
        )

    def test_hostname_with_spaces(self):
        result = scan_url("https://exam ple.com")
        self.assertEqual(result["level"], "INVALID INPUT")

    def test_empty_url(self):
        result = scan_url("")
        self.assertEqual(result["level"], "INVALID INPUT")

    def test_unsupported_scheme(self):
        result = scan_url("ftp://example.com")
        self.assertEqual(result["level"], "INVALID INPUT")

    def test_encoded_control_character(self):
        result = scan_url("https://example.com/%0aheader")
        self.assertGreater(result["score"], 0)
        self.assertTrue(
            any("control characters" in item for item in result["findings"])
        )

    def test_ordinary_percent_encoding(self):
        result = scan_url("https://example.com/search?q=hello%20world")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW")


if __name__ == "__main__":
    unittest.main()
