
import unittest

from analyzers.sender_analyzer import analyze_sender
from analyzers.url_analyzer import analyze_url
from analyzers.content_analyzer import analyze_content
from analyzers.header_analyzer import analyze_headers
from analyzers.brand_analyzer import analyze_brand


class TestSenderAnalyzer(unittest.TestCase):

    def test_valid_email(self):
        result = analyze_sender("john@example.com")
        self.assertTrue(result["valid"])

    def test_invalid_email(self):
        result = analyze_sender("invalid-email")
        self.assertFalse(result["valid"])

    def test_normal_security_sender(self):
        result = analyze_sender("security@example.com")
        self.assertEqual(result["risk"], "LOW")

    def test_suspicious_sender(self):
        result = analyze_sender("user123456@example.com")
        self.assertEqual(result["risk"], "LOW")
        self.assertTrue(
            any(
                "long number sequence" in item
                for item in result["indicators"]
            )
        )


class TestURLAnalyzer(unittest.TestCase):

    def test_valid_https_url(self):
        result = analyze_url("https://example.com")
        self.assertTrue(result["valid"])

    def test_invalid_url(self):
        result = analyze_url("not a valid url")
        self.assertFalse(result["valid"])

    def test_http_warning(self):
        result = analyze_url("http://example.com")
        self.assertIn(
            "URL does not use HTTPS",
            result["indicators"]
        )

    def test_ip_address_url(self):
        result = analyze_url("http://192.0.2.1/login")
        self.assertIn(
            "URL uses an IP address instead of a domain",
            result["indicators"]
        )

    def test_embedded_user_information(self):
        result = analyze_url(
            "https://user:password@example.com"
        )
        self.assertIn(
            "URL contains embedded user information",
            result["indicators"]
        )

    def test_punycode_domain(self):
        result = analyze_url("https://xn--example-ova.com")
        self.assertIn(
            "Domain contains internationalized encoding (punycode)",
            result["indicators"]
        )

    def test_normal_subdomain(self):
        result = analyze_url("https://login.example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["risk"], "LOW")

    def test_hostname_with_underscore(self):
        result = analyze_url("https://bad_name.com")
        self.assertFalse(result["valid"])

    def test_hostname_with_empty_label(self):
        result = analyze_url("https://example..com")
        self.assertFalse(result["valid"])

    def test_url_without_scheme(self):
        result = analyze_url("example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["risk"], "LOW")


class TestContentAnalyzer(unittest.TestCase):

    def test_normal_content(self):
        result = analyze_content(
            "Hello, I hope you are doing well."
        )
        self.assertEqual(result["risk"], "LOW")

    def test_suspicious_content(self):
        result = analyze_content(
            "URGENT! Verify your account immediately. "
            "Enter your password and OTP."
        )
        self.assertEqual(result["risk"], "HIGH")


class TestHeaderAnalyzer(unittest.TestCase):

    def test_missing_headers(self):
        result = analyze_headers("")
        self.assertTrue(result["valid"])
        self.assertIn(
            "Missing From header",
            result["indicators"]
        )

    def test_reply_to_mismatch(self):
        headers = (
            "From: Security Team <security@example.com>\n"
            "Reply-To: help@different-example.com\n"
            "Return-Path: bounce@example.com\n"
            "Authentication-Results: mail.example.com; "
            "spf=pass; dkim=pass; dmarc=pass\n"
        )

        result = analyze_headers(headers)

        self.assertIn(
            "Reply-To domain differs from sender domain",
            result["indicators"]
        )


class TestBrandAnalyzer(unittest.TestCase):

    def test_legitimate_brand_domain(self):
        result = analyze_brand("https://safaricom.co.ke")
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_legitimate_brand_subdomain(self):
        result = analyze_brand("https://help.google.com")
        self.assertEqual(result["risk"], "LOW")

    def test_suspicious_brand_domain(self):
        result = analyze_brand(
            "https://safaricom-security.example.com"
        )
        self.assertEqual(result["risk"], "HIGH")
        self.assertGreater(result["score"], 0)

    def test_unrelated_domain(self):
        result = analyze_brand("https://example.org")
        self.assertEqual(result["risk"], "LOW")

    # Regression tests: domains without URL schemes

    def test_suspicious_brand_domain_without_scheme(self):
        result = analyze_brand(
            "safaricom-security.example.com"
        )
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["score"], 4)
        self.assertTrue(result["indicators"])

    def test_legitimate_brand_domain_without_scheme(self):
        result = analyze_brand("safaricom.co.ke")
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
