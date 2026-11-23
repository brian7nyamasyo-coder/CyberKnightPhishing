
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reports.html_report_generator import (
    cleanup_old_reports,
    generate_html_report
)


class TestHTMLReportRetention(unittest.TestCase):

    def test_keeps_only_ten_newest_html_reports(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            for number in range(15):

                report = reports_dir / (
                    f"cyberknight_html_report_{number}.html"
                )

                report.write_text(
                    f"<html>Sample report {number}</html>",
                    encoding="utf-8"
                )

                os.utime(
                    report,
                    (number + 1000, number + 1000)
                )

            cleanup_old_reports(reports_dir)

            remaining_reports = list(
                reports_dir.glob("cyberknight_html_report_*.html")
            )

            self.assertEqual(len(remaining_reports), 10)

    def test_does_not_delete_html_reports_below_limit(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            for number in range(5):

                report = reports_dir / (
                    f"cyberknight_html_report_{number}.html"
                )

                report.write_text("<html>Sample report</html>")

            cleanup_old_reports(reports_dir)

            remaining_reports = list(
                reports_dir.glob("cyberknight_html_report_*.html")
            )

            self.assertEqual(len(remaining_reports), 5)

    def test_html_report_contains_application_metadata(self):

        sample_result = {
            "risk": "LOW",
            "score": 5,
            "valid": True,
            "indicators": [],
            "component_scores": {
                "sender": 0,
                "url": 0,
                "content": 0,
                "headers": 0,
                "brand": 0
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            with patch(
                "reports.html_report_generator.REPORTS_DIR",
                reports_dir
            ):

                report_path = generate_html_report(
                    "user@example.com",
                    "https://example.com",
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result
                )

                report_content = report_path.read_text(
                    encoding="utf-8"
                )

                self.assertIn(
                    "CYBERKNIGHT PHISHING DETECTOR",
                    report_content
                )

                self.assertIn(
                    "Version 1.0.0",
                    report_content
                )

                self.assertIn(
                    "LOW RISK",
                    report_content
                )

    def test_html_report_contains_security_notice(self):

        sample_result = {
            "risk": "LOW",
            "score": 5,
            "valid": True,
            "indicators": [],
            "component_scores": {
                "sender": 0,
                "url": 0,
                "content": 0,
                "headers": 0,
                "brand": 0
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            with patch(
                "reports.html_report_generator.REPORTS_DIR",
                reports_dir
            ):

                report_path = generate_html_report(
                    "user@example.com",
                    "https://example.com",
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result,
                    sample_result
                )

                report_content = report_path.read_text(
                    encoding="utf-8"
                )

                self.assertIn(
                    "This report uses heuristic analysis.",
                    report_content
                )

                self.assertIn(
                    "cannot guarantee that a message",
                    report_content
                )


if __name__ == "__main__":
    unittest.main()
