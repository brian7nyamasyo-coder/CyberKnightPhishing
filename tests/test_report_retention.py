
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reports.report_generator import (
    cleanup_old_reports,
    generate_report
)


class TestReportRetention(unittest.TestCase):

    def test_keeps_only_ten_newest_txt_reports(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            for number in range(15):

                report = reports_dir / (
                    f"cyberknight_report_{number}.txt"
                )

                report.write_text(
                    f"Sample report {number}",
                    encoding="utf-8"
                )

                report.touch()

                import os
                os.utime(report, (number + 1000, number + 1000))

            cleanup_old_reports(reports_dir)

            remaining_reports = list(
                reports_dir.glob("cyberknight_report_*.txt")
            )

            self.assertEqual(len(remaining_reports), 10)

    def test_does_not_delete_reports_below_limit(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            reports_dir = Path(temp_dir)

            for number in range(5):
                report = reports_dir / (
                    f"cyberknight_report_{number}.txt"
                )

                report.write_text("Sample report")

            cleanup_old_reports(reports_dir)

            remaining_reports = list(
                reports_dir.glob("cyberknight_report_*.txt")
            )

            self.assertEqual(len(remaining_reports), 5)

    def test_txt_report_contains_application_metadata(self):

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
                "reports.report_generator.REPORTS_DIR",
                reports_dir
            ):

                report_path = generate_report(
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
                    "Version: 1.0.0",
                    report_content
                )

                self.assertIn(
                    "Overall risk: LOW",
                    report_content
                )

    def test_txt_report_contains_security_notice(self):

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
                "reports.report_generator.REPORTS_DIR",
                reports_dir
            ):

                report_path = generate_report(
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
                    "The risk score is not a probability of phishing.",
                    report_content
                )


if __name__ == "__main__":
    unittest.main()
