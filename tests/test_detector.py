
import unittest

from core.detector import calculate_overall_risk


class TestOverallDetector(unittest.TestCase):

    def test_low_risk(self):
        sender = {"risk": "LOW", "indicators": []}
        url = {"score": 0, "indicators": []}
        content = {"score": 0, "indicators": []}
        headers = {"score": 0, "indicators": []}
        brand = {"score": 0, "indicators": []}

        result = calculate_overall_risk(
            sender, url, content, headers, brand
        )

        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_medium_risk(self):
        sender = {"risk": "MEDIUM", "indicators": []}
        url = {"score": 10, "indicators": []}
        content = {"score": 4, "indicators": []}
        headers = {"score": 0, "indicators": []}
        brand = {"score": 0, "indicators": []}

        result = calculate_overall_risk(
            sender, url, content, headers, brand
        )

        self.assertEqual(result["risk"], "MEDIUM")
        self.assertEqual(result["score"], 30)

    def test_high_risk(self):
        sender = {"risk": "HIGH", "indicators": []}
        url = {"score": 20, "indicators": []}
        content = {"score": 10, "indicators": []}
        headers = {"score": 10, "indicators": []}
        brand = {"score": 5, "indicators": []}

        result = calculate_overall_risk(
            sender, url, content, headers, brand
        )

        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["score"], 100)

    def test_brand_detection_contributes_to_score(self):
        sender = {"risk": "LOW", "indicators": []}
        url = {"score": 0, "indicators": []}
        content = {"score": 0, "indicators": []}
        headers = {"score": 0, "indicators": []}
        brand = {
            "score": 4,
            "indicators": [
                "Brand name 'safaricom' appears outside its reference domains"
            ]
        }

        result = calculate_overall_risk(
            sender, url, content, headers, brand
        )

        self.assertEqual(result["score"], 12)
        self.assertEqual(
            result["component_scores"]["brand"], 12
        )
        self.assertEqual(result["risk"], "LOW")
        self.assertTrue(
            any(
                indicator.startswith("Brand:")
                for indicator in result["indicators"]
            )
        )


if __name__ == "__main__":
    unittest.main()
