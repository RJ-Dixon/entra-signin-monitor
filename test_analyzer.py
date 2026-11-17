import unittest
from analyzer import find_suspicious_ips, count_failed_signins, validate_signins, detect_rapid_failures

class TestAnalyzer(unittest.TestCase):

    def test_suspicious_ip_threshold(self):
        failed_signins = {
            "192.0.2.10": 5,
            "198.51.100.20": 2,
            "203.0.113.30": 3
        }
        threshold = 3
        expected = {
            "192.0.2.10": 5,
            "203.0.113.30": 3
        }

        result = find_suspicious_ips(failed_signins, threshold)

        self.assertEqual(result, expected)

    def test_no_suspicious_ips(self):
        failed_signins = {
            "192.0.2.10": 2,
            "198.51.100.20": 1
        }
        threshold = 3
        expected = {}

        result = find_suspicious_ips(failed_signins, threshold)

        self.assertEqual(result, expected)

    def test_empty_failed_signins(self):
        expected = {}

        result = find_suspicious_ips({}, 2)

        self.assertEqual(result, expected)

    def test_malformed_signin_records(self):
        signins = [
            {"ipAddress": "192.0.2.10", "status": {"errorCode": 50126}, "createdDateTime": "2021-06-17T13:02:21Z"},
            {"ipAddress": "198.51.100.20", "status": {"errorCode": 0}, "createdDateTime": "2021-06-17T13:02:21Z"},
            {"ipAddress": "203.0.113.5", "status": None},
            {"ipAddress": "", "status": {"errorCode": 50126}}
        ]
        expected_failed_signins = {"192.0.2.10": 1}
        expected_rejected_records = [
            {"ipAddress": "203.0.113.5", "status": None},
            {"ipAddress": "", "status": {"errorCode": 50126}}
        ]

        valid_records, rejected_records = validate_signins(signins)

        failed_signins = count_failed_signins(valid_records)

        self.assertEqual(failed_signins, expected_failed_signins)
        self.assertEqual(rejected_records, expected_rejected_records)

    def test_rapid_failure_detection(self):
        signins = [
            {
                "ipAddress": "192.0.2.10",
                "status": {"errorCode": 50126},
                "createdDateTime": "2026-11-08T10:00:00Z"
            },
            {
                "ipAddress": "192.0.2.10",
                "status": {"errorCode": 50126},
                "createdDateTime": "2026-11-08T10:02:00Z"
            },
            {
                "ipAddress": "192.0.2.10",
                "status": {"errorCode": 50126},
                "createdDateTime": "2026-11-08T10:04:00Z"
            },
            {
                "ipAddress": "198.51.100.20",
                "status": {"errorCode": 50126},
                "createdDateTime": "2026-11-08T10:01:00Z"
            }
        ]

        expected_suspicious_ips = {"192.0.2.10": 3}

        suspicious_ips = detect_rapid_failures(signins, threshold=2, window_minutes=5)

        self.assertEqual(suspicious_ips, expected_suspicious_ips)

if __name__ == "__main__":
    unittest.main()