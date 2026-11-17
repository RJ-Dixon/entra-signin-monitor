import unittest
from unittest.mock import patch, Mock
from graph_client import fetch_signin_pages


class TestGraphClient(unittest.TestCase):

    def test_pagination(self):
        page1 = {
            "value": [
                {"id": "signin-1"},
                {"id": "signin-2"}
            ],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc"
        }

        page2 = {
            "value": [
                {"id": "signin-3"}
            ]
        }

        response1 = Mock()
        response1.status_code = 200
        response1.json.return_value = page1

        response2 = Mock()
        response2.status_code = 200
        response2.json.return_value = page2

        with patch("graph_client.requests.get") as mock_get:
            mock_get.side_effect = [response1, response2]

            result = fetch_signin_pages(
                token="dummy-token",
                params={"$top": 100}
            )

            self.assertEqual(
                result,
                [
                    {"id": "signin-1"},
                    {"id": "signin-2"},
                    {"id": "signin-3"}
                ]
            )

            self.assertEqual(mock_get.call_count, 2)


if __name__ == "__main__":
    unittest.main()