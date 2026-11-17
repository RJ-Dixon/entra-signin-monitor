import requests
from auth import get_access_token
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse


def fetch_signin_pages(token, params):
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"

    headers = {
        "Authorization": f"Bearer {token}"
    }

    all_signins = []
    next_url = url

    while next_url:
        validate_graph_url(next_url)

        response = requests.get(
            url=next_url,
            headers=headers,
            params=params,
            timeout=30,
            allow_redirects=False

        )

        response.raise_for_status()

        if 300 <= response.status_code < 400:
            raise ValueError("Unexpected Microsoft Graph redirect")

        records = response.json()

        all_signins.extend(records["value"])

        next_url = records.get("@odata.nextLink")

        params = None

    return all_signins

def get_signins():
    token = get_access_token()

    t1 = datetime.now(timezone.utc)
    td = timedelta(hours=24)
    t2 = t1 - td
    timestamp = t2.isoformat().replace("+00:00", "Z")

    params = {
        "$top": 100,
        "$filter": f"createdDateTime ge {timestamp}"
    }

    return fetch_signin_pages(token, params)

def validate_graph_url(url):
    parsed = urlparse(url)

    if parsed.scheme != 'https' or parsed.hostname != 'graph.microsoft.com':
        raise ValueError(f"Untrusted Microsoft Graph URL: {url}")

if __name__ == "__main__":
    signins = get_signins()
    print(len(signins))