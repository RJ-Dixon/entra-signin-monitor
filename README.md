# Microsoft Entra Sign-In Monitor

A Python-based security monitoring project that retrieves and analyzes Microsoft Entra ID authentication logs through Microsoft Graph.

The project explores authentication monitoring, suspicious sign-in detection, API integration, and security engineering practices.

**Status:** Active development — not intended for production deployment.

## Features

- Authenticate to Microsoft Graph using application credentials.
- Retrieve Microsoft Entra ID sign-in events.
- Filter events using UTC timestamps.
- Retrieve paginated API results.
- Validate incoming sign-in records.
- Count failed authentication attempts by IP address.
- Detect repeated failures within configurable time windows.
- Generate structured JSON reports.
- Analyze suspicious authentication activity using threshold-based detection.

## Technology Stack

- Python
- Microsoft Graph API
- Microsoft Entra ID
- MSAL (Microsoft Authentication Library)
- Requests
- Pytest
- Hypothesis

## How It Works

1. The application authenticates to Microsoft Graph.
2. It requests sign-in events from a specified time window.
3. Incoming records are validated.
4. Detection functions identify repeated authentication failures.
5. The application generates a JSON report containing the analysis results.

## Setup

### Requirements

- Python
- A Microsoft Entra tenant with access to sign-in logs
- An application registration with the appropriate Microsoft Graph permissions
- Microsoft Entra licensing that supports sign-in log retrieval

### Installation

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/YOUR_USERNAME/entra-signin-monitor.git
cd entra-signin-monitor
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy the example environment configuration:

```bash
cp .env.example .env
```

Update `.env` with your Microsoft Entra application credentials.

**Never commit your `.env` file or application secrets to source control.**

### Run

```bash
python main.py
```

Reports are written to the local `reports/` directory. Create this directory before running the application if it does not already exist.

## Testing

Run the automated tests using:

```bash
python -m pytest -v
```

The project includes unit tests for detection logic and uses simulated data to test application behavior.

## Current Limitations

- Persistent event tracking is not yet complete.
- API throttling and retry handling need improvement.
- Detection rules are basic and may generate false positives.
- Automated scheduling and alert delivery are not implemented.
- Additional integration and security testing is needed.

## Planned Improvements

- Persistent deduplication of sign-in events.
- Reliable processing across overlapping monitoring windows.
- Improved Microsoft Graph error handling.
- Expanded automated tests.
- Configurable detection thresholds and reporting.
- Additional security detection capabilities.

## Security

This project is intended for educational and portfolio purposes. It should not be considered a production-ready security monitoring system.

Authentication credentials are stored in environment variables, and real sign-in logs should not be committed to the repository.

## Development

This is an ongoing security engineering project focused on building practical experience with Microsoft identity security, API integration, detection logic, and Python application development.