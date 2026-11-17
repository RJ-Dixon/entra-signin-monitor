from graph_client import get_signins
from analyzer import count_failed_signins, find_suspicious_ips, detect_rapid_failures, validate_signins
from reporting import build_report, save_report


def main():
    threshold = 2
    window_minutes = 5

    signins = get_signins()

    valid_signins, rejected_records = validate_signins(signins)

    rapid_failures = detect_rapid_failures(
        valid_signins,
        threshold,
        window_minutes
    )

    print(f"IPs triggering rapid-failure detection: {len(rapid_failures)}")

    failed_signins = count_failed_signins(valid_signins)
    suspicious_ips = find_suspicious_ips(failed_signins, threshold)

    report = build_report(
        signins,
        failed_signins,
        suspicious_ips,
        threshold,
        rejected_records,
        rapid_failures,
        window_minutes
    )

    save_report(report, "reports/signin_report.json")

    print(report)

if __name__ == "__main__":
    main()