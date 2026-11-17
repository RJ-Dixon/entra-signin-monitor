import json

def build_report(signins, failed_signins, suspicious_ips, threshold, rejected_records, rapid_failures, window_minutes):
    if len(signins) == 0:
        rejection_rate = 0.0
    else:
        rejection_rate = (len(rejected_records)/len(signins)) * 100

    return {
        "total_records": len(signins),
        "failed_signins": failed_signins,
        "suspicious_ips": suspicious_ips,
        "detection_threshold": threshold,
        "rejected_count": len(rejected_records),
        "rejection_rate": rejection_rate,
        "rapid_failure_ips": rapid_failures,
        "rapid_failure_window_minutes": window_minutes
    }

def save_report(report, filename):
    with open(filename, "w") as file:
        json.dump(report, file, indent=4)