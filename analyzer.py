from datetime import datetime, timedelta

def count_failed_signins(signins):
    failed_signins = {}

    for signin in signins:
        status = signin['status']
        error_code = status['errorCode']
        ip = signin['ipAddress']

        if error_code != 0:
            failed_signins[ip] = failed_signins.get(ip, 0) + 1

    return failed_signins

def find_suspicious_ips(failed_signins, threshold):
    reached_threshold = {}

    for ip in failed_signins:
        if failed_signins[ip] >= threshold:
            reached_threshold[ip] = failed_signins[ip]

    return reached_threshold

def group_failed_signins_by_ip(signins):
    failed_signins = {}

    for signin in signins:
        status = signin["status"]["errorCode"]
        if status != 0:
            ip = signin["ipAddress"]
            timestamp = signin["createdDateTime"]
            if ip not in failed_signins:
                failed_signins[ip] = [timestamp]
            else:
                failed_signins[ip].append(timestamp)

    return failed_signins

def prepare_timestamps(grouped_signins):
    signins = {}

    for ip, timestamps in grouped_signins.items():
        stamp_list = []

        for timestamp in timestamps:
            stamp_list.append(datetime.fromisoformat(timestamp))

        stamp_list.sort()
        signins[ip] = stamp_list

    return signins

def count_max_failures_in_window(timestamps, window_minutes):
    window = timedelta(minutes=window_minutes)
    left = 0
    max_count = 0

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        count = right - left + 1
        if count > max_count:
            max_count = count

    return max_count

def detect_rapid_failures(signins, threshold, window_minutes):
    grouped_signins = group_failed_signins_by_ip(signins)

    prepared_timestamps = prepare_timestamps(grouped_signins)
    suspicious_ips = {}
    for ip, timestamps in prepared_timestamps.items():
        max_count = count_max_failures_in_window(timestamps, window_minutes)
        if max_count >= threshold:
            suspicious_ips[ip] = max_count

    return suspicious_ips

def validate_signins(signins):
    valid_records = []
    rejected_records = []

    for signin in signins:
        if not isinstance(signin, dict):
            rejected_records.append(signin)
            continue

        status = signin.get('status')

        if not isinstance(status, dict):
            rejected_records.append(signin)
            continue

        error_code = status.get('errorCode')

        if type(error_code) is not int:
            rejected_records.append(signin)
            continue

        ip = signin.get('ipAddress')

        if not isinstance(ip, str) or not ip:
            rejected_records.append(signin)
            continue

        timestamp = signin.get('createdDateTime')

        if not isinstance(timestamp, str):
            rejected_records.append(signin)
            continue

        try:
            datetime.fromisoformat(timestamp)
        except ValueError:
            rejected_records.append(signin)
            continue

        valid_records.append(signin)

    return valid_records, rejected_records