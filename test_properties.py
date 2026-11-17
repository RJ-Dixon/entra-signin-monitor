from hypothesis import given, strategies as st
from analyzer import find_suspicious_ips


@given(
    failed_signins=st.dictionaries(
        keys=st.ip_addresses().map(str),
        values=st.integers(min_value=0, max_value=100)
    ),
    threshold=st.integers(min_value=1, max_value=100)
)
def test_suspicious_ip_detection(failed_signins, threshold):
    result = find_suspicious_ips(failed_signins, threshold)

    expected = {
        ip: count
        for ip, count in failed_signins.items()
        if count >= threshold
    }

    assert result == expected