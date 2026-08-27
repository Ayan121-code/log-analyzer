from log_parser import parse_file
from collections import Counter


# ============================================================
# 1. FAILED LOGIN DETECTION
# ============================================================

def detect_failed_logins(records):
    """Find failed login requests."""

    return [
        record
        for record in records
        if record.status >= 400 and record.path == "/login"
    ]


# ============================================================
# 2. BRUTE-FORCE DETECTION
# ============================================================

def detect_bruteforce(failed_logins, threshold=5):
    """Detect IP addresses with repeated failed login attempts."""

    failed_by_ip = Counter(
        record.ip for record in failed_logins
    )

    alerts = []

    for ip, count in failed_by_ip.items():

        if count >= threshold:
            alerts.append((ip, count))

    return failed_by_ip, alerts


# ============================================================
# 3. HIGH REQUEST VOLUME DETECTION
# ============================================================

def detect_high_volume(records, threshold=10):
    """Detect IP addresses making many requests."""

    request_counts = Counter(
        record.ip for record in records
    )

    alerts = []

    for ip, count in request_counts.items():

        if count > threshold:
            alerts.append((ip, count))

    return request_counts, alerts


# ============================================================
# 4. SQL INJECTION DETECTION
# ============================================================

def detect_sql_injection(records):
    """
    Detect common SQL injection patterns
    in requested paths.
    """

    sql_patterns = [
        "union select",
        "union+select",
        "' or '1'='1",
        "' or 1=1",
        "or 1=1",
        "or+1=1",
        "'--",
        "--",
        "drop table",
        "drop+table",
        "insert into",
        "insert+into",
        "delete from",
        "delete+from",
        "select * from",
        "select+*+from",
        "information_schema",
        "sleep(",
        "benchmark("
    ]

    alerts = []

    for record in records:

        path_lower = record.path.lower()

        for pattern in sql_patterns:

            if pattern in path_lower:

                alerts.append({
                    "ip": record.ip,
                    "path": record.path,
                    "type": "SQL Injection",
                    "pattern": pattern
                })

                break

    return alerts


# ============================================================
# 5. XSS DETECTION
# ============================================================

def detect_xss(records):
    """
    Detect common Cross-Site Scripting (XSS)
    patterns in requested paths.
    """

    xss_patterns = [
        "<script",
        "%3cscript",
        "javascript:",
        "javascript%3a",
        "onerror=",
        "onload=",
        "onclick=",
        "<iframe",
        "%3ciframe",
        "alert(",
        "prompt(",
        "confirm("
    ]

    alerts = []

    for record in records:

        path_lower = record.path.lower()

        for pattern in xss_patterns:

            if pattern in path_lower:

                alerts.append({
                    "ip": record.ip,
                    "path": record.path,
                    "type": "XSS",
                    "pattern": pattern
                })

                break

    return alerts


# ============================================================
# 6. SUSPICIOUS REQUEST DETECTION
# ============================================================

def detect_suspicious_requests(records):
    """
    Combine different application-level attack detections.
    """

    sql_alerts = detect_sql_injection(records)
    xss_alerts = detect_xss(records)

    return sql_alerts + xss_alerts


# ============================================================
# 7. RISK SCORE
# ============================================================

def calculate_risk_score(
    failed_logins,
    total_requests,
    sql_injections=0,
    xss_attempts=0
):
    """
    Calculate a security risk score.

    Risk points:

    5+ failed logins       = +50
    More than 10 requests  = +20
    SQL injection attempt  = +30 each
    XSS attempt            = +20 each
    """

    score = 0

    # Brute-force risk
    if failed_logins >= 5:
        score += 50

    # High request volume risk
    if total_requests > 10:
        score += 20

    # SQL injection risk
    if sql_injections > 0:
        score += 30 * sql_injections

    # XSS risk
    if xss_attempts > 0:
        score += 20 * xss_attempts

    # Risk level
    if score >= 50:
        risk_level = "HIGH"

    elif score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return score, risk_level


# ============================================================
# 8. ERROR-HEAVY IP DETECTION
# ============================================================

def detect_error_heavy_ips(records, threshold=3):
    """Find IP addresses generating many errors."""

    error_counts = Counter(
        record.ip
        for record in records
        if record.status >= 400
    )

    return [
        (ip, count)
        for ip, count in error_counts.items()
        if count >= threshold
    ]


# ============================================================
# MAIN
# ============================================================

def main():

    records = parse_file("access.log")

    # --------------------------------------------------------
    # Failed Login Detection
    # --------------------------------------------------------

    failed_logins = detect_failed_logins(records)

    print("Failed login requests:", len(failed_logins))

    print("\nFailed login requests by IP:")

    for record in failed_logins:

        print(
            f"{record.ip} -> "
            f"{record.status} "
            f"{record.path}"
        )


    # --------------------------------------------------------
    # Brute-Force Detection
    # --------------------------------------------------------

    failed_by_ip, brute_force_alerts = detect_bruteforce(
        failed_logins
    )

    print("\nFailed login attempts by IP:")

    for ip, count in failed_by_ip.most_common():

        print(
            f"{ip}: "
            f"{count} failed login attempts"
        )


    print("\nPossible Brute-Force Attacks:")

    if not brute_force_alerts:

        print("No brute-force attacks detected.")

    else:

        for ip, count in brute_force_alerts:

            print(
                f"WARNING: "
                f"{ip} has "
                f"{count} failed login attempts"
            )


    # --------------------------------------------------------
    # High Request Volume
    # --------------------------------------------------------

    request_counts, volume_alerts = detect_high_volume(
        records
    )

    print("\nHigh Request Volume:")

    if not volume_alerts:

        print("No high request volume detected.")

    else:

        for ip, count in volume_alerts:

            print(
                f"WARNING: "
                f"{ip} made "
                f"{count} requests"
            )


    # --------------------------------------------------------
    # SQL Injection Detection
    # --------------------------------------------------------

    sql_alerts = detect_sql_injection(records)

    print("\nSQL Injection Detection:")

    if not sql_alerts:

        print("No SQL injection attempts detected.")

    else:

        for alert in sql_alerts:

            print(
                f"WARNING: SQL INJECTION | "
                f"IP: {alert['ip']} | "
                f"Path: {alert['path']} | "
                f"Pattern: {alert['pattern']}"
            )


    # --------------------------------------------------------
    # XSS Detection
    # --------------------------------------------------------

    xss_alerts = detect_xss(records)

    print("\nXSS Detection:")

    if not xss_alerts:

        print("No XSS attempts detected.")

    else:

        for alert in xss_alerts:

            print(
                f"WARNING: XSS ATTEMPT | "
                f"IP: {alert['ip']} | "
                f"Path: {alert['path']} | "
                f"Pattern: {alert['pattern']}"
            )


    # --------------------------------------------------------
    # Security Summary
    # --------------------------------------------------------

    print("\nSecurity Detection Summary:")

    print(
        "Brute-force alerts:",
        len(brute_force_alerts)
    )

    print(
        "High-volume alerts:",
        len(volume_alerts)
    )

    print(
        "SQL injection alerts:",
        len(sql_alerts)
    )

    print(
        "XSS alerts:",
        len(xss_alerts)
    )


    # --------------------------------------------------------
    # Risk Scoring
    # --------------------------------------------------------

    print("\nSecurity Risk Scores:")

    # Count SQL/XSS attacks by IP
    sql_by_ip = Counter(
        alert["ip"]
        for alert in sql_alerts
    )

    xss_by_ip = Counter(
        alert["ip"]
        for alert in xss_alerts
    )

    for ip in request_counts:

        failed_logins_count = failed_by_ip.get(
            ip,
            0
        )

        total_requests = request_counts[ip]

        sql_count = sql_by_ip.get(
            ip,
            0
        )

        xss_count = xss_by_ip.get(
            ip,
            0
        )

        score, risk_level = calculate_risk_score(
            failed_logins_count,
            total_requests,
            sql_count,
            xss_count
        )

        print(
            f"{ip}: "
            f"Score={score}, "
            f"Risk={risk_level}"
        )


    # --------------------------------------------------------
    # Security Alerts
    # --------------------------------------------------------

    print("\nSecurity Alerts:")

    any_alert = False


    # Risk alerts

    for ip in request_counts:

        failed_logins_count = failed_by_ip.get(
            ip,
            0
        )

        total_requests = request_counts[ip]

        sql_count = sql_by_ip.get(
            ip,
            0
        )

        xss_count = xss_by_ip.get(
            ip,
            0
        )

        score, risk_level = calculate_risk_score(
            failed_logins_count,
            total_requests,
            sql_count,
            xss_count
        )

        if risk_level == "HIGH":

            print(
                f"🚨 HIGH RISK: "
                f"{ip} | "
                f"Score: {score}"
            )

            any_alert = True

        elif risk_level == "MEDIUM":

            print(
                f"⚠️ MEDIUM RISK: "
                f"{ip} | "
                f"Score: {score}"
            )

            any_alert = True


    # SQL injection alerts

    for alert in sql_alerts:

        print(
            f"🚨 SQL INJECTION: "
            f"{alert['ip']} | "
            f"{alert['path']}"
        )

        any_alert = True


    # XSS alerts

    for alert in xss_alerts:

        print(
            f"🚨 XSS ATTEMPT: "
            f"{alert['ip']} | "
            f"{alert['path']}"
        )

        any_alert = True


    if not any_alert:

        print("No major security alerts detected.")


    # --------------------------------------------------------
    # Error-Heavy IP Detection
    # --------------------------------------------------------

    print("\nError-Heavy IPs:")

    error_heavy_ips = detect_error_heavy_ips(
        records
    )

    if not error_heavy_ips:

        print("No error-heavy IPs detected.")

    else:

        for ip, count in error_heavy_ips:

            print(
                f"WARNING: "
                f"{ip} generated "
                f"{count} errors"
            )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()