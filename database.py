import sqlite3
from log_parser import parse_file


# ============================================================
# DATABASE CREATION
# ============================================================

def create_database():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            path TEXT,
            status INTEGER,
            latency INTEGER,
            ip TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("Database created successfully!")


# ============================================================
# INSERT LOG
# ============================================================

def insert_log(record):

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO logs (
            method,
            path,
            status,
            latency,
            ip
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        record.method,
        record.path,
        record.status,
        record.latency,
        record.ip
    ))

    connection.commit()
    connection.close()


# ============================================================
# CLEAR OLD LOGS
# ============================================================

def clear_logs():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("DELETE FROM logs")

    connection.commit()
    connection.close()

    print("Old logs cleared!")


# ============================================================
# VIEW LOGS
# ============================================================

def view_logs():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM logs")

    logs = cursor.fetchall()

    print("\nStored Logs:")

    for log in logs:
        print(log)

    connection.close()


# ============================================================
# TOTAL REQUESTS
# ============================================================

def get_total_requests():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM logs
    """)

    total = cursor.fetchone()[0]

    connection.close()

    return total


# ============================================================
# ERROR COUNT
# ============================================================

def get_error_count():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM logs
        WHERE status >= 400
    """)

    errors = cursor.fetchone()[0]

    connection.close()

    return errors


# ============================================================
# AVERAGE LATENCY
# ============================================================

def get_average_latency():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT AVG(latency)
        FROM logs
    """)

    average = cursor.fetchone()[0]

    connection.close()

    return average if average is not None else 0


# ============================================================
# TOP IP ADDRESSES
# ============================================================

def get_top_ips():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ip,
            COUNT(*) AS request_count
        FROM logs
        GROUP BY ip
        ORDER BY request_count DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


# ============================================================
# MOST REQUESTED ENDPOINTS
# ============================================================

def get_top_endpoints():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            path,
            COUNT(*) AS request_count
        FROM logs
        GROUP BY path
        ORDER BY request_count DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


# ============================================================
# FAILED LOGIN ATTEMPTS
# ============================================================

def get_failed_logins():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ip,
            COUNT(*) AS failed_logins
        FROM logs
        WHERE path = '/login'
        AND status = 401
        GROUP BY ip
        ORDER BY failed_logins DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


# ============================================================
# BRUTE-FORCE DETECTION
# ============================================================

def get_brute_force_ips():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ip,
            COUNT(*) AS failed_logins
        FROM logs
        WHERE path = '/login'
        AND status = 401
        GROUP BY ip
        HAVING COUNT(*) >= 5
        ORDER BY failed_logins DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


# ============================================================
# SECURITY RISK SCORE
#
# PARAMETERS:
#
# 1. Failed login attempts >= 5  → +50
# 2. Total requests > 10         → +20
# 3. Error rate >= 50%           → +30
#
# Maximum score = 100
# ============================================================

def get_risk_scores():

    connection = sqlite3.connect("log_analyzer.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ip,

            COUNT(*) AS total_requests,

            SUM(
                CASE
                    WHEN path = '/login'
                    AND status = 401
                    THEN 1
                    ELSE 0
                END
            ) AS failed_logins,

            SUM(
                CASE
                    WHEN status >= 400
                    THEN 1
                    ELSE 0
                END
            ) AS errors

        FROM logs

        GROUP BY ip
    """)

    rows = cursor.fetchall()

    connection.close()

    results = []

    for ip, total_requests, failed_logins, errors in rows:

        # Start with zero risk
        score = 0

        # ----------------------------------------------------
        # PARAMETER 1
        # Brute-force / Failed Login Risk
        # ----------------------------------------------------

        if failed_logins >= 5:
            score += 50

        # ----------------------------------------------------
        # PARAMETER 2
        # High Request Volume Risk
        # ----------------------------------------------------

        if total_requests > 10:
            score += 20

        # ----------------------------------------------------
        # PARAMETER 3
        # High Error Rate Risk
        # ----------------------------------------------------

        error_rate = (
            errors / total_requests
            if total_requests > 0
            else 0
        )

        if error_rate >= 0.50:
            score += 30

        # ----------------------------------------------------
        # Maximum Risk Score
        # ----------------------------------------------------

        if score > 100:
            score = 100

        results.append(
            (ip, score)
        )

    # Highest risk first
    results.sort(
        key=lambda item: item[1],
        reverse=True
    )

    return results


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print("========================================")
    print("       LOG ANALYZER DATABASE")
    print("========================================")

    # --------------------------------------------------------
    # Create database
    # --------------------------------------------------------

    create_database()

    # --------------------------------------------------------
    # Clear old logs
    # --------------------------------------------------------

    clear_logs()

    # --------------------------------------------------------
    # Parse access.log
    # --------------------------------------------------------

    records = parse_file("access.log")

    print(
        f"\nParsed {len(records)} log records."
    )

    # --------------------------------------------------------
    # Insert parsed logs
    # --------------------------------------------------------

    for record in records:
        insert_log(record)

    print("Logs inserted successfully!")

    # ========================================================
    # GENERAL STATISTICS
    # ========================================================

    print("\n========================================")
    print("GENERAL STATISTICS")
    print("========================================")

    total = get_total_requests()

    print(
        "Total Requests:",
        total
    )

    errors = get_error_count()

    print(
        "Errors:",
        errors
    )

    average_latency = get_average_latency()

    print(
        "Average Latency:",
        round(
            average_latency,
            2
        ),
        "ms"
    )

    # Error rate
    error_rate = (
        (errors / total) * 100
        if total > 0
        else 0
    )

    print(
        "Error Rate:",
        round(
            error_rate,
            2
        ),
        "%"
    )

    # ========================================================
    # TOP IP ADDRESSES
    # ========================================================

    print("\n========================================")
    print("TOP IP ADDRESSES")
    print("========================================")

    top_ips = get_top_ips()

    for ip, count in top_ips:

        print(
            f"{ip}: {count} requests"
        )

    # ========================================================
    # MOST REQUESTED ENDPOINTS
    # ========================================================

    print("\n========================================")
    print("MOST REQUESTED ENDPOINTS")
    print("========================================")

    top_endpoints = get_top_endpoints()

    for path, count in top_endpoints:

        print(
            f"{path}: {count} requests"
        )

    # ========================================================
    # FAILED LOGIN ATTEMPTS
    # ========================================================

    print("\n========================================")
    print("FAILED LOGIN ATTEMPTS")
    print("========================================")

    failed_logins = get_failed_logins()

    if failed_logins:

        for ip, count in failed_logins:

            print(
                f"{ip}: "
                f"{count} failed login attempts"
            )

    else:

        print(
            "No failed login attempts detected."
        )

    # ========================================================
    # BRUTE-FORCE DETECTION
    # ========================================================

    print("\n========================================")
    print("BRUTE-FORCE DETECTION")
    print("========================================")

    brute_force = get_brute_force_ips()

    if brute_force:

        for ip, count in brute_force:

            print(
                f"WARNING: {ip} has "
                f"{count} failed login attempts"
            )

    else:

        print(
            "No possible brute-force attacks detected."
        )

    # ========================================================
    # SECURITY RISK SCORES
    # ========================================================

    print("\n========================================")
    print("SECURITY RISK SCORES")
    print("========================================")

    risk_scores = get_risk_scores()

    for ip, score in risk_scores:

        if score >= 50:

            risk = "HIGH"

        elif score >= 20:

            risk = "MEDIUM"

        else:

            risk = "LOW"

        print(
            f"{ip}: "
            f"Score={score}, "
            f"Risk={risk}"
        )

    # ========================================================
    # RISK PARAMETERS
    # ========================================================

    print("\n========================================")
    print("RISK PARAMETERS")
    print("========================================")

    print(
        "1. Failed logins >= 5  → +50 points"
    )

    print(
        "2. Requests > 10       → +20 points"
    )

    print(
        "3. Error rate >= 50%   → +30 points"
    )

    print(
        "Maximum Risk Score     → 100"
    )

    print("\n========================================")
    print("DATABASE ANALYSIS COMPLETE")
    print("========================================")