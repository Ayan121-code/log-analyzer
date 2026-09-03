import sqlite3

from log_parser import parse_file


# ============================================================
# DATABASE FILE
# ============================================================

DATABASE_NAME = "log_analyzer.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    return sqlite3.connect(
        DATABASE_NAME
    )


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            method TEXT NOT NULL,

            path TEXT NOT NULL,

            status INTEGER NOT NULL,

            latency INTEGER NOT NULL,

            ip TEXT NOT NULL

        )
    """)

    connection.commit()

    connection.close()

    print(
        "Database created successfully!"
    )


# ============================================================
# INSERT LOG
# ============================================================

def insert_log(record):

    connection = get_connection()

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
# INSERT MULTIPLE LOGS
# ============================================================

def insert_logs(records):

    if not records:
        return

    connection = get_connection()

    cursor = connection.cursor()

    cursor.executemany("""
        INSERT INTO logs (

            method,
            path,
            status,
            latency,
            ip

        )

        VALUES (?, ?, ?, ?, ?)

    """, [

        (
            record.method,
            record.path,
            record.status,
            record.latency,
            record.ip
        )

        for record in records

    ])

    connection.commit()

    connection.close()


# ============================================================
# CLEAR OLD LOGS
# ============================================================

def clear_logs():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM logs"
    )

    connection.commit()

    connection.close()

    print(
        "Old logs cleared!"
    )


# ============================================================
# TOTAL REQUESTS
# ============================================================

def get_total_requests():

    connection = get_connection()

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

    connection = get_connection()

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

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT AVG(latency)
        FROM logs
    """)

    average = cursor.fetchone()[0]

    connection.close()

    if average is None:
        return 0

    return average


# ============================================================
# TOP IP ADDRESSES
# ============================================================

def get_top_ips():

    connection = get_connection()

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

    connection = get_connection()

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

    connection = get_connection()

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

    connection = get_connection()

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
# SECURITY RISK SCORES
# ============================================================

def get_risk_scores():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            ip,

            COUNT(*) AS total_requests,

            SUM(

                CASE

                    WHEN status = 401
                    AND path = '/login'

                    THEN 1

                    ELSE 0

                END

            ) AS failed_logins,

            SUM(

                CASE

                    WHEN status IN (403, 404)

                    THEN 1

                    ELSE 0

                END

            ) AS suspicious_responses

        FROM logs

        GROUP BY ip
    """)

    rows = cursor.fetchall()

    connection.close()

    results = []


    for (

        ip,

        total_requests,

        failed_logins,

        suspicious_responses

    ) in rows:

        failed_logins = (
            failed_logins or 0
        )

        suspicious_responses = (
            suspicious_responses or 0
        )


        score = 0


        # ----------------------------------------------------
        # BRUTE-FORCE
        # ----------------------------------------------------

        if failed_logins >= 5:

            score += 50


        # ----------------------------------------------------
        # HIGH REQUEST VOLUME
        # ----------------------------------------------------

        if total_requests > 10:

            score += 20


        # ----------------------------------------------------
        # SCANNING / RECONNAISSANCE
        # ----------------------------------------------------

        if suspicious_responses >= 5:

            score += 30


        # ----------------------------------------------------
        # MAXIMUM SCORE
        # ----------------------------------------------------

        if score > 100:

            score = 100


        results.append(

            (
                ip,
                score
            )

        )


    # Highest risk first

    results.sort(

        key=lambda item: item[1],

        reverse=True

    )

    return results


# ============================================================
# HTTP STATUS DISTRIBUTION
# ============================================================

def get_status_distribution():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            status,

            COUNT(*) AS request_count

        FROM logs

        GROUP BY status

        ORDER BY status
    """)

    results = cursor.fetchall()

    connection.close()

    return results


# ============================================================
# IP ANALYSIS
# ============================================================

def get_ip_analysis():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            ip,

            COUNT(*) AS total_requests,

            SUM(

                CASE

                    WHEN status >= 400

                    THEN 1

                    ELSE 0

                END

            ) AS errors,

            AVG(latency) AS average_latency

        FROM logs

        GROUP BY ip

        ORDER BY total_requests DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    results = []


    for (

        ip,

        total_requests,

        errors,

        average_latency

    ) in rows:

        errors = errors or 0

        average_latency = (
            average_latency or 0
        )


        if total_requests > 0:

            error_rate = (
                errors /
                total_requests
            ) * 100

        else:

            error_rate = 0


        results.append({

            "ip":
                ip,

            "total_requests":
                total_requests,

            "errors":
                errors,

            "error_rate":
                round(
                    error_rate,
                    2
                ),

            "average_latency_ms":
                round(
                    average_latency,
                    2
                )

        })


    return results


# ============================================================
# ENDPOINT ANALYSIS
# ============================================================

def get_endpoint_analysis():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            path,

            COUNT(*) AS total_requests,

            SUM(

                CASE

                    WHEN status >= 400

                    THEN 1

                    ELSE 0

                END

            ) AS errors,

            AVG(latency) AS average_latency

        FROM logs

        GROUP BY path

        ORDER BY total_requests DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    results = []


    for (

        path,

        total_requests,

        errors,

        average_latency

    ) in rows:

        errors = errors or 0

        average_latency = (
            average_latency or 0
        )


        if total_requests > 0:

            error_rate = (
                errors /
                total_requests
            ) * 100

        else:

            error_rate = 0


        results.append({

            "endpoint":
                path,

            "total_requests":
                total_requests,

            "errors":
                errors,

            "error_rate":
                round(
                    error_rate,
                    2
                ),

            "average_latency_ms":
                round(
                    average_latency,
                    2
                )

        })


    return results

# ============================================================
# GET ALL LOGS FOR AI ANALYSIS
# ============================================================

def get_all_logs():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            method,
            path,
            status,
            latency,
            ip
        FROM logs
        ORDER BY id ASC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows

# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print()
    print("========================================")
    print("       LOG ANALYZER DATABASE")
    print("========================================")
    print()

    # Create database

    create_database()


    # Clear existing logs

    clear_logs()


    # Parse access.log

    records = parse_file(
        "access.log"
    )

    print(
        f"Parsed {len(records)} log records."
    )


    # Insert logs

    insert_logs(
        records
    )

    print(
        "Logs inserted successfully!"
    )


    # ========================================================
    # GENERAL STATISTICS
    # ========================================================

    print()
    print("========================================")
    print("GENERAL STATISTICS")
    print("========================================")

    total = get_total_requests()

    errors = get_error_count()

    average_latency = (
        get_average_latency()
    )


    if total > 0:

        error_rate = (
            errors /
            total
        ) * 100

    else:

        error_rate = 0


    print(
        "Total Requests:",
        total
    )

    print(
        "Errors:",
        errors
    )

    print(
        "Average Latency:",
        round(
            average_latency,
            2
        ),
        "ms"
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
    # TOP IPS
    # ========================================================

    print()
    print("========================================")
    print("TOP IP ADDRESSES")
    print("========================================")

    for ip, count in get_top_ips():

        print(
            f"{ip}: {count} requests"
        )


    # ========================================================
    # TOP ENDPOINTS
    # ========================================================

    print()
    print("========================================")
    print("MOST REQUESTED ENDPOINTS")
    print("========================================")

    for path, count in get_top_endpoints():

        print(
            f"{path}: {count} requests"
        )


    # ========================================================
    # FAILED LOGINS
    # ========================================================

    print()
    print("========================================")
    print("FAILED LOGIN ATTEMPTS")
    print("========================================")

    failed_logins = (
        get_failed_logins()
    )


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
    # BRUTE FORCE
    # ========================================================

    print()
    print("========================================")
    print("BRUTE-FORCE DETECTION")
    print("========================================")

    brute_force = (
        get_brute_force_ips()
    )


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
    # RISK SCORES
    # ========================================================

    print()
    print("========================================")
    print("SECURITY RISK SCORES")
    print("========================================")

    risk_scores = (
        get_risk_scores()
    )


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
    # STATUS DISTRIBUTION
    # ========================================================

    print()
    print("========================================")
    print("HTTP STATUS DISTRIBUTION")
    print("========================================")

    for status, count in get_status_distribution():

        print(
            f"{status}: {count} requests"
        )


    print()
    print("========================================")
    print("DATABASE ANALYSIS COMPLETE")
    print("========================================")