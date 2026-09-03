from statistics import mean

from sklearn.ensemble import IsolationForest

import database
from log_parser import LogRecord


# ============================================================
# BUILD FEATURES
# ============================================================

def build_ip_features(records):
    """
    Convert raw log records into numerical features
    for each IP address.
    """

    ip_data = {}

    for record in records:

        if record.ip not in ip_data:

            ip_data[record.ip] = {
                "total_requests": 0,
                "errors": 0,
                "failed_logins": 0,
                "latencies": []
            }

        data = ip_data[record.ip]

        # Total requests
        data["total_requests"] += 1

        # Errors
        if record.status >= 400:
            data["errors"] += 1

        # Failed login
        if (
            record.path == "/login"
            and record.status == 401
        ):
            data["failed_logins"] += 1

        # Latency
        data["latencies"].append(
            record.latency
        )

    features = []
    ips = []

    for ip, data in ip_data.items():

        total_requests = data["total_requests"]
        errors = data["errors"]
        failed_logins = data["failed_logins"]

        average_latency = mean(
            data["latencies"]
        )

        # Error rate
        error_rate = (
            errors / total_requests
            if total_requests > 0
            else 0
        )

        features.append([
            total_requests,
            errors,
            failed_logins,
            average_latency,
            error_rate
        ])

        ips.append(ip)

    return ips, features


# ============================================================
# AI ANOMALY DETECTION
# ============================================================

def detect_anomalies(records):
    """
    Detect unusual IP behavior using
    Isolation Forest.
    """

    ips, features = build_ip_features(records)

    # Need at least 3 IPs for meaningful comparison
    if len(features) < 3:
        return []

    # Isolation Forest
    model = IsolationForest(
        contamination="auto",
        random_state=42
    )

    model.fit(features)

    predictions = model.predict(features)

    anomaly_scores = (
        model.decision_function(features)
    )

    results = []

    for (
        ip,
        prediction,
        score,
        feature
    ) in zip(
        ips,
        predictions,
        anomaly_scores,
        features
    ):

        total_requests = feature[0]
        errors = feature[1]
        failed_logins = feature[2]
        average_latency = feature[3]
        error_rate = feature[4]

        if prediction == -1:

            status = "ANOMALY"

        else:

            status = "NORMAL"

        results.append({

            "ip":
                ip,

            "status":
                status,

            "anomaly_score":
                round(
                    float(score),
                    4
                ),

            "total_requests":
                total_requests,

            "errors":
                errors,

            "failed_logins":
                failed_logins,

            "average_latency":
                round(
                    average_latency,
                    2
                ),

            "error_rate":
                round(
                    error_rate * 100,
                    2
                )

        })

    # Most suspicious first
    results.sort(
        key=lambda item:
            item["anomaly_score"]
    )

    return results


# ============================================================
# LOAD LOGS FROM SQLITE
# ============================================================

def load_database_records():
    """
    Load all logs from SQLite and convert them
    into LogRecord objects.
    """

    rows = database.get_all_logs()

    records = []

    for row in rows:

        method = row[0]
        path = row[1]
        status = int(row[2])
        latency = int(row[3])
        ip = row[4]

        record = LogRecord(
            method=method,
            path=path,
            status=status,
            latency=latency,
            ip=ip
        )

        records.append(record)

    return records


# ============================================================
# DATABASE AI ANALYSIS
# ============================================================

def analyze_database():
    """
    Run AI anomaly detection on logs stored
    in the SQLite database.
    """

    records = load_database_records()

    if not records:
        return []

    return detect_anomalies(records)


# ============================================================
# PRINT RESULTS
# ============================================================

def print_results(results):

    if not results:

        print(
            "\nNot enough data for anomaly detection."
        )

        return

    print("\nAI Analysis Results:")

    for result in results:

        print(
            f"\nIP: {result['ip']}"
        )

        print(
            f"Status: {result['status']}"
        )

        print(
            f"Anomaly Score: "
            f"{result['anomaly_score']}"
        )

        print(
            f"Total Requests: "
            f"{result['total_requests']}"
        )

        print(
            f"Errors: "
            f"{result['errors']}"
        )

        print(
            f"Failed Logins: "
            f"{result['failed_logins']}"
        )

        print(
            f"Average Latency: "
            f"{result['average_latency']} ms"
        )

        print(
            f"Error Rate: "
            f"{result['error_rate']}%"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():

    print("========================================")
    print(" AI ANOMALY DETECTION")
    print("========================================")

    print(
        "\nLoading logs from SQLite database..."
    )

    records = load_database_records()

    print(
        f"Loaded {len(records)} log records."
    )

    results = detect_anomalies(records)

    if not results:

        print(
            "\nNot enough IP data for anomaly detection."
        )

        return

    print_results(results)

    # --------------------------------------------------------
    # Anomaly Summary
    # --------------------------------------------------------

    anomalies = [
        result
        for result in results
        if result["status"] == "ANOMALY"
    ]

    print("\n========================================")
    print(" AI ANOMALY SUMMARY")
    print("========================================")

    print(
        f"Total IPs analyzed: "
        f"{len(results)}"
    )

    print(
        f"Anomalous IPs: "
        f"{len(anomalies)}"
    )

    if anomalies:

        print("\nSuspicious IPs:")

        for result in anomalies:

            print(
                f"⚠️ {result['ip']} "
                f"| Score: "
                f"{result['anomaly_score']}"
            )

    else:

        print(
            "\n✅ No unusual IP behavior detected."
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()