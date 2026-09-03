from flask import Flask, jsonify, render_template, request

import database
import ai_detector


app = Flask(__name__)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "message": "Log Analyzer API is running",
        "stats_endpoint": "/stats",
        "security_endpoint": "/security",
        "ip_analysis_endpoint": "/ip-analysis",
        "status_endpoint": "/status-analysis",
        "endpoint_analysis_endpoint": "/endpoint-analysis",
        "ai_endpoint": "/ai",
        "generator": "/generator",
        "generator_api": "/api/generator/logs",
        "dashboard": "/dashboard"
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/report")
def report():
    return render_template("report.html")

# ============================================================
# LOG GENERATOR PAGE
# ============================================================

@app.route("/generator")
def generator():
    return render_template("generator.html")


# ============================================================
# GENERATOR API
# Receives generated logs and stores them in SQLite
# ============================================================

@app.route("/api/generator/logs", methods=["POST"])
def receive_generated_logs():

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "success": False,
                "error": "No JSON data received"
            }), 400

        logs = data.get("logs", [])

        if not isinstance(logs, list):
            return jsonify({
                "success": False,
                "error": "logs must be a list"
            }), 400

        if len(logs) == 0:
            return jsonify({
                "success": False,
                "error": "No logs supplied"
            }), 400

        inserted = 0

        for log in logs:

            try:

                method = log.get("method")
                path = log.get("path")
                status = int(log.get("status"))
                latency = int(log.get("latency"))
                ip = log.get("ip")

                if not all([method, path, ip]):
                    continue

                record = type(
                    "GeneratedLog",
                    (),
                    {
                        "method": method,
                        "path": path,
                        "status": status,
                        "latency": latency,
                        "ip": ip
                    }
                )()

                database.insert_log(record)

                inserted += 1

            except Exception as log_error:

                print(
                    "Skipping invalid generated log:",
                    log_error
                )

        if inserted > 0:

            return jsonify({
                "success": True,
                "message": "Generated logs inserted into database",
                "received": len(logs),
                "inserted": inserted,
                "database": "log_analyzer.db"
            })

        return jsonify({
            "success": False,
            "error": "No valid logs were inserted"
        }), 400

    except Exception as e:

        print("Generator API error:", e)

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# GENERAL STATISTICS
# ============================================================

@app.route("/stats")
def stats():

    total = database.get_total_requests()

    errors = database.get_error_count()

    average_latency = database.get_average_latency()

    top_ips = database.get_top_ips()

    top_endpoints = database.get_top_endpoints()


    if average_latency is None:
        average_latency = 0


    if total > 0:
        error_rate = (errors / total) * 100
    else:
        error_rate = 0


    return jsonify({

        "total_requests": total,

        "errors": errors,

        "error_rate": round(
            error_rate,
            2
        ),

        "average_latency_ms": round(
            average_latency,
            2
        ),

        "top_ips": [
            {
                "ip": ip,
                "requests": count
            }

            for ip, count in top_ips
        ],

        "top_endpoints": [
            {
                "endpoint": path,
                "requests": count
            }

            for path, count in top_endpoints
        ]

    })


# ============================================================
# IP ANALYSIS
# ============================================================

@app.route("/ip-analysis")
def ip_analysis():

    results = database.get_ip_analysis()

    return jsonify({

        "success": True,

        "ip_analysis": results

    })


# ============================================================
# HTTP STATUS ANALYSIS
# ============================================================

@app.route("/status-analysis")
def status_analysis():

    status_data = database.get_status_distribution()

    results = []

    for status, count in status_data:

        results.append({

            "status": status,

            "requests": count

        })


    return jsonify({

        "success": True,

        "status_distribution": results

    })


# ============================================================
# ENDPOINT ANALYSIS
# ============================================================

@app.route("/endpoint-analysis")
def endpoint_analysis():

    results = database.get_endpoint_analysis()

    return jsonify({

        "success": True,

        "endpoint_analysis": results

    })


# ============================================================
# SECURITY ANALYSIS
# ============================================================

@app.route("/security")
def security():

    failed_logins = database.get_failed_logins()

    risk_scores = database.get_risk_scores()

    brute_force = database.get_brute_force_ips()


    alerts = []


    # --------------------------------------------------------
    # BRUTE FORCE ALERTS
    # --------------------------------------------------------

    for ip, count in brute_force:

        alerts.append({

            "type": "BRUTE_FORCE",

            "severity": "HIGH",

            "ip": ip,

            "message":
                f"{ip} has {count} failed login attempts"

        })


    # --------------------------------------------------------
    # RISK SCORE ALERTS
    # --------------------------------------------------------

    for ip, score in risk_scores:

        if score >= 50:

            alerts.append({

                "type": "RISK",

                "severity": "HIGH",

                "ip": ip,

                "message":
                    f"{ip} has a high security risk score of {score}"

            })


        elif score >= 20:

            alerts.append({

                "type": "RISK",

                "severity": "MEDIUM",

                "ip": ip,

                "message":
                    f"{ip} has a medium security risk score of {score}"

            })


    # --------------------------------------------------------
    # FAILED LOGIN DATA
    # --------------------------------------------------------

    failed_login_data = [

        {
            "ip": ip,
            "attempts": count
        }

        for ip, count in failed_logins

    ]


    # --------------------------------------------------------
    # RISK SCORE DATA
    # --------------------------------------------------------

    risk_score_data = []


    for ip, score in risk_scores:

        if score >= 50:

            risk = "HIGH"

        elif score >= 20:

            risk = "MEDIUM"

        else:

            risk = "LOW"


        risk_score_data.append({

            "ip": ip,

            "score": score,

            "risk": risk

        })


    return jsonify({

        "failed_logins":
            failed_login_data,

        "risk_scores":
            risk_score_data,

        "security_alerts":
            alerts

    })


# ============================================================
# AI ANOMALY DETECTION
# ============================================================

@app.route("/ai")
def ai_analysis():

    try:

        # ----------------------------------------------------
        # Load logs directly from SQLite database
        # ----------------------------------------------------

        records = ai_detector.load_database_records()


        # ----------------------------------------------------
        # Run Isolation Forest anomaly detection
        # ----------------------------------------------------

        results = ai_detector.detect_anomalies(
            records
        )


        # ----------------------------------------------------
        # Get only anomalous IPs
        # ----------------------------------------------------

        anomalies = [

            result

            for result in results

            if result.get("status") == "ANOMALY"

        ]


        # ----------------------------------------------------
        # Calculate total logs analyzed
        # ----------------------------------------------------

        total_logs = sum(

            result["total_requests"]

            for result in results

        )


        # ----------------------------------------------------
        # Return AI analysis
        # ----------------------------------------------------

        return jsonify({

            "success": True,

            "data_source": "SQLite database",

            "total_logs_analyzed":
                total_logs,

            "total_ips_analyzed":
                len(results),

            "anomalous_ips":
                len(anomalies),

            "results":
                results,

            "anomalies":
                anomalies

        })


    except Exception as e:

        print(
            "AI analysis error:",
            e
        )


        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


# ============================================================
# 404 ERROR HANDLER
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({

        "success": False,

        "error": "Endpoint not found",

        "available_endpoints": [

            "/",

            "/dashboard",

            "/generator",

            "/stats",

            "/security",

            "/ip-analysis",

            "/status-analysis",

            "/endpoint-analysis",

            "/ai",

            "/api/generator/logs"

        ]

    }), 404


# ============================================================
# 500 ERROR HANDLER
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({

        "success": False,

        "error": "Internal server error"

    }), 500


# ============================================================
# START FLASK APPLICATION
# ============================================================

if __name__ == "__main__":

    database.create_database()

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )