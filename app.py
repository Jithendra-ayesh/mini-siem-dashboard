from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from analyzer.logger import log_event
from analyzer.log_analyzer import analyze_logs, analyze_top_ips, analyze_top_usernames, analyze_daily_activity, analyze_hourly_activity
from analyzer.threat_detector import detect_credential_stuffing, detect_username_enumeration
from analyzer.threat_history import load_threat_history, mark_ip_blocked
from analyzer.blocklist import is_ip_blocked
from io import StringIO
from datetime import datetime
import csv, json

app = Flask(__name__)
app.secret_key = "mini_siem_secret_key"


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        ip_address = request.remote_addr

        if is_ip_blocked(ip_address):

            return render_template(
                "login.html",
                message="Access Denied - IP Address Blocked"
            )

        if username == "admin" and password == "1234":

            log_event(
                "LOGIN_SUCCESS",
                username,
                ip_address
            )

            return render_template(
                "response.html",
                message="Login Successful"
            )

        log_event(
            "LOGIN_FAILED",
            username,
            ip_address
        )

        return render_template(
            "login.html",
            message="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        ip_address = request.remote_addr

        if is_ip_blocked(ip_address):

            return render_template(
                "admin_login.html",
                message="Access Denied - IP Address Blocked"
            )

        if username == "admin" and password == "admin123":
            session["admin"] = True
            return redirect(url_for("dashboard"))

        return render_template(
            "admin_login.html",
            message="Invalid username or password"
        )

    return render_template("admin_login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    
    stats = analyze_logs()
    credential_alerts = detect_credential_stuffing()
    enumeration_alerts = detect_username_enumeration()
    threat_history = load_threat_history()
    high_alerts = len([
        t for t in threat_history
        if t["severity"] == "HIGH"
    ])

    medium_alerts = len([
        t for t in threat_history
        if t["severity"] == "MEDIUM"
    ])

    open_alerts = len([
        t for t in threat_history
        if t["status"] == "OPEN"
    ])
    top_ips = analyze_top_ips()
    top_usernames = analyze_top_usernames()
    daily_activity = analyze_daily_activity()
    hourly_activity = analyze_hourly_activity()
    try:
        with open(
            "logs/blocked_ips.json",
            "r"
        ) as file:

            blocked_ips = json.load(file)

    except:
        blocked_ips = []

    return render_template(
        "dashboard.html",
        total_events=stats["total_events"],
        successful_logins=stats["successful_logins"],
        failed_logins=stats["failed_logins"],
        recent_events=stats["recent_events"],
        credential_alerts=credential_alerts,
        enumeration_alerts=enumeration_alerts,
        threat_history=threat_history,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        open_alerts=open_alerts,
        top_ips=top_ips,
        top_usernames=top_usernames,
        daily_activity=daily_activity,
        hourly_activity=hourly_activity,
        blocked_count=len(blocked_ips)
    )

@app.route("/dashboard-data")
def dashboard_data():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    stats = analyze_logs()

    credential_alerts = detect_credential_stuffing()
    enumeration_alerts = detect_username_enumeration()
    threat_history = load_threat_history()
    top_ips = analyze_top_ips()
    top_usernames = analyze_top_usernames()
    daily_activity = analyze_daily_activity()
    hourly_activity = analyze_hourly_activity()

    return jsonify({
        "total_events": stats["total_events"],
        "successful_logins": stats["successful_logins"],
        "failed_logins": stats["failed_logins"],
        "recent_events": stats["recent_events"],
        "credential_alerts": credential_alerts,
        "enumeration_alerts": enumeration_alerts,
        "threat_history": threat_history,
        "top_ips": top_ips,
        "top_usernames": top_usernames,
        "daily_activity": daily_activity,
        "hourly_activity": hourly_activity
    })

@app.route("/export")
def export_csv():

    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    with open("logs/security_logs.json", "r") as file:
        logs = json.load(file)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp",
        "Event Type",
        "Username",
        "IP Address"
    ])

    for log in logs:
        writer.writerow([
            log["timestamp"],
            log["event_type"],
            log["username"],
            log["ip_address"]
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=security_report.csv"

    return response

@app.route("/block-ip/<ip>")
def block_ip(ip):

    try:
        with open(
            "logs/blocked_ips.json",
            "r"
        ) as file:

            blocked_ips = json.load(file)

    except:
        blocked_ips = []

    if ip not in blocked_ips:
        blocked_ips.append({
            "ip": ip,
            "blocked_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "reason": "Manual block from dashboard"
        })

    with open(
        "logs/blocked_ips.json",
        "w"
    ) as file:

        json.dump(
            blocked_ips,
            file,
            indent=4
        )

    mark_ip_blocked(ip)

    return redirect(
        url_for("dashboard")
    )

@app.route("/logout")
def logout():

    session.pop("admin", None)

    return redirect(url_for("admin_login"))

if __name__ == "__main__":
    app.run(debug=True)