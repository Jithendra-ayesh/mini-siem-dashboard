from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from analyzer.logger import log_event
from analyzer.log_analyzer import analyze_logs, analyze_top_ips, analyze_top_usernames, analyze_daily_activity, analyze_hourly_activity
from analyzer.threat_detector import detect_credential_stuffing, detect_username_enumeration
from analyzer.threat_history import load_threat_history
from io import StringIO
import csv

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
    top_ips = analyze_top_ips()
    top_usernames = analyze_top_usernames()
    daily_activity = analyze_daily_activity()
    hourly_activity = analyze_hourly_activity()

    return render_template(
        "dashboard.html",
        total_events=stats["total_events"],
        successful_logins=stats["successful_logins"],
        failed_logins=stats["failed_logins"],
        recent_events=stats["recent_events"],
        credential_alerts=credential_alerts,
        enumeration_alerts=enumeration_alerts,
        threat_history=threat_history,
        top_ips=top_ips,
        top_usernames=top_usernames,
        daily_activity=daily_activity,
        hourly_activity=hourly_activity,
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

@app.route("/logout")
def logout():

    session.pop("admin", None)

    return redirect(url_for("admin_login"))

if __name__ == "__main__":
    app.run(debug=True)