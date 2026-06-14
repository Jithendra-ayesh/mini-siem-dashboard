from flask import Flask, render_template, request, redirect, url_for, session
from analyzer.logger import log_event
from analyzer.log_analyzer import analyze_logs
from analyzer.threat_detector import (detect_credential_stuffing, detect_username_enumeration)

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

    return render_template(
        "dashboard.html",
        total_events=stats["total_events"],
        successful_logins=stats["successful_logins"],
        failed_logins=stats["failed_logins"],
        recent_events=stats["recent_events"],
        credential_alerts=credential_alerts,
        enumeration_alerts=enumeration_alerts
    )

@app.route("/logout")
def logout():

    session.pop("admin", None)

    return redirect(url_for("admin_login"))

if __name__ == "__main__":
    app.run(debug=True)