from flask import Flask, render_template, request
from analyzer.logger import log_event

app = Flask(__name__)


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
            "response.html",
            message="Login Failed"
        )

    return render_template("login.html")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "admin123":

            return render_template("dashboard.html")

        return render_template(
            "response.html",
            message="Invalid Admin Credentials"
        )

    return render_template("admin_login.html")


@app.route("/dashboard")
def dashboard():

    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True)