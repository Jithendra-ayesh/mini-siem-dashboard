from flask import Flask, render_template, request
from analyzer.logger import log_event

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        ip_address = request.remote_addr

        if username == "admin" and password == "1234":
            log_event("LOGIN_SUCCESS", username, ip_address)
            return "<h2>Login Successful</h2>"

        log_event("LOGIN_FAILED", username, ip_address)
        return "<h2>Login Failed</h2>"

    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)