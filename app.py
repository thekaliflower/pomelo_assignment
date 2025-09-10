import os
import sqlite3
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, render_template_string
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth

def init_db():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    text TEXT,
                    submitted_at TEXT
                )""")
    conn.commit()
    conn.close()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
    init_db()

    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )

    oauth = OAuth(app)
    google = oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        access_token_url="https://oauth2.googleapis.com/token",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        api_base_url="https://www.googleapis.com/oauth2/v2/",
        client_kwargs={"scope": "openid email profile"},
    )

    @app.route("/")
    def index():
        user = session.get("user")
        return render_template_string("""
            {% if user %}
              <p>Logged in as: {{ user.['email'] }}</p>
              <a href="{{ url_for('logout') }}">Logout</a> |
              <a href="{{ url_for('page2') }}">Go to /page2 (protected)</a>
            {% else %}
              <a href="{{ url_for('login') }}">Login with Google</a>
            {% endif %}
        """)

    @app.route("/login")
    def login():
        redirect_uri = url_for("auth_callback", _external=True)
        return google.authorize_redirect(redirect_uri)

    @app.route("/auth/callback")
    def auth_callback():
        token = google.authorize_access_token()
        userinfo = google.get("userinfo").json()
        session["user"] = userinfo
        return redirect(url_for("page2"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))




    @app.route("/page1", methods=["GET", "POST"])
    def page1():
        conn = sqlite3.connect("data.db")
        c = conn.cursor()
        rows = []

        if request.method == "POST":
            user_input = request.form["user_input"]
            submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Deliberately vulnerable to SQL injection
            try:
                c.execute(f"INSERT INTO submissions (text, submitted_at) VALUES ('{user_input}', '{submitted_at}')")
                conn.commit()
                c.execute("SELECT text, submitted_at FROM submissions")

            except Exception as e:
                return f"<h3>DB error:</h3><pre>{e}</pre>", 500

            finally:
                rows = c.fetchall()
                conn.close()

        return render_template("page1.html", rows=rows)


    @app.route("/page2", methods=["GET", "POST"])
    def page2():
        if "user" not in session:
            return redirect(url_for("login"))
        
        conn = sqlite3.connect("data.db")
        c = conn.cursor()

        if request.method == "POST":
            user_input = request.form["user_input"]
            submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Deliberately vulnerable to SQL injection
            c.execute(f"INSERT INTO submissions (text, submitted_at) VALUES ('{user_input}', '{submitted_at}')")
            conn.commit()

        c.execute("SELECT text, submitted_at FROM submissions")
        rows = c.fetchall()
        conn.close()

        return render_template("page2.html", rows=rows)

    return app
