from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import sqlite3
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key-before-deployment"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # Set True when using HTTPS
DB = "smart_campus.db"


def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    con = connect()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student'
    );
    CREATE TABLE IF NOT EXISTS attendance(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT NOT NULL,
        date TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('Present','Absent','Late'))
    );
    CREATE TABLE IF NOT EXISTS results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        marks INTEGER NOT NULL,
        total INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """)
    if not con.execute("SELECT id FROM users WHERE email=?", ("admin@smartcampus.com",)).fetchone():
        con.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                    ("Administrator", "admin@smartcampus.com",
                     generate_password_hash("Admin123!"), "admin"))
    con.commit()
    con.close()


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, "Invalid form security token. Refresh and try again.")


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


@app.route("/")
def home():
    return render_template("home.html", title="Home")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 6:
            flash("Fill all fields. Password must be at least 6 characters.", "warning")
            return redirect(url_for("register"))
        con = connect()
        try:
            con.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                        (name, email, generate_password_hash(password), "student"))
            con.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("This email is already registered.", "danger")
        finally:
            con.close()
    return render_template("register.html", title="Student Registration")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        con = connect()
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        con.close()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session.update(user_id=user["id"], name=user["name"],
                          email=user["email"], role=user["role"],
                          csrf_token=secrets.token_hex(24))
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html", title="Login")


@app.route("/dashboard")
@login_required()
def dashboard():
    return redirect(url_for("admin" if session["role"] == "admin" else "student"))


@app.route("/student")
@login_required("student")
def student():
    con = connect()
    attendance = con.execute("SELECT * FROM attendance WHERE student_email=? ORDER BY date DESC, id DESC",
                            (session["email"],)).fetchall()
    results = con.execute("SELECT * FROM results WHERE student_email=? ORDER BY id DESC",
                          (session["email"],)).fetchall()
    notices = con.execute("SELECT * FROM notices ORDER BY id DESC").fetchall()
    con.close()
    present = sum(1 for a in attendance if a["status"] == "Present")
    attendance_pct = round(present / len(attendance) * 100, 1) if attendance else 0
    return render_template("student.html", title="Student Dashboard", attendance=attendance,
                           results=results, notices=notices, attendance_pct=attendance_pct)


@app.route("/admin")
@login_required("admin")
def admin():
    con = connect()
    students = con.execute("SELECT id,name,email FROM users WHERE role='student' ORDER BY id DESC").fetchall()
    attendance = con.execute("SELECT * FROM attendance ORDER BY id DESC LIMIT 20").fetchall()
    results = con.execute("SELECT * FROM results ORDER BY id DESC LIMIT 20").fetchall()
    notices = con.execute("SELECT * FROM notices ORDER BY id DESC").fetchall()
    totals = {
        "students": con.execute("SELECT COUNT(*) n FROM users WHERE role='student'").fetchone()["n"],
        "attendance": con.execute("SELECT COUNT(*) n FROM attendance").fetchone()["n"],
        "results": con.execute("SELECT COUNT(*) n FROM results").fetchone()["n"],
        "notices": con.execute("SELECT COUNT(*) n FROM notices").fetchone()["n"],
    }
    con.close()
    return render_template("admin.html", title="Admin Dashboard", students=students,
                          attendance=attendance, results=results, notices=notices, totals=totals)


@app.route("/add-attendance", methods=["POST"])
@login_required("admin")
def add_attendance():
    email = request.form.get("email", "").strip().lower()
    date = request.form.get("date", "")
    status = request.form.get("status", "")
    if not email or not date or status not in ("Present", "Absent", "Late"):
        flash("Please provide valid attendance details.", "warning")
        return redirect(url_for("admin"))
    con = connect()
    student = con.execute("SELECT id FROM users WHERE email=? AND role='student'", (email,)).fetchone()
    duplicate = con.execute("SELECT id FROM attendance WHERE student_email=? AND date=?", (email, date)).fetchone()
    if not student:
        flash("Student email not found.", "danger")
    elif duplicate:
        flash("Attendance already exists for that student and date.", "warning")
    else:
        con.execute("INSERT INTO attendance(student_email,date,status) VALUES(?,?,?)", (email, date, status))
        con.commit()
        flash("Attendance saved.", "success")
    con.close()
    return redirect(url_for("admin"))


@app.route("/add-result", methods=["POST"])
@login_required("admin")
def add_result():
    email = request.form.get("email", "").strip().lower()
    subject = request.form.get("subject", "").strip()
    try:
        marks, total = int(request.form.get("marks", "")), int(request.form.get("total", ""))
    except (ValueError, TypeError):
        flash("Marks and total must be whole numbers.", "warning")
        return redirect(url_for("admin"))
    con = connect()
    student = con.execute("SELECT id FROM users WHERE email=? AND role='student'", (email,)).fetchone()
    if not student:
        flash("Student email not found.", "danger")
    elif not subject or total < 1 or marks < 0 or marks > total:
        flash("Check subject and marks (marks must not exceed total).", "warning")
    else:
        con.execute("INSERT INTO results(student_email,subject,marks,total) VALUES(?,?,?,?)",
                    (email, subject, marks, total))
        con.commit()
        flash("Result saved.", "success")
    con.close()
    return redirect(url_for("admin"))


@app.route("/add-notice", methods=["POST"])
@login_required("admin")
def add_notice():
    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    if not title or not message:
        flash("Notice title and message are required.", "warning")
        return redirect(url_for("admin"))
    con = connect()
    con.execute("INSERT INTO notices(title,message) VALUES(?,?)", (title, message))
    con.commit()
    con.close()
    flash("Notice published.", "success")
    return redirect(url_for("admin"))


@app.route("/delete-student/<int:user_id>", methods=["POST"])
@login_required("admin")
def delete_student(user_id):
    con = connect()
    user = con.execute("SELECT email FROM users WHERE id=? AND role='student'", (user_id,)).fetchone()
    if user:
        email = user["email"]
        con.execute("DELETE FROM users WHERE id=? AND role='student'", (user_id,))
        con.execute("DELETE FROM attendance WHERE student_email=?", (email,))
        con.execute("DELETE FROM results WHERE student_email=?", (email,))
        con.commit()
        flash("Student and associated records deleted.", "success")
    else:
        flash("Student not found.", "warning")
    con.close()
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for("home"))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", title="Bad Request", code=400,
                          message="The form security check failed. Refresh and try again."), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", title="Forbidden", code=403,
                          message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", title="Not Found", code=404,
                          message="The page could not be found."), 404


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
