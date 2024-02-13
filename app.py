from flask import render_template
from . import app, login_manager
from flask import request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models.database import session
from .models.user import User


def signup():
    if request.method == "POST":
        username = request.form["name"]
        password = request.form["password"]

        user = session.query(User).where(User.username == username).first()

        if user:
            flash("Цей користувач вже існує!")
            return redirect("login")

        new_user = User(
            username=username,
            password=generate_password_hash(password)
        )
        try:
            session.add(new_user)
            session.commit()
        except Exception as exc:
            return f"При збереженні користувача виникла помилка: {exc}"
        finally:
            session.close()
            return redirect("/login")
    else:
        return render_template("signup.html")

@app.route("login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form["name"]
        password = request.form["password"]
        remember = True if request.form['remember'] else False

        user = session.query(User).where(User.username == username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Будь ласка перевірте свій логін та пароль ш спробуйте знову!")
            return redirect("/login")
        login_user(user=user, remember=remember)
        return redirect(url_for('main'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("main")

@login_manager.user_loader
def load_users(user_id):
    return session.query(User).get(int(user_id))