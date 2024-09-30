from flask import Flask,render_template, request, redirect, flash
import flask_login
from app import db
from flask_login import login_user, logout_user, current_user, login_required
from app import models, forms
from app.models import User
from app.forms import RegistrationForm, LoginForm, UpdateAccountForm
import bcrypt
from flask import url_for
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('view_account'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Вы успешно зарегистрировались', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Пользователь с таким email уже зарегистрирован.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('view_account'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            print(current_user.is_authenticated)  # Проверка, аутентифицирован ли пользователь

            return redirect(url_for('view_account'))
        else:
            flash('Введены неверные данные', 'danger')

    return render_template('login.html', form=form)

@app.route('/check_auth')
def check_auth():
    if current_user.is_authenticated:
        return "Пользователь авторизован"
    else:
        return "Пользователь не авторизован"


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/account')
@login_required
def view_account():
    return render_template('account.html')


@app.route('/edit', methods=['GET', 'POST'])
@login_required
def edit_account():
    print(current_user.is_authenticated)  # Проверка аутентификации
    form = UpdateAccountForm()

    if form.validate_on_submit():
        # Обновление имени и email
        current_user.username = form.username.data
        current_user.email = form.email.data

        # Обновление пароля (если введен новый)
        if form.password.data:
            current_user.password = generate_password_hash(form.password.data)

        # Сохранение изменений в базе данных
        db.session.commit()
        flash('Ваш аккаунт был обновлен!', 'success')
        return redirect(url_for('view_account'))

    # Заполнение формы текущими данными пользователя при GET-запросе
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('edit_account.html', form=form)
