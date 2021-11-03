# IMPORTS
import logging
from functools import wraps
from werkzeug.security import check_password_hash
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask_login import current_user, login_user, logout_user
from datetime import datetime
from app import db
from lottery.views import lottery
from models import User
import pyotp
from users.forms import RegisterForm, LoginForm
from flask_login import login_required
# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        pin_key=form.pin_key.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Security warning for when a user is registered
        logging.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():

    # if session attribute logins doesnt exist create new attribute logins
    if not session.get('logins'):
        session['logins'] = 0
    # if login attempts is more than 3 return error message
    elif session.get('logins') >= 3:
        flash('Number of incorrect logins exceeded')

    form = LoginForm()

    if form.validate_on_submit():

        # increase login attempts by 1
        session['logins'] += 1

        user = User.query.filter_by(email=form.username.data).first()

        if not user or not check_password_hash(user.password, form.password.data):
            # if user not authenticated, return error message depending on login attempts
            if session['logins'] == 3:
                flash('Number of incorrect login attempts exceeded')
                # Security warning for when a user tries to log in 3 times unsuccessfully
                logging.warning('SECURITY - Invalid Login attempt 3 [%s, %s]', form.username.data, request.remote_addr)
            elif session['logins'] == 2:
                flash('Please check your login details and try again. 1 login attempt remaining')
                # Security warning for when a user tries to log in 2 times unsuccessfully
                logging.warning('SECURITY - Invalid Login attempt 2 [%s, %s]', form.username.data, request.remote_addr)
            elif session['logins'] == 1:
                flash('Please check your login details and try again. 2 login attempt remaining')
                # Security warning for when a user tries to log in once unsuccessfully
                logging.warning('SECURITY - Invalid Login attempt 1 [%s, %s]', form.username.data, request.remote_addr)
            else:
                flash('Please check your login details and try again')
                # Security warning for when a user tries to log in unsuccessfully
                logging.warning('SECURITY - Invalid Login attempt [%s, %s]', form.username.data, request.remote_addr)

            return render_template('login.html', form=form)

        if pyotp.TOTP(user.pin_key).verify(form.pin.data):
            # if user is verified reset login attempts
            session['logins'] = 0

            login_user(user)

            user.last_logged_in = user.current_logged_in
            user.current_logged_in = datetime.now()
            db.session.add(user)
            db.session.commit()

            # Security warning for when a user logs in
            logging.warning('SECURITY - Log in [%s,%s, %s]', current_user.id, current_user.email, request.remote_addr)

            # Redirect to appropriate page according to role
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin'))
            else:
                return redirect(url_for('users.profile'))

        if not pyotp.TOTP(user.pin_key).verify(form.pin.data):
            flash('Wrong 2FA token', 'danger')
    return render_template('login.html', form=form)

@users_blueprint.route('/logout')
@login_required
def logout():

    # Security warning for when a user logs out
    logging.warning('SECURITY - Log out [%s,%s, %s]', current_user.id, current_user.email, request.remote_addr)

    logout_user()
    return redirect(url_for('index'))


# view user profile
@users_blueprint.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name="PLACEHOLDER FOR FIRSTNAME")


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE")
