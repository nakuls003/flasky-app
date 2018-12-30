from flask import render_template, request, redirect, url_for, flash
from . import auth
from flask_login import login_required, login_user, logout_user, current_user
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, ForgotPasswordForm, ResetPasswordForm, \
    ChangeEmailForm
from ..models import User
from .. import db
from ..email import send_email


@auth.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid username or password')
    return render_template('auth/login.html', form = form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email('Flasky | Confirm your account', user.email, 'auth/email/confirm', user=user, token=token)
        flash('An email containing an account confirmation link has been sent to you')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm_user(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed and request.blueprint != 'auth' and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email('Flasky | Confirm your account', current_user.email, 'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation link has been sent to your email address.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.current_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash('You have changed your password successfully.')
            return redirect(url_for('main.index'))
        else:
            flash('The current password you entered was not correct. Please try again.')
    return render_template('auth/change-password.html', form=form)


@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email('Flasky | Reset Password', user.email, 'auth/email/reset-password', user=user, token=token)
            flash('An email containing a link to reset password has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Unknown email address.')
    return render_template('auth/forgot-password.html', form=form)


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash('Your password has been reset. You can login now.')
            return redirect(url_for('auth.login'))
        else:
            flash('Password reset link is invalid or has expired.')
            return redirect(url_for('main.index'))
    return render_template('auth/reset-password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        token = current_user.generate_email_change_token(form.email.data)
        send_email('Flasky | Change Email', form.email.data, 'auth/email/change-email', user=current_user, token=token)
        flash('An email has been sent to the address provided by you. Kindly check your inbox.')
        return redirect(url_for('main.index'))
    return render_template('auth/change-email.html', form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash('Your email was updated successfully.')
    else:
        flash('The email change link has expired or is invalid.')
    return redirect(url_for('main.index'))
