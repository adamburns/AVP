from app.models import Company
from flask_wtf import Form, RecaptchaField
from datetime import datetime
import pytz
from wtforms import StringField, TextAreaField, PasswordField, SelectField, FileField, DateField, BooleanField, SubmitField
from wtforms.validators import DataRequired, InputRequired, Email, EqualTo, Length, ValidationError, StopValidation
from wtforms.ext.sqlalchemy.fields import QuerySelectField


PRETTY_TIMEZONE_CHOICES = []
for tz in pytz.common_timezones:
    now = datetime.now(pytz.timezone(tz))
    ofs = now.strftime("%z")
    PRETTY_TIMEZONE_CHOICES.append((int(ofs), tz, "(GMT%s) %s" % (ofs, tz)))
PRETTY_TIMEZONE_CHOICES.sort()
for i in xrange(len(PRETTY_TIMEZONE_CHOICES)):
    PRETTY_TIMEZONE_CHOICES[i] = PRETTY_TIMEZONE_CHOICES[i][1:]


def all_companies():
    return Company.query


class SetPasswordForm(Form):
    password = PasswordField('New password', validators=[InputRequired('Please enter a password.'),
                             EqualTo('password_confirm', message='Passwords do not match.'),
                             Length(6, 255, 'Passwords must be greater than 6 characters.')])
    password_confirm = PasswordField('Confirm password')
    time_zone = SelectField('Time Zone', choices=PRETTY_TIMEZONE_CHOICES, default="US/Central")
    submit = SubmitField('Set Password')


class RequestForm(Form):
    first_name = StringField('First Name', validators=[DataRequired('Please enter a first name.')])
    last_name = StringField('Last Name', validators=[DataRequired('Please enter a last name.')])
    email = StringField('Email', validators=[DataRequired('Please enter an email address.'),
                        Email('Please enter a valid email address.')])
    phone = StringField('Phone', validators=[DataRequired('Please enter a phone number.')])
    company = QuerySelectField('Broker/Dealer or RIA Name',
                               query_factory=all_companies, get_label='company_name',
                               allow_blank=True, blank_text='None/Other')
    broker_dealer = StringField('If None/Other')
    advisor_number = StringField('Advisor CRD Number', validators=[DataRequired('Please enter your CRD number.')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Submit')


class ManageAccountForm(Form):
    email = StringField('Email (Username)', description='Note that changing your email address will \
                        require you to confirm the new address. Please only enter a working email address.',
                        validators=[DataRequired('Please enter an email address.'),
                        Email('Please enter a valid email address.')])
    first_name = StringField('First Name', validators=[DataRequired('Please enter a first name.')])
    last_name = StringField('Last Name', validators=[DataRequired('Please enter a last name.')])
    notification_rate = SelectField('Email Alerts', description='Choose how often you would like to \
                                    receive email notifications about new documents.',
                                    choices=[
                                    ('0', 'Immediately'),
                                    ('1', 'Every day'),
                                    ('3', 'Every 3 days'),
                                    ('7', 'Every week')])
    time_zone = SelectField('Time Zone', choices=PRETTY_TIMEZONE_CHOICES)

    submit = SubmitField('Update')
