from flask import Flask
from flask_mail import Mail
from flask.ext import breadcrumbs
from flask.ext.compress import Compress
from flask_sqlalchemy import SQLAlchemy
from flask_debugtoolbar import DebugToolbarExtension

app = Flask(__name__)
app.config.from_object('config')
Compress(app)
db = SQLAlchemy(app)
mail = Mail(app)
breadcrumbs.Breadcrumbs(app=app)
toolbar = DebugToolbarExtension(app)
import stripe
stripe.api_key = app.config['STRIPE_KEYS']['SK']

if app.config['SLACK_KEY']:
    from slacker import Slacker
    slack = Slacker(app.config['SLACK_KEY'])

from app.models import User, Role
from flask_security import Security, SQLAlchemyUserDatastore
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

from app.util import assets
from app import views
from app.admin.views import mod_admin as admin_module
from app.user.views import mod_user as user_module
app.register_blueprint(admin_module)
app.register_blueprint(user_module)


## Global Jinja2 filters

from datetime import date
from flask_security import current_user
import pytz
from jinja2.exceptions import UndefinedError

def get_year():
    return date.today().year

def format_currency(value, format='full'):
    if format == 'full':
        return "${:,.2f}".format(value)
    elif format == 'pretty':
        return "${:,.0f}".format(value)
    elif format == 'decimal':
        return "{:,.2f}".format(value)

def format_datetime(value, format='medium'):
    try:
        tz = pytz.timezone(current_user.time_zone)
        tzoffset = tz.utcoffset(value)
        tzvalue = value + tzoffset
        if format == 'full':
            return tzvalue.strftime('%c')
        elif format == 'pretty':
            return tzvalue.strftime('%m/%d/%Y at %I:%M %p')
        elif format == 'medium':
            return tzvalue.strftime('%m/%d/%Y')
        elif format == 'sort':
            return tzvalue.strftime('%s')
    except (AttributeError, TypeError):
        return ''

def format_phonenumber(value):
    try:
        clean_phone_number = re.sub('[^0-9]+', '', value)
        formatted_phone_number = re.sub("(\d)(?=(\d{3})+(?!\d))", r"\1-", "%d" % int(clean_phone_number[:-1])) + clean_phone_number[-1]
        return formatted_phone_number
    except (AttributeError, TypeError):
        return value

app.jinja_env.globals.update(get_year=get_year)
app.jinja_env.filters['datetime'] = format_datetime
app.jinja_env.filters['currency'] = format_currency
app.jinja_env.filters['phonenumber'] = format_phonenumber


## Initialize the app

if __name__ == '__main__':
    app.run()
