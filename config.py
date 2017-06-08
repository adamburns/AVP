# For dev/test only -- DO NOT DEPLOY!

DEBUG = True
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BASE_URL = "https://advisordd.com"

APP_NAME = "Advisor Vantage Point"
APP_STYLED_NAME = "FactRight"
COMPANY_NAME = "FactRight, LLC"
COMPANY_ADDRESS = "10125 Crosstown Circle, Suite 300, Eden Prairie, MN 55344"
COMPANY_PHONE = "(847) 805-6242"
COMPANY_LINK = "http://www.factright.com/"
CONTACT_LINK = "http://www.factright.com/contact-us/"
OWNER_NAME = "Great Lakes Fund Solutions, Inc"
OWNER_LINK = "http://glfsi.com/"
CONTACT_EMAIL = "bcoia@glfsi.com"
ADMINS = ['bcoia@glfsi.com']

SQLALCHEMY_DATABASE_URI = "mysql://frrm:bdenm94JgAnwxeJW@localhost/frrm"
SECURITY_PASSWORD_HASH = "sha512_crypt"
SECURITY_PASSWORD_SALT = "whirlpool"
SECURITY_POST_LOGIN_VIEW = "/redirect"
SECURITY_RECOVERABLE = True
SECURITY_CHANGEABLE = True
SECURITY_CONFIRMABLE = True
SECURITY_REGISTERABLE = True
SECURITY_TRACKABLE = True
SECURITY_EMAIL_SENDER = (APP_NAME, "no-reply@advisordd.com")
THREADS_PER_PAGE = 2
CSRF_ENABLED = True
CSRF_SESSION_KEY = "d6a2f8981c6848f257ebc0cb75c822a98dd2150981"
SECRET_KEY = "da2b5019c6a2f8981c6848f257ebc0cb75c822a98d"

# Change STRIPE_TEST to False to enable links to Live panel
STRIPE_TEST = True
STRIPE_KEYS = {
    'SK': "sk_test_0AzsDKDKvcKJK0273d9R77z4",
    'PK': "pk_test_CNcvMN3YT8qDWDEoAQ2nl5G6"
}

# Enable for S3 uploads
AMAZON_WEB_SERVICES_KEYS = {
    'ACCESS_KEY': "AKIAIBQMWFA6E26QRJBA",
    'SECRET_ACCESS_KEY': "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",
    'REGION_NAME': "us-west-2",
    'BUCKET': "frrm-dev"
}

ANALYTICS_TOKEN = "UA-57602751-1"

RECAPTCHA_PUBLIC_KEY = "6LesTf8SAAAAAKUKIF-QUXM_LL4PFABLYbngoN7Q"
RECAPTCHA_PRIVATE_KEY = "6LesTf8SAAAAAEpiBUmKTKAH31b_hunjB4fLX0KM"
RECAPTCHA_API_SERVER = "https://www.google.com/recaptcha/api.js"

MAIL_SERVER = 'smtp.mailgun.org'
MAIL_PORT = 587
MAIL_USE_SSL = False
MAIL_USERNAME = 'postmaster@advisordd.com'
MAIL_PASSWORD = '9259a4d8e41851d4a247a6ef342e4100'

SECURITY_EMAIL_SUBJECT_REGISTER = "Your new %s account" % APP_NAME
SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE = "%s password reset" % APP_NAME
SECURITY_EMAIL_SUBJECT_PASSWORD_RESET = "%s password reset confirmation" % APP_NAME
SECURITY_EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE = "%s password change confirmation" % APP_NAME
SECURITY_EMAIL_SUBJECT_CONFIRM = "Please confirm your %s account" % APP_NAME

REPORT_IMAGE = 'https://partnershipaccounting.com/images/frreport.jpg'
