from app.models import Company, Role, ReportGroup, ReportFolder, Program,\
                       EmailDomain, Sponsor, User, DenyReason
from flask import url_for
from flask_security import current_user
from flask_wtf import Form
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, TextAreaField, PasswordField, SelectField,\
                    DateField, BooleanField, SubmitField,\
                    DecimalField, SelectMultipleField, widgets, IntegerField
from wtforms.validators import DataRequired, InputRequired, Email, EqualTo,\
                               Length, ValidationError, StopValidation,\
                               NumberRange
from wtforms.ext.sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField


def available_companies():
    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        return Company.query.order_by(Company.company_name)
    else:
        return Company.query.filter(Company.company_id == current_user.company_id)

def available_roles():
    return Role.query.filter(Role.id >= current_user.get_role_id())

def available_report_groups():
    return ReportGroup.query.order_by(ReportGroup.report_group_name)

def available_report_folders():
    return ReportFolder.query.order_by(ReportFolder.report_folder_name)

def available_programs():
    return Program.query.order_by(Program.program_name)

def available_sponsors():
    return Sponsor.query.order_by(Sponsor.sponsor_name)

def available_domains():
    return EmailDomain.query.order_by(EmailDomain.domain_name)

def available_users():
    return User.query.order_by(User.email)

def available_reasons():
    return DenyReason.query.order_by(DenyReason.name)

def available_company_users():
    return User.query.\
           filter_by(company_id=current_user.company_id).\
           join(User.roles).\
           filter(Role.name.in_(['alladvisor', 'advisor', 'user'])).\
           order_by(User.email)

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


## Users

class UserForm(Form):
    email = StringField('Email/Username', validators=[DataRequired('Please enter an email address.'),\
                        Email('Please enter a valid email address.')])
    first_name = StringField('First Name', validators=[DataRequired('Please enter a first name.')])
    last_name = StringField('Last Name', validators=[DataRequired('Please enter a last name.')])
    phone = StringField('Phone')
    company = QuerySelectField('Broker/Dealer', validators=[DataRequired('Please choose a broker/dealer.')],
                               query_factory=available_companies, get_label='company_name', allow_blank=True)
    role = QuerySelectField('Role', validators=[DataRequired('Please choose a role.')],
                            query_factory=available_roles, description='\
                            <em>Home Office Admins</em> can manage users and access within their broker/dealer.<br/>\
                            <em>Broker/Dealers</em> can view everything that Home Office Admins can, but cannot edit.<br/>\
                            <em>All-Access Advisors</em> can purchase or subscribe to any report.<br/>\
                            <em>Advisors</em> can subscribe to report groups validated by their broker/dealer.<br/>',
                            get_label='description', allow_blank=True)
    active = BooleanField('Active', description='Inactive accounts are disabled and cannot be accessed. \
                          Newly created inactive accounts do not receive invitation emails, but are pre-registered \
                          when requesting access.', default=True)
    submit = SubmitField('Submit')


class UserApproveForm(Form):
    company = QuerySelectField('Broker/Dealer', query_factory=available_companies, get_label='company_name',
                               validators=[DataRequired('Please select a broker/dealer.')],
                               allow_blank=True)
    role = QuerySelectField('Role', query_factory=available_roles, description='\
                            <em>Home Office Admins</em> can manage users and access within their broker/dealer.<br/>\
                            <em>Broker/Dealers</em> can view everything that Home Office Admins can, but cannot edit.<br/>\
                            <em>All-Access Advisors</em> can purchase or subscribe to any report.<br/>\
                            <em>Advisors</em> can subscribe to report groups validated by their broker/dealer.<br/>',
                            get_label='description')
    submit = SubmitField('Approve and Create User')


class UserDenyForm(Form):
    reason = QuerySelectField('Reason', query_factory=available_reasons, get_label='name',
                              validators=[DataRequired('Please select a reason.')],
                              allow_blank=True)
    otherreason = TextAreaField('If other, explain:')
    submit = SubmitField('Submit and Deny User')


class UploadUsersForm(Form):
    file = FileField('File', validators=[
                      FileRequired('Please upload a CSV.'),
                      FileAllowed(['csv'], 'Please upload a CSV.')], 
                      description='Files must be CSVs in the following format, with header:<br/>\
                      <samp>Email,First Name,Last Name,Role</samp><br/>\
                      Example: <samp>admin@factright.com,John,Smith,admin</samp><br/>\
                      Available roles are: <em>superadmin, admin, brokeradmin, broker, alladvisor, advisor</em>')
    company = QuerySelectField('Broker/Dealer', query_factory=available_companies, get_label='company_name')
    active = BooleanField('Active', description='Active users are registered immediately and \
                          <em>will receive a registration email</em>.<br/>\
                          Inactive users are pre-registered and must use the Request \
                          form to activate their account.', default=True)
    submit = SubmitField('Upload')


## Subscriptions

class AddIndividualSubscriptionForm(Form):
    user = QuerySelectField('User', validators=[DataRequired('Please choose a user.')],
                            query_factory=available_users, get_label='email', allow_blank=True)
    report_group = QuerySelectField('Subscription Group', validators=[DataRequired('Please choose a report group.')],
                                    query_factory=available_report_groups, get_label='report_group_name',\
                                    description='Add included access to the chosen report group to this user.\
                                    Included access is unlimited and lasts until deletion.', allow_blank=True)
    submit = SubmitField('Create')


class AddCompanyDiscountForm(Form):
    company = QuerySelectField('Broker/Dealer', validators=[DataRequired('Please choose a broker/dealer.')],
                               query_factory=available_companies, get_label='company_name', allow_blank=True)
    report_group = QuerySelectField('Subscription Group', validators=[DataRequired('Please choose a report group.')],
                                    query_factory=available_report_groups, get_label='report_group_name',\
                                    description='Add subscription adjustments to the chosen report group to this \
                                    <strong>entire broker/dealer</strong>. Discount is unlimited, and lasts until deletion.',
                                    allow_blank=True)
    discount = IntegerField('Percent Discount', validators=[DataRequired('Please enter a discount.'),
                                                            NumberRange(min=0, max=100)],
                            description="Enter the percentage discount that this broker/dealer will receive.")
    free = BooleanField('Free (included access)',
                        description='All users in the broker/dealer will receive immediate access to free subscriptions.')
    submit = SubmitField('Create')


class SubscriptionSeatsForm(Form):
    users = QuerySelectMultipleField('Users with Seats', query_factory=available_company_users,
                                     description="Chosen advisors will receive full access to \
                                                  this report group. Your subscription charges will \
                                                  be pro-rated as you add and remove seats, and \
                                                  you will only be charged for the active duration \
                                                  of each seat.")
    submit = SubmitField('Update Subscription')


## Documents

class UploadForm(Form):
    file = FileField('File', validators=[FileRequired('Please upload a file.')], description='Upload limit: 16MB')
    document_display_name = StringField('Report Name', validators=[DataRequired('Please enter a report name.')])
    public = BooleanField('Public', description='Public documents will be available <strong>for free</strong> \
                          to all users, regardless of subscriptions and valid programs.')
    report_folder = QuerySelectField('Report Folder', query_factory=available_report_folders, get_label='report_folder_name',
                                     allow_blank=True, blank_text='None',
                                     description="To view a document, the selected folder must be available within \
                                                  the user's subscription groups.")
    program = QuerySelectField('Program', query_factory=available_programs, get_label='program_name',
                               allow_blank=True, blank_text='None',
                               description="To view a document, the selected program must be available within \
                               the user's broker/dealer's valid programs.")
    price = DecimalField('Price', description='Leave blank or enter 0 for subscription-only.<br/>\
                                               This price can be adjusted later.')
    submit = SubmitField('Submit')


## Entities

class CompanyForm(Form):
    company_name = StringField('Broker/Dealer Name', validators=[DataRequired('Please enter a broker/dealer name.')])
    programs = QuerySelectMultipleField('Valid Programs', query_factory=available_programs, get_label='program_name',
                                        description='Users can only view documents from the selected valid programs.')
    email_domains = QuerySelectMultipleField('Email Domains', query_factory=available_domains, get_label='domain_name',
                                             description='Recognized email domains for users from this broker/dealer.')
    submit = SubmitField('Submit')


class ProgramForm(Form):
    program_name = StringField('Program Name', validators=[DataRequired('Please enter a program name.')])
    sponsor = QuerySelectField('Sponsor', query_factory=available_sponsors, get_label='sponsor_name',
                               allow_blank=True, blank_text='None')
    submit = SubmitField('Submit')


class ReportGroupForm(Form):
    report_group_name = StringField('Subscription Group Name', validators=[DataRequired('Please enter a report group name.')])
    price = DecimalField('Price', validators=[NumberRange(min=0, max=10000,\
                         message='Please enter a price up to $10,000 (or $0 for free).')],
                         description='Leave blank or enter 0 for free groups.<br/><strong>Setting \
                                      a price will permanently lock the group in at this price.</strong> \
                                      You must create a new group to adjust pricing.')
    submit = SubmitField('Submit')


class ReportFolderForm(Form):
    report_folder_name = StringField('Report Folder Name', validators=[DataRequired('Please enter a report folder name.')])
    report_group = QuerySelectField('Subscription Group', query_factory=available_report_groups, get_label='report_group_name',
                                    allow_blank=True, blank_text='None')
    submit = SubmitField('Submit')


class SponsorForm(Form):
    sponsor_name = StringField('Sponsor Name', validators=[DataRequired('Please enter a sponsor name.')])
    submit = SubmitField('Submit')


class DomainForm(Form):
    domain_name = StringField('Domain', validators=[DataRequired('Please enter an email domain.')])
    submit = SubmitField('Submit')
