from flask import Blueprint, render_template, request, redirect, url_for,\
                  flash, session, g, jsonify
from flask.ext import breadcrumbs
from flask_security import login_required, roles_accepted, current_user, utils
from flask_security.confirmable import send_confirmation_instructions
from flask_security.recoverable import send_reset_password_instructions
from flask_security.registerable import register_user
import boto3
from colour import Color
from datetime import datetime
from random import SystemRandom
import re
from sqlalchemy import desc, or_
from sqlalchemy.exc import IntegrityError
from string import ascii_uppercase, digits
from wtforms.validators import ValidationError
from app import app, db, stripe, user_datastore
from app.admin.forms import UserForm, ReportGroupForm, UploadUsersForm,\
                            UploadForm, ReportFolderForm, CompanyForm,\
                            ProgramForm, SponsorForm, UserApproveForm,\
                            UserDenyForm, DomainForm,\
                            AddIndividualSubscriptionForm,\
                            AddCompanyDiscountForm, SubscriptionSeatsForm
from app.decorators import crossdomain
from app.models import Company, ReportGroup, ReportFolder, Document, Sponsor,\
                       Program, Role, User, ValidProgram,\
                       ReportSubscription, Download, EmailDomain, ValidDomain,\
                       EmailQueue, CompanySubscription,\
                       DenyReason, CompanyDiscount, ReportNotification,\
                       SubscriptionSeat
from app.util.upload import UnicodeDictReader
from app.util.email import send_email


mod_admin = Blueprint('admin', __name__, url_prefix='/admin')


## Dashboard/Top-level admin functions

@mod_admin.route('/')
@mod_admin.route('/dashboard')
@breadcrumbs.register_breadcrumb(mod_admin, '.',
                                 '<i class="fa fa-fw fa-th-large"></i>')
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def dashboard():
    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        totals = {
            'users': User.query.\
                     with_entities(User.id).\
                     filter(or_(User.review_status == 'APPROVED',
                                User.review_status == None)).\
                     filter(Role.id >= current_user.get_role_id()).\
                     filter(User.confirmed_at != None).\
                     filter(User.time_deleted == None).\
                     group_by(User.id).\
                     count(),
            'companies': Company.query.\
                         with_entities(Company.company_id).\
                         count(),
            'documents': Document.query.\
                         with_entities(Document.document_id).\
                         count(),
            'pending_users': User.query.\
                             with_entities(User.id).\
                             filter(User.review_status == 'PENDING').\
                             count()
        }
        data = {
            'users': User.query.\
                     filter(or_(User.review_status == 'APPROVED',
                                User.review_status == None)).\
                     filter(Role.id >= current_user.get_role_id()).\
                     filter(User.confirmed_at != None).\
                     filter(User.time_deleted == None).\
                     order_by(desc(User.confirmed_at)).\
                     group_by(User.id).\
                     limit(5),
            'pending_users': User.query.\
                             filter(User.review_status == 'PENDING').\
                             filter(Role.id >= current_user.get_role_id()).\
                             group_by(User.id).\
                             all(),
            'companies': Company.query.\
                         order_by(desc(Company.time_created)).\
                         limit(5),
            'documents': Document.query.\
                         order_by(desc(Document.time_created)).\
                         limit(5),
            'totals': totals
        }
    else:
        company_id = current_user.company_id
        valid_programs = ValidProgram.query.\
                         filter_by(company_id=company_id).\
                         all()
        totals = {
            'users': User.query.\
                     with_entities(User.id).\
                     filter(or_(User.review_status == 'APPROVED',
                                User.review_status == None)).\
                     filter(Role.id >= current_user.get_role_id()).\
                     filter(User.company_id == current_user.company_id).\
                     filter(User.confirmed_at != None).\
                     filter(User.time_deleted == None).\
                     group_by(User.id).\
                     count(),
            'documents': Document.query.\
                         with_entities(Document.document_id).\
                         filter(Document.program_id.\
                                in_(v.program_id for v in valid_programs)).\
                         count()
        }
        data = {
            'users': User.query.\
                     filter(or_(User.review_status == 'APPROVED',
                                User.review_status == None)).\
                     filter(Role.id >= current_user.get_role_id()).\
                     filter(User.company_id == current_user.company_id).\
                     filter(User.confirmed_at != None).\
                     filter(User.time_deleted == None).\
                     order_by(desc(User.confirmed_at)).\
                     group_by(User.id).\
                     limit(5),
            'pending_users': User.query.\
                             filter(User.review_status == 'PENDING').\
                             filter(Role.id >= current_user.get_role_id()).\
                             filter(User.company_id == current_user.company_id).\
                             group_by(User.id).\
                             all(),
            'documents': Document.query.\
                         filter(Document.program_id.\
                                in_(v.program_id for v in valid_programs)).\
                         order_by(desc(Document.time_created)).\
                         limit(5),
            'totals': totals
        }
    return render_template('admin/dashboard.html', data=data, dashboard=True)


## User Management

@mod_admin.route('/users')
@breadcrumbs.register_breadcrumb(mod_admin, '.users', 'Users')
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def users_list():
    if current_user.has_role('superadmin'):
        users = User.query.\
                filter(or_(User.review_status == 'APPROVED', User.review_status == None)).\
                all()
        pending_users = User.query.\
                        filter(User.review_status == 'PENDING').\
                        all()
    elif current_user.has_role('admin'):
        users = User.query.\
                filter(Role.id >= current_user.get_role_id()).\
                filter(User.time_deleted == None).\
                all()
        pending_users = User.query.join(User.roles).filter(User.review_status == 'PENDING').all()
    else:
        users = User.query.\
                filter(Role.id >= current_user.get_role_id()).\
                filter(User.company_id == current_user.company_id).\
                filter(User.time_deleted == None).\
                all()
        pending_users = None

    data = {
        "users": users,
        "pending_users": pending_users
    }

    return render_template('admin/userslist.html', data=data)


def user_approve_dlc(*args, **kwargs):
    user_id = request.view_args['user_id']
    user = User.query.get(user_id)
    return [{'text': '%s %s' % (user.first_name, user.last_name), 'url': url_for('admin.user_info', user_id=user_id)},
            {'text': 'Approve User', 'url': url_for('admin.approve_user', user_id=user_id)}]


@mod_admin.route('/users/approve/<int:user_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.approve', '',
                                 dynamic_list_constructor=user_approve_dlc)
@roles_accepted('superadmin', 'admin')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserApproveForm(obj=user, role=user.get_role())

    if not user.review_status == 'PENDING':
        flash('%s is not Pending, and thus cannot be approved.' % user.email, 'error')
        return redirect(request.referrer)

    if form.validate_on_submit():
        user.company = form.company.data
        user.role = form.role.data
        user.approve()
        flash('%s is now approved, and has been sent a Welcome email.' % user.email, 'success')
        return redirect(url_for('admin.users_list'))

    return render_template('admin/_form.html', form=form, user=user, title="Approve User",
                           description="Choose a Broker/Dealer and Role for the new user. Upon completion of this form, \
                                        the user will receive an email with instructions to activate their account.")


def user_deny_dlc(*args, **kwargs):
    user_id = request.view_args['user_id']
    user = User.query.get(user_id)
    return [{'text': '%s %s' % (user.first_name, user.last_name), 'url': url_for('admin.user_info', user_id=user_id)},
            {'text': 'Deny User', 'url': url_for('admin.deny_user', user_id=user_id)}]


@mod_admin.route('/users/deny/<int:user_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.deny', '',
                                 dynamic_list_constructor=user_deny_dlc)
@roles_accepted('superadmin', 'admin')
def deny_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDenyForm(obj=user)

    if not user.review_status == 'PENDING':
        flash('%s is not Pending, and thus cannot be denied.' % user.email, 'error')
        return redirect(request.referrer)

    if form.otherreason.data:
        del form.reason
        user.deny(form.otherreason.data)

        flash('%s has been denied, and has been sent a denial email.' % user.email, 'success')
        return redirect(url_for('admin.users_list'))
    elif form.validate_on_submit():
        reason = form.reason.data
        user.deny(reason.description)

        flash('%s has been denied, and has been sent a denial email.' % user.email, 'success')
        return redirect(url_for('admin.users_list'))

    return render_template('admin/denyuser.html', form=form, user=user)


def user_info_dlc(*args, **kwargs):
    user_id = request.view_args['user_id']
    user = User.query.get(user_id)
    return [{'text': '%s %s' % (user.first_name, user.last_name), 'url': url_for('admin.user_info', user_id=user_id)}]


@mod_admin.route('/users/info/<int:user_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.info', '',
                                 dynamic_list_constructor=user_info_dlc)
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def user_info(user_id):
    user = User.query.get_or_404(user_id)

    data = {
        'user': user
    }

    return render_template('admin/userinfo.html', data=data)


def user_edit_dlc(*args, **kwargs):
    user_id = request.view_args['user_id']
    user = User.query.get(user_id)
    return [{'text': '%s %s' % (user.first_name, user.last_name), 'url': url_for('admin.user_info', user_id=user_id)},
            {'text': 'Edit User', 'url': url_for('admin.edit_user', user_id=user_id)}]


@mod_admin.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.edit', '',
                                 dynamic_list_constructor=user_edit_dlc)
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def edit_user(user_id):    
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user, role=user.get_role())

    if request.method == 'POST':
        try:
            if form.validate_on_submit():
                user = User.query.get(user_id)
                user.email = request.form["email"]
                user.first_name = request.form["first_name"]
                user.last_name = request.form["last_name"]
                user.phone = request.form["phone"]
                user.company_id = request.form["company"]
                if request.form.get("active", False):
                    user.active = 1
                else:
                    user.active = 0

                roles = Role.query.all()
                for role in roles:
                    if role.id == int(request.form["role"]):
                        user_datastore.add_role_to_user(user, role)
                    else:
                        user_datastore.remove_role_from_user(user, role)

                db.session.commit()
                flash('Saved changes to %s.' % (user.email), 'success')
                return redirect(url_for('admin.user_info', user_id=user_id))
        except IntegrityError:
            flash('Email already registered. Please use a different email address.', 'error')
            return redirect(url_for('admin.edit_user', user_id=user_id))
    
    return render_template('admin/_form.html', user=user, form=form, title="Edit User")


@mod_admin.route('/users/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.new', 'New User')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def new_user():
    form = UserForm()

    if form.validate_on_submit():
        try:
            email = request.form["email"]
            password = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(12))
            first_name = request.form["first_name"]
            last_name = request.form["last_name"]
            phone = request.form["phone"]
            company_id = request.form["company"]
            if request.form.get("active", False):
                active = 1
            else:
                active = 0
            role = Role.query.get(request.form["role"])

            if current_user.has_role('brokeradmin'):
                newuser = user_datastore.create_user(email=email, password=utils.encrypt_password(password),
                                                     first_name=first_name, last_name=last_name, phone=phone,
                                                     company_id=company_id, active=active, login_count=0,
                                                     review_status='PENDING')
            elif active == 1:
                newuser = register_user(email=email, password=password,
                                        first_name=first_name, last_name=last_name, phone=phone,
                                        company_id=company_id, active=active, login_count=0)
            else:
                newuser = user_datastore.create_user(email=email, password=utils.encrypt_password(password),
                                                     first_name=first_name, last_name=last_name, phone=phone,
                                                     company_id=company_id, active=active, login_count=0)

            user_datastore.add_role_to_user(newuser, role)

            # Add notifications for included groups to new user
            report_groups = ReportGroup.query.filter(ReportGroup.price == 0).all()
            for report_group in report_groups:
                if report_group.is_free_access_for_user(newuser):
                    report_group.enable_notifications_for_user(newuser)
            db.session.commit()

            if current_user.has_role('brokeradmin'):
                flash('Account created for %s. User must be approved by %s before the account is activated.'\
                      % (newuser.email, app.config['COMPANY_NAME']), 'success')
            elif active == 0:
                flash('Account created for %s. User is pre-registered and must request access before the account is activated.'\
                      % (newuser.email), 'success')
            return redirect(url_for('admin.users_list'))
        except IntegrityError:
            flash('Email already registered. Please use a different email address.', 'error')
            db.session.rollback()

    if current_user.has_role('superadmin') or current_user.has_role('admin'):
        data = {
            'companies': Company.query.all(),
            'roles': Role.query.filter(Role.id >= current_user.get_role_id())
        }
    else:
        data = {
            'companies': Company.query.filter(Company.company_id == current_user.company_id),
            'roles': Role.query.filter(Role.id >= current_user.get_role_id())
        }

    return render_template('admin/_form.html', data=data, form=form, title="New User")


@mod_admin.route('/users/upload', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.users.upload', 'Upload')
@roles_accepted('superadmin', 'admin')
def upload_users():
    form = UploadUsersForm()
    newusers = []
    active = 0
    company = None

    if form.validate_on_submit():
        try:
            company = form.company.data
            if request.form.get("active", False):
                active = 1

            file = form.file.data
            reader = UnicodeDictReader(file, 'cp1252')
            errors = 0

            for row in reader:
                email = row['Email']
                first_name = row['First Name']
                last_name = row['Last Name']
                role = row['Role']

                # Row validation
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    error = 'Invalid email address'
                elif User.query.filter_by(email=email).first():
                    error = 'Email already exists'
                elif not Role.query.filter_by(name=role).first():
                    error = 'Role does not exist'
                else:
                    error = ''

                newusers.append({'email':email, 'first_name':first_name, 'last_name':last_name, 'role':role, 'error':error})
                if error:
                    errors += 1
                    continue

                # All checks passed, create the user
                password = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(12))
                newuser = user_datastore.create_user(email=email, password=utils.encrypt_password(password),
                                                     first_name=first_name, last_name=last_name,
                                                     company_id=company.company_id, active=active, login_count=0)
                user_datastore.add_role_to_user(newuser, role)

                # Add all included groups to new user
                included_subscriptions = ReportGroup.query.filter(ReportGroup.price == 0).all()
                for included_subscription in included_subscriptions:
                    subscription = ReportSubscription()
                    subscription.user_id = newuser.id
                    subscription.report_group_id = included_subscription.report_group_id
                    subscription.notifications = True
                    db.session.add(subscription)
                company_subscriptions = CompanySubscription.query.\
                                       filter(CompanySubscription.company_id == newuser.company_id).all()
                for company_subscription in company_subscriptions:
                    subscription = ReportSubscription()
                    subscription.user_id = newuser.id
                    subscription.report_group_id = company_subscription.report_group_id
                    subscription.notifications = True
                    db.session.add(subscription)

            if errors == 0:
                flash('All users have been successfully uploaded.', 'success')
            else:
                flash('Upload complete; however, not all users could be uploaded. See errors below.', 'warning')
            db.session.commit()
        except KeyError:
            flash('Your file could not be processed. Please ensure your file matches the excepted format.', 'error')

    data = {
        "active": active,
        "company": company,
        "newusers": newusers
    }

    return render_template('admin/uploadusers.html', form=form, data=data)


@mod_admin.route('/users/resetpassword/<int:user_id>')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def reset_user_password(user_id):
    user = User.query.get(user_id)

    if user.get_role_id() < current_user.get_role_id():
        flash('You do not have permission to modify this account.', 'error')
        return redirect(request.referrer)

    send_reset_password_instructions(user)

    flash('Password reset instructions sent to %s.' % (user.email))

    return redirect(url_for('admin.user_info', user_id=user_id))


@mod_admin.route('/users/delete/<int:user_id>')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def del_user(user_id):
    user = User.query.get(user_id)
    
    if user.get_role_id() < current_user.get_role_id():
        flash('You do not have permission to delete this account.', 'error')
        return redirect(request.referrer)

    # Soft-delete the user, unless they have already been deleted, in which superadmins can permanently delete
    if user.time_deleted and current_user.has_role('superadmin'):
        Download.query.filter_by(user_id=user_id).delete()
        ReportSubscription.query.filter_by(user_id=user_id).delete()
        EmailQueue.query.filter_by(user_id=user_id).delete()
        ReportNotification.query.filter_by(user_id=user_id).delete()
        user_datastore.delete_user(user)
        flash('Account permanently deleted.', 'success')
    else:
        user.time_deleted = datetime.utcnow()
        user.who_deleted = current_user.email
        user.active = False
        flash('Account deleted.', 'success')

    db.session.commit()
    return redirect(url_for('admin.users_list'))


@mod_admin.route('/users/resendconfirmation/<int:user_id>')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def resend_email_confirmation(user_id):
    user = User.query.get_or_404(user_id)

    if user.get_role_id() < current_user.get_role_id():
        flash('You do not have permission to modify this account.', 'error')
        return redirect('/')

    send_confirmation_instructions(user)

    flash('Email confirmation instructions sent to %s.' % (user.email), 'success')

    return redirect(url_for('admin.user_info', user_id=user_id))


@mod_admin.route('/users/resendwelcome/<int:user_id>')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def resend_welcome_email(user_id):
    user = User.query.get_or_404(user_id)

    if user.get_role_id() < current_user.get_role_id():
        flash('You do not have permission to modify this account.', 'error')
        return redirect('/')

    user.welcome_email()

    flash('Welcome email sent to %s.' % (user.email), 'success')

    return redirect(url_for('admin.user_info', user_id=user_id))


@mod_admin.route('/users/deletesubscription/<int:subscription_id>')
@roles_accepted('superadmin', 'admin')
def delete_subscription(subscription_id):
    subscription = ReportSubscription.query.get_or_404(subscription_id)
    report_group_name = subscription.report_group.report_group_name
    
    if subscription.stripe_id:
        flash('You cannot delete paid subscriptions. Please manage this subscription through Stripe.', 'error')
        return redirect(request.referrer)

    # Unsubscribe from notifications
    ReportNotification.query.\
    filter_by(user_id=subscription.user_id).\
    filter_by(report_group_id=subscription.report_group_id).\
    delete()

    db.session.delete(subscription)
    db.session.commit()
    flash('Unsubscribed user from %s.' % (report_group_name), 'success')

    return redirect(request.referrer)


## Documents

@mod_admin.route('/documents')
@breadcrumbs.register_breadcrumb(mod_admin, '.documents', 'Documents')
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def documents_list():
    if current_user.has_role('superadmin'):
        documents = Document.query.all()
    else:
        documents = Document.query.filter(Document.time_deleted == None).all()

    data = {
        'documents': documents
    }
    
    return render_template('admin/documents.html', data=data)


@mod_admin.route('/documents/upload', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.documents.upload', 'Upload')
@roles_accepted('superadmin', 'admin')
def upload_document():
    form = UploadForm()

    if form.validate_on_submit():
        doc = Document()
        doc.document_display_name = form.document_display_name.data
        doc.document_name = form.file.data.filename
        doc.document_type = form.file.data.mimetype
        if form.public.data:
            doc.public = True
        else:
            doc.report_folder = form.report_folder.data
            doc.program = form.program.data
            doc.price = form.price.data

        if doc.price > 0:
            doc.get_stripe_sku()

        if app.config['AMAZON_WEB_SERVICES_KEYS']:
            # Connect to S3
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
            # Assign S3 directory name
            if doc.report_folder:
                folder_name = doc.report_folder.report_folder_name
            elif doc.public:
                folder_name = 'Public'
            else:
                folder_name = 'None'
            s3key = "%s/%s" % (folder_name, doc.document_name)
            # Check for duplicates before uploading
            duplicate_doc = Document.query.filter_by(document_data=s3key).first()
            if duplicate_doc:
                flash('File already exists in this report folder. Please change the file name before reuploading.', 'error')
                return redirect(url_for('admin.upload_document'))
            s3.put_object(Key=s3key,
                          Body=form.file.data.stream.read(),
                          ContentType=doc.document_type,
                          ACL='public-read'
                         )
            doc.document_data = s3key
            doc.document_server = 's3'
        else:
            doc.document_data = form.file.data.stream.read()
        db.session.add(doc)

        # Create a new notification in the queue for all subscribed users
        if doc.report_folder and doc.program:
            users_to_notify = ReportNotification.query.\
                              filter_by(report_group_id=doc.report_folder.report_group_id).\
                              all()
            for user_to_notify in users_to_notify:
                if doc.is_valid_for(user_to_notify.user) and user_to_notify.user.active and user_to_notify.user.confirmed_at is not None:
                    notification = EmailQueue()
                    notification.user_id = user_to_notify.user_id
                    notification.document_id = doc.document_id
                    notification.sent = False
                    db.session.add(notification)

        db.session.commit()
        flash('Successfully uploaded %s.' % (doc.document_name), 'success')

        return redirect(url_for('admin.document_info', document_id=doc.document_id))

    data = {
        'report_folders': ReportFolder.query.all(),
        'programs': Program.query.all()
    }

    return render_template('admin/upload.html', data=data, form=form, title='Edit Document')


def document_info_dlc(*args, **kwargs):
    document_id = request.view_args['document_id']
    document = Document.query.get(document_id)
    return [{'text': document.document_display_name, 'url': url_for('admin.document_info', document_id=document_id)}]


@mod_admin.route('/documents/info/<int:document_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.documents.info', '',
                                 dynamic_list_constructor=document_info_dlc)
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def document_info(document_id):
    document = Document.query.get_or_404(document_id)
    downloads = document.get_downloads()

    data = {
        'document': document,
        'downloads': downloads
    }

    return render_template('admin/documentinfo.html', data=data)


@mod_admin.route('/documents/toggleprogram/<int:document_id>')
@roles_accepted('superadmin', 'admin', 'brokeradmin')
def toggle_document_program(document_id):
    document = Document.query.get_or_404(document_id)
    program = Program.query.get(document.program_id)
    valid_program = ValidProgram.query.\
                    filter_by(company_id=current_user.company_id).\
                    filter_by(program_id=program.program_id).first()
    if valid_program:
        ValidProgram.query.\
        filter_by(company_id=current_user.company_id).\
        filter_by(program_id=program.program_id).delete()
        db.session.commit()
        flash('Your company can no longer view documents from program %s.' % program.program_name, 'success')
    else:
        valid_program = ValidProgram()
        valid_program.company_id = current_user.company_id
        valid_program.program_id = program.program_id
        db.session.add(valid_program)
        db.session.commit()
        flash('Your company can now view documents from program %s.' % program.program_name, 'success')

    return redirect(request.referrer)


def document_edit_dlc(*args, **kwargs):
    document_id = request.view_args['document_id']
    document = Document.query.get(document_id)
    return [{'text': document.document_display_name, 'url': url_for('admin.document_info', document_id=document_id)},
            {'text': 'Edit Document', 'url': url_for('admin.edit_document', document_id=document_id)}]


@mod_admin.route('/documents/edit/<int:document_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.documents.edit', '',
                                 dynamic_list_constructor=document_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_document(document_id):
    document = Document.query.get_or_404(document_id)
    form = UploadForm(obj=document)
    del form.file

    if form.validate_on_submit():
        document.document_display_name = form.document_display_name.data
        document.program = form.program.data

        # Check for public toggle first; if unchanged, update folder
        location_updated = False
        if form.public.data and not document.public:
            document.public = True
            document.report_folder = None
            document.program = None
            location_updated = True
        elif not form.public.data and document.public:
            document.public = False
            document.report_folder = form.report_folder.data
            location_updated = True
        elif document.report_folder != form.report_folder.data:
            document.report_folder = form.report_folder.data
            location_updated = True

        if form.price.data > 0:
            document.get_stripe_sku()
            if form.price.data != document.price:
                document.price = form.price.data
                document.update_stripe_price()

        document.price = form.price.data

        # Update location on S3
        if location_updated and app.config['AMAZON_WEB_SERVICES_KEYS'] and document.document_server == 's3':
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
            if document.report_folder:
                folder_name = document.report_folder.report_folder_name
            elif document.public:
                folder_name = 'Public'
            else:
                folder_name = 'None'
            s3key = "%s/%s" % (folder_name, document.document_name)
            # Check for duplicates before moving
            duplicate_doc = Document.query.filter_by(document_data=s3key).first()
            if duplicate_doc:
                if int(duplicate_doc.document_id) != int(document_id):
                    flash('File already exists in this report folder. \
                          Please choose a new file name or edit the existing file.', 'error')
                    return redirect(url_for('admin.edit_document', document_id=document_id))
            # Copy to the new key
            copy_source = "%s/%s" % (app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'], document.document_data)
            s3.Object(s3key).copy_from(CopySource=copy_source,
                                       ContentType=document.document_type,
                                       ACL='public-read'
                                      )
            # Delete original key
            s3.Object(document.document_data).delete()
            # Update key in database
            document.document_data = s3key

        db.session.commit()
        flash('Saved changes to %s.' % (document.document_name), 'success')
        return redirect(url_for('admin.document_info', document_id=document_id))

    return render_template('admin/upload.html', form=form, title='Edit Document')


@mod_admin.route('/documents/delete/<int:document_id>')
@roles_accepted('superadmin', 'admin')
def del_document(document_id):
    document = Document.query.get_or_404(document_id)

    # Soft-delete the document, unless it has been deleted previously
    if not document.time_deleted:
        email_queue = EmailQueue.query.filter(EmailQueue.document_id == document_id).\
                                       filter(EmailQueue.time_sent == None).all()
        for queued_email in email_queue:
            queued_email.time_sent = datetime.utcnow()
            queued_email.who_sent = 'Document deleted, notification unsent'
        document.time_deleted = datetime.utcnow()
        document.who_deleted = current_user.email
        flash('Document deleted.', 'success')
    elif document.time_deleted and current_user.has_role('superadmin'):
        EmailQueue.query.filter_by(document_id=document_id).delete()
        Download.query.filter_by(document_id=document_id).delete()
        db.session.commit()
        # Connect to S3 and delete file
        if document.document_server == 's3' and app.config['AMAZON_WEB_SERVICES_KEYS']:
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
            s3.Object(document.document_data).delete()
        Document.query.filter_by(document_id=document_id).delete()
        flash('Document permanently deleted.', 'success')
    else:
        flash('You do not have permission to delete this document.', 'error')

    db.session.commit()

    return redirect(url_for('admin.documents_list'))


## Valid Programs

@mod_admin.route('/validprograms', methods=["GET", "POST"])
@breadcrumbs.register_breadcrumb(mod_admin, '.validprograms', 'Valid Programs')
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def valid_programs():
    company_id = current_user.company_id

    if request.method == 'POST':
        checked_programs = request.form.getlist("valid_programs")
        ValidProgram.query.filter_by(company_id=company_id).delete()
        for program_id in checked_programs:
            vp = ValidProgram()
            vp.company_id = company_id
            vp.program_id = program_id
            db.session.add(vp)

        flash('Valid programs updated.', 'success')
        db.session.commit()

        return redirect(url_for('admin.valid_programs'))

    valid_programs = g.valid_programs
    selected_programs = []
    for valid_program in valid_programs:
        selected_programs.append(valid_program.program_id)
    data = {
        "programs": Program.query.order_by(Program.program_name).all(),
        "selected_programs": selected_programs
    }

    return render_template('admin/validprograms.html', data=data)


## Subscriptions

@mod_admin.route('/subscriptions')
@breadcrumbs.register_breadcrumb(mod_admin, '.subscriptions', 'Subscriptions')
@roles_accepted('superadmin', 'admin')
def subscriptions_list():
    user_subscriptions = ReportSubscription.query.all()
    company_subscriptions = CompanySubscription.query.all()
    company_discounts = CompanyDiscount.query.all()

    data = {
        "user_subscriptions": user_subscriptions,
        "company_subscriptions": company_subscriptions,
        "company_discounts": company_discounts
    }

    return render_template('admin/subscriptions.html', data=data)


@mod_admin.route('/subscriptions/addsubscription', methods=['GET', 'POST'])
@mod_admin.route('/subscriptions/addsubscription/<int:user_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.subscriptions.addindividualsubscription', 'Add Individual Subscription')
@roles_accepted('superadmin', 'admin')
def new_individual_subscription(user_id=None):
    form = AddIndividualSubscriptionForm()

    if form.validate_on_submit():
        user = form.user.data
        report_group = form.report_group.data
        # Check for existing subscription
        existing_subscription = ReportSubscription.query.\
                                filter_by(user_id=user.id).\
                                filter_by(report_group_id=report_group.report_group_id).\
                                first()
        if existing_subscription:
            flash('%s already has a subscription to %s.' % (user.email, report_group.report_group_name), 'error')
        else:
            subscription = ReportSubscription()
            subscription.user = user
            subscription.report_group = report_group
            subscription.report_group.enable_notifications_for_user(user)

            db.session.add(subscription)
            db.session.commit()
            flash('Added subscription to %s for %s.' % (report_group.report_group_name, user.email), 'success')
            return redirect('%s%s' % (url_for('admin.subscriptions_list'), '#usersubscriptions'))

    if user_id:
        form.user.data = User.query.get_or_404(user_id)

    return render_template('admin/_form.html', form=form, title="Add Individual Subscription")


@mod_admin.route('/subscriptions/adddiscount', methods=['GET', 'POST'])
@mod_admin.route('/subscriptions/adddiscount/<int:company_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.subscriptions.addcompanydiscount', 'Add Broker/Dealer Discount')
@roles_accepted('superadmin', 'admin')
def new_company_discount(company_id=None):
    form = AddCompanyDiscountForm()

    if form.free.data == True:
        del form.discount
    if form.validate_on_submit():
        company_discount = CompanyDiscount()
        company_discount.company = form.company.data
        company_discount.report_group = form.report_group.data
        if form.free.data == True:
            company_discount.discount = 100
        else:
            company_discount.discount = form.discount.data

        try:
            company_discount.create_stripe_discount()
        except Exception, e:
            flash(str(e), 'error')
            return redirect(url_for('admin.new_company_discount', company_id=company_discount.company.company_id))

        db.session.add(company_discount)
        db.session.commit()
        flash('Added discount to %s for %s.' % (company_discount.company.company_name, company_discount.report_group.report_group_name), 'success')
        return redirect('%s%s' % (url_for('admin.subscriptions_list'), '#companydiscounts'))

    if company_id:
        form.company.data = Company.query.get_or_404(company_id)

    return render_template('admin/companydiscount.html', form=form)


@mod_admin.route('/_check_company_subscription')
def check_company_subscription():
    company = Company.query.get(request.args.get('company'))
    report_group = ReportGroup.query.get(request.args.get('report_group'))
    company_subscription = CompanySubscription.query.filter_by(company_id=company.company_id).\
                   filter_by(report_group_id=report_group.report_group_id).first()
    company_discount = CompanyDiscount.query.filter_by(company_id=company.company_id).\
               filter_by(report_group_id=report_group.report_group_id).first()

    price = report_group.price
    subscription = False
    discount = False
    if company_subscription:
        price = company_subscription.amount_paid
        subscription = True
    elif company_discount:
        price = report_group.get_price()
        discount = True
    data = {
        'subscription': subscription,
        'discount': discount,
        'price': price
    }
    return jsonify(result=data)


## Company Subscription Management

@mod_admin.route('/companysubscriptions')
@breadcrumbs.register_breadcrumb(mod_admin, '.companysubscriptions', 'Broker/Dealer Subscriptions')
@roles_accepted('brokeradmin')
@crossdomain(origin='*')
def company_subscriptions_list():
    groups = ReportGroup.query.all()
    for group in groups:
        group.price = group.get_price()

    data = {
        'groups': groups,
        'stripepk': app.config['STRIPE_KEYS']['PK']
    }

    return render_template('admin/companysubscriptions.html', data=data)


def subscription_seats_dlc(*args, **kwargs):
    report_group_id = request.view_args['report_group_id']
    report_group = ReportGroup.query.get(report_group_id)
    return [{'text': 'Broker/Dealer Subscriptions', 'url': url_for('admin.company_subscriptions_list')},
            {'text': '%s Seats' % report_group.report_group_name, 'url': url_for('admin.subscription_seats', report_group_id=report_group_id)}]


@mod_admin.route('/companysubscriptions/subscriptionseats/<int:report_group_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.companysubscriptions.subscriptionseats', '',
                                 dynamic_list_constructor=subscription_seats_dlc)
@roles_accepted('brokeradmin')
def subscription_seats(report_group_id):
    subscription = CompanySubscription.query.\
                   filter_by(report_group_id=report_group_id).\
                   filter_by(company_id=current_user.company_id).\
                   first_or_404()
    form = SubscriptionSeatsForm(users=[s.user for s in subscription.seats])

    if form.validate_on_submit():
        users = request.form.getlist("users")
        previous_seats = SubscriptionSeat.query.filter_by(company_subscription_id=subscription.company_subscription_id).all()
        previous_ids = []
        for previous_seat in previous_seats:
            previous_ids.append(int(previous_seat.user.id))
        SubscriptionSeat.query.filter_by(company_subscription_id=subscription.company_subscription_id).delete()
        for user_id in users:
            seat = SubscriptionSeat()
            seat.company_subscription_id = subscription.company_subscription_id
            seat.user_id = user_id
            db.session.add(seat)
            user = User.query.get(user_id)
            print user_id
            print previous_ids
            if not int(user_id) in previous_ids:
                send_email("Your %s subscription on behalf of %s" % (subscription.report_group.report_group_name, user.company.company_name),
                           app.config['SECURITY_EMAIL_SENDER'],
                           ["%s %s" % (user.first_name, user.last_name), user.email],
                           render_template('email/seat_added.txt', user=user, subscription=subscription),
                           render_template('email/seat_added.html', user=user, subscription=subscription))

        # Get the Stripe Customer and update their subscription seats
        customer = stripe.Customer.retrieve(current_user.stripe_id)
        stripe_subscription = customer.subscriptions.retrieve(subscription.stripe_id)
        stripe_subscription.quantity = len(users)
        stripe_subscription.save()

        db.session.commit()
        flash('Updated subscription to %s.' % (subscription.report_group.report_group_name), 'success')
        return redirect(url_for('admin.company_subscriptions_list'))

    return render_template('admin/subscriptionseats.html', form=form, subscription=subscription)


@mod_admin.route('/_processpayment')
@roles_accepted('brokeradmin')
def pay():
    group_id = request.args.get('groupid')
    report_group = ReportGroup.query.get_or_404(group_id)
    company_discount = report_group.get_company_discount()

    # Get the credit card details submitted by the form
    token = request.args.get('token')

    try:
        if current_user.stripe_id:
            # Subscribe the existing user to the plan
            customer = stripe.Customer.retrieve(current_user.stripe_id)
        else:
            # Create a Customer and subscribe them to the plan
            description = "%s (Subscribed by %s %s)" % (current_user.company.company_name, current_user.first_name, current_user.last_name)
            customer = stripe.Customer.create(
                card = token,
                email = current_user.email,
                description = description
            )
            current_user.stripe_id = customer.id

        address = customer.sources.data[0]
        current_user.address = address.address_line1
        current_user.address_2 = address.address_line2
        current_user.city = address.address_city
        current_user.state_or_prov = address.address_state
        current_user.postal_code = address.address_zip
        current_user.country = address.country

        # Apply discount, if available
        subscription = None
        if company_discount:
            if company_discount.stripe_id:
                subscription = customer.subscriptions.create(plan=report_group.stripe_id,
                                                             coupon=company_discount.stripe_id,
                                                             quantity=0)
        if not subscription:
            subscription = customer.subscriptions.create(plan=report_group.stripe_id)
    except stripe.error.CardError, e:
        # The card has been declined
        flash('Your card was declined. Please try again.', 'error')
        return jsonify(id=0, price=0)
    except stripe.error.RateLimitError, e:
        # Too many requests made to the API too quickly
        flash('Too many requests to Stripe. Please try again.', 'error')
        return jsonify(id=0, price=0)
    except stripe.error.InvalidRequestError, e:
        # Invalid parameters were supplied to Stripe's API
        flash('Something is wrong with your Stripe request. Please try again.', 'error')
        return jsonify(id=0, price=0)
    except stripe.error.AuthenticationError, e:
        # Authentication with Stripe's API failed
        # (maybe you changed API keys recently)
        flash('Stripe could not authenticate. Please try again.', 'error')
        return jsonify(id=0, price=0)
    except stripe.error.APIConnectionError, e:
        # Network communication with Stripe failed
        flash('Could not connect to Stripe. Please try again.', 'error')
        return jsonify(id=0, price=0)
    except stripe.error.StripeError, e:
        # Display a very generic error to the user
        flash('An unknown error occured when connecting to Stripe. Please try again.', 'error')
        return jsonify(id=0, price=0)

    company_subscription = CompanySubscription()
    company_subscription.company = current_user.company
    company_subscription.report_group = report_group
    company_subscription.stripe_id = subscription.id
    company_subscription.stripe_autorenew = 1
    company_subscription.current_period_start = datetime.fromtimestamp(
        int(subscription.current_period_start)
    ).strftime('%Y-%m-%d %H:%M:%S')
    company_subscription.current_period_end = datetime.fromtimestamp(
        int(subscription.current_period_end)
    ).strftime('%Y-%m-%d %H:%M:%S')
    company_subscription.amount_paid = report_group.get_price()
    report_group.enable_notifications()

    db.session.add(company_subscription)
    db.session.commit()
    flash('Thank you! You are now subscribed to %s.' % (company_subscription.report_group.report_group_name), 'success')

    sub_id = company_subscription.company_subscription_id
    price = report_group.get_price()
    group_name = report_group.report_group_name

    return jsonify(id=sub_id, price=price, group_name=group_name, group_id=group_id)


@mod_admin.route('/_renew')
@roles_accepted('brokeradmin')
def enable_autorenew_ajax():
    report_group = ReportGroup.query.get_or_404(request.args.get('groupid'))
    company_subscription = report_group.get_company_subscription()
    
    # Get the Stripe Customer and reactivate their current subscription
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    subscription = customer.subscriptions.retrieve(company_subscription.stripe_id)
    subscription.plan = report_group.stripe_id
    subscription.save()

    company_subscription.stripe_autorenew = 1

    db.session.commit()
    flash('Auto-renewal enabled for %s.' % (report_group.report_group_name), 'success')

    return jsonify(result=1)


@mod_admin.route('/_unrenew')
@roles_accepted('brokeradmin')
def disable_autorenew_ajax():
    report_group = ReportGroup.query.get_or_404(request.args.get('groupid'))
    company_subscription = report_group.get_company_subscription()
    
    # Get the Stripe Customer and delete their subscription at_period_end
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    customer.subscriptions.retrieve(company_subscription.stripe_id).delete(at_period_end=True)

    company_subscription.stripe_autorenew = 0

    db.session.commit()
    flash('Auto-renewal disabled for %s.' % (report_group.report_group_name), 'success')

    return jsonify(result=1)


## Broker/Dealers

@mod_admin.route('/brokerdealers')
@breadcrumbs.register_breadcrumb(mod_admin, '.brokerdealers', 'Broker/Dealers')
@roles_accepted('superadmin', 'admin')
def company_list():
    companies = Company.query.all()

    return render_template('admin/companies.html', companies=companies)


def company_info_dlc(*args, **kwargs):
    company_id = request.view_args['company_id']
    company = Company.query.get(company_id)
    return [{'text': company.company_name, 'url': url_for('admin.company_info', company_id=company_id)}]


@mod_admin.route('/brokerdealers/info/<int:company_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.brokerdealers.info', '',
                                 dynamic_list_constructor=company_info_dlc)
@roles_accepted('superadmin', 'admin')
def company_info(company_id):
    company = Company.query.get_or_404(company_id)

    data = {
        'company': company
    }

    return render_template('admin/companyinfo.html', data=data)


def company_edit_dlc(*args, **kwargs):
    company_id = request.view_args['company_id']
    company = Company.query.get(company_id)
    return [{'text': company.company_name, 'url': url_for('admin.company_info', company_id=company_id)},
            {'text': 'Edit Broker/Dealer', 'url': url_for('admin.edit_company', company_id=company_id)}]


@mod_admin.route('/brokerdealers/edit/<int:company_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.brokerdealers.edit', '',
                                 dynamic_list_constructor=company_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_company(company_id):
    company = Company.query.get_or_404(company_id)
    form = CompanyForm(obj=company,
                       programs=[p.program for p in company.valid_programs],
                       email_domains=[d.domain for d in company.valid_domains])
    if form.validate_on_submit():
        company.company_name = form.company_name.data

        checked_programs = request.form.getlist("programs")
        ValidProgram.query.filter_by(company_id=company_id).delete()
        for program_id in checked_programs:
            vp = ValidProgram()
            vp.company_id = company_id
            vp.program_id = program_id
            db.session.add(vp)

        checked_domains = request.form.getlist("email_domains")
        ValidDomain.query.filter_by(company_id=company_id).delete()
        for domain_id in checked_domains:
            vd = ValidDomain()
            vd.company_id = company_id
            vd.domain_id = domain_id
            db.session.add(vd)

        db.session.commit()
        flash('Saved changes to %s.' % (company.company_name), 'success')
        return redirect(url_for('admin.company_info', company_id=company_id))

    data = {
        'company': company
    }

    return render_template('admin/_form.html', data=data, form=form, title='Edit Broker/Dealer')


@mod_admin.route('/brokerdealers/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.brokerdealers.new', 'New Broker/Dealer')
@roles_accepted('superadmin', 'admin')
def new_company():
    form = CompanyForm()
    if form.validate_on_submit():
        company = Company()
        company.company_name = form.company_name.data
        db.session.add(company)
        db.session.commit()

        programs = request.form.getlist("programs")
        for program_id in programs:
            vp = ValidProgram()
            vp.company_id = company.company_id
            vp.program_id = program_id
            db.session.add(vp)

        domains = request.form.getlist("email_domains")
        for domain_id in domains:
            vd = ValidDomain()
            vd.company_id = company.company_id
            vd.domain_id = domain_id
            db.session.add(vd)

        db.session.commit()
        flash('Created new company %s.' % (company.company_name), 'success')

        return redirect(url_for('admin.company_info', company_id=company.company_id))

    data = {
        'programs': Program.query.all()
    }

    return render_template('admin/_form.html', data=data, form=form, title='New Broker/Dealer')


@mod_admin.route('/brokerdealers/delete/<int:company_id>')
@roles_accepted('superadmin', 'admin')
def del_company(company_id):
    company = Company.query.get_or_404(company_id)
    try:
        company.delete()
        flash('Broker/dealer deleted.', 'success')
    except RuntimeError, e:
        flash('Unable to delete group. %s' % str(e), 'error')
        return redirect(url_for('admin.company_info', company_id=company.company_id))

    return redirect(url_for('admin.company_list'))


@mod_admin.route('/brokerdealers/newdomain', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.brokerdealers.newdomain', 'New Domain')
@roles_accepted('superadmin', 'admin')
def new_domain():
    form = DomainForm()

    if request.method == 'POST':
        domain = EmailDomain()
        domain.domain_name = request.form["domain_name"]
        domain.date_created = datetime.utcnow()
        domain.who_created = current_user.email

        db.session.add(domain)
        db.session.commit()
        flash('Created new email domain %s.' % (domain.domain_name), 'success')

        return redirect(url_for('admin.company_list'))

    return render_template('admin/_form.html', form=form, title='Add New Email Domain')


@mod_admin.route('/brokerdealers/deletesubscription/<int:subscription_id>')
@roles_accepted('superadmin', 'admin')
def delete_company_subscription(subscription_id):
    subscription = CompanySubscription.query.get_or_404(subscription_id)
    report_group_name = subscription.report_group.report_group_name
    company_name = subscription.company.company_name

    if subscription.stripe_id:
        flash('This is a paid subscription. You must cancel or refund it through Stripe.', 'error')
    else:
        db.session.delete(subscription)
        db.session.commit()
        flash('Removed subscription from %s for %s.' % (report_group_name, company_name), 'success')

    return redirect(request.referrer)


@mod_admin.route('/brokerdealers/deletediscount/<int:company_discount_id>')
@roles_accepted('superadmin', 'admin')
def delete_company_discount(company_discount_id):
    company_discount = CompanyDiscount.query.get_or_404(company_discount_id)
    report_group_name = company_discount.report_group.report_group_name
    company_name = company_discount.company.company_name

    company_discount.delete()
    flash('Removed discount from %s for %s.' % (report_group_name, company_name), 'success')
    return redirect(request.referrer)


## Programs

@mod_admin.route('/programs')
@breadcrumbs.register_breadcrumb(mod_admin, '.programs', 'Programs')
@roles_accepted('superadmin', 'admin')
def programs_list():
    programs = Program.query.all()

    return render_template('admin/programs.html', programs=programs)


def program_info_dlc(*args, **kwargs):
    program_id = request.view_args['program_id']
    program = Program.query.get(program_id)
    return [{'text': program.program_name, 'url': url_for('admin.program_info', program_id=program_id)}]


@mod_admin.route('/programs/info/<int:program_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.programs.info', '',
                                 dynamic_list_constructor=program_info_dlc)
@roles_accepted('superadmin', 'admin')
def program_info(program_id):
    program = Program.query.get_or_404(program_id)

    data = {
        'program': program
    }

    return render_template('admin/programinfo.html', data=data)


def program_edit_dlc(*args, **kwargs):
    program_id = request.view_args['program_id']
    program = Program.query.get(program_id)
    return [{'text': program.program_name, 'url': url_for('admin.program_info', program_id=program_id)},
            {'text': 'Edit Program', 'url': url_for('admin.edit_program', program_id=program_id)}]


@mod_admin.route('/programs/edit/<int:program_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.programs.edit', '',
                                 dynamic_list_constructor=program_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_program(program_id):
    program = Program.query.get_or_404(program_id)
    form = ProgramForm(obj=program)

    if form.validate_on_submit():
        program.program_name = form.program_name.data
        program.sponsor = form.sponsor.data

        db.session.commit()
        flash('Saved changes to %s.' % (program.program_name), 'success')
        return redirect(url_for('admin.program_info', program_id=program_id))

    return render_template('admin/_form.html', form=form, title="Edit Program")


@mod_admin.route('/programs/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.programs.new', 'New Program')
@roles_accepted('superadmin', 'admin')
def new_program():
    form = ProgramForm()

    if form.validate_on_submit():
        program = Program()
        program.program_name = form.program_name.data
        program.sponsor = form.sponsor.data

        db.session.add(program)
        db.session.commit()
        flash('Created new program %s.' % (program.program_name), 'success')
        return redirect(url_for('admin.program_info', program_id=program.program_id))

    return render_template('admin/_form.html', form=form, title="New Program")


@mod_admin.route('/programs/delete/<int:program_id>')
@roles_accepted('superadmin', 'admin')
def del_program(program_id):
    program = Program.query.get_or_404(program_id)
    if program.protected:
        flash('You do not have permission to delete this program.', 'error')
    else:
        ValidProgram.query.filter_by(program_id=program_id).delete()    
        documents = Document.query.filter_by(program_id=program_id).all()
        for document in documents:
            document.program_id = 0
        db.session.commit()

        Program.query.filter_by(program_id=program_id).delete()
        db.session.commit()
        flash('Program deleted.', 'success')

    return redirect(url_for('admin.programs_list'))


## Report Folders

@mod_admin.route('/folders')
@breadcrumbs.register_breadcrumb(mod_admin, '.folders', 'Report Folders')
@roles_accepted('superadmin', 'admin')
def manage_folders():
    folders = ReportFolder.query.all()

    return render_template('admin/folders.html', folders=folders)


def report_folder_info_dlc(*args, **kwargs):
    report_folder_id = request.view_args['report_folder_id']
    report_folder = ReportFolder.query.get(report_folder_id)
    return [{'text': report_folder.report_folder_name, 'url': url_for('admin.folder_info', report_folder_id=report_folder_id)}]


@mod_admin.route('/folders/info/<int:report_folder_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.folders.info', '',
                                 dynamic_list_constructor=report_folder_info_dlc)
@roles_accepted('superadmin', 'admin')
def folder_info(report_folder_id):
    folder = ReportFolder.query.get_or_404(report_folder_id)

    data = {
        'folder': folder
    }

    return render_template('admin/folderinfo.html', data=data)


def report_folder_edit_dlc(*args, **kwargs):
    report_folder_id = request.view_args['report_folder_id']
    report_folder = ReportFolder.query.get(report_folder_id)
    return [{'text': report_folder.report_folder_name, 'url': url_for('admin.folder_info', report_folder_id=report_folder_id)},
            {'text': 'Edit Report Folder', 'url': url_for('admin.edit_folder', report_folder_id=report_folder_id)}]


@mod_admin.route('/folders/edit/<int:report_folder_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.folders.edit', '',
                                 dynamic_list_constructor=report_folder_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_folder(report_folder_id):
    folder = ReportFolder.query.get_or_404(report_folder_id)
    form = ReportFolderForm(obj=folder)

    if form.validate_on_submit():
        name_change = False
        if folder.report_folder_name != form.report_folder_name.data:
            folder.report_folder_name = form.report_folder_name.data
            name_change = True
        folder.report_group = form.report_group.data

        if name_change and app.config['AMAZON_WEB_SERVICES_KEYS']:
            # Connect to S3
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
            folder_documents = Document.query.filter_by(report_folder_id=report_folder_id).\
                                              filter_by(document_server='s3').all()
            for document in folder_documents:
                # Update location on S3
                s3key = "%s/%s" % (folder.report_folder_name, document.document_name)
                # Check for duplicates before moving
                duplicate_doc = Document.query.filter_by(document_data=s3key).first()
                if duplicate_doc:
                    if int(duplicate_doc.document_id) != int(document.document_id):
                        flash('File %s already exists in this report folder. \
                              Please choose a new file name or edit the existing file.' % document.document_name,
                              'error')
                        return redirect(url_for('admin.edit_folder', report_folder_id=report_folder_id))
                # Copy to the new key
                copy_source = "%s/%s" % (app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'], document.document_data)
                s3.Object(s3key).copy_from(CopySource=copy_source,
                                           ContentType=document.document_type,
                                           ACL='public-read'
                                          )
                # Delete original key
                s3.Object(document.document_data).delete()
                # Update key in database
                document.document_data = s3key

        db.session.commit()
        flash('Saved changes to %s.' % (folder.report_folder_name), 'success')
        return redirect(url_for('admin.folder_info', report_folder_id=report_folder_id))

    return render_template('admin/_form.html', form=form, title='Edit Report Folder')


@mod_admin.route('/folders/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.folders.new', 'New Report Folder')
@roles_accepted('superadmin', 'admin')
def new_folder():
    form = ReportFolderForm()

    if form.validate_on_submit():
        folder = ReportFolder()
        folder.report_folder_name = form.report_folder_name.data
        folder.report_group = form.report_group.data

        db.session.add(folder)
        db.session.commit()
        flash('Created new folder %s.' % (folder.report_folder_name), 'success')
        return redirect(url_for('admin.folder_info', report_folder_id=folder.report_folder_id))

    return render_template('admin/_form.html', form=form, title='New Report Folder')


@mod_admin.route('/folders/delete/<int:report_folder_id>')
@roles_accepted('superadmin', 'admin')
def del_folder(report_folder_id):
    folder = ReportFolder.query.get_or_404(report_folder_id)
    if folder.protected:
        flash('You do not have permission to delete this folder.', 'error')
    else:
        documents = Document.query.filter_by(report_folder_id=report_folder_id).all()
        # Connect to S3
        if app.config['AMAZON_WEB_SERVICES_KEYS']:
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
        for document in documents:
            # Set all documents to folder None
            document.report_folder_id = None        

            # Update location on S3
            if document.document_server == 's3':
                s3key = "%s/%s" % ('None', document.document_name)
                # Check for duplicates before moving
                duplicate_doc = Document.query.filter_by(document_data=s3key).first()
                if duplicate_doc:
                    if int(duplicate_doc.document_id) != int(document.document_id):
                        flash('File %s already exists in the document root. \
                               Please reassign or delete this document.' % document.document_name,
                               'error')
                        return redirect(url_for('admin.folder_info', report_folder_id=report_folder_id))
                # Copy to the new key
                copy_source = "%s/%s" % (app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'], document.document_data)
                s3.Object(s3key).copy_from(CopySource=copy_source,
                                           ContentType=document.document_type,
                                           ACL='public-read'
                                          )
                # Delete original key
                s3.Object(document.document_data).delete()
                # Update key in database
                document.document_data = s3key
        db.session.commit()

        # Delete the folder
        ReportFolder.query.filter_by(report_folder_id=report_folder_id).delete()
        db.session.commit()
        if documents:
            flash('Folder deleted. All documents have been reassigned to the "None" folder.', 'success')
        else:
            flash('Folder deleted.', 'success')

    return redirect(url_for('admin.manage_folders'))


## Subscription Groups

@mod_admin.route('/groups')
@breadcrumbs.register_breadcrumb(mod_admin, '.groups', 'Subscription Groups')
@roles_accepted('superadmin', 'admin')
def manage_groups():
    groups = ReportGroup.query.all()

    return render_template('admin/groups.html', groups=groups)


def report_group_info_dlc(*args, **kwargs):
    report_group_id = request.view_args['report_group_id']
    report_group = ReportGroup.query.get(report_group_id)
    return [{'text': report_group.report_group_name, 'url': url_for('admin.group_info', report_group_id=report_group_id)}]


@mod_admin.route('/groups/info/<int:report_group_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.groups.info', '',
                                 dynamic_list_constructor=report_group_info_dlc)
@roles_accepted('superadmin', 'admin')
def group_info(report_group_id):
    group = ReportGroup.query.get_or_404(report_group_id)

    data = {
        'group': group
    }

    return render_template('admin/groupinfo.html', data=data)


def report_group_edit_dlc(*args, **kwargs):
    report_group_id = request.view_args['report_group_id']
    report_group = ReportGroup.query.get(report_group_id)
    return [{'text': report_group.report_group_name, 'url': url_for('admin.group_info', report_group_id=report_group_id)},
            {'text': 'Edit Subscription Group', 'url': url_for('admin.edit_group', report_group_id=report_group_id)}]


@mod_admin.route('/groups/edit/<int:report_group_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.groups.edit', '',
                                 dynamic_list_constructor=report_group_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_group(report_group_id):
    group = ReportGroup.query.get_or_404(report_group_id)
    form = ReportGroupForm(obj=group)

    if form.validate_on_submit():
        group.report_group_name = form.report_group_name.data
        group.price = form.price.data

        # Create paid plans on Stripe's servers
        if group.price > 0:
            try:
                group.stripe_id = "pln_%s" % datetime.utcnow().strftime('%s')
                plan = stripe.Plan.create(
                    amount = int(group.price * 100),
                    interval = 'year',
                    name = group.report_group_name,
                    currency = 'usd',
                    id = group.stripe_id
                )
            except: # Plan already exists, update existing plan
                plan = stripe.Plan.retrieve(group.stripe_id)
                plan.name = group.report_group_name
                plan.save()

        db.session.commit()
        flash('Saved changes to %s.' % (group.report_group_name), 'success')
        return redirect(url_for('admin.group_info', report_group_id=group.report_group_id))

    return render_template('admin/editgroup.html', form=form, group=group)


@mod_admin.route('/groups/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.groups.new', 'New Subscription Group')
@roles_accepted('superadmin', 'admin')
def new_group():
    form = ReportGroupForm()
    
    if form.validate_on_submit():
        group = ReportGroup()
        group.report_group_name = form.report_group_name.data
        group.price = form.price.data

        # Create paid plans on Stripe
        if group.price > 0:
            try:
                group.create_stripe_plan()
            except Exception, e:
                flash(str(e), 'error')
                return render_template('admin/newgroup.html', form=form)

        db.session.add(group)
        db.session.commit()
        flash('Created new group %s.' % (group.report_group_name), 'success')
        return redirect(url_for('admin.group_info', report_group_id=group.report_group_id))

    return render_template('admin/newgroup.html', form=form)


@mod_admin.route('/groups/delete/<int:report_group_id>')
@roles_accepted('superadmin', 'admin')
def del_group(report_group_id):
    group = ReportGroup.query.get_or_404(report_group_id)
    try:
        group.delete()
        flash('Group deleted.', 'success')
    except RuntimeError, e:
        flash('Unable to delete group. %s' % str(e), 'error')
        return redirect(url_for('admin.group_info', report_group_id=group.report_group_id))

    return redirect(url_for('admin.manage_groups'))


## Sponsors

@mod_admin.route('/sponsors')
@breadcrumbs.register_breadcrumb(mod_admin, '.sponsors', 'Sponsors')
@roles_accepted('superadmin', 'admin')
def sponsors_list():
    sponsors = Sponsor.query.all()

    return render_template('admin/sponsors.html', sponsors=sponsors)


def sponsor_info_dlc(*args, **kwargs):
    sponsor_id = request.view_args['sponsor_id']
    sponsor = Sponsor.query.get(sponsor_id)
    return [{'text': sponsor.sponsor_name, 'url': url_for('admin.sponsor_info', sponsor_id=sponsor_id)}]


@mod_admin.route('/sponsors/info/<int:sponsor_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_admin, '.sponsors.info', '',
                                 dynamic_list_constructor=sponsor_info_dlc)
@roles_accepted('superadmin', 'admin')
def sponsor_info(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)

    data = {
        'sponsor': sponsor
    }

    return render_template('admin/sponsorinfo.html', data=data)


def sponsor_edit_dlc(*args, **kwargs):
    sponsor_id = request.view_args['sponsor_id']
    sponsor = Sponsor.query.get(sponsor_id)
    return [{'text': sponsor.sponsor_name, 'url': url_for('admin.sponsor_info', sponsor_id=sponsor_id)},
            {'text': 'Edit Sponsor', 'url': url_for('admin.edit_sponsor', sponsor_id=sponsor_id)}]


@mod_admin.route('/sponsors/edit/<int:sponsor_id>', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.sponsors.edit', '',
                                 dynamic_list_constructor=sponsor_edit_dlc)
@roles_accepted('superadmin', 'admin')
def edit_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    form = SponsorForm(obj=sponsor)

    if form.validate_on_submit():
        sponsor.sponsor_name = form.sponsor_name.data

        db.session.commit()
        flash('Saved changes to %s.' % (sponsor.sponsor_name), 'success')
        return redirect(url_for('admin.sponsor_info', sponsor_id=sponsor_id))

    return render_template('admin/_form.html', form=form, title='Edit Sponsor')


@mod_admin.route('/sponsors/new', methods=['GET', 'POST'])
@breadcrumbs.register_breadcrumb(mod_admin, '.sponsors.new', 'New Sponsor')
@roles_accepted('superadmin', 'admin')
def new_sponsor():
    form = SponsorForm()

    if form.validate_on_submit():
        sponsor = Sponsor()
        sponsor.sponsor_name = form.sponsor_name.data

        db.session.add(sponsor)
        db.session.commit()
        flash('Created new sponsor %s.' % (sponsor.sponsor_name), 'success')
        return redirect(url_for('admin.sponsor_info', sponsor_id=sponsor.sponsor_id))

    return render_template('admin/_form.html', form=form, title='New Sponsor')


@mod_admin.route('/sponsors/delete/<int:sponsor_id>')
@roles_accepted('superadmin', 'admin')
def del_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    if sponsor.protected:
        flash('You do not have permission to delete this sponsor.', 'error')
    else:
        programs = Program.query.filter_by(sponsor_id=sponsor_id).all()
        for program in programs:
            program.sponsor_id = 0
        db.session.commit()

        Sponsor.query.filter_by(sponsor_id=sponsor_id).delete()
        db.session.commit()
        flash('Sponsor deleted.', 'success')

    return redirect(url_for('admin.sponsors_list'))


## Reports

@mod_admin.route('/reports/downloads')
@breadcrumbs.register_breadcrumb(mod_admin, '.downloadreport', 'Download Report')
@roles_accepted('superadmin', 'admin', 'brokeradmin', 'broker')
def download_report():
    documents = Document.query.all()
    downloads = Download.query.all()
    year_selected = 0
    if request.args.get('year'):
        year_selected = int(request.args.get('year'))
    if year_selected > 0:
        downloads = Download.query.filter(Download.downloaded_at > ('%s-01-01 00:00:00' % year_selected)).\
                    filter(Download.downloaded_at < ('%s-12-31 23:59:59' % year_selected)).all()
    folders = ReportFolder.query.all()
    no_folder = ReportFolder()
    no_folder.report_folder_id = 0
    no_folder.report_folder_name = 'None'
    folders.append(no_folder)

    # For Brokers, remove downloads from outside of company
    if current_user.has_role('brokeradmin') or current_user.has_role('broker'):
        for download in downloads:
            try:
                if download.user.company_id != current_user.company_id:
                    downloads.remove(download)
            except:
                downloads.remove(download)

    # Only display documents with downloads (within valid programs, for brokers)
    documents_with_downloads = []
    for document in documents:
        if len(document.downloads) > 0:
            if current_user.has_role('superadmin') or current_user.has_role('admin'):
                documents_with_downloads.append(document)
            elif document.is_valid():
                documents_with_downloads.append(document)

    # Filter only this year's downloads
    for document in documents_with_downloads:
        document.year_downloads = 0
        if year_selected > 0:
            for download in document.downloads:
                if int(download.downloaded_at.strftime('%Y')) == year_selected:
                    document.year_downloads += 1
        else:
            document.year_downloads = len(document.downloads)
    for document in documents_with_downloads:
        if document.year_downloads == 0:
            documents_with_downloads.remove(document)

    # Assign colors based on report folder name
    for folder in folders:
        folder.color = Color(pick_for=folder.report_folder_name)

    # Build the totals array by iterating through Downloads and building a Matrix
    totals = {}
    for download in downloads:
        if download.document.report_folder:
            folder_id = int(download.document.report_folder.report_folder_id)
        else:
            folder_id = 0
        download_month = download.downloaded_at.strftime('%B')
        try:
            totals[folder_id,download_month] += 1
        except KeyError:
            totals[folder_id,download_month] = 1

    # Find the first year with downloads and build the Year dropdown until today
    years = []
    current_year = int(datetime.utcnow().strftime('%Y'))
    first_year = current_year
    if downloads:
        first_year = int(Download.query.order_by(Download.downloaded_at).first().downloaded_at.strftime('%Y'))
    for year in reversed(range(first_year, current_year+1)):
        years.append(year)

    data = {
        'documents': documents_with_downloads,
        'downloads': downloads,
        'folders': folders,
        'totals': totals,
        'years': years,
        'year_selected': year_selected
    }
    
    return render_template('admin/downloads.html', data=data)


@mod_admin.route('/reports/matrix')
@breadcrumbs.register_breadcrumb(mod_admin, '.matrix', 'Matrix')
@roles_accepted('superadmin', 'admin')
def matrix():
    companies = Company.query.all()
    programs = Program.query.all()

    for company in companies:
        company_id = company.company_id
        company.valid_programs = ValidProgram.query.filter_by(company_id=company_id).all()
        company.programs = []
        for valid_program in company.valid_programs:
            company.programs.append(valid_program.program)

    data = {
        'companies': companies,
        'programs': programs
    }
    return render_template('admin/matrix.html', data=data)
