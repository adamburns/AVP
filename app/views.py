from flask import render_template, request, redirect, url_for, flash,\
                  send_file, session, make_response, jsonify, g
from flask_security import login_required, roles_accepted, current_user, utils
from flask_security.changeable import change_user_password
from flask_security.confirmable import send_confirmation_instructions,\
                                       generate_confirmation_link
import boto3
from datetime import datetime, timedelta
from io import BytesIO
import json
from PyPDF2 import PdfFileWriter, PdfFileReader
from random import SystemRandom
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import re
from sqlalchemy.exc import IntegrityError
from string import ascii_uppercase, digits
import StringIO
from app import app, db, slack, user_datastore
from app.forms import SetPasswordForm, RequestForm, ManageAccountForm
from app.models import Document, Role, User, ValidProgram, Download,\
                       ValidDomain, EmailQueue, ReportGroup,\
                       CompanyDiscount
from app.util.email import send_email


@app.before_request
def load_user():
    if current_user.is_authenticated:
        g.valid_programs = ValidProgram.query.\
                           filter_by(company_id=current_user.company_id).\
                           all()


## Error handlers and static files

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if app.config['SLACK_KEY'] and app.config['SLACK_CHANNEL']:
        slack.chat.post_message(app.config['SLACK_CHANNEL'],
                                "Error: %s" % error,
                                username=app.config['APP_NAME'],
                                icon_url="%s%s" % (app.config['BASE_URL'],
                                url_for('static',
                                        filename='images/stripelogo.png')))
    return render_template('500.html'), 500

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    ten_days_ago = datetime.utcnow() - timedelta(days=10)

    sitemap_xml = render_template('sitemap.xml', date=ten_days_ago)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"

    return response

@app.route('/robots.txt', methods=['GET'])
def robotstxt():
    return render_template('_robots.txt')


## Home

@app.route('/')
def index():
    if current_user.is_active:
        return redirect(url_for('login_redirect'))
    return render_template('index.html')


@app.route('/redirect/')
@login_required
def login_redirect():
    if current_user.login_count == 1:
        return redirect(url_for('new_user_set_password'))
    elif current_user.has_role('superadmin') or current_user.has_role('admin')\
         or current_user.has_role('brokeradmin') or current_user.has_role('broker'):
        return redirect(url_for('admin.dashboard'))
    else:
        current_user.check_subscriptions()
        return redirect(url_for('user.dashboard'))


## Registration

@app.route('/request/', methods=['GET', 'POST'])
def request_access():
    form = RequestForm()

    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        phone = form.phone.data
        company = form.company.data
        broker_dealer = form.broker_dealer.data
        advisor_number = form.advisor_number.data

        user = User.query.filter_by(email=email).first()

        # If user preregistered, send registration email; otherwise send message to admin
        if user:
            if user.login_count == 0 and not user.review_status:
                confirmation_link, token = generate_confirmation_link(user)
                utils.send_mail("Your %s account" % app.config['APP_NAME'], user.email, 'welcome',
                                user=user, confirmation_link=confirmation_link)

                user.active = 1
                db.session.commit()

                title = 'Account Activated'
                message = 'You have been pre-approved! Check your email for a link to activate your account.'
                outcome = 'success'
            elif user.review_status == 'PENDING':
                title = 'Account In Review'
                message = 'Your account is still in review.<br/>\
                           Please contact <a href="mailto:%s">%s</a> with any questions.'\
                           % (app.config['CONTACT_EMAIL'], app.config['CONTACT_EMAIL'])
                outcome = 'warning'
            elif user.review_status == 'DENIED':
                title = 'Account Denied'
                message = 'Your account was denied access.<br/><strong>Reason:</strong> %s<br/>\
                           Please contact <a href="mailto:%s">%s</a> with any questions.'\
                           % (user.review_reason, app.config['CONTACT_EMAIL'], app.config['CONTACT_EMAIL'])
                outcome = 'danger'
            else:
                title = 'Account Exists'
                message = 'An account with this email address already exists.<br/>\
                           Please use the <a href="/reset">Forgot Password form</a> if you have forgotten your credentials.'
                outcome = 'warning'
        else:
            password = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(12))
            user = user_datastore.create_user(email=email, password=utils.encrypt_password(password),
                                              first_name=first_name, last_name=last_name,
                                              crd_number=advisor_number, phone=phone,
                                              active=False, login_count=0, review_status='PENDING')
            user.company = company
            role = Role.query.filter_by(name='advisor').first()
            user_datastore.add_role_to_user(user, role)
            user.broker_dealer = broker_dealer

            send_email("%s access request confirmation" % app.config['APP_NAME'],
                       app.config['SECURITY_EMAIL_SENDER'],
                       ["%s %s" % (user.first_name, user.last_name), user.email],
                       render_template('email/request_user.txt', user=user),
                       render_template('email/request_user.html', user=user))
            send_email("New %s user request: %s %s" % (app.config['APP_NAME'], user.first_name, user.last_name),
                       app.config['SECURITY_EMAIL_SENDER'],
                       app.config['ADMINS'],
                       render_template('email/request_admin.txt', user=user),
                       render_template('email/request_admin.html', user=user))

            db.session.add(user)
            db.session.commit()
            title = 'Account Requested'
            message = 'Your request has been submitted. You will receive an email as soon as your account is reviewed.<br/>\
                       Thank you!'
            outcome = 'success'
        return render_template('confirmation.html', title=title, message=message, outcome=outcome)

    return render_template('request.html', form=form)


@app.route('/_check_domain')
def check_domain():
    email = request.args.get('email')
    try:
        email_domain = re.search('@.*', email).group().lstrip('@')
        domain_found = ValidDomain.query.filter(ValidDomain.domain.has(domain_name=email_domain)).all()
        if len(domain_found) == 1:
            company_id = domain_found[0].company_id
            return jsonify(result=company_id)
    except AttributeError:
        pass
    except TypeError:
        pass
    return jsonify(result=0)


## Account Management

@app.route('/account/', methods=['GET', 'POST'])
@login_required
def account():
    form = ManageAccountForm(obj=current_user)

    if form.validate_on_submit():
        try:
            current_user.first_name = form.first_name.data
            current_user.last_name = form.last_name.data
            current_user.notification_rate = form.notification_rate.data
            current_user.time_zone = form.time_zone.data
            if current_user.email != form.email.data:
                current_user.email = form.email.data
                current_user.confirmed_at = None
                db.session.commit()
                send_confirmation_instructions(current_user)
                flash('You must log in again using your new email. Please click the verification link sent to %s.' % (request.form["email"]))
                utils.logout_user()
                return redirect(url_for('index'))

            db.session.commit()
            flash('Saved changes to your account.', 'success')
            return redirect(url_for('index'))
        except IntegrityError:
            flash('Email already registered. Please use a different email address.', 'error')
            db.session.rollback()

    return render_template('manageaccount.html', form=form)

@app.route('/setpassword/', methods=['GET', 'POST'])
@login_required
def new_user_set_password():
    form = SetPasswordForm()

    if request.method == 'GET':
        if current_user.login_count > 1:
            return redirect('/change')

    if request.method == 'POST':
        if form.validate_on_submit():
            password = request.form["password"]
            current_user.time_zone = request.form["time_zone"]

            change_user_password(current_user, password)
            current_user.login_count += 1
            db.session.commit()
            flash("Password set, you are now logged in!", 'success')
            
            return redirect(url_for('login_redirect'))

    return render_template('security/set_password.html', form=form)


## Document access

@app.route('/download/<int:document_id>', methods=['GET'])
@app.route('/view/<int:document_id>', methods=['GET'])
@app.route('/preview/<int:document_id>', methods=['GET'])
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # If not an admin, check if user has access to the given file; send to Unauthorized if not
    if current_user.has_role('alladvisor') or current_user.has_role('advisor') or current_user.has_role('user'):
        if not document.is_valid() or not document.is_subscribed():
            if not 'preview' in request.path and not document.is_free_access() and not document.get_purchase():
                flash('You are not authorized to access this report.', 'error')
                return redirect(url_for('index'))

    # Log the download
    download = Download()
    download.document_id = document_id
    download.user_id = current_user.id
    download.downloaded_at = datetime.utcnow()
    db.session.add(download)
    db.session.commit()

    # Initialize Amazon S3
    if app.config['AMAZON_WEB_SERVICES_KEYS']:
        aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                    aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                    region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
        s3resource = aws.resource('s3')
        s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])

    # If not an admin, add a watermark to PDFs
    if 'pdf' in document.document_type and (current_user.has_role('advisor') or current_user.has_role('user')):
        # create a new PDF with Reportlab
        if 'preview' in request.path:
            watermark = "%s %s - PREVIEW" % (current_user.first_name, current_user.last_name)
        else:
            watermark = "%s %s - %s" % (current_user.first_name, current_user.last_name,
                                        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        packet = StringIO.StringIO()
        can = canvas.Canvas(packet, pagesize=letter)
        can.setFont("Helvetica", 36)
        can.setFillColorRGB(0.5, 0.5, 0.5, alpha=0.5)
        can.rotate(45)
        can.drawString(100, 0, watermark)
        can.save()

        # Move to the beginning of the StringIO buffer
        packet.seek(0)
        new_pdf = PdfFileReader(packet)
        # Read existing PDF
        existing_data = BytesIO()
        if s3 and document.document_server == 's3':
            s3object = s3.Object(document.document_data)
            body = s3object.get()
            body = body['Body']
            # Write the file in chunks to prevent memory overload
            for chunk in iter(lambda: body.read(4096), b''):
                existing_data.write(chunk)
        else:
            existing_data.write(document.document_data)
        existing_pdf = PdfFileReader(existing_data)
        output = PdfFileWriter()
        # Limit preview to 1 page
        if 'preview' in request.path:
            max_pages = 1
        else:
            max_pages = existing_pdf.getNumPages()
        # Add the "watermark" (which is the new pdf) on the existing pages
        for page in range(0, max_pages):
            page = existing_pdf.getPage(page)
            page.mergePage(new_pdf.getPage(0))
            output.addPage(page)
        # Finally, write "output" to a file
        document_data = BytesIO()
        output.write(document_data)
        document_data.seek(0)
    else:
        # Download the document
        document_data = BytesIO()
        if s3 and document.document_server == 's3':
            s3object = s3.Object(document.document_data)
            body = s3object.get()
            body = body['Body']
            # Write the file in chunks to prevent memory overload
            for chunk in iter(lambda: body.read(4096), b''):
                document_data.write(chunk)
        else:
            document_data.write(document.document_data)
        document_data.seek(0)

    if 'view' in request.path:
        if 'video' in document.document_type or 'audio' in document.document_type:
            return render_template('_mediaviewer.html', document=document, document_data=document_data)
        else:
            return send_file(document_data, mimetype=document.document_type, attachment_filename=document.document_name)
    else:
        return send_file(document_data, attachment_filename=document.document_name, as_attachment=True)


## Help

@app.route('/help/')
def help_index():
    return render_template('help.html')


## Miscellaneous functions

@app.route('/unsubscribe/')
def global_unsubscribe():
    """Mailgun Unsubscribe endpoint, users are forwarded to here after unsubscribing."""
    md_email = request.args.get('md_email')
    flash('Your email address, %s, has been unsubscribed from all mailing lists.' % md_email, 'success')
    return redirect(url_for('index'))


@app.route('/demo/changerole/<int:role_id>')
@login_required
def demo_change_role(role_id):
    """In Demo Mode, allows users to quickly change to other roles."""
    if not app.config['DEMO_MODE']:
        flash('App is not in Demo Mode.', 'danger')
        return redirect(url_for('index'))

    selected_role = Role.query.get_or_404(role_id)
    roles = Role.query.all()
    for role in roles:
        if role.id == role_id:
            user_datastore.add_role_to_user(current_user, role)
        else:
            user_datastore.remove_role_from_user(current_user, role)
    db.session.commit()

    flash('Your role is now %s.' % selected_role.description, 'success')
    return redirect(url_for('index'))


@app.route('/sendnotifications/')
def send_notifications():
    """Send all queued notifications from EmailQueue."""
    notification_queue = EmailQueue.query.filter_by(time_sent=None).order_by(EmailQueue.user_id).all()
    
    # Find users due for notifications
    to_notify = []
    for notification in notification_queue:
        last_notified = notification.user.last_notified or notification.user.confirmed_at or notification.user.time_created
        if (datetime.utcnow() - timedelta(days=notification.user.notification_rate)) > last_notified:
            to_notify.append(notification)

    # Iterate through the users to notify
    last_user = User()
    last_user.id = 0
    documents = []
    for notification in to_notify:
        notification.time_sent = datetime.utcnow()
        if last_user.id > 0 and notification.user_id != last_user.id:
            to_email = []
            to_email.append(("%s %s" % (last_user.first_name, last_user.last_name), last_user.email))
            send_email("New reports available at %s" % app.config['APP_NAME'],
                       app.config['SECURITY_EMAIL_SENDER'],
                       to_email,
                       render_template('email/digest.txt', user=last_user, documents=documents),
                       render_template('email/digest.html', user=last_user, documents=documents))
            last_user.last_notified = datetime.utcnow()
            documents = []

        documents.append(notification.document)
        last_user = notification.user

    # Pop the last email
    if last_user.id > 0:
        to_email = []
        to_email.append(("%s %s" % (last_user.first_name, last_user.last_name), last_user.email))
        send_email("New reports available at %s" % app.config['APP_NAME'],
                   app.config['SECURITY_EMAIL_SENDER'],
                   to_email,
                   render_template('email/digest.txt', user=last_user, documents=documents),
                   render_template('email/digest.html', user=last_user, documents=documents))
        last_user.last_notified = datetime.utcnow()

    db.session.commit()
    return redirect(url_for('index'))

# Stripe webhook handler
@app.route('/_stripe', methods=['POST'])
def stripe_webhook():
    """Respond to Stripe's webhooks (see https://stripe.com/docs/webhooks)."""
    event_json = request.get_json()
    event_type = event_json['type']
    event_object = event_json['data']['object']
    try:
        event_object_id = event_object['id']
    except KeyError:
        event_object_id = None

    # Response message - Assume failure until success occurs
    # Stripe expects 2xx or will repeat requests every 15 minutes for 24 hours
    # Use 202 for failure, 200 for success
    status = 202
    message = 'Unknown error'

    # Log the event
    print "Stripe Webhook Event: %s %s - %s" % (event_type, event_object_id, event_object)

    if event_type == 'plan.created':
        group = ReportGroup.query.filter_by(stripe_id=event_object_id).first()
        if not group:
            group = ReportGroup()
            group.stripe_id = event_object_id
            group.report_group_name = event_object['name']
            group.price = event_object['amount']
            db.session.add(group)
            db.session.commit()
            status = 200
            message = 'Successfully created %s' % group.report_group_name
        else:
            status = 200
            message = 'Group %s already exists' % group.report_group_name
    elif event_type == 'plan.updated':
        group = ReportGroup.query.filter_by(stripe_id=str(event_object_id)).first()
        if group:
            group.report_group_name = event_object['name']
            group.price = event_object['amount']
            db.session.commit()
            status = 200
            message = 'Successfully updated %s' % group.report_group_name
        else:
            message = 'Unknown plan %s' % event_object_id
    elif event_type == 'plan.deleted':
        group = ReportGroup.query.filter_by(stripe_id=event_object_id).first()
        if group:
            try:
                group.delete()
                status = 200
                message = 'Successfully deleted group'
            except RuntimeError as e:
                message = 'Unable to delete group: %s' % e.value
        else:
            status = 200
            message = 'Group already deleted or does not exist'
    elif event_type == 'coupon.created':
        status = 200
        message = 'Coupon created outside of software, ignoring'
    elif event_type == 'coupon.deleted':
        CompanyDiscount.query.filter_by(stripe_id=event_object_id).delete()
        status = 200
        message = 'Coupon deleted, deleted all matching local Stripe IDs'
    else:
        status = 200
        message = 'Unhandled/unknown request type %s' % event_type

    if status != 200 and app.config['SLACK_KEY'] and app.config['SLACK_CHANNEL']:
        slack.chat.post_message(app.config['SLACK_CHANNEL'],
                                "Stripe Error: %s" % message,
                                username=app.config['APP_NAME'],
                                icon_url="%s%s" % (app.config['BASE_URL'], url_for('static', filename='images/stripelogo.png')))
    response_message = {
        'status': status,
        'message': message
    }
    resp = jsonify(response_message)
    resp.status_code = status

    return resp
