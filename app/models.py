from flask import request, g, render_template, url_for, session
from flask_security import RoleMixin, UserMixin, current_user, utils
from flask_security.confirmable import generate_confirmation_link
from flask_sqlalchemy import event
import boto3
from datetime import datetime
from dateutil.relativedelta import relativedelta
import json
from sqlalchemy import desc, event, PrimaryKeyConstraint
from app import app, db, stripe
from app.decorators import async
from app.util.email import send_email


def on_create_audited(mapper, connection, audited):
    audited.time_created = datetime.utcnow()
    try:
        audited.who_created = current_user.email
    except AttributeError:
        audited.who_created = request.environ['REMOTE_ADDR']


def on_update_audited(mapper, connection, audited):
    audited.time_modified = datetime.utcnow()
    try:
        audited.who_modified = current_user.email
    except AttributeError:
        audited.who_modified = request.environ['REMOTE_ADDR']


def on_sent(mapper, connection, audited):
    audited.time_sent = datetime.utcnow()
    try:
        audited.who_sent = current_user.email
    except AttributeError:
        audited.who_sent = request.environ['REMOTE_ADDR']


class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    __table_args__ = (
        PrimaryKeyConstraint('user_id', 'role_id'),
    )

    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'), nullable=False)


class Company(db.Model):
    __tablename__ = 'companies'
    company_id = db.Column(db.Integer(), primary_key=True)
    company_name = db.Column(db.String(255), nullable=False)
    protected = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

    users = db.relationship('User', backref=db.backref('Company'))
    valid_domains = db.relationship('ValidDomain', backref=db.backref('Company'))
    valid_programs = db.relationship('ValidProgram', backref=db.backref('Company'))
    company_subscriptions = db.relationship('CompanySubscription', backref=db.backref('Company'))
    company_discounts = db.relationship('CompanyDiscount', backref=db.backref('Company'))

    def delete(self):
        company_id = self.company_id
        if self.protected:
            raise RuntimeError('You do not have permission to delete this group.')
        for subscription in self.company_subscriptions:
            if subscription.stripe_id:
                raise RuntimeError('You must first cancel or refund any existing paid subscriptions for this company.')
        CompanySubscription.query.filter_by(company_id=company_id).delete()
        CompanyDiscount.query.filter_by(company_id=company_id).delete()
        ValidProgram.query.filter_by(company_id=company_id).delete()
        ValidDomain.query.filter_by(company_id=company_id).delete()
        company_users = User.query.filter_by(company_id=company_id).all()
        for user in company_users:
            user.company_id = None
        db.session.commit()

        Company.query.filter_by(company_id=company_id).delete()
        db.session.commit()
        return True

event.listen(Company, 'before_insert', on_create_audited)
event.listen(Company, 'before_update', on_update_audited)


class ReportGroup(db.Model):
    __tablename__ = 'report_groups'
    report_group_id = db.Column(db.Integer(), primary_key=True)
    report_group_name = db.Column(db.String(100), unique=True, nullable=False)
    stripe_id = db.Column(db.String(32))
    price = db.Column(db.Float())
    protected = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

    folders = db.relationship('ReportFolder', backref=db.backref('ReportGroup'))
    subscriptions = db.relationship('ReportSubscription', backref=db.backref('ReportGroup'))

    def create_stripe_plan(self):
        if self.price > 0:
            try:
                self.stripe_id = "pln_%s" % datetime.utcnow().strftime('%s')
                return stripe.Plan.create(
                    amount = int(self.price * 100),
                    interval = 'year',
                    name = self.report_group_name,
                    currency = 'usd',
                    id = self.stripe_id,
                    metadata = {
                        'report_group': self.report_group_name
                    }
                )
            except stripe.error.InvalidRequestError, e:
                raise Exception('Stripe error: %s' % str(e.message))
            except stripe.error.RateLimitError, e:
                raise Exception('Too many requests to Stripe. Please try again.')
            except stripe.error.AuthenticationError, e:
                raise Exception('Stripe could not authenticate. Please try again.')
            except stripe.error.APIConnectionError, e:
                raise Exception('Could not connect to Stripe. Please try again.')
            except stripe.error.StripeError, e:
                raise Exception('An unknown error occured when connecting to Stripe. Please try again.')
        else:
            raise Exception('Plan must have a price before submitting to Stripe.')

    def get_subscription_period(self):
        subscription = ReportSubscription.query.\
                       filter_by(user_id=current_user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       first()

        date_after_year = subscription.time_created + relativedelta(years=1)
        return date_after_year.strftime('%Y/%m/%d')

    def get_subscription(self):
        return ReportSubscription.query.\
               filter_by(user_id=current_user.id).\
               filter_by(report_group_id=self.report_group_id).\
               first()

    def get_subscription_renew(self):
        subscription = ReportSubscription.query.\
                       filter_by(user_id=current_user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       first()

        return subscription.stripe_autorenew

    def get_company_subscription(self):
        company_subscription = CompanySubscription.query.\
                               filter_by(company_id=current_user.company_id).\
                               filter_by(report_group_id=self.report_group_id).\
                               first()

        return company_subscription

    def get_company_discount(self):
        company_discount = CompanyDiscount.query.\
                           filter_by(company_id=current_user.company_id).\
                           filter_by(report_group_id=self.report_group_id).\
                           first()

        return company_discount

    def is_subscribed(self):
        company_subscriptions = current_user.get_company_subscriptions()
        company_discounts = current_user.get_company_discounts()
        for subscription in current_user.subscriptions:
            if self.report_group_id == subscription.report_group_id:
                return True
        for subscription in company_subscriptions:
            if self.report_group_id == subscription.report_group_id:
                return True
        for discount in company_discounts:
            if self.is_free_access():
                return True
        return False

    def is_free_access(self):
        if not self.price or self.price == 0:
            return True
        free_access = CompanyDiscount.query.\
                      filter_by(company_id=current_user.company_id).\
                      filter_by(report_group_id=self.report_group_id).\
                      first()
        if free_access:
            if free_access.discount == 100:
                return True
        return False

    def is_free_access_for_user(self, user):
        if not self.price or self.price == 0:
            return True
        free_access = CompanyDiscount.query.\
                      filter_by(company_id=user.company_id).\
                      filter_by(report_group_id=self.report_group_id).\
                      first()
        if free_access:
            if free_access.discount == 100:
                return True
        return False

    def get_price(self):
        company_discount = CompanyDiscount.query.\
                           filter_by(company_id=current_user.company_id).\
                           filter_by(report_group_id=self.report_group_id).\
                           first()
        if company_discount:
            if company_discount.discount:
                return self.price - (self.price * (company_discount.discount * .01));
        else:
            return self.price

    def enable_notifications(self):
        notification = ReportNotification()
        notification.report_group_id = self.report_group_id
        notification.user_id = current_user.id
        db.session.add(notification)
        db.session.commit()

    def enable_notifications_for_user(self, user):
        notification = ReportNotification()
        notification.report_group_id = self.report_group_id
        notification.user_id = user.id
        db.session.add(notification)
        db.session.commit()

    def disable_notifications(self):
        notification = ReportNotification.query.\
                       filter_by(user_id=current_user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       delete()

    def disable_notifications_for_user(self, user):
        notification = ReportNotification.query.\
                       filter_by(user_id=user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       delete()

    def is_notification_enabled(self):
        notification = ReportNotification.query.\
                       filter_by(user_id=current_user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       first()
        if notification:
            return True
        return False

    def is_notification_enabled_for_user(self, user):
        notification = ReportNotification.query.\
                       filter_by(user_id=user.id).\
                       filter_by(report_group_id=self.report_group_id).\
                       first()
        if notification:
            return True
        return False

    def delete(self):
        report_group_id = self.report_group_id
        if self.protected:
            raise RuntimeError('You do not have permission to delete this group.')
        elif self.price > 0 and len(self.subscriptions) > 0:
            raise RuntimeError('You cannot delete paid groups with active subscriptions. \
                                You must remove all subscriptions through Stripe.')
        else:
            if self.stripe_id:
                try:
                    plan = stripe.Plan.retrieve(self.stripe_id)
                    plan.delete()
                except: # Plan was already deleted or does not exist
                    pass
            folders = ReportFolder.query.filter_by(report_group_id=report_group_id).all()
            for folder in folders:
                folder.report_group_id = None
            db.session.commit()

            ReportSubscription.query.filter_by(report_group_id=report_group_id).delete()
            ReportNotification.query.filter_by(report_group_id=report_group_id).delete()
            ReportGroup.query.filter_by(report_group_id=report_group_id).delete()
            db.session.commit()
        return True

event.listen(ReportGroup, 'before_insert', on_create_audited)
event.listen(ReportGroup, 'before_update', on_update_audited)


class ReportFolder(db.Model):
    __tablename__ = 'report_folders'
    report_folder_id = db.Column(db.Integer(), primary_key=True)
    report_folder_name = db.Column(db.String(100), unique=True, nullable=False)
    report_group_id = db.Column(db.ForeignKey('report_groups.report_group_id'))
    report_group = db.relationship('ReportGroup', backref=db.backref('ReportFolder', lazy='dynamic'))
    price = db.Column(db.Float())
    protected = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

    documents = db.relationship('Document', backref=db.backref('ReportFolder'))

event.listen(ReportFolder, 'before_insert', on_create_audited)
event.listen(ReportFolder, 'before_update', on_update_audited)


class Document(db.Model):
    __tablename__ = 'documents'
    document_id = db.Column(db.Integer(), primary_key=True)
    document_data = db.Column(db.LargeBinary())
    document_type = db.Column(db.String(255), nullable=False)
    document_name = db.Column(db.String(255), nullable=False)
    document_display_name = db.Column(db.String(255))
    report_folder_id = db.Column(db.ForeignKey('report_folders.report_folder_id'))
    report_folder = db.relationship('ReportFolder', backref=db.backref('Document', lazy='dynamic'))
    program_id = db.Column(db.ForeignKey('programs.program_id'))
    program = db.relationship('Program', backref=db.backref('Document', lazy='dynamic'))
    document_server = db.Column(db.String(100))
    price = db.Column(db.Float())
    stripe_product_id = db.Column(db.String(32))
    stripe_sku_id = db.Column(db.String(32))
    public = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))
    time_deleted = db.Column(db.DateTime())
    who_deleted = db.Column(db.String(255))

    downloads = db.relationship('Download', backref=db.backref('Document'))
    purchases = db.relationship('DocumentPurchase', backref=db.backref('Document'))

    def is_valid(self):
        if self.public:
            return True
        if current_user.has_role('alladvisor'):
            return True
        for valid_program in g.valid_programs:
            if self.program_id == valid_program.program_id:
                return True
        return False

    def is_valid_for(self, user):
        if self.public:
            return True
        if user.has_role('alladvisor'):
            return True
        valid_programs = ValidProgram.query.filter_by(company_id=user.company_id).all()
        for valid_program in valid_programs:
            if int(self.program_id) == int(valid_program.program_id):
                return True
        return False

    def is_subscribed(self):
        if self.public:
            return True
        company_discounts = current_user.get_company_discounts()
        for subscription in current_user.subscriptions:
            if self.report_folder:
                if self.report_folder.report_group_id == subscription.report_group_id:
                    return True
        for seat in current_user.subscription_seats:
            if self.report_folder:
                if self.report_folder.report_group_id == seat.company_subscription.report_group_id:
                    return True
        for discount in company_discounts:
            if self.is_free_access():
                return True
        return False

    def is_free_access(self):
        if self.public:
            return True
        if self.report_folder:
            if self.report_folder.report_group:
                if self.report_folder.report_group.is_free_access():
                    return True
        return False

    def is_new(self):
        if current_user.last_login_at:
            last_time = current_user.last_login_at
        else:
            last_time = current_user.confirmed_at
        if self.time_created > last_time:
            return True
        return False

    def get_size(self):
        if self.document_server == 's3':
            aws = boto3.session.Session(aws_access_key_id=app.config['AMAZON_WEB_SERVICES_KEYS']['ACCESS_KEY'],\
                                        aws_secret_access_key=app.config['AMAZON_WEB_SERVICES_KEYS']['SECRET_ACCESS_KEY'],\
                                        region_name=app.config['AMAZON_WEB_SERVICES_KEYS']['REGION_NAME'])
            s3resource = aws.resource('s3')
            s3 = s3resource.Bucket(app.config['AMAZON_WEB_SERVICES_KEYS']['BUCKET'])
            s3object = s3.Object(self.document_data)
            return s3object.content_length
        else:
            return db.engine.execute("select sum(length(document_data)) from documents where document_id = %s"\
                                     % self.document_id).fetchall()[0][0]

    def get_downloads(self):
        if current_user.has_role('brokeradmin') or current_user.has_role('broker'):
            users = User.query.with_entities(User.id).filter_by(company_id=current_user.company_id).distinct()
            downloads = Download.query.filter_by(document_id=self.document_id).filter(Download.user_id.in_(users)).all()
        else:
            downloads = self.downloads
        return downloads

    def get_stripe_product(self):
        if self.stripe_product_id:
            product = stripe.Product.retrieve(self.stripe_product_id)
        else:
            product = stripe.Product.create(
                name = self.document_name,
                description = self.document_display_name,
                caption = self.document_display_name,
                attributes = ['name', 'type', 'program', 'folder'],
                images = [app.config['REPORT_IMAGE']],
                shippable = False,
                # url = url_for('admin.document_info', document_id=self.document_id)
            )
            self.stripe_product_id = product.id
            db.session.commit()
        return product

    def get_stripe_sku(self):
        if not self.stripe_product_id:
            self.get_stripe_product()

        if self.program:
            program_name = self.program.program_name
        else:
            program_name = 'None'
        if self.report_folder:
            report_folder_name = self.report_folder.report_folder_name
        else:
            report_folder_name = 'None'
        if self.price:
            price = int(self.price * 100)
        else:
            price = 1

        new_sku = False
        if self.stripe_sku_id:
            sku = stripe.SKU.retrieve(self.stripe_sku_id)
            if self.document_display_name != sku.attributes['name'] or program_name != sku.attributes['program'] or report_folder_name != sku.attributes['folder']:
                new_sku = True
        else:
            new_sku = True

        if new_sku:
            sku = stripe.SKU.create(
                product = self.stripe_product_id,
                attributes = {
                    'name': self.document_display_name,
                    'type': self.document_type,
                    'program': program_name,
                    'folder': report_folder_name
                },
                price = price,
                currency = 'usd',
                inventory = {
                    'type': 'infinite'
                }
            )
            self.stripe_sku_id = sku.id
            db.session.commit()
        return sku

    def update_stripe_price(self):
        if not self.stripe_sku_id:
            self.get_stripe_sku()

        sku = stripe.SKU.retrieve(self.stripe_sku_id)
        sku.price = int(self.price * 100)
        sku.save()

    def is_in_cart(self):
        try:
            if self.stripe_sku_id in session['cart']:
                return True
        except KeyError:
            return False
        return False

    def get_price_label(self):
        if self.public:
            return 'Public'
        elif self.is_subscribed():
            return 'Part of your subscription'
        elif self.price:
            return "${:,.2f}".format(self.price)
        elif self.is_free_access():
            return 'Free'
        else:
            return 'Subscription required'

    def get_purchase(self):
        document_purchase = DocumentPurchase.query.\
                            filter_by(user_id=current_user.id).\
                            filter_by(document_id=self.document_id).\
                            first()
        if document_purchase:
            return document_purchase
        return False

event.listen(Document, 'before_insert', on_create_audited)
event.listen(Document, 'before_update', on_update_audited)


class DocumentPurchase(db.Model):
    __tablename__ = 'document_purchases'
    document_purchase_id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('DocumentPurchase', lazy='dynamic'))
    document_id = db.Column(db.ForeignKey('documents.document_id'), nullable=False)
    document = db.relationship('Document', backref=db.backref('DocumentPurchase', lazy='dynamic'))
    stripe_order_id = db.Column(db.String(32))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

event.listen(DocumentPurchase, 'before_insert', on_create_audited)
event.listen(DocumentPurchase, 'before_update', on_update_audited)


class Sponsor(db.Model):
    __tablename__ = 'sponsors'
    sponsor_id = db.Column(db.Integer(), primary_key=True)
    sponsor_name = db.Column(db.String(255), nullable=False)
    protected = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

    programs = db.relationship('Program', backref=db.backref('Sponsor'))

event.listen(Sponsor, 'before_insert', on_create_audited)
event.listen(Sponsor, 'before_update', on_update_audited)


class Program(db.Model):
    __tablename__ = 'programs'
    program_id = db.Column(db.Integer(), primary_key=True)
    program_name = db.Column(db.String(255), nullable=False)
    sponsor_id = db.Column(db.ForeignKey('sponsors.sponsor_id'))
    sponsor = db.relationship('Sponsor', backref=db.backref('Program', lazy='dynamic'))
    protected = db.Column(db.Boolean())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

    valid_companies = db.relationship('ValidProgram', backref=db.backref('Program'))
    documents = db.relationship('Document', backref=db.backref('Program'))

event.listen(Program, 'before_insert', on_create_audited)
event.listen(Program, 'before_update', on_update_audited)


class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    address = db.Column(db.String(255))
    address_2 = db.Column(db.String(255))
    city = db.Column(db.String(128))
    state_or_prov = db.Column(db.String(128))
    postal_code = db.Column(db.String(32))
    country = db.Column(db.String(128))
    phone = db.Column(db.String(16))
    crd_number = db.Column(db.String(16))
    company_id = db.Column(db.ForeignKey('companies.company_id'))
    active = db.Column(db.Boolean())
    stripe_id = db.Column(db.String(32))
    confirmed_at = db.Column(db.DateTime())
    login_count = db.Column(db.Integer())
    time_zone = db.Column(db.String(50), default='US/Central')
    notification_rate = db.Column(db.Integer(), default=1)
    last_notified = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(32))
    current_login_ip = db.Column(db.String(32))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    review_status = db.Column(db.String(16))
    review_reason = db.Column(db.String(512))
    time_reviewed = db.Column(db.DateTime())
    who_reviewed = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))
    time_deleted = db.Column(db.DateTime())
    who_deleted = db.Column(db.String(255))

    company = db.relationship('Company', backref=db.backref('User', lazy='dynamic'))
    roles = db.relationship('Role', secondary=RolesUsers.__table__,
                            backref=db.backref('User', lazy='dynamic'))
    subscriptions = db.relationship('ReportSubscription', backref=db.backref('User'))
    subscription_seats = db.relationship('SubscriptionSeat', backref=db.backref('User'))
    downloads = db.relationship('Download', backref=db.backref('User'))
    purchases = db.relationship('DocumentPurchase', backref=db.backref('User'))

    def get_id(self):
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

    def get_company_id(self):
        try:
            return unicode(self.company_id)  # python 2
        except NameError:
            return str(self.company_id)  # python 3

    def get_role_id(self):
        return self.roles[0].id

    def get_role(self):
        return self.roles[0]

    def get_company_subscriptions(self):
        return CompanySubscription.query.filter_by(company_id=self.company_id).all()

    def get_company_discounts(self):
        return CompanyDiscount.query.filter_by(company_id=self.company_id).all()

    def get_user_documents(self):
        if self.has_role('alladvisor'):
            return Document.query.\
                   filter(Document.report_folder != None).\
                   filter(Document.time_deleted == None).\
                   order_by(desc(Document.time_created)).\
                   all()
        else:
            return Document.query.\
                   filter(Document.report_folder != None).\
                   filter(Document.time_deleted == None).\
                   filter(Document.program_id.in_(v.program_id for v in g.valid_programs)).\
                   order_by(desc(Document.time_created)).\
                   all()

    def get_public_documents(self):
        return Document.query.\
               filter(Document.time_deleted == None).\
               filter(Document.public == True).\
               order_by(desc(Document.time_created)).\
               all()

    def get_recent_user_documents(self):
        if self.has_role('alladvisor'):
            return Document.query.\
                   filter(Document.report_folder != None).\
                   filter(Document.time_deleted == None).\
                   order_by(desc(Document.time_created)).\
                   limit(5)
        else:
            return Document.query.\
                   filter(Document.report_folder != None).\
                   filter(Document.time_deleted == None).\
                   filter(Document.program_id.in_(v.program_id for v in g.valid_programs)).\
                   order_by(desc(Document.time_created)).\
                   limit(5)

    def get_recent_public_documents(self):
        return Document.query.\
               filter(Document.time_deleted == None).\
               filter(Document.public == True).\
               order_by(desc(Document.time_created)).\
               limit(5)

    def approve(self):
        self.active = 1
        self.review_status = 'APPROVED'
        self.time_reviewed = datetime.utcnow()
        self.who_reviewed = current_user.email
        confirmation_link, token = generate_confirmation_link(self)
        utils.send_mail("Your new %s account" % app.config['APP_NAME'], self.email, 'welcome',
                        user=self, confirmation_link=confirmation_link)
        db.session.commit()

    def welcome_email(self):
        confirmation_link, token = generate_confirmation_link(self)
        utils.send_mail("Your new %s account" % app.config['APP_NAME'], self.email, 'welcome',
                        user=self, confirmation_link=confirmation_link)

    def deny(self, reason):
        self.review_status = 'DENIED'
        self.review_reason = reason
        self.time_reviewed = datetime.utcnow()
        self.who_reviewed = current_user.email
        send_email("Your %s account" % app.config['APP_NAME'],
                   app.config['SECURITY_EMAIL_SENDER'],
                   ["%s %s" % (self.first_name, self.last_name), self.email],
                   render_template('email/userdeny.txt', user=self),
                   render_template('email/userdeny.html', user=self))
        db.session.commit()

    @async
    def check_subscriptions(self):
        with app.app_context():
            report_subscriptions = ReportSubscription.query.filter_by(user_id=self.id).all()
            for report_subscription in report_subscriptions:
                report_group_name = report_subscription.report_group.report_group_name
                if report_subscription.stripe_id:
                    # Get the Stripe Customer and check subscription status
                    customer = stripe.Customer.retrieve(self.stripe_id)
                    try:
                        subscription = customer.subscriptions.retrieve(report_subscription.stripe_id)

                        # Update subscription periods for renewed subscriptions
                        db_start_time = report_subscription.current_period_start
                        stripe_start_time = datetime.fromtimestamp(int(subscription.current_period_start)).\
                                            strftime('%Y-%m-%d %H:%M:%S')
                        if db_start_time != stripe_start_time:
                            report_subscription.current_period_start = stripe_start_time

                        db_end_time = report_subscription.current_period_end
                        stripe_end_time = datetime.fromtimestamp(int(subscription.current_period_end)).\
                                          strftime('%Y-%m-%d %H:%M:%S')
                        if db_end_time != stripe_end_time:
                            report_subscription.current_period_end = stripe_end_time

                        # Update auto-renew status
                        if subscription.cancel_at_period_end:
                            report_subscription.stripe_autorenew = False
                        else:
                            report_subscription.stripe_autorenew = True

                        # Delete expired subscriptions
                        if subscription.status != 'active':
                            db.session.delete(report_subscription)
                    except:
                        # Delete missing subscriptions
                        db.session.delete(report_subscription)

            db.session.commit()

    def __repr__(self):
        return '%s %s (%s)' % (self.first_name, self.last_name, self.email)

event.listen(User, 'before_insert', on_create_audited)
event.listen(User, 'before_update', on_update_audited)


class ValidProgram(db.Model):
    __tablename__ = 'valid_programs'
    valid_program_id = db.Column(db.Integer(), primary_key=True)
    program_id = db.Column(db.ForeignKey('programs.program_id'), nullable=False)
    program = db.relationship('Program', backref=db.backref('ValidProgram', lazy='dynamic'))
    company_id = db.Column(db.ForeignKey('companies.company_id'), nullable=False)
    company = db.relationship('Company', backref=db.backref('ValidProgram', lazy='dynamic'))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

event.listen(ValidProgram, 'before_insert', on_create_audited)


class ReportSubscription(db.Model):
    __tablename__ = 'report_subscriptions'
    report_subscription_id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('ReportSubscription', lazy='dynamic'))
    report_group_id = db.Column(db.ForeignKey('report_groups.report_group_id'), nullable=False)
    report_group = db.relationship('ReportGroup', backref=db.backref('ReportSubscription', lazy='dynamic'))
    stripe_id = db.Column(db.String(32))
    stripe_autorenew = db.Column(db.Boolean())
    amount_paid = db.Column(db.Float())
    current_period_start = db.Column(db.DateTime())
    current_period_end = db.Column(db.DateTime())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

    def enable_notifications(self):
        notification = ReportNotification()
        notification.report_group_id = self.report_group_id
        notification.user_id = self.user_id
        db.session.add(notification)
        db.session.commit()

    def disable_notifications(self):
        notification = ReportNotification.query.\
                       filter_by(user_id=self.user_id).\
                       filter_by(report_group_id=self.report_group_id).\
                       delete()

    def is_notification_enabled(self):
        notification = ReportNotification.query.\
                       filter_by(user_id=self.user_id).\
                       filter_by(report_group_id=self.report_group_id).\
                       first()
        if notification:
            return True
        return False

event.listen(ReportSubscription, 'before_insert', on_create_audited)


class ReportNotification(db.Model):
    __tablename__ = 'report_notifications'
    report_notification_id = db.Column(db.Integer(), primary_key=True)
    report_group_id = db.Column(db.ForeignKey('report_groups.report_group_id'), nullable=False)
    report_group = db.relationship('ReportGroup', backref=db.backref('ReportNotification', lazy='dynamic'))
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('ReportNotification', lazy='dynamic'))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

event.listen(ReportNotification, 'before_insert', on_create_audited)


class CompanyDiscount(db.Model):
    __tablename__ = 'company_discounts'
    company_discount_id = db.Column(db.Integer(), primary_key=True)
    company_id = db.Column(db.ForeignKey('companies.company_id'), nullable=False)
    company = db.relationship('Company', backref=db.backref('CompanyDiscount', lazy='dynamic'))
    report_group_id = db.Column(db.ForeignKey('report_groups.report_group_id'), nullable=False)
    report_group = db.relationship('ReportGroup', backref=db.backref('CompanyDiscount', lazy='dynamic'))
    discount = db.Column(db.Float())
    stripe_id = db.Column(db.String(32))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

    def get_price(self):
        if self.report_group.price:
            if self.discount:
                return self.report_group.price - (self.report_group.price * (self.discount * .01));
            return self.report_group.price
        return 0

    def is_free_access(self):
        if not self.report_group.price:
            return True
        if self.discount:
            if self.discount == 100:
                return True
        return False

    def create_stripe_discount(self):
        if self.discount:
            try:
                self.stripe_id = 'company_%s_%s' % (self.company.company_id, self.report_group.report_group_id)
                return stripe.Coupon.create(
                    id = self.stripe_id,
                    percent_off = self.discount,
                    currency = 'usd',
                    duration = 'forever',
                    metadata = {
                        'company': self.company.company_name,
                        'report_group': self.report_group.report_group_name
                    }
                )
            except stripe.error.InvalidRequestError, e:
                raise Exception('Stripe error: %s' % str(e.message))
            except stripe.error.RateLimitError, e:
                raise Exception('Too many requests to Stripe. Please try again.')
            except stripe.error.AuthenticationError, e:
                raise Exception('Stripe could not authenticate. Please try again.')
            except stripe.error.APIConnectionError, e:
                raise Exception('Could not connect to Stripe. Please try again.')
            except stripe.error.StripeError, e:
                raise Exception('An unknown error occured when connecting to Stripe. Please try again.')
        else:
            raise Exception('Discount must be a positive integer.')

    def delete(self):
        if self.stripe_id:
            try:
                coupon = stripe.Coupon.retrieve(self.stripe_id)
                coupon.delete()
            except: # Plan was already deleted or does not exist
                pass
        CompanyDiscount.query.filter_by(company_discount_id=self.company_discount_id).delete()
        db.session.commit()
        return True

event.listen(CompanyDiscount, 'before_insert', on_create_audited)


class CompanySubscription(db.Model):
    __tablename__ = 'company_subscriptions'
    company_subscription_id = db.Column(db.Integer(), primary_key=True)
    company_id = db.Column(db.ForeignKey('companies.company_id'), nullable=False)
    company = db.relationship('Company', backref=db.backref('CompanySubscription', lazy='dynamic'))
    report_group_id = db.Column(db.ForeignKey('report_groups.report_group_id'), nullable=False)
    report_group = db.relationship('ReportGroup', backref=db.backref('CompanySubscription', lazy='dynamic'))
    stripe_id = db.Column(db.String(32))
    stripe_autorenew = db.Column(db.Boolean())
    amount_paid = db.Column(db.Float())
    current_period_start = db.Column(db.DateTime())
    current_period_end = db.Column(db.DateTime())
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

    seats = db.relationship('SubscriptionSeat', backref=db.backref('CompanySubscription'))

    def get_discount(self):
        return CompanyDiscount.query.filter_by(company_id=self.company_id).filter_by(report_group_id=self.report_group_id).first()

    def get_price(self):
        if self.report_group.price:
            company_discount = self.get_discount()
            if company_discount:
                return self.report_group.price - (self.report_group.price * (company_discount.discount * .01));
            return self.report_group.price
        return 0

    def enable_notifications_for_company(self, company):
        for user in company.users:
            notification = ReportNotification()
            notification.report_group_id = self.report_group_id
            notification.user_id = user.id
            db.session.add(notification)
            db.session.commit()

    def get_seated_users(self):
        users = []
        for seat in self.seats:
            users.append(seat.user)
        return users


event.listen(CompanySubscription, 'before_insert', on_create_audited)


class SubscriptionSeat(db.Model):
    __tablename__ = 'subscription_seats'
    subscription_seat_id = db.Column(db.Integer(), primary_key=True)
    company_subscription_id = db.Column(db.ForeignKey('company_subscriptions.company_subscription_id'))
    company_subscription = db.relationship('CompanySubscription', backref=db.backref('SubscriptionSeat', lazy='dynamic'))
    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('SubscriptionSeat', lazy='dynamic'))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

event.listen(SubscriptionSeat, 'before_insert', on_create_audited)


class Download(db.Model):
    __tablename__ = 'downloads'
    download_id = db.Column(db.Integer(), primary_key=True)
    document_id = db.Column(db.ForeignKey('documents.document_id'), nullable=False)
    document = db.relationship('Document', backref=db.backref('Download', lazy='dynamic'))
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('Download', lazy='dynamic'))
    downloaded_at = db.Column(db.DateTime())


class EmailDomain(db.Model):
    __tablename__= "email_domains"
    domain_id = db.Column(db.Integer(), primary_key=True)
    domain_name = db.Column(db.String(255), nullable=False)
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))
    time_modified = db.Column(db.DateTime())
    who_modified = db.Column(db.String(255))

event.listen(EmailDomain, 'before_insert', on_create_audited)
event.listen(EmailDomain, 'before_update', on_update_audited)


class ValidDomain(db.Model):
    __tablename__ = 'valid_domains'
    valid_domain_id = db.Column(db.Integer(), primary_key=True)
    domain_id = db.Column(db.ForeignKey('email_domains.domain_id'), nullable=False)
    domain = db.relationship('EmailDomain', backref=db.backref('ValidDomain', lazy='dynamic'))
    company_id = db.Column(db.ForeignKey('companies.company_id'), nullable=False)
    company = db.relationship('Company', backref=db.backref('ValidDomain', lazy='dynamic'))
    time_created = db.Column(db.DateTime())
    who_created = db.Column(db.String(255))

event.listen(ValidDomain, 'before_insert', on_create_audited)


class EmailQueue(db.Model):
    __tablename__ = 'email_queue'
    email_queue_id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('EmailQueue', lazy='dynamic'))
    document_id = db.Column(db.ForeignKey('documents.document_id'), nullable=False)
    document = db.relationship('Document', backref=db.backref('EmailQueue', lazy='dynamic'))
    time_sent = db.Column(db.DateTime())
    who_sent = db.Column(db.String(255))

event.listen(EmailQueue, 'before_update', on_sent)


class DenyReason(db.Model):
    __tablename__ = 'deny_reasons'
    deny_reason_id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(512), nullable=False)
