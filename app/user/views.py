from flask import Blueprint, render_template, request, redirect, url_for,\
                  flash, send_file, session, escape, jsonify, g
from flask.ext import breadcrumbs
from flask_security import login_required, roles_accepted, current_user, utils
from datetime import datetime
from io import BytesIO
from sqlalchemy import desc
from app import app, db, stripe
from app.decorators import crossdomain
from app.models import Company, ReportGroup, ReportFolder, Document, Sponsor,\
                       Program, Role, User, ValidProgram, ReportSubscription,\
                       DocumentPurchase
from app.util.email import send_email


mod_user = Blueprint('user', __name__, url_prefix='/user')


@mod_user.route('/')
@mod_user.route('/dashboard')
@breadcrumbs.register_breadcrumb(mod_user, '.', '<i class="fa fa-fw fa-th-large"></i>')
@login_required
def dashboard():
    documents = current_user.get_recent_user_documents()
    public_documents = current_user.get_recent_public_documents()
    document_library = []
    for purchase in current_user.purchases:
        if len(document_library) <= 5:
            document_library.append(purchase.document)

    data = {
        'documents': documents,
        'public_documents': public_documents,
        'document_library': document_library,
        'subscriptions': current_user.subscriptions
    }

    return render_template('user/dashboard.html', data=data, dashboard=True)


@mod_user.route('/reports')
@breadcrumbs.register_breadcrumb(mod_user, '.reports', 'Reports')
@login_required
def documents_list():
    documents = current_user.get_user_documents()

    data = {
        'documents': documents
    }

    return render_template('user/documents.html', data=data)


@mod_user.route('/publicreports')
@breadcrumbs.register_breadcrumb(mod_user, '.publicreports', 'Public Reports')
@login_required
def public_documents_list():
    public_documents = current_user.get_public_documents()

    data = {
        'public_documents': public_documents
    }

    return render_template('user/publicdocuments.html', data=data)


@mod_user.route('/library')
@breadcrumbs.register_breadcrumb(mod_user, '.library', 'My Library')
@login_required
def library_list():
    document_library = []
    for purchase in current_user.purchases:
        document_library.append(purchase.document)

    data = {
        'document_library': document_library
    }

    return render_template('user/library.html', data=data)


def document_info_user_dlc(*args, **kwargs):
    document_id = request.view_args['document_id']
    document = Document.query.get(document_id)
    return [{'text': document.document_display_name, 'url': url_for('user.document_info', document_id=document_id)}]


@mod_user.route('/reports/info/<int:document_id>', methods=['GET'])
@breadcrumbs.register_breadcrumb(mod_user, '.reports.info', '',
                                 dynamic_list_constructor=document_info_user_dlc)
@login_required
def document_info(document_id):
    document = Document.query.get_or_404(document_id)
    if not document.is_free_access() and not document.get_purchase() and not document.is_subscribed():
        if not document.is_valid():
            flash('You do not have permission to view this resource.', 'error')
            return redirect(url_for('user.dashboard'))

    data = {
        'document': document
    }

    return render_template('user/documentinfo.html', data=data)


@mod_user.route('/cart')
@breadcrumbs.register_breadcrumb(mod_user, '.cart', 'Shopping Cart')
@login_required
def shopping_cart():
    cart = []
    total = 0
    try:
        for item in session['cart']:
            document = Document.query.filter_by(stripe_sku_id=item).first()
            if document:
                cart.append(document)
                total += document.price
    except KeyError:
        cart = []

    data = {
        'cart': cart,
        'total': total,
        'stripepk': app.config['STRIPE_KEYS']['PK']
    }

    return render_template('user/cart.html', data=data, simpletable=True)


# Subscription management

@mod_user.route('/subscriptions')
@breadcrumbs.register_breadcrumb(mod_user, '.subscriptions', 'Subscriptions')
@login_required
@crossdomain(origin='*')
def subscriptions_list():
    groups = ReportGroup.query.all()
    for group in groups:
        group.price = group.get_price()

    data = {
        'groups': groups,
        'subscriptions': current_user.subscriptions,
        'stripepk': app.config['STRIPE_KEYS']['PK']
    }

    return render_template('user/subscriptions.html', data=data, simpletable=True)


@mod_user.route('/subscriptions/subscribe/<int:group_id>')
@login_required
def subscribe_to(group_id):
    report_group = ReportGroup.query.get_or_404(group_id)
    
    if report_group.price > 0 and not report_group.is_free_access():
        flash('You must pay to access this group.', 'error')
        return redirect(url_for('user.subscriptions_list'))

    subscription = ReportSubscription()
    subscription.user_id = current_user.id
    subscription.report_group_id = group_id
    subscription.enable_notifications()

    db.session.add(subscription)
    db.session.commit()
    flash('Subscribed to %s.' % (subscription.report_group.report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


@mod_user.route('/subscriptions/unsubscribe/<int:group_id>')
@login_required
def unsubscribe_to(group_id):
    subscription = ReportSubscription.query.filter_by(user_id=current_user.id).\
                   filter(ReportSubscription.report_group_id == group_id).first_or_404()
    report_group_name = subscription.report_group.report_group_name

    subscription.disable_notifications()

    if subscription.report_group.price > 0 and subscription.stripe_id:
        flash('You cannot unsubscribe to paid groups. Please disable auto-renewal if you wish to cancel.', 'error')
        return redirect(url_for('user.subscriptions_list'))

    db.session.delete(subscription)
    db.session.commit()
    flash('Unsubscribed from %s.' % (report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


@mod_user.route('/subscriptions/notify/<int:group_id>')
@login_required
def enable_notifications_from(group_id):
    report_group = ReportGroup.query.get_or_404(group_id)
    if not report_group.is_subscribed() and not report_group.is_free_access():
        flash('You cannot receive notifications from unsubscribed groups.', 'error')
    else:    
        report_group.enable_notifications()
        db.session.commit()

    flash('Email notifications enabled for %s.' % (report_group.report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


@mod_user.route('/subscriptions/unnotify/<int:group_id>')
@login_required
def disable_notifications_from(group_id):
    report_group = ReportGroup.query.get_or_404(group_id)
    
    report_group.disable_notifications()

    db.session.commit()
    flash('Email notifications disabled for %s.' % (report_group.report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


@mod_user.route('/subscriptions/renew/<int:group_id>')
@login_required
def enable_autorenew(group_id):
    report_subscription = ReportSubscription.query.filter_by(user_id=current_user.id).\
                          filter(ReportSubscription.report_group_id == group_id).first_or_404()
    report_group_name = report_subscription.report_group.report_group_name
    
    # Get the Stripe Customer and reactivate their current subscription
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    subscription = customer.subscriptions.retrieve(report_subscription.stripe_id)
    subscription.plan = report_subscription.report_group_id
    subscription.save()

    report_subscription.stripe_autorenew = 1

    db.session.commit()
    flash('Auto-renewal enabled for %s.' % (report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


@mod_user.route('/subscriptions/unrenew/<int:group_id>')
@login_required
def disable_autorenew(group_id):
    report_subscription = ReportSubscription.query.filter_by(user_id=current_user.id).\
                          filter(ReportSubscription.report_group_id == group_id).first_or_404()
    report_group_name = report_subscription.report_group.report_group_name
    
    # Get the Stripe Customer and delete their subscription at_period_end
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    customer.subscriptions.retrieve(report_subscription.stripe_id).delete(at_period_end=True)

    report_subscription.stripe_autorenew = 0

    db.session.commit()
    flash('Auto-renewal disabled for %s.' % (report_group_name), 'success')

    return redirect(url_for('user.subscriptions_list'))


## Payments and Subscription Management (AJAX)

@mod_user.route('/_addtocart')
@login_required
def add_to_cart(document_id=None):
    if request.args.get('document_id'):
        document_id = request.args.get('document_id')
    if not document_id:
        return jsonify(result=0)
    document = Document.query.get_or_404(document_id)
    try:
        session['cart'].append(str(document.stripe_sku_id))
    except KeyError:
        session['cart'] = []
        session['cart'].append(str(document.stripe_sku_id))

    return jsonify(result=1, name=document.document_display_name)


@mod_user.route('/_removefromcart')
@login_required
def remove_from_cart(document_id=None):
    if request.args.get('document_id'):
        document_id = request.args.get('document_id')
    if not document_id:
        return jsonify(result=0)
    document = Document.query.get_or_404(document_id)
    try:
        session['cart'].remove(str(document.stripe_sku_id))
    except KeyError:
        return jsonify(result=0)
    return jsonify(result=1, name=document.document_display_name)


@mod_user.route('/_clearcart')
@login_required
def clear_cart():
    try:
        del session['cart']
        flash('Your cart has been emptied.', 'success')
    except KeyError:
        flash('Your cart was already empty.', 'error')
        return jsonify(result=0)
    return jsonify(result=1)


@mod_user.route('/_processpayment')
@login_required
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
            description = "%s %s (User %s)" % (current_user.first_name, current_user.last_name, current_user.id)
            customer = stripe.Customer.create(
                card = token,
                email = current_user.email,
                description = description
            )
            current_user.stripe_id = customer.id

        # Update address
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
                subscription = customer.subscriptions.create(plan=report_group.stripe_id, coupon=company_discount.stripe_id)
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

    report_subscription = ReportSubscription()
    report_subscription.user_id = current_user.id
    report_subscription.report_group_id = group_id
    report_subscription.stripe_id = subscription.id
    report_subscription.stripe_autorenew = 1
    report_subscription.current_period_start = datetime.fromtimestamp(
        int(subscription.current_period_start)
    ).strftime('%Y-%m-%d %H:%M:%S')
    report_subscription.current_period_end = datetime.fromtimestamp(
        int(subscription.current_period_end)
    ).strftime('%Y-%m-%d %H:%M:%S')
    report_subscription.amount_paid = report_group.get_price()
    report_subscription.enable_notifications()

    db.session.add(report_subscription)
    db.session.commit()
    flash('Thank you! You are now subscribed to %s.' % (report_subscription.report_group.report_group_name), 'success')

    sub_id = report_subscription.report_subscription_id
    price = report_group.get_price()
    group_name = report_group.report_group_name

    return jsonify(id=sub_id, price=price, group_name=group_name, group_id=group_id)


@mod_user.route('/_processreportpayment')
@login_required
def pay_for_reports():
    # Build list of items from provided cart
    items = []
    try:
        cart = session['cart']
        for item in cart:
            items.append({'type': 'sku', 'parent': str(item)})
    except KeyError:
        flash('Your cart is empty. You must add reports before you can check out.', 'error')
        return jsonify(success=0)

    # Get the credit card details submitted by the form
    token = request.args.get('token')

    try:
        description = "%s %s (User %s)" % (current_user.first_name, current_user.last_name, current_user.id)
        if current_user.stripe_id:
            # Update the customer's card
            customer = stripe.Customer.retrieve(current_user.stripe_id)
            customer.source = token
            customer.email = current_user.email
            customer.description = description
        else:
            # Create a new customer
            customer = stripe.Customer.create(
                source = token,
                email = current_user.email,
                description = description
            )
            current_user.stripe_id = customer.id

        # Update address
        address = customer.sources.data[0]
        current_user.address = address.address_line1
        current_user.address_2 = address.address_line2
        current_user.city = address.address_city
        current_user.state_or_prov = address.address_state
        current_user.postal_code = address.address_zip
        current_user.country = address.country

        # Create a Stripe Relay order
        order = stripe.Order.create(
            currency = 'usd',
            items = items,
            customer = customer.id,
            email = current_user.email
        )
        # Pay for the order
        order.pay(
            customer = customer.id
        )
    except stripe.error.CardError, e:
        # The card has been declined
        flash('Your card was declined. Please try again.', 'error')
        return jsonify(success=0)
    except stripe.error.RateLimitError, e:
        # Too many requests made to the API too quickly
        flash('Too many requests to Stripe. Please try again.', 'error')
        return jsonify(success=0)
    except stripe.error.InvalidRequestError, e:
        # Invalid parameters were supplied to Stripe's API
        flash('Something is wrong with your Stripe request. Please try again.', 'error')
        return jsonify(success=0)
    except stripe.error.AuthenticationError, e:
        # Authentication with Stripe's API failed
        # (maybe you changed API keys recently)
        flash('Stripe could not authenticate. Please try again.', 'error')
        return jsonify(success=0)
    except stripe.error.APIConnectionError, e:
        # Network communication with Stripe failed
        flash('Could not connect to Stripe. Please try again.', 'error')
        return jsonify(success=0)
    except stripe.error.StripeError, e:
        # Display a very generic error to the user
        flash('An unknown error occured when connecting to Stripe. Please try again.', 'error')
        return jsonify(success=0)

    documents_purchased = []
    for item in items:
        document = Document.query.filter_by(stripe_sku_id=item['parent']).first()
        document_purchase = DocumentPurchase()
        document_purchase.user_id = current_user.id
        document_purchase.document_id = document.document_id
        document_purchase.stripe_order_id = order.id
        db.session.add(document_purchase)
        documents_purchased.append({
            'id': document.document_id,
            'name': document.document_display_name,
            'sku': document.stripe_sku_id,
            'category': 'Individual Reports',
            'price': document.price
        })

    db.session.commit()
    flash('Thank you! Your order has been completed. Your reports are now available in your library.', 'success')
    del session['cart']

    stripe_order_id = order.id
    total = (order.amount / 100)

    return jsonify(success=1, stripe_order_id=stripe_order_id, total=total, items=documents_purchased)


@mod_user.route('/_renew')
@login_required
def enable_autorenew_ajax():
    report_group = ReportGroup.query.get_or_404(request.args.get('groupid'))
    report_subscription = ReportSubscription.query.\
                          filter_by(user_id=current_user.id).\
                          filter_by(report_group_id=report_group.report_group_id).\
                          first_or_404()
    
    # Get the Stripe Customer and reactivate their current subscription
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    subscription = customer.subscriptions.retrieve(report_subscription.stripe_id)
    subscription.plan = report_group.stripe_id
    subscription.save()

    report_subscription.stripe_autorenew = 1

    db.session.commit()
    flash('Auto-renewal enabled for %s.' % report_group.report_group_name, 'success')

    return jsonify(result=1)

@mod_user.route('/_unrenew')
@login_required
def disable_autorenew_ajax():
    report_group = ReportGroup.query.get_or_404(request.args.get('groupid'))
    report_subscription = ReportSubscription.query.\
                          filter_by(user_id=current_user.id).\
                          filter_by(report_group_id=report_group.report_group_id).\
                          first_or_404()
    
    # Get the Stripe Customer and delete their subscription at_period_end
    customer = stripe.Customer.retrieve(current_user.stripe_id)
    customer.subscriptions.retrieve(report_subscription.stripe_id).delete(at_period_end=True)

    report_subscription.stripe_autorenew = 0

    db.session.commit()
    flash('Auto-renewal disabled for %s.' % report_group.report_group_name, 'success')

    return jsonify(result=1)
