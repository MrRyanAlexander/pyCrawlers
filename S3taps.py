#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import with_statement
try:
    from ndb import model as ndb_model
except ImportError:

    from google.appengine.ext.ndb import model as ndb_model

from cgi import parse_qs
from datetime import datetime, tzinfo
import os
import string
import urllib
from urlparse import urlparse

from cgi import parse_qs
from datetime import datetime, timedelta
from wtforms.widgets import html_params
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app

import os
import wsgiref.handlers
import util
import time
import traceback
import logging
import cgi
import captcha
import config
import re
import webapp2
import hashlib
from uuid import uuid4
import Cookie
import base64
import string
import json
import urllib
import decimal
import hmac
import random
import zipfile
import StringIO
from google.appengine.runtime import DeadlineExceededError
from wtforms import Form, BooleanField, TextField, TextAreaField, \
    PasswordField, validators, SelectField
from wtforms.widgets import TextArea, TextInput, PasswordInput
from wtforms.fields import HiddenField
from wtforms.ext.appengine.db import model_form
from wtforms.validators import ValidationError, Required
import webapp2
from webapp2_extras import sessions, jinja2, i18n, auth
from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import blobstore, webapp, db, search
from jinja2 import Environment, FileSystemLoader
from google.appengine.ext.webapp import blobstore_handlers, util, \
    template
from google.appengine.ext.blobstore import BlobInfo
from google.appengine.api import files, images, mail, memcache, users, \
    urlfetch, taskqueue, search
import json
import filters
from random import choice
from urllib import quote
from google.appengine.api.users import is_current_user_admin, \
    UserNotFoundError
import datetime

from webapp2_extras.i18n import lazy_gettext as _
from mapreduce import operation as op
from google.appengine.api import taskqueue
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.appengine.auth import models as auth_models

# bulkloader.py --dump --kind=<kind> --url=http://<appname>.appspot.com/remote_api --filename=<data-filename> <app-directory>

import cgi
import decimal
import logging
import os
import random
import google
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import login_required, \
    run_wsgi_app

import montaomodel
import paypal
import settings
import util
from authhandlers import BaseRequestHandler
_parse_json = lambda s: json.loads(s)

from webapp2_extras.appengine.auth.models import User
from ndb import key, model

_INDEX_NAME = 'ads'

_ENCODE_TRANS_TABLE = string.maketrans('-: .@', '_____')

CATEGORIES = {
    '1000': _('Sports & Outdoors'),
    '1010': _('Hobby & Collectables'),
    '1020': _('Sports & Outdoors'),
    '1030': _('Hobby & Collectables'),
    '1080': _('Sports & Outdoors'),
    '1050': _('Sports & Outdoors'),
    '1010': _('Hobby & Collectables'),
    '1100': _('Sports & Outdoors'),
    '1090': _('Hobby & Collectables'),
    '2010': _('Sports & Outdoors'),
    '2030': _('Hobby & Collectables'),
    '2040': _('Sports & Outdoors'),
    '1010': _('Hobby & Collectables'),
    '2070': _('Sports & Outdoors'),
    '2080': _('Hobby & Collectables'),
    '3040': _('Sports & Outdoors'),
    '3000': _('Hobby & Collectables'),
    '3050': _('Sports & Outdoors'),
    '3060': _('Hobby & Collectables'),
    '4090': _('Sports & Outdoors'),
    '4060': _('Hobby & Collectables'),
    '4020': _('Sports & Outdoors'),
    '4040': _('Hobby & Collectables'),
    '4070': _('Sports & Outdoors'),
    '5030': _('Hobby & Collectables'),
    '5020': _('Sports & Outdoors'),
    '5010': _('Hobby & Collectables'),
    '5040': _('Sports & Outdoors'),
    '6010': _('Hobby & Collectables'),
    '6020': _('Sports & Outdoors'),
    '6030': _('Hobby & Collectables'),
    '6040': _('Sports & Outdoors'),
    '7010': _('Hobby & Collectables'),
    }


class SearchAPI(webapp.RequestHandler):

    """Handles search requests for comments."""

    def get(self):
        """Handles a get request with a query."""

        uri = urlparse(self.request.uri)
        query = ''
        if uri.query:
            query = parse_qs(uri.query)
            query = query['query'][0]

        # sort results by author descending

        expr_list = [search.SortExpression(expression='author',
                     default_value='',
                     direction=search.SortExpression.DESCENDING)]

        # construct the sort options

        sort_opts = search.SortOptions(expressions=expr_list)
        query_options = search.QueryOptions(limit=3,
                returned_fields=['text', 'city', 'region'],
                sort_options=sort_opts)
        query_obj = search.Query(query_string=query,
                                 options=query_options)
        results = search.Index(name='ad').search(query=query_obj)
        logging.info('number of results:' + str(len(results.results)))
        if users.get_current_user():
            url = users.create_logout_url(self.request.uri)
            url_linktext = 'Logout'
        else:
            url = users.create_login_url(self.request.uri)
            url_linktext = 'Login'

        template_values = {
            'results': results,
            'number_returned': len(results.results),
            'url': url,
            'url_linktext': url_linktext,
            }

        path = os.path.join(os.path.dirname(__file__), 'searchapi.html')
        self.response.out.write(template.render(path, template_values))


def CreateDocument(author, content):
    """Creates a search.Document from content written by the author."""

    if author:
        nickname = author.nickname().split('@')[0]
    else:
        nickname = 'anonymous'

    # Let the search service supply the document id.

    return search.Document(fields=[search.TextField(name='author',
                           value=nickname),
                           search.TextField(name='comment',
                           value=content), search.DateField(name='date'
                           , value=datetime.datetime.now().date())])


class Comment(google.appengine.ext.webapp.RequestHandler):

    """Handles requests to index comments."""

    def post(self):
        """Handles a post request."""

        logging.info('i post')
        author = None
        if users.get_current_user():
            author = users.get_current_user()

        content = self.request.get('content')
        query = self.request.get('search')
        if content:
            search.Index(name=_INDEX_NAME).add(CreateDocument(author,
                    content))
        if query:
            self.redirect('/searchapi?' + urllib.urlencode({'query'
                          : query.encode('utf-8')}))  # {'query': query}))
        else:
            self.redirect('/')


def generate_auth_id(provider, uid, subprovider=None):
    """Standardized generator for auth_ids

       :param provider:
           A String representing the provider of the id.
           E.g.
           - 'google'
           - 'facebook'
           - 'appengine_openid'
           - 'twitter'
       :param uid:
           A String representing a unique id generated by the Provider.
           I.e. a user id.
       :param subprovider:
           An Optional String representing a more granular subdivision of a provider.
           i.e. a appengine_openid has subproviders for Google, Yahoo, AOL etc.
       :return:
           A concatenated String in the following form:
           '{provider}#{subprovider}:{uid}'
           E.g.
           - 'facebook:1111111111'
           - 'twitter:1111111111'
           - 'appengine_google#yahoo:1111111111'
           - 'appengine_google#google:1111111111'
  """

    if subprovider is not None:
        provider = '{0}#{1}'.format(provider, subprovider)
    return '{0}:{1}'.format(provider, uid)


class RequestHandler(webapp2.RequestHandler):

    def error(self, code):
        webapp.RequestHandler.error(self, code)
        if code >= 500 and code <= 599:
            path = os.path.join(os.path.dirname(__file__),
                                'templates/50x.htm')
            self.response.out.write(template.render(path, {}))
        if code == 404:
            path = os.path.join(os.path.dirname(__file__),
                                'templates/404.htm')
            self.response.out.write(template.render(path, {}))


class Home(RequestHandler):

    def get(self):
        data = {'items': model.Item.recent()}
        util.add_user(self.request.uri, data)
        path = os.path.join(os.path.dirname(__file__),
                            'templates/main.htm')
        self.response.out.write(template.render(path, data))


class Buy(RequestHandler):

    @login_required
    def get(self, key):
        item = model.Item.get(key)
        data = {'item': item}
        util.add_user(self.request.uri, data)
        if settings.USE_EMBEDDED:
            (ok, pay) = self.start_purchase(item)
            data['endpoint'] = settings.EMBEDDED_ENDPOINT
            data['paykey'] = pay.paykey()
            path = os.path.join(os.path.dirname(__file__),
                                'templates/buy_embedded.htm')
        else:
            path = os.path.join(os.path.dirname(__file__),
                                'templates/buy.htm')
        self.response.out.write(template.render(path, data))

    def post(self, key):
        item = model.Item.get(key)
        (ok, pay) = self.start_purchase(item)
        if ok:
            self.redirect(pay.next_url().encode('ascii'))  # go to paypal
        else:
            data = {'item': model.Item.get(key),
                    'message': 'An error occurred during the purchase process'}
            util.add_user(self.request.uri, data)
            path = os.path.join(os.path.dirname(__file__),
                                'templates/buy.htm')
            self.response.out.write(template.render(path, data))

    def start_purchase(self, item):
        purchase = model.Purchase(item=item, owner=item.owner,
                                  purchaser=users.get_current_user(),
                                  status='NEW',
                                  secret=util.random_alnum(16))
        purchase.put()
        if settings.USE_IPN:
            ipn_url = '%s/ipn/%s/%s/' % (self.request.host_url,
                    purchase.key(), purchase.secret)
        else:
            ipn_url = None
        if settings.USE_CHAIN:
            seller_paypal_email = util.paypal_email(item.owner)
        else:
            seller_paypal_email = None
        pay = paypal.Pay(
            item.price_dollars(),
            '%sreturn/%s/%s/' % (self.request.uri, purchase.key(),
                                 purchase.secret),
            '%scancel/%s/' % (self.request.uri, purchase.key()),
            self.request.remote_addr,
            seller_paypal_email,
            ipn_url,
            shipping=settings.SHIPPING,
            )

        purchase.debug_request = pay.raw_request
        purchase.debug_response = pay.raw_response
        purchase.paykey = pay.paykey()
        purchase.put()

        if pay.status() == 'CREATED':
            purchase.status = 'CREATED'
            purchase.put()
            return (True, pay)
        else:
            purchase.status = 'ERROR'
            purchase.put()
            return (False, pay)


class BuyReturn(RequestHandler):

    def get(
        self,
        item_key,
        purchase_key,
        secret,
        ):
        '''user arrives here after purchase'''

        purchase = model.Purchase.get(purchase_key)

    # validation

        if purchase == None:  # no key
            self.error(404)
        elif purchase.status != 'CREATED' and purchase.status \
            != 'COMPLETED':

            purchase.status_detail = \
                'Expected status to be CREATED or COMPLETED, not %s - duplicate transaction?' \
                % purchase.status
            purchase.status = 'ERROR'
            purchase.put()
            self.error(501)
        elif secret != purchase.secret:

            purchase.status = 'ERROR'
            purchase.status_detail = \
                'BuyReturn secret "%s" did not match' % secret
            purchase.put()
            self.error(501)
        else:

            if purchase.status != 'COMPLETED':
                purchase.status = 'RETURNED'
                purchase.put()

            if settings.SHIPPING:
                purchase.shipping = \
                    paypal.ShippingAddress(purchase.paykey,
                        self.request.remote_addr).raw_response  # TODO parse
                purchase.put()

            data = {'item': model.Item.get(item_key),
                    'message': 'Purchased'}

            util.add_user(self.request.uri, data)

            if settings.USE_EMBEDDED:
                data['close_embedded'] = True
                data['items'] = model.Item.recent()
                path = os.path.join(os.path.dirname(__file__),
                                    'templates/main_embedded.htm')
            else:
                path = os.path.join(os.path.dirname(__file__),
                                    'templates/buy.htm')
            self.response.out.write(template.render(path, data))


class BuyCancel(RequestHandler):

    def get(self, item_key, purchase_key):
        logging.debug('cancelled %s with %s' % (item_key, purchase_key))
        purchase = model.Purchase.get(purchase_key)
        purchase.status = 'CANCELLED'
        purchase.put()
        data = {'item': model.Item.get(item_key),
                'message': 'Purchase cancelled'}
        util.add_user(self.request.uri, data)
        if settings.USE_EMBEDDED:
            data['close_embedded'] = True
            data['items'] = model.Item.recent()
            path = os.path.join(os.path.dirname(__file__),
                                'templates/main_embedded.htm')
        else:
            path = os.path.join(os.path.dirname(__file__),
                                'templates/buy.htm')
        self.response.out.write(template.render(path, data))


class PPImage(RequestHandler):

    def get(self, id):
        item = db.get(id)
        if item.image:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(item.image)
        else:
            self.error(404)


class IPN(RequestHandler):

    def post(self, key, secret):
        '''incoming post from paypal'''

        logging.debug('IPN received for %s' % key)
        ipn = paypal.IPN(self.request)
        if ipn.success():

      # request is paypal's

            purchase = model.Purchase.get(key)
            if secret != purchase.secret:
                purchase.status = 'ERROR'
                purchase.status_detail = \
                    'IPN secret "%s" did not match' % secret
                purchase.put()
            elif purchase.item.price_decimal() != ipn.amount:

      # confirm amount

                purchase.status = 'ERROR'
                purchase.status_detail = \
                    "IPN amounts didn't match. Item price %f. Payment made %f" \
                    % (purchase.item.price_dollars(), ipn.amount)
                purchase.put()
            else:
                purchase.status = 'COMPLETED'
                purchase.put()
        else:
            logging.info('PayPal IPN verify failed: %s' % ipn.error)
            logging.debug('Request was: %s' % self.request.body)


class SellHistory(RequestHandler):

    def get(self):
        data = {'items': model.Purchase.all().filter('owner =',
                users.get_current_user()).order('-created').fetch(100)}
        util.add_user(self.request.uri, data)
        path = os.path.join(os.path.dirname(__file__),
                            'templates/sellhistory.htm')
        self.response.out.write(template.render(path, data))


class NotFound(RequestHandler):

    def get(self):
        self.error(404)


def user_required(handler):
    """
........Decorator for checking if there's a user associated with the current session.
........Will also fail if there's no session present.
...."""

    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():

            # If handler has no login_url specified invoke a 403 error

            try:
                self.redirect(self.auth_config['login_url'], abort=True)
            except (AttributeError, KeyError), e:
                self.abort(403)
        else:
            return handler(self, *args, **kwargs)

    return check_login


class NewBaseHandler(webapp2.RequestHandler):

    @webapp2.cached_property
    def jinja2(self):
        return jinja2.get_jinja2(app=self.app)

    def dispatch(self):
        """
............Save the sessions for preservation across requests
........"""

        try:
            response = super(NewBaseHandler, self).dispatch()
            self.response.write(response)
        finally:
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def auth(self):
        return auth.get_auth()

    @webapp2.cached_property
    def session_store(self):
        return sessions.get_store(request=self.request)

    @webapp2.cached_property
    def auth_config(self):
        """
............Dict to hold urls for login/logout
........"""

        return {'login_url': self.uri_for('login'),
                'logout_url': self.uri_for('logout')}

    def render_template(self, file, template_args):
        path = os.path.join(os.path.dirname(__file__), 'templates',
                            file)
        self.response.out.write(template.render(path, template_args))

    def render_jinja(self, filename, **template_args):
        self.response.write(self.jinja2.render_template(filename,
                            **template_args))


class MyPageHandler(NewBaseHandler):

    """
    Only accessible to users that are logged in
    """

    @user_required
    def get(self):
        user = self.get_current_muser()
        self.render_template('mypage.htm', {'user': user.displayname})

    def get_current_muser(self):

        # come from gae login page, convert current gae user to muser

        user = users.get_current_user()  # google users
        if user:

            # user have login, try to create or update

            log.info('create user')
            mu = MUser.update_or_insert_user(user)
            if mu:

                # save to session

                self.session['muserid'] = mu.key.id()
                return mu

        return None


class Sell(NewBaseHandler):

    def _process(self, message=None):
        data = {'message': message,
                'items': model.Item.all().filter('owner =',
                users.get_current_user()).fetch(100)}
        util.add_user(self.request.uri, data)
        path = os.path.join(os.path.dirname(__file__),
                            'templates/sell.htm')
        self.response.out.write(template.render(path, data))

    @user_required
    def get(self, command=None):
        self._process()

    def post(self, command):
        user = users.get_current_user()
        if not user:
            self.redirect(users.create_login_url('/sell'))
        else:
            if command == 'add':
                image = self.request.get('image')
                item = model.Item(owner=user,
                                  title=self.request.get('title'),
                                  price=long(float(self.request.get('price'
                                  )) * 100), image=db.Blob(image),
                                  enabled=True)
                item.put()
                self._process('The item was added.')
            else:
                self._process('Unsupported command.')


class NewLoginHandler(NewBaseHandler):

    def get(self):
        """
............Returns a simple HTML form for login
........"""

        return """
                        <!DOCTYPE hml>
                        <html>
                                <head>
                                        <title>webapp2 auth example</title>
                                </head>
                                <body>
                                <form action="%s" method="post">
                                        <fieldset>
                                                <legend>Login form</legend>
                                                <label>Email <input type="text" name="email" placeholder="Your email" /></label>
                                                <label>Password <input type="password" name="password" placeholder="Your password" /></label>
                                        </fieldset>
                                        <button>Login</button>
                                </form>
                        </html>
                """ \
            % self.request.url

    def post(self):
        """
............username: Get the username from POST dict
............password: Get the password from POST dict
........"""

        email = self.request.POST.get('email')
        password = self.request.POST.get('password')

        # Try to login user with password
        # Raises InvalidAuthIdError if user is not found
        # Raises InvalidPasswordError if provided password doesn't match with specified user

        try:
            self.auth.get_user_by_password(email, password)
            logging.info('authenticated')

            # self.redirect('/secure')

            self.redirect(webapp2.uri_for('secure'))
        except (InvalidAuthIdError, InvalidPasswordError), e:

            # Returns error message to self.response.write in the BaseHandler.dispatcher
            # Currently no message is attached to the exceptions

            return 'login failed'  # e


class RegionField(SelectField):

    def __init__(self, *args, **kwargs):
        super(RegionField, self).__init__(*args, **kwargs)
        self.choices = []
        for region in montaomodel.Region.all().order('name'
                ).fetch(99999):
            self.choices.append([region.key().id(), region.name])


class AddCityForm(Form):

    region = RegionField()
    name = TextField(_('Name'))


class AddCityByDDDForm(Form):

    my_choices = [
        ('11', _('11')),
        ('12', _('12')),
        ('13', _('13')),
        ('14', _('14')),
        ('15', _('15')),
        ('16', _('16')),
        ('17', _('17')),
        ('18', _('18')),
        ('19', _('19')),
        ('21', _('21')),
        ('22', _('22')),
        ('24', _('24')),
        ('27', _('27')),
        ('28', _('28')),
        ('31', _('31')),
        ('32', _('32')),
        ('33', _('33')),
        ('34', _('34')),
        ('35', _('35')),
        ('36', _('36')),
        ('37', _('37')),
        ('38', _('38')),
        ('39', _('39')),
        ('40', _('40')),
        ('41', _('41')),
        ('42', _('42')),
        ('43', _('43')),
        ('44', _('44')),
        ('45', _('45')),
        ('46', _('46')),
        ('47', _('47')),
        ('48', _('48')),
        ('49', _('49')),
        ('50', _('50')),
        ('51', _('51')),
        ('52', _('52')),
        ('53', _('53')),
        ('54', _('54')),
        ('55', _('55')),
        ('61', _('61')),
        ('62', _('62')),
        ('63', _('63')),
        ('65', _('65')),
        ('67', _('67')),
        ('68', _('68')),
        ('69', _('69')),
        ('71', _('71')),
        ('79', _('79')),
        ('81', _('81')),
        ('82', _('82')),
        ('83', _('83')),
        ('84', _('84')),
        ('85', _('85')),
        ('86', _('86')),
        ('91', _('91')),
        ('92', _('92')),
        ('95', _('95')),
        ('96', _('96')),
        ('98', _('98')),
        ]
    ddd = SelectField(choices=my_choices)
    name = TextField(_('Name'))
    region = RegionField()


class AddDDDByRegionForm(Form):

    ddd = TextField(_('ddd'))
    region = RegionField()


class AddCityHandler(BaseRequestHandler):

    def get(self):
        logging.info('i get')
        self.render('addcity.html', {'form': AddCityForm(), 'form_url'
                    : self.request.url})

    def post(self):
        logging.info('i post')
        form = AddCityForm(self.request.params)
        logging.info('i post name' + form.name.data)
        logging.info('i post region' + form.region.data)
        region = montaomodel.Region.get_by_id(long(form.region.data))
        city = montaomodel.City(region=region.key(),
                                name=form.name.data)
        city.put()
        self.redirect(r'/addcity')


class AddCityByDDDHandler(BaseRequestHandler):

    def get(self):
        self.render('addcitybyddd.html', {'form': AddCityByDDDForm(),
                    'form_url': self.request.url})

    def post(self):
        form = AddCityByDDDForm(self.request.params)
        region = montaomodel.Region.get_by_id(long(form.region.data))
        city = montaomodel.City(region=region.key(),
                                areacode=int(form.ddd.data),
                                name=form.name.data)
        city.put()
        self.redirect(r'/addcity_by_ddd')


class AddDDDByRegionHandler(BaseRequestHandler):

    def get(self):
        self.render('adddddbyregion.html', {'form'
                    : AddDDDByRegionForm(), 'form_url'
                    : self.request.url})

    def post(self):
        form = AddDDDByRegionForm(self.request.params)
        region = montaomodel.Region.get_by_id(long(form.region.data))
        logging.info('region: %s' % region.name)
        region.put()
        region.areacodes.append(int(form.ddd.data))
        region.put()
        self.redirect(r'/addddd_by_region')


class AddregionsHandler(NewBaseHandler):

    def get(self):
        """
............Returns a simple HTML form for create a new region
........"""

        return """
                        <!DOCTYPE hml>
                        <html>
                                <head>
                                        <title>webapp2 auth example</title>
                                </head>
                                <body>
                                <form action="%s" method="post">
                                        <fieldset>
                                                <legend>Create region form</legend>


                                                <label>Name <input type="text" name="name" placeholder="Region name" /></label>
                                                
                                        </fieldset>
                                        <button>Add region</button>
                                </form>
                        </html>
                """ \
            % self.request.url

    def post(self):
        logging.info('gettting region name')
        region = montaomodel.Region(name=self.request.POST.get('name'))
        region.put()

        # Region is created, let's try redirecting....

        self.redirect('/')


class NewLogoutHandler(NewBaseHandler):

    """
........Destroy user session and redirect to login
...."""

    def get(self):
        self.auth.unset_session()

        # User is logged out, let's try redirecting to login page

        try:
            self.redirect(self.auth_config['login_url'])
        except (AttributeError, KeyError), e:
            return 'User is logged out'


class SecureRequestHandler(NewBaseHandler):

    """
........Only accessible to users that are logged in
...."""

    @user_required
    def get(self, **kwargs):

        # a = self.app.config.get('foo')

        auser = self.auth.get_user_by_session()
        userid = auser['user_id']
        user = auth_models.User.get_by_id(auser['user_id'])

        try:
            email = user.email
            return "Secure zone %s <a href='%s'>Logout</a>" % (userid,
                    self.auth_config['logout_url'])
        except (AttributeError, KeyError), e:

          # return 'User did not have email'

            return """
                        <!DOCTYPE hml>
                        <html>
                                <head>
                                        <title>add your email</title>
                                </head>
                                <body>
                                <form action="%s" method="post">
                                        <fieldset>
                                                <legend>Add email</legend>
                                                <label>User ID <input type="text" name="username" placeholder="%s" readonly /></label>
                                                <label>Email <input type="text" name="email" placeholder="Your email" /></label>
                                        </fieldset>
                                        <button>Create user</button>
                                </form>
                        </html>
                """ \
                % (self.request.url, userid)

    @user_required
    def post(self, **kwargs):
        email = self.request.POST.get('email')
        auser = self.auth.get_user_by_session()
        userid = auser['user_id']
        user = auth_models.User.get_by_id(auser['user_id'])
        existing_user = auth_models.User.get_by_auth_id(email)

        if existing_user is not None:

            # You need to handle duplicates.
            # Maybe you merge the users? Maybe you return an error?

            return 'email existed already'

        # Test the uniqueness of the auth_id. We must do this to
        # be consistent with User.user_create()

        unique = \
            '{0}.auth_id:{1}'.format(auth_models.__class__.__name__,
                email)

        if auth_models.User.unique_model.create(unique):

            # Append email to the auth_ids list

            user.auth_ids.append(email)
            user.put()
            return 'Email updated'
        else:
            return 'some error'


class FBUser(db.Model):

    id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    name = db.StringProperty(required=True)
    profile_url = db.StringProperty()
    access_token = db.StringProperty(required=True)
    name = db.StringProperty(required=True)
    picture = db.StringProperty()
    email = db.StringProperty()
    friends = db.StringListProperty()
    dirty = db.BooleanProperty()


class BaseHandler(webapp2.RequestHandler):

    @webapp2.cached_property
    def jinja2(self):
        return jinja2.get_jinja2(app=self.app)

    facebook = None
    user = None
    csrf_protect = True

    def render_template(self, file, template_args):
        path = os.path.join(os.path.dirname(__file__), 'templates',
                            file)
        self.response.out.write(template.render(path, template_args))

    def dispatch(self):

        # Get a session store for this request.
    # logging.info('in dispatch %s' % self.request.host)

        self.session_store = sessions.get_store(request=self.request)
        if self.request.host.find('.br') > 0:  # for a Brazilian domain that uses Portuguese

        # logging.info('in dispatch 2 %s' % self.request.host)

            i18n.get_i18n().set_locale('pt-br')
        else:

        # or   lang_code = os.environ.get("HTTP_ACCEPT_LANGUAGE")

        # if self.request.host.find('phoread') > 0:  # for a Brazilian domain that uses Portuguese

        # or   lang_code = os.environ.get("HTTP_ACCEPT_LANGUAGE")

        #    i18n.get_i18n().set_locale('hr')

             # all other domains currently use English

            lang_code = self.session.get('HTTP_ACCEPT_LANGUAGE', None)
            if not lang_code:
                lang_code = os.environ.get('HTTP_ACCEPT_LANGUAGE')
            if lang_code:
                i18n.get_i18n().set_locale(lang_code)
            lang_code_get = self.request.get('hl', None)
            if lang_code_get:
                self.session['HTTP_ACCEPT_LANGUAGE'] = lang_code_get
                i18n.get_i18n().set_locale(lang_code_get)
        try:

            # Dispatch the request.

            webapp2.RequestHandler.dispatch(self)
        finally:

            # Save all sessions.

            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):

        # Returns a session using the default cookie key.

        return self.session_store.get_session()

    @property
    def current_email(self):
        if not hasattr(self, '_current_email'):
            self._current_email = None
            host = self.request.host
            if host.find('.br') > 0:
                email = 'Montao.com.br <info@montao.com.br>'
            else:
                email = 'Kool Business <info@koolbusiness.com>'

            self._current_email = email
        return self._current_email

    @property
    def current_host(self):
        if not hasattr(self, '_current_host'):
            self._current_host = self.request.host
        return self._current_host

    @property
    def current_logo(self):
        if not hasattr(self, '_current_logo'):
            self._current_logo = self.request.host.replace('www', '')
        return self._current_logo

    def initialize(self, request, response):
        """General initialization for every request"""

        super(BaseHandler, self).initialize(request, response)

        # logging.debug('logging init')

        try:
            self.init_csrf()
            self.response.headers['P3P'] = 'CP=HONK'  # iframe cookies in IE

            # Decide the language

            if self.request.host.find('montao.com.br') > 0:
                i18n.get_i18n().set_locale('pt-br')
            elif self.request.host.find('gralumo.com') > 0:

                i18n.get_i18n().set_locale('es-ar')
        except Exception, ex:

            self.log_exception(ex)
            raise

    def handle_exception(self, ex, debug_mode):
        """Invoked for unhandled exceptions by webapp"""

        self.log_exception(ex)
        self.render('error', trace=traceback.format_exc(),
                    debug_mode=debug_mode)

    def log_exception(self, ex):
        """Internal logging handler to reduce some App Engine noise in errors"""

        msg = (str(ex) or ex.__class__.__name__) + ': \n' \
            + traceback.format_exc()
        if isinstance(ex, urlfetch.DownloadError) or isinstance(ex,
                CsrfException) or isinstance(ex,
                taskqueue.TransientError):
            logging.warn(msg)
        else:
            logging.error(msg)

    def set_cookie(
        self,
        name,
        value,
        expires=None,
        ):

        if value is None:
            value = 'deleted'
            expires = datetime.timedelta(minutes=-50000)
        jar = Cookie.SimpleCookie()
        jar[name] = value
        jar[name]['path'] = '/'
        if expires:
            if isinstance(expires, datetime.timedelta):
                expires = datetime.datetime.now() + expires
            if isinstance(expires, datetime.datetime):
                expires = expires.strftime('%a, %d %b %Y %H:%M:%S')
            jar[name]['expires'] = expires
        self.response.headers.add_header(*jar.output().split(': ', 1))

    def set_webapp2_cookie(
        self,
        name,
        value,
        expires=None,
        ):

        if value is None:
            self.response.delete_cookie(name)
        if expires:
            if isinstance(expires, datetime.timedelta):
                expires = datetime.datetime.now() + expires
            if isinstance(expires, datetime.datetime):
                expires = expires.strftime('%a, %d %b %Y %H:%M:%S')
        response.set_cookie(
            name,
            value,
            max_age=expires,
            path='/',
            domain=self.request.host.replace('www', ''),
            secure=True,
            )

    def render_jinja(self, name, **data):  # if we put two stars in front of the dictionary when calling the function, the dictionary is transformed into named arguments

        logo_url = '/_/img/kool_business.png'
        if self.request.host.find('.br') > 0:
            logo_url = '/_/img/montao_small.gif'

        if not data:
            data = {}

        data['logged_in_user'] = self.user
        data['message'] = self.get_message()
        data['csrf_token'] = self.csrf_token
        data['user'] = users.get_current_user()
        user = users.get_current_user()
        host = self.request.host

        data['host'] = host
        data['logo'] = host.replace('www.', '').capitalize()

        data['user_url'] = \
            (users.create_logout_url(self.request.uri) if users.get_current_user() else users.create_login_url(self.request.uri))

        data['request'] = self.request
        data['logo_url'] = logo_url
        data['admin'] = users.is_current_user_admin()
        self.response.write(self.jinja2.render_template(name + '.html',
                            **data))

    def render(self, name, **data):

        logo = 'Koolbusiness.com'
        logo_url = '/_/img/kool_business.png'
        domain = 'koolbusiness'

        if not data:
            data = {}
        data['message'] = self.get_message()
        data['csrf_token'] = self.csrf_token

        data['user'] = users.get_current_user()
        data['fbuser'] = self.user

        user = users.get_current_user()

        data['login_url'] = users.create_login_url(self.request.uri)
        host = self.request.host
        data['host'] = host
        if host.find('.br') > 0:
            logo_url = '/_/img/montao_small.gif'

        data['logo'] = logo
        data['logo_url'] = logo_url
        data['user_url'] = \
            (users.create_logout_url(self.request.uri) if users.get_current_user() else users.create_login_url(self.request.uri))
        data['admin'] = users.is_current_user_admin()

        self.response.out.write(template.render(os.path.join(os.path.dirname(__file__),
                                'templates', name + '.html'), data))

    def init_csrf(self):
        """Issue and handle CSRF token as necessary"""

        self.csrf_token = self.request.cookies.get('c')
        if not self.csrf_token:
            self.csrf_token = str(uuid4())[:8]
            self.set_cookie('c', self.csrf_token)

        # if self.request.method == 'POST' and self.csrf_protect \
        #    and self.csrf_token != self.request.get('_csrf_token'):
        #    raise CsrfException('Missing or invalid CSRF token.')

    def set_message(self, **obj):
        """Simple message support"""

        self.set_cookie('m',
                        (base64.b64encode(json.dumps(obj)) if obj else None))

    def get_message(self):
        """Get and clear the current message"""

        message = self.request.cookies.get('m')
        if message:
            self.set_message()  # clear the current cookie
            return json.loads(base64.b64decode(message))


class SyncwithFacebook(NewBaseHandler):

    """
........Only accessible to users that are logged in
...."""

    @user_required
    def get(self, **kwargs):

        # a = self.app.config.get('foo')

        auser = self.auth.get_user_by_session()
        userid = auser['user_id']
        user = auth_models.User.get_by_id(auser['user_id'])

        try:
            email = user.email
            return "Secure zone %s <a href='%s'>Logout</a>" % (userid,
                    self.auth_config['logout_url'])
        except (AttributeError, KeyError), e:

          # return 'User did not have email'

            return """
                        <!DOCTYPE hml>
                        <html>
                                <head>
                                        <title>add your email</title>
                                </head>
                                <body>
                                <form action="%s" method="post">
                                        <fieldset>
                                                <legend>Add facebook ID</legend>
                                                <label>User ID <input type="text" name="username" placeholder="%s" readonly /></label>
                                                <label>Email <input type="text" name="email" placeholder="Your email" /></label>
                                        </fieldset>
                                        <button>Create user</button>
                                </form>
                        </html>
                """ \
                % (self.request.url, self.current_user.id)

    @user_required
    def post(self, **kwargs):
        auser = self.auth.get_user_by_session()
        user = auth_models.User.get_by_id(auser['user_id'])
        existing_user = \
            auth_models.User.get_by_auth_id(self.current_user.id)

        if existing_user is not None:

            # You need to handle duplicates.
            # Maybe you merge the users? Maybe you return an error?

            pass

        # Test the uniqueness of the auth_id. We must do this to
        # be consistent with User.user_create()

        unique = \
            '{0}.auth_id:{1}'.format(auth_models.__class__.__name__,
                self.current_user.id)

        if auth_models.User.unique_model.create(unique):

            # Append fbuserid to the auth_ids list

            user.auth_ids.append(self.current_user.id)
            user.put()
            return 'Profile updated'
        else:
            return 'some error'


class FileUploadFormHandler(BaseHandler):

    def get(self):
        cookie_django_language = self.request.get('hl', '')  # edit
        if self.request.get('id'):
            ad = Ad.get_by_id(long(self.request.get('id')))
            form = AdForm(instance=ad)
        else:
            form = AdForm()
        if cookie_django_language:
            if cookie_django_language == 'unset':
                del self.request.COOKIES['django_language']
            else:
                self.request.COOKIES['django_language'] = \
                    cookie_django_language
                translation.activate(cookie_django_language)
        self.render_jinja('market_contact_jinja', form=form,
                          form_url=blobstore.create_upload_url('/contactfileupload'
                          ), logout_url=users.create_logout_url('/'))


class ContactFileUploadHandler(blobstore_handlers.BlobstoreUploadHandler):

    def post(self):
        upload_files = self.get_uploads('file')
        blob_info = upload_files[0]
        blob_reader = blobstore.BlobReader(blob_info.key())
        message = mail.EmailMessage(sender='Kool Business <info@koolbusiness.com',
                                    subject=self.request.get('subject'))
        message.body = '''%s
%s
%s
http://koolbusiness.com/''' \
            % (self.request.get('name'), self.request.get('email'),
               self.request.get('text'))
        message.to = 'info@montao.com.br'
        message.bcc = 'info@koolbusiness.com'
        message.attachments = [blob_info.filename, blob_reader.read()]
        message.send()
        blob = blobstore.BlobInfo.get(blob_info.key())
        blob.delete()
        self.redirect('/customer_service.htm')


class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):

    def get(self, resource):
        resource = str(urllib.unquote(resource))
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info)


class KMLHandler2(blobstore_handlers.BlobstoreDownloadHandler):

    def get(self):
        resource = \
            'AMIfv965WtxAc_rWOVjSSx423_oe6f-g5obWYNKX5scg-1gqvISyaZCnv6lRaqro2wOVNOogttyMOylFLsRYZ3Y9UYIe-A69vAt4pdJB2-SHUcdVEM2v0XVLxzT3fTlxwXQVhzmsHPwALH_rCSFIvmYcuV37asVD0Q'
        resource = str(urllib.unquote(resource))
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info)


class CreateKMLHandler(webapp2.RequestHandler):

    def post(self):

        # Create the file

        logging.info('creating file')
        file_name = \
            files.blobstore.create(mime_type='application/octet-stream')

        url = 'http://montaoproject.appspot.com/list.kml'

        result = urlfetch.fetch(url, deadline=100)
        if not result.content:
            return

        # Open the file and write to it

        logging.info('opening file')

        with files.open(file_name, 'a') as f:
            f.write(result.content)

        # Finalize the file. Do this before attempting to read it.

        files.finalize(file_name)

        # Get the file's blob key

        logging.info('getting blob key of file')

        blob_key = files.blobstore.get_blob_key(file_name)
        logging.info('new blob key:' + str(blob_key))
        im = Image.get_by_id(4468185)
        im.primary_image = blob_key
        im.put()
        logging.info('new image key:' + str(im.primary_image))
        logging.info('finished KML handling and put image')


class CreateKMLTask(webapp2.RequestHandler):

    def get(self):
        logging.info('creating KML task')
        taskqueue.add(url=r'/createkml/')
        self.redirect('/')


class PostKeyHandler(BaseHandler):

    def get(self, id):
        region = None
        city = None
        ad = Ad()
        url = self.request.url
        image_url = None
        logging.info('getting data')
        url = \
            'http://api.3taps.com/posting/get/%s?authID=7db0b67453620552e2c695855ae41c6e' \
            % id
        result = urlfetch.fetch(url)
        jsondata = json.loads(result.content)
        ad.threetapsid = jsondata['postKey']
        ad.text = jsondata['body']
        ad.title = jsondata['heading']
        ad.city = jsondata['annotations']['locality']
        ad.region = jsondata['annotations']['locality']
        ad.type = jsondata['status']
        ad.price = str(jsondata['price'])
        ad.geopt = db.GeoPt(jsondata['latitudeEstimated'],
                            jsondata['longitudeEstimated'])

        if ad.price:  # and doesn't contain separators
            try:
                price = \
                    i18n.I18n(self.request).format_decimal(int(ad.price))
            except Exception, e:
                price = ad.price
        else:
            price = ad.price

        image_url = None
        if jsondata['images']:
            image_url = jsondata['images'][0]
        self.render_jinja(
            'view_post_jinja',
            image_url=image_url,
            len=1,
            region=ad.region,
            city=ad.city,
            ad=ad,
            price=price,
            user_url=(users.create_logout_url(self.request.uri) if users.get_current_user() else None),
            current_user=self.current_user,
            linebreak_txt=(ad.text.replace('\n', '<br>'
                           ) if ad.text else None),
            user=(users.get_current_user() if users.get_current_user() else None),
            )


class AddAdCityForm(Form):

    id = TextField(_('Id'))


class NewAdHandler(BaseHandler):

    def get_ad(self, key):
        data = memcache.get(key)
        if data is not None:
            return data
        else:
            data = Ad.get_by_id(long(key))
            memcache.add(key, data, 60)
            return data

    def get_image(self, ad):
        data = memcache.get(str(ad.key()))
        if data is not None:
            return data
        else:
            data = ad.matched_images.get()
            memcache.add(str(ad.key()), data, 60)
            return data

    def get_images(self, ad):
        data = memcache.get(str(ad.key()) + 'images')
        if data is not None:
            return data
        else:
            data = ad.matched_images
            memcache.add(str(ad.key()) + 'images', data, 60)
            return data

    def get(self, id, html):
        region = None
        city = None
        ad = self.get_ad(id)
        if not ad or not ad.published:
            self.error(404)
            return
        image = self.get_image(ad)
        url = self.request.url
        image_url = None
        if image:
            if image.primary_image:
                try:
                    image_url = \
                        images.get_serving_url(str(image.primary_image.key()),
                            size=640)
                except Exception, e:
                    image_url = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
            else:
                image_url = '/images/' + str(image.key().id()) \
                    + '_small.jpg'
        imv = []
        for i in self.get_images(ad):
            if i.primary_image:
                try:
                    i1 = \
                        images.get_serving_url(str(i.primary_image.key()))
                    imv.append(i1)
                except Exception, e:
                    i1 = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
                    imv.append(i1)
        price = ad.price
        if ad.geopt and not ad.city:
            logging.info('geopt:' + str(ad.geopt))
            url = 'http://maps.googleapis.com/maps/api/geocode/json' \
                + '?latlng={},{}&sensor=false'.format(ad.geopt.lat,
                    ad.geopt.lon)
            result = urlfetch.fetch(url)
            jsondata = json.loads(result.content)

            for result in jsondata['results']:
                for component in result['address_components']:
                    if 'administrative_area_level_1' \
                        in component['types']:
                        region = component['long_name'].replace('County'
                                , '')
                    if 'locality' in component['types']:
                        city = component['long_name']

            if ad.city != city:
                ad.city = city
                ad.put()

            if ad.region != region:
                ad.region = region
                ad.put()

            if ad.price:  # and doesn't contain separators
                try:
                    price = \
                        i18n.I18n(self.request).format_decimal(int(ad.price))
                except Exception, e:
                    price = ad.price
        else:
            city = ad.city
            region = ad.region  # if ad.region eller get region

        if region == None:
            region = ''

        if region == None:
            region = ''
        regionentity = montaomodel.Region.all().filter('name =', region).get()
        cityentity = montaomodel.City.all().filter('name =', city).get()
        self.render_jinja(
            'view_ad_jinja',
            image_url=image_url,
            region=ad.region,regionentity=regionentity,cityentity=cityentity,
            city=city,
            imv=imv,
            len=len(imv),
            ad=ad,
            price=price,
            user_url=(users.create_logout_url(self.request.uri) if users.get_current_user() else None),
            admin=users.is_current_user_admin(),
            linebreak_txt=(ad.text.replace('\n', '<br>'
                           ) if ad.text else None),
            image=image,
            user=(users.get_current_user() if users.get_current_user() else None),
            form=AddAdCityForm(),
            form_url=self.request.url,
            )

    def post(self, id, html):
        form = AddAdCityForm(self.request.params)
        logging.debug('i post' + form.id.data)
        city = montaomodel.City.get_by_id(long(form.id.data))
        region = city.region
        ad = Ad.get_by_id(long(id))
        ad.cities = []
        ad.regions = []
        ad.cities.append(city.key())
        ad.regions.append(region.key())
        ad.city = city.name
        ad.region = region.name
        ad.put()
        logging.debug('put data')
        self.redirect('/vi/%s.html' % id)


class Ad3tapsHandler(BaseHandler):

    def get(self, id):
        region = None
        city = None

        # ad = Ad.get_by_id(long(id))
        # if not ad or not ad.published:
        #    self.error(404)
        #    return
        # image = ad.matched_images.get()

        url = self.request.url

        # image_url = None
        # if image:
        #    if image.primary_image:
        #        try:
        #            image_url = \
        #                images.get_serving_url(str(image.primary_image.key()),
        #                    size=640)
        #        except Exception, e:
        #            image_url = '/images/' + str(image.key().id()) \
        #                + '_small.jpg'
        #    else:
        #        image_url = '/images/' + str(image.key().id()) \
        #            + '_small.jpg'
        # imv = []
        # for i in ad.matched_images:
        #    if i.primary_image:
        #        try:
        #            i1 = \
        #                images.get_serving_url(str(i.primary_image.key()))
        #            imv.append(i1)
        #        except Exception, e:
        #            i1 = '/images/' + str(image.key().id()) \
        #                + '_small.jpg'
        #            imv.append(i1)

        if True:  # ad.geopt:
            logging.info('getting data')
            url = \
                'http://api.3taps.com/posting/get/X7J67W?authID=7db0b67453620552e2c695855ae41c6e'  # http://maps.googleapis.com/maps/api/geocode/json' \

                # + '?latlng={},{}&sensor=false'.format(ad.geopt.lat,
                #    ad.geopt.lon)

            result = urlfetch.fetch(url)
            jsondata = json.loads(result.content)
            logging.info('data:' + str(jsondata))

            # for result in jsondata['results']:
            #    for component in result['address_components']:
            #        if 'administrative_area_level_1' \
            #            in component['types']:
            #            region = component['long_name'].replace('County'
            #                    , '')
            #        if 'locality' in component['types']:
            #            city = component['long_name']

            # ad.city = city
            # ad.put()

            # if ad.price:  # and doesn't contain separators
            #    try:
            #        price = \
            #            i18n.I18n(self.request).format_decimal(int(ad.price))
            #    except Exception, e:
            #        price = ad.price
            # else:

             #   price = ad.price

            self.render_jinja('view_ad_jinja',
                              user=(users.get_current_user() if users.get_current_user() else None))  # image_url=image_url,
                                                                                                      # region=region,
                                                                                                      # city=city,
                                                                                                      # imv=imv,
                                                                                                      # len=len(imv),
                                                                                                      # ad=ad,
                                                                                                      # price=price,
                                                                                                      # user_url=(users.create_logout_url(self.request.uri) if users.get_current_user() else None),
                                                                                                      # current_user=self.current_user,
                                                                                                      # linebreak_txt=(ad.text.replace('\n', '<br>'
                                                                                                      #              ) if ad.text else None),
                                                                                                      # image=image,


class CurrentAdHandler(BaseHandler):

    def get(self, ad_id):
        region = None
        city = None
        ad = Ad.get_by_id(long(ad_id))
        if not ad or not ad.published:
            self.error(404)
            return
        image = ad.matched_images.get()
        url = self.request.url
        image_url = None
        if image:
            if image.primary_image:
                try:
                    image_url = \
                        images.get_serving_url(str(image.primary_image.key()),
                            size=640)
                except Exception, e:
                    image_url = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
            else:
                image_url = '/images/' + str(image.key().id()) \
                    + '_small.jpg'
        imv = []
        for i in ad.matched_images:
            if i.primary_image:
                try:
                    i1 = \
                        images.get_serving_url(str(i.primary_image.key()))
                    imv.append(i1)
                except Exception, e:
                    i1 = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
                    imv.append(i1)

        if ad.geopt:
            logging.info('geopt:' + str(ad.geopt))
            url = 'http://maps.googleapis.com/maps/api/geocode/json' \
                + '?latlng={},{}&sensor=false'.format(ad.geopt.lat,
                    ad.geopt.lon)
            result = urlfetch.fetch(url)
            jsondata = json.loads(result.content)

            for result in jsondata['results']:
                for component in result['address_components']:
                    if 'administrative_area_level_1' \
                        in component['types']:
                        region = component['long_name'].replace('County'
                                , '')
                    if 'locality' in component['types']:
                        city = component['long_name']

            # ad.city = city
            # ad.put() unnecesarry to write to datastore just because of a view

            if ad.price:  # and doesn't contain separators
                try:
                    price = \
                        i18n.I18n(self.request).format_decimal(int(ad.price))
                except Exception, e:
                    price = ad.price
            else:
                price = ad.price

            self.render_jinja(
                'view_ad_jinja',
                image_url=image_url,
                region=region,
                city=city,
                imv=imv,
                len=len(imv),
                ad=ad,
                price=price,
                user_url=(users.create_logout_url(self.request.uri) if users.get_current_user() else None),
                current_user=self.current_user,
                linebreak_txt=(ad.text.replace('\n', '<br>'
                               ) if ad.text else None),
                image=image,
                user=(users.get_current_user() if users.get_current_user() else None),
                )


class AboutHandler(NewBaseHandler):

    def get(self):
        user = self.auth.get_user_by_session()
        logging.info('user:' + str(user))
        self.render('about')


class RulesHandler(NewBaseHandler):

    def get(self):
        self.render('rules')


class AdWatch(NewBaseHandler, BaseHandler):

    def get(self):
        user = self.auth.get_user_by_session()
        logging.info('user:' + str(user))
        self.render_jinja('favourites',
                          favorites=self.session.get('favorites'))


class WatchAdHandler(NewBaseHandler, BaseHandler):

    def get(self):
        user = self.auth.get_user_by_session()
        logging.info('user:' + str(user))
        favorites = self.session.get('favorites')
        if favorites:
            favorites.append(Ad.get_by_id(long(self.request.GET['aid'
                             ])))
        else:
            favorites = []
        self.session['favorites'] = favorites

        self.render_jinja('favourites',
                          favorites=self.session.get('favorites'))


class SecurityHandler(BaseHandler):

    def get(self):
        self.render('security')


class Passwordreset(BaseHandler):

    csrf_protect = False

    def get(self):
        template_values = {}
        self.render_jinja('newpasswd')

    def post(self):
        email = self.request.POST['email']
        user = auth_models.User.get_by_auth_id(email)
        token = auth_models.User.token_model.create(user.key.id(),
                'passwordreset').token
        if user:
            message = mail.EmailMessage(sender='niklasro@gmail.com',
                    subject='Password reset successful')
            message.to = email
            output = \
                "You're receiving this e-mail because you requested a password reset. Your new password can be updated from: " \
                + self.request.host + '/passwdresetcomplete/' + token
            message.body = '%s' % output
            message.send()
            self.response.out.write('We have e-mailed a password reset to the e-mail address you submitted. You should be receiving it shortly.'
                                    )
        else:
            self.response.out.write('Unknown user')


class BlobHandler(BaseHandler):

    def get(self, file_id):
        image = Image.get_by_id(long(file_id))
        if not image:
            self.error(404)
            return
        url = images.get_serving_url(str(image.primary_image.key()),
                size=120)
        self.render_template('info.html', {'image': image, 'url': url})


import google


class Ad(db.Model):

    cities = db.ListProperty(db.Key)
    regions = db.ListProperty(db.Key)
    primary_image = blobstore.BlobReferenceProperty()
    usr = db.ReferenceProperty()  # ndb_model.KeyProperty()

    # decimal_price = DecimalProperty()

    userID = db.StringProperty(verbose_name='User ID')
    integer_price = db.IntegerProperty()

    # threetapsid = db.StringProperty(verbose_name='threetaps ID')

    ip = db.StringProperty(verbose_name='ip')
    ipcountry = db.StringProperty(indexed=False, verbose_name='origin')
    tags = db.ListProperty(db.Category)
    category = db.CategoryProperty(verbose_name='Category')

    # subcategory = db.CategoryProperty(verbose_name='Subcategory')
    # vehiclecategory = db.CategoryProperty(choices=categories.keys(),
            # default='cars', verbose_name='Category')

    title = db.StringProperty(verbose_name='title')  # required
    type = db.StringProperty(verbose_name='ContentType')  # sell,wanted,rent,lease,buy
    company_ad = db.BooleanProperty(default=False,
                                    verbose_name='company_ad')  # false or nothing
    user = db.UserProperty(verbose_name='userid')
    im = db.IMProperty(verbose_name='nickname')  # optional, xmpp
    city = db.StringProperty()  # postaladdress should work instead
    region = db.StringProperty()  # postaladdress should work instead

    url = db.StringProperty(verbose_name='url')
    # link = db.LinkProperty(verbose_name='Link')  # enable

    geopt = db.GeoPtProperty(verbose_name='geopt')
    text = db.TextProperty(verbose_name='text')
    currency = db.StringProperty(choices=(
        'INR',
        'EUR',
        'ARS',
        'AUD',
        'BRL',
        'GBP',
        'CAD',
        'CZK',
        'DKK',
        'HKD',
        'HUF',
        'ILS',
        'JPY',
        'MXN',
        'NZD',
        'NOK',
        'PLN',
        'PHP',
        'SGD',
        'SEK',
        'SGD',
        'CHF',
        'USD',
        'THB',
        'TWB',
        ), verbose_name='Currency')
    price = db.StringProperty(verbose_name='price')
    phonenumber = db.PhoneNumberProperty(indexed=False,
            verbose_name='phonenumber')  # viewbit

    # postaladress = db.PostalAddressProperty(indexed=False,
    #        verbose_name='postaladdress')

    phoneview = db.BooleanProperty(default=False,
                                   verbose_name='phoneview')
    email = db.EmailProperty(verbose_name='Email')  # optional
    name = db.StringProperty(verbose_name='Name')
    published = db.BooleanProperty(default=True,
                                   verbose_name='published')

    address = db.StringProperty(verbose_name='address')
    number_of_rooms = db.IntegerProperty()
    size = db.FloatProperty()
    regdate = db.IntegerProperty()
    mileage = db.IntegerProperty()
    added = db.DateTimeProperty(verbose_name='added', auto_now_add=True)  # readonly
    modified = db.DateTimeProperty(verbose_name='modified',
                                   auto_now_add=True)
    last_modified = db.DateTimeProperty(required=True, auto_now=True)
    crypted_password = db.StringProperty()  # set default true random
    salt = db.StringProperty()  # merge with passwrd, set default true random or why even store?
    timestamp = db.DateTimeProperty(auto_now=True)  # backupsystem

    def __unicode__(self):
        return self.title

    def to_json(self):
        data = {}
        for prop in self.properties().values():
            data[prop.name] = prop.get_value_for_datastore(self)
        return json(data)

    def __encrypt(self, plaintext, salt=''):
        """returns the SHA1 hexdigest of a plaintext and salt"""

        phrase = hashlib.sha1()
        phrase.update('%s--%s' % (plaintext, salt))
        return phrase.hexdigest()

    def set_password(self, new_password):
        """sets the crypted_password"""

        import datetime
        if not self.salt:
            self.salt = self.__encrypt(str(datetime.datetime.now()))
        self.crypted_password = self.__encrypt(new_password, self.salt)

    def set_geography(self):
        """sets the ad's region and city"""

        url = 'http://maps.googleapis.com/maps/api/geocode/json' \
            + '?latlng={},{}&sensor=false'.format(self.geopt.lat,
                self.geopt.lon)
        logging.info('url%s' % url)
        result = urlfetch.fetch(url)
        jsondata = json.loads(result.content)

        for result in jsondata['results']:
            for component in result['address_components']:
                logging.info('components:' + str(component))
                logging.info('components type:' + str(component['types'
                             ]))
                if 'administrative_area_level_1' in component['types']:
                    self.region = component['long_name'
                            ].replace('County', '')
                if 'locality' in component['types']:
                    self.city = component['long_name']
        if self.city and self.region:
            self.place = self.city + ', ' + self.region
        elif self.city:
            self.place = self.city
        elif self.region:
            self.place = self.region

    def check_password(self, plaintext):
        return self.__encrypt(plaintext, self.salt) \
            == self.crypted_password

    def next(self):
        return (Ad.all().filter('published =', True).filter('modified >'
                , self.modified).get() if Ad.all().filter('published ='
                , True).filter('modified >',
                self.modified).get() else self)

    def prev(self):
        return Ad.all().filter('published =', True).filter('modified <'
                , self.modified).get()

    def get_city(self):
        return montaomodel.City.get(self.cities[0])

    def get_categoryname(self):
        return CATEGORIES[str(ad.category)]

    def uri2view(self):
        try:
            return images.get_serving_url(str(self.matched_images.get().primary_image.key()),
                    100)
        except Exception, e:
            return None

    @classmethod
    def count_all(cls):
        """
        Count *all* of the rows (without maxing out at 1000)
        """

        count = 0
        query = cls.all().order('__key__')

        while True:
            current_count = query.count()
            if current_count == 0:
                return count
            count += current_count

            if current_count == 1000:
                last_key = query.fetch(1, 999)[0].key()
                query = query.filter('__key__ > ', last_key)

        return count


def levenshtein(s1, s2):  # proximity
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s1:
        return len(s2)
    previous_row = xrange(len(s2) + 1)
    for (i, c1) in enumerate(s1):
        current_row = [i + 1]
        for (j, c2) in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions,
                               substitutions))
        previous_row = current_row
    return previous_row[-1]


def lev(a, b):
    if not a:
        return len(b)
    if not b:
        return len(a)
    return min(lev(a[1:], b[1:]) + (a[0] != b[0]), lev(a[1:], b) + 1,
               lev(a, b[1:]) + 1)


def delete_all_in_index(index_name):
    """Delete all the docs in the given index."""

    doc_index = search.Index(name=index_name)

    while True:

        # Get a list of documents populating only the doc_id field and extract the ids.

        document_ids = [document.doc_id for document in
                        doc_index.get_range(ids_only=True)]
        if not document_ids:
            break

        # Delete the documents for the given ids from the Index.

        doc_index.delete(document_ids)


# class AdPlace(db.Model):
#  ad = db.ReferenceProperty(Ad, collection_name='adcities')
#  place = db.ReferenceProperty(City, collection_name='ads')


class Profile(RequestHandler, NewBaseHandler):

    @user_required
    def get(self):
        data = \
            {'profile': model.Profile.from_user(users.get_current_user())}
        util.add_user(self.request.uri, data)
        path = os.path.join(os.path.dirname(__file__),
                            'templates/profile.htm')
        self.response.out.write(template.render(path, data))

    def post(self):
        profile = model.Profile.from_user(users.get_current_user())
        if profile == None:
            profile = model.Profile(owner=users.get_current_user())
        profile.paypal_email = self.request.get('paypal_email')
        profile.put()
        data = {'profile': profile, 'message': 'Profile updated'}
        util.add_user(self.request.uri, data)
        path = os.path.join(os.path.dirname(__file__),
                            'templates/profile.htm')
        self.response.out.write(template.render(path, data))


class Image(db.Model):  # migrate to blobstore

    reference = db.ReferenceProperty(Ad,
            collection_name='matched_images', verbose_name='Title')
    primary_image = blobstore.BlobReferenceProperty()
    title = db.StringProperty(multiline=True, verbose_name='Title')
    avatar = db.BlobProperty(default=None)
    text = db.TextProperty(default=None)
    name = db.StringProperty(default=None)
    email = db.EmailProperty(indexed=False, verbose_name='Email')
    name = db.StringProperty()
    desc = db.StringProperty()
    owner = db.UserProperty()
    secret = db.StringProperty()
    full = db.BlobProperty(default=None)
    full_ext = db.StringProperty()
    small = db.BlobProperty(default=None)
    small_ext = db.StringProperty()
    thumb = db.BlobProperty(default=None)
    thumb_ext = db.StringProperty()
    published = db.BooleanProperty(default=True,
                                   verbose_name='published')
    added = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now_add=True)
    timestamp = db.DateTimeProperty(auto_now=True)

    def thumb_name(self):
        return '%s.%s' % (self.key(), self.thumb_ext)

    def small_name(self):
        return '%s_small.%s' % (self.key(), self.small_ext)

    def full_name(self):
        return '%s_full.%s' % (self.key(), self.full_ext)

    def uri2view(self):
        view = None
        if self.primary_image:
            if self.primary_image.key():
                try:
                    view = \
                        images.get_serving_url(str(self.primary_image.key()))
                except Exception, e:
                    view = '/images' + str(self.key().id()) + '.jpg'
            else:
                view = '/images' + str(self.key().id()) + '.jpg'
        return view


class ChangeEmailForm(Form):

    email = TextField('Email', [validators.Length(min=6,
                      message=_(u'Little short for an email address?'
                      )),
                      validators.Email(message=_(u'That\'s not a valid email address.'
                      ))])


class EditImagePage(BaseHandler):

    def get(self):
        if self.request.get('id'):
            id = int(self.request.get('id'))
            image = Image.get(db.Key.from_path('Image', id))

            # im = ad.matched_images

            editImageForm = ImageForm(instance=image)
            self.response.out.write('<form method="POST" action="/edit"><table>'
                                    )
            self.response.out.write(ImageForm(instance=image))
            self.response.out.write('</table><input type="hidden" name="_id" value="%s"><input type="submit"></form></body></html>'
                                     % id)
            self.response.out.write('</table><input type="submit"></form></body></html>'
                                    )


class ImagePage(webapp2.RequestHandler):

    def get(self):
        if users.is_current_user_admin():
            if self.request.get('h'):
                then = datetime.now() \
                    - timedelta(hours=int(self.request.get('h')))
                query = \
                    db.GqlQuery('SELECT * FROM Image where added > :1 ORDER BY added desc'
                                , then)
            else:
                query = \
                    db.GqlQuery('SELECT * FROM Image ORDER BY added desc limit '
                                 + self.request.get('limit')
                                + ' offset ' + self.request.get('offset'
                                ))

                                    # clean

            count = 20
            self.response.out.write(str(count) + '<table border ="1">')
            for image in query:
                self.response.out.write('<tr><td><a href="/admin/Image/edit/%s/"><img src="/images/%d'
                         % (image.key(), image.key().id()))
                if image.thumb_ext:
                    self.response.out.write('.' + image.thumb_ext
                            + '"></a>')
                try:
                    self.response.out.write('</td><td><a href="/%d/url">'
                             % image.reference.key().id())
                    self.response.out.write('%s</a>'
                            % image.reference.url + '<br/>'
                            + image.reference.title)
                    self.response.out.write('</td><td> %s '
                            % image.reference.added)
                    self.response.out.write('</td><td>ad published? %s '
                             % image.reference.published)
                    self.response.out.write('</td><td>image published? %s '
                             % image.published)
                    self.response.out.write('</td><td><a href="/edit?id=%d">Edit ad</a> - '
                             % image.reference.key().id())
                    self.response.out.write('</td></tr>')
                except:
                    self.response.out.write('no reference')
            self.response.out.write('</table><br/>')
            nextoffset = int(self.request.get('offset')) \
                + int(self.request.get('limit'))
            self.response.out.write('<a href="/images.html?limit='
                                    + self.request.get('limit')
                                    + '&offset=' + str(nextoffset)
                                    + '">next</a>')


class ImageBlobPage(webapp2.RequestHandler):

    def get(self):
        id = int(self.request.get('id'))
        image = Image.get(db.Key.from_path('Image', id))
        if users.is_current_user_admin():
            self.response.headers['Content-Type'] = 'jpg'
            self.response.out.write(image.full)


class ServeImageById(webapp2.RequestHandler):

    def get(
        self,
        idd,
        sz,
        ext,
        ):

        id = int(idd)
        im = Image.get(db.Key.from_path('Image', id))
        if not im or not im.published:
            self.error(404)
            return
        if sz == '.':
            d = im.thumb
        elif sz == '_small.':
            d = im.small
        elif sz == '_full.':
            d = im.full
        elif sz == '_o.' and im.full > 80:
            d = sq_thumb(im.thumb, 80)
        else:
            raise Exception('wrong sz %r' % sz)
        if not d:
            d = im.full
        else:
            self.response.headers.add_header('Expires',
                    'Thu, 01 Dec 2014 16:00:00 GMT')
        try:
            tmp = images.Image(d)
        except Exception:
            pass
        if tmp.width > 800:
            d = im.small
        self.response.headers['Content-Type'] = mimetypes[ext]
        self.response.out.write(d)


class RemoveImageById(webapp2.RequestHandler):

    def get(self, idd):
        id = int(self.request.get('id'))
        adid = int(self.request.get('adid'))
        ad = Ad.get(db.Key.from_path('Ad', adid))
        if users.is_current_user_admin() or users.get_current_user() \
            == ad.user and ad.user is not None:
            image = Image.get(db.Key.from_path('Image', id))
            image.delete()
            self.redirect('/vi/%s.html' % adid)


class PublishAdById(webapp2.RequestHandler):

    def get(self, id):
        ad = Ad.get(db.Key.from_path('Ad', ad))
        if users.is_current_user_admin() or users.get_current_user() \
            == ad.user and ad.user is not None:
            ad.published = True
            ad.save()
            self.redirect('/%s' % adid)


class AddImage(BaseHandler, blobstore_handlers.BlobstoreUploadHandler):

    def post(self):
        logging.info('adding image')
        ad_id = self.request.get('_id')

        def create_image(
            number,
            self,
            file1,
            ad,
            ):

            try:
                logging.info('creating image')
                filedata = file1
                im = Image(reference=ad)
                if number == 'file':
                    ad.save
                form = cgi.FieldStorage()
                file_name = \
                    files.blobstore.create(mime_type=self.request.get('file'
                        ).type,
                        _blobinfo_uploaded_filename=self.request.get('file'
                        ).filename)
                with files.open(file_name, 'a') as f:
                    f.write(file1)
                files.finalize(file_name)
                blob_key = files.blobstore.get_blob_key(file_name)
                logging.info('creating blob key')
                im.primary_image = blob_key
                logging.info('saving image')
                im.put()
                ad.put()
                file_name = self.request.get(number).filename
                im.published = True
                im.save()
            except:
                logging.error('imageadderror')
                pass

        try:
            logging.info('trying')
            logging.info('trying with id' + ad_id)
            logging.info('trying with id from session'
                         + self.session.get('edit'))
            ad = Ad.get(db.Key.from_path('Ad', int(ad_id)))
            self.response.out.write(ad.title)

            if users.is_current_user_admin() \
                or users.get_current_user() == ad.user and ad.user \
                is not None or int(ad_id) == int(self.session.get('edit'
                    )):
                logging.info('trying')
                if ad.matched_images.count() < 6:
                    for upload in self.get_uploads():
                        try:
                            img = Image(reference=ad)
                            img.primary_image = upload.key()
                            img.put()
                            ad.put()
                        except Exception, e:
                            logging.error('imageadderror' + str(e))
        except:

                    # create_image('file', self,
                     #            self.request.get('file'
                      #           ).file.read(), ad)

            self.redirect('/vi/%s.html' % ad_id)  # make this finally
        self.redirect('/vi/%s.html' % ad_id)


class EditAdPage(BaseHandler):

    csrf_protect = False

    def get(self):
        auth = False
        if self.session.get('edit'):
            if users.get_current_user() or int(self.request.get('id')) \
                == int(self.session.get('edit')):
                auth = True
        else:
            if users.get_current_user():
                auth = True
        if auth:
            if self.request.get('id'):
                id = int(self.request.get('id'))
                ad = Ad.get(db.Key.from_path('Ad', id))
                im = ad.matched_images
                editAdForm = AdForm(obj=ad)
                if str(users.get_current_user()) == str(ad.user) \
                    or users.is_current_user_admin():
                    self.render_jinja(
                        'edit',
                        form_url=blobstore.create_upload_url('/addimage'
                                ),
                        admin=users.is_current_user_admin(),
                        user_url=(users.create_logout_url('/'
                                  ) if users.get_current_user() else users.create_login_url(self.request.uri)),
                        user=users.get_current_user(),
                        ad=ad,
                        form=editAdForm,
                        )
                    return
                if users.is_current_user_admin() \
                    or users.get_current_user() == ad.user and ad.user \
                    is not None:
                    if not im:
                        self.response.out.write('<html><body bgcolor="FFFFEB"><form method="POST" action="/edit"><table>'
                                )
                    else:
                        self.response.out.write('<html><body bgcolor="FFFFEB">'
                                )
                        for o in im[0:5]:
                            if o.published and o.thumb_ext:
                                self.response.out.write('<img src="/images/%d.%s"><a href="removeimage?id=%d&adid=%s">remove</a>'
                                         % (o.key().id(),
                                        str(o.thumb_ext), o.key().id(),
                                        id))

                            if o.primary_image:
                                i1 = \
                                    images.get_serving_url(str(o.primary_image.key()))

                                self.response.out.write('<img src="/%s"><a href="removeimage?id=%d&adid=%s">remove</a>'
                                         % (i1, str(o.thumb_ext),
                                        o.key().id(), id))

                    if ad.matched_images.count() < 55:
                        self.response.out.write('<form method="POST"   enctype="multipart/form-data"  action="/addimage"><input type="file" id="file"  name="file" size="35" ><input type="hidden" name="_id" value="%s"><input type="submit" value="Add image" /></form>'
                                 % id)
                    self.response.out.write('<form method="POST" action="/edit"><table>'
                            )
                    self.response.out.write(AdForm(instance=ad))
                    self.response.out.write('</table><input type="hidden" name="_id" value="%s"><input type="submit"></form></body></html>'
                             % id)
                else:
                    self.redirect(users.create_login_url(self.request.uri))
            else:
                ad = (Ad(user=users.get_current_user(),
                      name=users.get_current_user().nickname(),
                      email=users.get_current_user().email()) if users.get_current_user() else Ad())
                self.response.out.write('<html><body bgcolor="FBFBD3"><form method="POST"  action="/edit"><table>'
                        )
                self.response.out.write(AdForm(instance=ad))
                self.response.out.write('</table><input type="submit"></form></body></html>'
                        )

    def post(self):
        if self.request.get('_id'):
            id = int(self.request.get('_id'))
            ad = Ad.get(db.Key.from_path('Ad', id))
            if users.is_current_user_admin() \
                or str(users.get_current_user()) == str(ad.user) \
                or int(self.request.get('id')) \
                == int(self.session.get('edit')) and ad.user != None:
                data = AdForm(self.request.params)  # data=self.request.POST, instance=ad)
                if True:  # data.is_valid():

                # Save data, redirect to view

                    logging.debug('Save data, redirect to view')
                    ad.name = data.name.data
                    ad.title = data.title.data
                    ad.text = data.text.data
                    ad.price = data.price.data

                    # entity = data.save(commit=False)

                    # entity.user = users.get_current_user()

                    ad.put()
                    self.redirect('/vi/%s.html' % id)
                else:

                # Reprint the form

                    self.response.out.write('<html><body><form method="POST"  action="/edit"><table>'
                            )
                    self.response.out.write(data)
                    self.response.out.write('</table><input type="hidden" name="_id" value="%s"><input type="submit"></form></body></html>'
                             % id)
        else:
            data = AdForm(data=self.request.POST)
            if data.is_valid():

                # Save the data, and redirect to the view page

                entity = data.save(commit=False)
                entity.user = \
                    (users.get_current_user() if users.get_current_user() else None)
                entity.put()
                self.response.out.write('posted' + entity.title)


class MyTextInput(TextInput):

    def __init__(self, error_class=u'has_errors'):
        super(MyTextInput, self).__init__()
        self.error_class = error_class

    def __call__(self, field, **kwargs):
        if field.errors:
            c = kwargs.pop('class', '') or kwargs.pop('class_', '')
            kwargs['class'] = u'%s %s' % (self.error_class, c)
        return super(MyTextInput, self).__call__(field, **kwargs)


class MyPasswordInput(PasswordInput):

    def __init__(self, error_class=u'has_errors'):
        super(MyPasswordInput, self).__init__()
        self.error_class = error_class

    def __call__(self, field, **kwargs):
        if field.errors:
            c = kwargs.pop('class', '') or kwargs.pop('class_', '')
            kwargs['class'] = u'%s %s' % (self.error_class, c)
        return super(MyPasswordInput, self).__call__(field, **kwargs)


class RequiredIf(Required):

    # a validator which makes a field required if
    # another field is set and has a truthy value

    def __init__(
        self,
        other_field_name,
        *args,
        **kwargs
        ):

        self.other_field_name = other_field_name
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise Exception('no field named "%s" in form'
                            % self.other_field_name)
        if other_field.data:
            logging.info('other_field.data 2' + str(other_field.data))
            super(RequiredIf, self).__call__(form, field)


class PasswordMatch(Required):

    # a validator which makes a password field not validate if
    # another field is set and has not the same value

    def __init__(
        self,
        other_field_name,
        *args,
        **kwargs
        ):

        self.other_field_name = other_field_name
        super(PasswordMatch, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field.data != field.data:
            raise Exception('Passwords do not match')
        if other_field.data:
            logging.info('other_field.data 2' + str(other_field.data))
            super(PasswordMatch, self).__call__(form, field)


class MyTextArea(TextArea):

    def __init__(self, error_class=u'has_errors'):
        super(MyTextArea, self).__init__()
        self.error_class = error_class

    def __call__(self, field, **kwargs):
        if field.errors:
            c = kwargs.pop('class', '') or kwargs.pop('class_', '')
            kwargs['class'] = u'%s %s' % (self.error_class, c)
        return super(MyTextArea, self).__call__(field, **kwargs)


class SearchForm(Form):

    categories = [
        ('1', _('All categories')),
        ('2', _('VEHICLES')),
        ('2010', _('Cars')),
        ('3', _('Motorcycles')),
        ('4', _('Accessories & Parts')),
        ('5', _('PROPERTIES')),
        ('7', _('Apartments')),
        ('8', _('Houses')),
        ('9', _('Commercial properties')),
        ('10', _('Land')),
        ('11', _('ELECTRONICS')),
        ('12', _('Mobile phones & Gadgets')),
        ('13', _('TV/Audio/Video/Cameras')),
        ('14', _('Computers')),
        ('15', _('HOME & PERSONAL ITEMS')),
        ('16', _('Home & Garden')),
        ('17', _('Clothes/Watches/Accessories')),
        ('18', _('For Children')),
        ('19', _('LEISURE/SPORTS/HOBBIES')),
        ('20', _('Sports & Outdoors')),
        ('21', _('Hobby & Collectables')),
        ('22', _('Music/Movies/Books')),
        ('23', _('Pets')),
        ('20', _('BUSINESS TO BUSINESS')),
        ('24', _('Hobby & Collectables')),
        ('25', _('Professional/Office equipment')),
        ('26', _('Business for sale')),
        ('27', _('JOBS & SERVICES')),
        ('28', _('Jobs')),
        ('29', _('Services')),
        ('30', _('Events & Catering')),
        ('31', _('Others')),
        ('1000', _('Sports & Outdoors')),
        ('1010', _('Hobby & Collectables')),
        ('1020', _('Hobby & Collectables')),
        ('1030', _('Music/Movies/Books')),
        ('1050', _('Pets')),
        ('1080', _('BUSINESS TO BUSINESS')),
        ('1100', _('Hobby & Collectables')),
        ('1090', _('Professional/Office equipment')),
        ('2010', _('Business for sale')),
        ('2030', _('Sports & Outdoors')),
        ('2040', _('Hobby & Collectables')),
        ('2080', _('Music/Movies/Books')),
        ('2070', _('Pets')),
        ('3000', _('BUSINESS TO BUSINESS')),
        ('3040', _('Hobby & Collectables')),
        ('3050', _('Professional/Office equipment')),
        ('3060', _('Business for sale')),
        ('4000', _('Sports & Outdoors')),
        ('4010', _('Hobby & Collectables')),
        ('4020', _('Music/Movies/Books')),
        ('4040', _('Pets')),
        ('4030', _('BUSINESS TO BUSINESS')),
        ('4090', _('Hobby & Collectables')),
        ('4060', _('Professional/Office equipment')),
        ('4070', _('Business for sale')),
        ('5030', _('Music/Movies/Books')),
        ('5020', _('Pets')),
        ('5010', _('BUSINESS TO BUSINESS')),
        ('5040', _('Hobby & Collectables')),
        ('6010', _('Professional/Office equipment')),
        ('6020', _('Business for sale')),
        ('6030', _('Music/Movies/Books')),
        ('6040', _('Pets')),
        ('7010', _('BUSINESS TO BUSINESS')),
        ('Other', _('Hobby & Collectables')),
        ]

    regions = [
        ('4703187', u'Andaman & Nicobar Islands'),
        ('4694186', u'Andhra Pradesh'),
        ('4699188', u'Arunachal Pradesh'),
        ('4692186', u'Assam'),
        ('4702186', u'Bihar'),
        ('4698185', u'Chandigarh'),
        ('4676188', u'Chhattisgarh'),
        ('4691190', u'Dadra & Nagar Haveli'),
        ('4704183', u'Daman & Diu'),
        ('4699183', u'Delhi'),
        ('4702187', u'Goa'),
        ('4691189', u'Gujarat'),
        ('4700186', u'Haryana'),
        ('4703185', u'Himachal Pradesh'),
        ('4694187', u'Jammu & Kashmir'),
        ('4699189', u'Jharkhand'),
        ('4701185', u'Karnataka'),
        ('4695189', u'Kerala'),
        ('4700189', u'Lakshadweep'),
        ('4697186', u'Madhya Pradesh'),
        ('4694184', u'Maharashtra'),
        ('4700187', u'Manipur'),
        ('4703186', u'Meghalaya'),
        ('4698184', u'Mizoram'),
        ('4692187', u'Nagaland'),
        ('4696185', u'Orissa'),
        ('4676189', u'Pondicherry'),
        ('4693185', u'Punjab'),
        ('4701186', u'Rajasthan'),
        ('4701187', u'Sikkim'),
        ('4701188', u'Tamil Nadu'),
        ('4697187', u'Tripura'),
        ('4699190', u'Uttaranchal'),
        ('4692188', u'Uttar Pradesh'),
        ('4700188', u'West Bengal'),
        ]
    cities = [('', _(u'«Choose city»')), ('3', _(u'Mumbai')), ('4',
              _(u'Delhi'))]
    search = TextField(_('Search'),
                       [validators.Required(message=_('Name is required'
                       ))], widget=MyTextInput())

    w = SelectField(_('Region'), choices=regions,
                    validators=[validators.Required(message=_('Region is required'
                    ))])
    area = SelectField(_('City'), choices=cities,
                       validators=[validators.Required(message=_('City is required'
                       ))])
    category_group = SelectField(_('Category'), choices=categories,
                                 validators=[validators.Required(message=_('Category is required'
                                 ))])

    def refresh(self):
        self.w.choices = [
            ('4703187', 'Andaman & Nicobar Islands'),
            ('4694186', 'Andhra Pradesh'),
            ('4699188', 'Arunachal Pradesh'),
            ('4692186', 'Assam'),
            ('4702186', 'Bihar'),
            ('4698185', 'Chandigarh'),
            ('4676188', 'Chhattisgarh'),
            ('4691190', 'Dadra & Nagar Haveli'),
            ('4704183', 'Daman & Diu'),
            ('4699183', 'Delhi'),
            ('4702187', 'Goa'),
            ('4691189', 'Gujarat'),
            ('4700186', 'Haryana'),
            ('4703185', 'Himachal Pradesh'),
            ('4694187', 'Jammu & Kashmir'),
            ('4699189', 'Jharkhand'),
            ('4701185', 'Karnataka'),
            ('4695189', 'Kerala'),
            ('4700189', 'Lakshadweep'),
            ('4697186', 'Madhya Pradesh'),
            ('4694184', 'Maharashtra'),
            ('4700187', 'Manipur'),
            ('4696185', 'Orissa'),
            ('4676189', 'Pondicherry'),
            ('4693185', 'Punjab'),
            ('4701186', 'Rajasthan'),
            ('4701187', 'Sikkim'),
            ('4701188', 'Tamil Nadu'),
            ('4696185', 'Tripura'),
            ('4699190', 'Uttaranchal'),
            ('4692188', 'Uttar Pradesh'),
            ('4700188', 'West Bengal'),
            ]


class SelectWithDisable(object):

    """
    Renders a select field.

    If `multiple` is True, then the `size` property should be specified on
    rendering to make the field useful.

    The field must provide an `iter_choices()` method which the widget will
    call on rendering; this method must yield tuples of
    `(value, label, selected, disabled)`.
    """

    def __init__(self, multiple=False):
        self.multiple = multiple

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        if self.multiple:
            kwargs['multiple'] = 'multiple'
        html = [u'<select %s>' % html_params(name=field.name, **kwargs)]
        for (val, label, selected, disabled) in field.iter_choices():
            html.append(self.render_option(val, label, selected,
                        disabled))
        html.append(u'</select>')
        return HTMLString(u''.join(html))

    @classmethod
    def render_option(
        cls,
        value,
        label,
        selected,
        disabled,
        ):

        options = {'value': value}
        if selected:
            options['selected'] = u'selected'
        if disabled:
            options['disabled'] = u'disabled'
        return HTMLString(u'<option %s>%s</option>'
                          % (html_params(**options),
                          escape(unicode(label))))


class SelectFieldWithDisable(SelectField):

    widget = SelectWithDisable()

    def iter_choices(self):
        for (value, label, selected, disabled) in self.choices:
            yield (value, label, selected, disabled, self.coerce(value)
                   == self.data)


from wtforms.widgets import html_params, HTMLString
from cgi import escape


class MyOption(object):

    def __call__(self, field, **kwargs):
        options = dict(kwargs, value=field._value())
        if field.checked:
            options['selected'] = True

        label = field.label.text
        render_params = (html_params(**options), escape(unicode(label)))
        return HTMLString(u'<option %s>%s</option>' % render_params)


from wtforms.widgets import Select


class SelectWithRedFrame(Select):

    def __init__(self, error_class=u'has_errors'):
        super(SelectWithRedFrame, self).__init__()
        self.error_class = error_class

    def __call__(self, field, **kwargs):
        if field.errors:
            c = kwargs.pop('class', '') or kwargs.pop('class_', '')
            kwargs['class'] = u'%s %s' % (self.error_class, c)
        return super(SelectWithRedFrame, self).__call__(field, **kwargs)


class AdForm(Form):

    categories = [
        ('1', _('All categories')),
        ('disabled', _('VEHICLES')),
        ('2010', _('Cars')),
        ('3', _('Motorcycles')),
        ('4', _('Accessories & Parts')),
        ('disabled', _('PROPERTIES')),
        ('7', _('Apartments')),
        ('8', _('Houses')),
        ('9', _('Commercial properties')),
        ('10', _('Land')),
        ('disabled', _('ELECTRONICS')),
        ('12', _('Mobile phones & Gadgets')),
        ('13', _('TV/Audio/Video/Cameras')),
        ('14', _('Computers')),
        ('disabled', _('HOME & PERSONAL ITEMS')),
        ('16', _('Home & Garden')),
        ('17', _('Clothes/Watches/Accessories')),
        ('18', _('For Children')),
        ('disabled', _('LEISURE/SPORTS/HOBBIES')),
        ('20', _('Sports & Outdoors')),
        ('21', _('Hobby & Collectables')),
        ('22', _('Music/Movies/Books')),
        ('23', _('Pets')),
        ('20', _('BUSINESS TO BUSINESS')),
        ('24', _('Hobby & Collectables')),
        ('25', _('Professional/Office equipment')),
        ('26', _('Business for sale')),
        ('disabled', _('JOBS & SERVICES')),
        ('28', _('Jobs')),
        ('29', _('Services')),
        ('30', _('Events & Catering')),
        ('31', _('Others')),
        ('1000', _('Sports & Outdoors')),
        ('1010', _('Hobby & Collectables')),
        ('1020', _('Hobby & Collectables')),
        ('1030', _('Music/Movies/Books')),
        ('1050', _('Pets')),
        ('1080', _('BUSINESS TO BUSINESS')),
        ('1100', _('Hobby & Collectables')),
        ('1090', _('Professional/Office equipment')),
        ('2010', _('Business for sale')),
        ('2030', _('Sports & Outdoors')),
        ('2040', _('Hobby & Collectables')),
        ('2080', _('Music/Movies/Books')),
        ('2070', _('Pets')),
        ('3000', _('BUSINESS TO BUSINESS')),
        ('3040', _('Hobby & Collectables')),
        ('3050', _('Professional/Office equipment')),
        ('3060', _('Business for sale')),
        ('4000', _('Sports & Outdoors')),
        ('4010', _('Hobby & Collectables')),
        ('4020', _('Music/Movies/Books')),
        ('4040', _('Pets')),
        ('4030', _('BUSINESS TO BUSINESS')),
        ('4090', _('Hobby & Collectables')),
        ('4060', _('Professional/Office equipment')),
        ('4070', _('Business for sale')),
        ('5030', _('Music/Movies/Books')),
        ('5020', _('Pets')),
        ('5010', _('BUSINESS TO BUSINESS')),
        ('5040', _('Hobby & Collectables')),
        ('6010', _('Professional/Office equipment')),
        ('6020', _('Business for sale')),
        ('6030', _('Music/Movies/Books')),
        ('6040', _('Pets')),
        ('7010', _('BUSINESS TO BUSINESS')),
        ('Other', _('Hobby & Collectables')),
        ]

    regions = [('', _('Choose')), ('3', _('Delhi')), ('4', _('Maharasta'
               )), ('7', _('Gujarat'))]
    cities = [('', _('«Choose city»')), ('3', _('Mumbai')), ('4',
              _('Delhi'))]
    nouser = HiddenField(_('No user'))  # dummy variable to know whether user is logged in
    name = TextField(_('Name'),
                     [validators.Required(message=_('Name is required'
                     ))], widget=MyTextInput())
    title = TextField(_('Subject'),
                      [validators.Required(message=_('Subject is required'
                      ))], widget=MyTextInput())
    text = TextAreaField(_('Ad text'),
                         [validators.Required(message=_('Text is required'
                         ))], widget=MyTextArea())
    phonenumber = TextField(_('Phone'), [validators.Optional()])
    type = TextField(_('Type'), [validators.Required(message=_('Type is required'
                         ))])
    phoneview = BooleanField(_('Display phone number on site'))
    price = TextField(_('Price'), [validators.Regexp('^[0-9]+$',
                      message=_('This is not an integer number, please see the example and try again'
                      )), validators.Optional()], widget=MyTextInput())
    email = TextField(_('Email'),
                      [validators.Required(message=_('Email is required'
                      )),
                      validators.Email(message=_('Your email is invalid'
                      ))], widget=MyTextInput())

    # region = SelectField(_('Region'),validators=[validators.Required(message=_('Region is required'))],option_widget=SelectWithRedFrame())

    area = SelectField(_('City'), choices=cities,
                       validators=[validators.Required(message=_('City is required'
                       ))])
    category_group = SelectField(_('Category'), choices=categories,
                                 validators=[validators.Required(message=_('Category is required'
                                 ))])

    def validate_name(form, field):
        if len(field.data) > 50:
            raise ValidationError(_('Name must be less than 50 characters'
                                  ))

    def validate_email(form, field):
        if len(field.data) > 60:
            raise ValidationError(_('Email must be less than 60 characters'
                                  ))

    def validate_price(form, field):
        if len(field.data) > 8:
            raise ValidationError(_('Price must be less than 9 integers'
                                  ))


class PreviewAdForm(Form):

    nouser = HiddenField(_('No user'))  # dummy variable to know whether user already is logged in
    password = PasswordField(_('Password'), [validators.Required(),
                             validators.EqualTo('password_ver',
                             message=_('Passwords must match.'))])
    password_ver = PasswordField(_('Confirm password'),
                                 [validators.Required()])


class AdLister(BaseRequestHandler,
    blobstore_handlers.BlobstoreUploadHandler):

    csrf_protect = False

    def post(self):
        message = ''
        import random
        twenty = random.randint(1, 5) > 3
        lat = '0'
        lng = '0'
        try:
            lat = self.request.get('lat', '0')
            lng = self.request.get('lng', '0')
        except Exception:
            pass
        #if self.request.get('lat'):
         #   ad = Ad(location=db.GeoPt(lat, lng))
            #ad.update_location()
          #  ad.geopt = db.GeoPt(lat, lng)
           # ad.set_geography()
        #else:
        ad = Ad()

        # ad.put()

        if users.get_current_user():
            ad.user = users.get_current_user()
        if self.request.get('type'):
            ad.type = self.request.get('type')
        if self.request.get('address'):
            ad.address = self.request.get('address')
        if self.request.get('rooms'):
            ad.number_of_rooms = int(self.request.get('rooms'))
        if self.request.get('size'):
            ad.size = float(self.request.get('size'))
        if self.request.get('regdate'):
            ad.regdate = int(self.request.get('regdate'))
        if self.request.get('mileage'):
            ad.mileage = int(self.request.get('mileage'))

        ad.category = self.request.get('category_group')

        form = AdForm(self.request.params)

        for city in montaomodel.City.all().fetch(9999999):  # to do: only do this for the region

            # logging.info('inserting %s' %city.name)

            form.area.choices.insert(city.key().id(),
                    (str(city.key().id()), 'Select...'))

        if form.validate():
            ad.title = form.title.data
            self.session['title'] = ad.title
            ad.name = unicode(form.name.data, "utf8")
            self.session['name'] = ad.name
            ad.email = form.email.data
            self.session['email'] = ad.email
            ad.phoneview = form.phoneview.data
            self.session['phoneview'] = ad.phoneview
            try:
                if form.phonenumber.data:
                    ad.phonenumber = form.phonenumber.data
                    self.session['phonenumber'] = ad.phonenumber
            except:
                pass

            text =  unicode(form.text.data, "utf8")
	    ad.text = text
            self.session['text'] = ad.text

            ad.price = form.price.data.replace(' ', '').replace(',00',
                    '').replace('.00', '')
            try:
                if form.price.data:
                    ad.integer_price = form.price.data.replace(' ', ''
                            ).replace(',00', '').replace('.00', '')
            except:
                pass
            self.session['price'] = ad.price
            ad.url = self.request.host
            self.session['url'] = self.request.host
            ad.place = self.request.get('place')
            self.session['place'] = ad.place
            ad.postaladress = self.request.get('place')
            self.session['postaladress'] = ad.postaladress
            ad.put()
            self.session['ad_id'] = ad.key().id()
        else:
            logging.debug('form did not validate')
            self.render('2.html', {
                'user': self.current_user,
                'session': self.auth.get_user_by_session(),
                'request': self.request,
                'form': form, 'name':unicode(form.name.data, "utf-8"),
                })
            return
        if self.request.get('currency'):
            ad.currency = self.request.get('currency')
            self.session['currency'] = ad.currency
        if self.request.get('cg'):
            ad.category = self.request.get('cg')  # form.cg.data
            self.session['category'] = ad.category
        if self.request.get('company_ad') == '1':
            ad.company_ad = True
            self.session['company_ad'] = 'True'
        ad.put()

        ad.url = self.request.host

        for upload in self.get_uploads():
            try:
                img = Image(reference=ad)
                img.primary_image = upload.key()
                img.put()
                ad.put()
            except:
                pass
        ad.published = False
        if self.request.get('area'):
            logging.info('getting area ' + self.request.get('area'))
            city = \
                montaomodel.City.get_by_id(long(self.request.get('area'
                    )))
            region = montaomodel.Region.get(city.region.key())
            logging.info('region: %s' % region.name)
            ad.cities.append(city.key())
            ad.regions.append(region.key())
            ad.city = unicode(city.name)
            ad.region = unicode(region.name)
            ad.put()

        param = {'address': ad.city.encode('utf-8'), 'sensor': 'false'}
        encoded_param = urllib.urlencode(param)
        url = 'http://maps.googleapis.com/maps/api/geocode/json'
        url = url + '?' + encoded_param
        result = urlfetch.fetch(url)

        jsondata = json.loads(result.content)

        # logging.info('jsondata:'+str(jsondata))

        latlng = jsondata['results'][0]['geometry']['location']
        lat = latlng['lat']
        lon = latlng['lng']
        ad.geopt = db.GeoPt(lat, lon)
        ad.put()

        if self.current_user:
            ad.userID = str(self.current_user.auth_ids[0])
            logging.debug('setting usr')
            ad.usr = self.current_user.key.to_old_key()
            ad.put()

        # msg = _('Added %s.') % str(self.request.get('title'))

        image = ad.matched_images.get()
        image_url = None
        if image:
            if image.primary_image:
                try:
                    image_url = \
                        images.get_serving_url(str(image.primary_image.key()),
                            size=640)
                except Exception, e:
                    image_url = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
            else:
                image_url = '/images/' + str(image.key().id()) \
                    + '_small.jpg'
        imv = []
        for i in ad.matched_images:
            if i.primary_image:
                try:
                    i1 = \
                        images.get_serving_url(str(i.primary_image.key()))
                    imv.append(i1)
                except Exception, e:
                    i1 = '/images/' + str(image.key().id()) \
                        + '_small.jpg'
                    imv.append(i1)

        if ad.price:  # and doesn't contain separators
            try:
                price = \
                    i18n.I18n(self.request).format_decimal(int(ad.price))
            except Exception, e:
                price = ad.price
        else:
            price = ad.price

        self.render('preview.html', {
            'user': self.current_user,
            'session': self.auth.get_user_by_session(),
            'request': self.request,
            'ad': ad,
            'image_url': image_url,
            'imv': imv,
            'len': len(imv),
            'form': PreviewAdForm(),
            'price': price,
            })


class SendMail(webapp2.RequestHandler):

    def get_host(self):
        return self.request.host

    def get(self, key, detail):
        ad = db.get(db.Key(key))
        if not ad:
            self.error(404)
            return
        matched_images = ad.matched_images
        if detail == 'mailc2c':
            path = os.path.join(os.path.dirname(__file__), 'market',
                                'market_mailc2c.html')
            self.response.out.write(template.render(path, {'ad': ad,
                                    'matched_images': matched_images}))
        else:
            self.response.out.write(utils.render_to_mako('market/market_full.html'
                                    , {'ad': ad, 'matched_images'
                                    : matched_images}))
        return

    def post(self, key, detail):
        ad = db.get(db.Key(key))
        if not ad:
            self.error(404)
            return
        matched_images = ad.matched_images
        email = self.request.POST['email']
        msg = self.request.POST['adreply_body']
        name = self.request.POST['name']
        if isinstance(name, unicode):
            name = name.encode('utf-8')
        if users.get_current_user():
            senderemail = users.get_current_user().email()
        elif self.self.request.host.endswith('.br'):
            senderemail = 'info@montao.com.br'
        else:
            senderemail = 'info@koolbusiness.com'
        message = mail.EmailMessage(sender=senderemail,
                                    subject=unicode('%s %s about %s'
                                    % (name, email, ad.title)))
        message.to = ad.email
        if isinstance(msg, unicode):
            msg = msg.encode('utf-8')

        message.body = '%s %s/%s/%s' % (msg, self.self.request.host,
                ad.key().id(), email)
        message.send()
        if ad.user:
            email = ad.user.email()
        else:
            email = ad.email
        self.response.out.write('emailed')
        if detail == 'mailc2c':
            path = os.path.join(os.path.dirname(__file__), 'market',
                                'market_mailc2c.html')
            self.response.out.write(template.render(path, {'ad': ad,
                                    'matched_images': matched_images}))
        else:
            path = os.path.join(os.path.dirname(__file__), 'market',
                                'market_full.html')
            self.response.out.write(template.render(path, {'ad': ad,
                                    'matched_images': matched_images}))
        return


class Recommend(BaseHandler):

    csrf_protect = False

    def post(self, key):
        ad = db.get(db.Key(key))
        email = self.request.POST['tip_email']
        msg = unicode(self.request.POST['tip_msg'])
        if isinstance(msg, unicode):
            msg = msg.encode('utf-8')
        name = self.request.POST['tip_name']
        if isinstance(name, unicode):
            name = name.encode('utf-8')
        title = ad.title
        if isinstance(title, unicode):
            title = title.encode('utf-8')
        host = self.request.host
        senderemail = \
            (users.get_current_user().email() if users.get_current_user() else ('info@montao.com.br'
              if host.endswith('.br') else 'Kool Business <info@koolbusiness.com>'))
        recommends = _('has recommended')
        message = mail.EmailMessage(sender=senderemail,
                                    subject='%s %s %s' % (name,
                                    recommends, title))
        message.to = email
        message.body = '%s %s/vi/%s.html' % (msg, host, ad.key().id())  # , slugify(ad.title.encode('utf-8')))
        message.send()
        matched_images = ad.matched_images
        count = matched_images.count()
        if ad.text:
            p = re.compile(r'(www[^ ]*|http://[^ ]*)')
            text = p.sub(r'<a href="http://\1" rel="nofollow">\1</a>',
                         ad.text.replace('http://', ''))
        else:
            text = None
        self.response.out.write('Message sent<br>')
        self.redirect('/vi/%d.html' % (ad.key().id(), ))


class PreviewForm(webapp2.RequestHandler):

    def post(self, key):
        ad = db.get(db.Key(key))
        try:
            ad.set_password(self.request.get('password'))
        except:
            pass
        path = os.path.join(os.path.dirname(__file__), 'market',
                            'credit.html')
        self.response.out.write(template.render(path, {'ad': ad}))


class CreditHandler(webapp2.RequestHandler):

    def get(self):

        path = os.path.join(os.path.dirname(__file__), 'market',
                            'credit.html')
        self.response.out.write(template.render(path, {}))


class RemoveHandler(webapp2.RequestHandler):

    def get(self):

        id = int(self.request.get('id'))
        ad = Ad.get(db.Key.from_path('Ad', id))

        if ad.facebookID == int(self.user.id):
            self.response.out.write('Removed')


class RemoveAd(BaseHandler):

    csrf_protect = False

    def get(self, key):
        ad = db.get(db.Key(key))
        if (not ad or not ad.published) \
            and not users.is_current_user_admin():
            self.response.out.write('removed')  # translate
            return
        path = os.path.join(os.path.dirname(__file__), 'market',
                            'market_ad_remove.html')
        self.response.out.write(template.render(path, {'ad': ad}))

    def post(self, key):
        guser = users.get_current_user()
        ad = db.get(db.Key(key))
        if not ad or not ad.published:
            self.error(404)
            return
        if ad.user is not None and ad.user == guser:
            ad.published = False
            ad.save()
            self.response.out.write('removed %s' % ad.key())
            return

        if self.current_user:

            if self.current_user.id is not None and ad.facebookID \
                == int(self.current_user.id):
                ad.published = False
                ad.save()
                self.response.out.write('removed %s' % ad.key())
                return

        passwd = self.request.POST['passwd']
        if ad.check_password(passwd) or users.is_current_user_admin():
            ad.published = False
            self.response.out.write('deleting %s' % ad.title)
            query = 'adID = ' + str(ad.key().id())
            self.response.out.write('.deleting %s' % ad.title)

            query_options = search.QueryOptions(limit=50)
            self.response.out.write('..deleting %s' % ad.title)

            query_obj = search.Query(query_string=query,
                    options=query_options)
            self.response.out.write('...deleting %s' % ad.title)

            result = \
                search.Index(name=_INDEX_NAME).search(query=query_obj)
            self.response.out.write('....deleting %s' % ad.title)

            for element in result:
                doc_index.delete(element.doc_id)
            self.response.out.write('.....deleting %s' % ad.title)

            ad.save()
            self.response.out.write('deleted %s' % ad.title)
            return
        self.response.out.write(_('Wrong password '))


class RenewAd(BaseHandler):

    csrf_protect = False

    def get(self, key):
        ad = db.get(db.Key(key))
        if not ad:
            self.error(404)
            return
        if users.get_current_user():
            user_url = users.create_logout_url(self.request.uri)
            remoteinfo = ''
            if users.is_current_user_admin():
                remoteinfo = ''
                if ad.ip:
                    remoteinfo = ad.url + ' ' + str(ad.ip) + ' ' \
                        + ad.ipcountry
                url_linktext = remoteinfo
            else:
                url_linktext = remoteinfo
        else:
            user_url = users.create_login_url(self.request.uri)
        host = os.environ.get('HTTP_HOST', os.environ['SERVER_NAME'])
        template_values = {
            'ad': ad,
            'url': host,
            'user_url': (users.create_logout_url(self.request.uri) if users.get_current_user() else users.create_login_url(self.request.uri)),
            'user': users.get_current_user(),
            'admin': users.is_current_user_admin(),
            }
        path = os.path.join(os.path.dirname(__file__), 'market',
                            'market_ad_renew.html')
        self.response.out.write(template.render(path, template_values))

    def post(self, key):
        ad = db.get(db.Key(key))
        if not ad:  # or not ad.published:
            self.error(404)
            return
        user = users.get_current_user()
        if users.is_current_user_admin():
            ad.modified = datetime.datetime.now()
            ad.published = True
            ad.save()
            self.response.out.write('renewed %s' % ad.title)
        if not user == None and ad.user == user:
            ad.modified = datetime.datetime.now()
            ad.published = True
            ad.save()
            self.response.out.write('renewed %s %s' % (ad.title,
                                    ad.key()))
            return

        if self.user:
            if self.user.id is not None and ad.facebookID \
                == int(self.user.id):
                logging.debug('user id ' + self.user.id)

                ad.modified = datetime.datetime.now()
                ad.published = True
                ad.save()
                self.response.out.write('renewed %s %s' % (ad.title,
                        ad.key()))
                return
        if not users.is_current_user_admin():
            if ad.check_password(self.request.POST['passwd']):
                if not users.is_current_user_admin():
                    ad.modified = datetime.datetime.now()
                ad.published = True
                ad.save()
                self.response.out.write('renewed %s' % ad.title)
            else:
                self.response.out.write('wrong password')


class NewPassword(BaseHandler):

    def get(self, key):
        ad = db.get(db.Key(key))
        if not ad:  # or not ad.published:
            self.error(404)
            return
        template_values = {'ad': ad}
        path = os.path.join(os.path.dirname(__file__),
                            'market/market_ad_newpasswd.html')
        self.response.out.write(template.render(path, template_values))

    def post(self, key):

        ad = db.get(db.Key(key))
        if not ad:  # or not ad.published:
            self.error(404)
            return
        email = self.request.POST['email']
        if ad.email == email:  # or ad.user.email() == email:
            size = 9
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            password = ''
            from random import randint
            from random import choice
            import random
            minpairs = 4
            maxpairs = 6
            for x in range(1, random.randint(int(minpairs),
                           int(maxpairs))):
                consonant = consonants[random.randint(1,
                        len(consonants) - 1)]
                if random.choice([1, 0]):
                    consonant = string.upper(consonant)
                password = password + consonant
                vowel = vowels[random.randint(1, len(vowels) - 1)]
                if random.choice([1, 0]):
                    vowel = string.upper(vowel)
                password = password + vowel
                newpasswd = password
            ad.set_password(newpasswd)
            ad.save()
            url = (os.environ['HTTP_HOST'] if os.environ.get('HTTP_HOST'
                   ) else os.environ['SERVER_NAME'])
            if users.get_current_user():
                senderemail = users.get_current_user().email()
            elif url.endswith('.br'):
                senderemail = 'info@montao.com.br'
                translation.activate('pt-br')
            else:
                senderemail = 'info@koolbusiness.com'
            message = mail.EmailMessage(sender=senderemail,
                    subject=unicode(_('Password reset successful')))
            if ad.user:
                message.to = ad.user.email()
            else:
                message.to = ad.email
            to = message.to
            output = \
                _("You're receiving this e-mail because you requested a password reset"
                  ) + ' ' + _('Your new password is: %(new_password)s') \
                % {'new_password': newpasswd}
            msg = output
            if isinstance(msg, unicode):
                msg = msg.encode('utf-8')
            message.body = '%s %s/vi/%d.html' % (msg, url,
                    ad.key().id())
            message.send()
            self.response.out.write(_("We've e-mailed a new password to the e-mail address you submitted. You should be receiving it shortly."
                                    ))
        else:
            self.response.out.write('unknown email ')


from webapp2_extras import security


class ResetPassword(BaseHandler):

    csrf_protect = False

    def get(self):
        self.render_jinja('newpasswd')

    def post(self):
        email = self.request.POST['email']
        user = auth_models.User.get_by_auth_id(email)
        if email:
            size = 9
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            password = ''
            from random import randint
            from random import choice
            import random
            minpairs = 4
            maxpairs = 6
            for x in range(1, random.randint(int(minpairs),
                           int(maxpairs))):
                consonant = consonants[random.randint(1,
                        len(consonants) - 1)]
                if random.choice([1, 0]):
                    consonant = string.upper(consonant)
                password = password + consonant
                vowel = vowels[random.randint(1, len(vowels) - 1)]
                if random.choice([1, 0]):
                    vowel = string.upper(vowel)
                password = password + vowel
                newpasswd = password

            user.password = security.generate_password_hash(newpasswd,
                    length=12)
            user.put()

            message = mail.EmailMessage(sender='Kool Business <info@koolbusiness.com'
                    , subject=unicode(_('Password reset successful')))
            message.to = email

            output = \
                _("You're receiving this e-mail because you requested a password reset"
                  ) + ' ' + _('Your new password is: %(new_password)s') \
                % {'new_password': newpasswd}

            message.body = output
            message.send()
            self.response.out.write(_("We've e-mailed a new password to the e-mail address you submitted. You should be receiving it shortly."
                                    ))
        else:
            self.response.out.write('unknown email ')


class UsersAdLister(webapp2.RequestHandler):

    def get(self, view):
        user = users.get_current_user()
        if user is not None:
            ads = Ad.all().filter('user =', user).order('-modified')
        else:
            self.response.out.write('Sign in or register')
            return
        nperpage = 30
        page = 1
        offset = 0
        if self.request.get('page'):
            page = int(self.request.get('page'))
            offset = nperpage * (int(self.request.get('page')) - 1)
        if page > 0:
            next = page + 1
            previous = page - 1
        else:
            next = previous = None
        if view == 'wanted':
            ads = Ad.all().filter('type =', 'w').filter('published =',
                    True).order('-modified').fetch(100)
        else:
            if page > 1:
                nperpage = 0
            if page > 2:
                nperpage = -30 * (page - 2)
        if util.self.request.host.endswith('.mx'):
            logo = 'montonmx'
        elif util.self.request.host.endswith('.cl'):
            logo = 'montoncl'
        elif util.self.request.host.endswith('.br'):
            logo = 'montao'
        if users.get_current_user():
            user_url = users.create_logout_url(self.request.uri)
        else:
            user_url = users.create_login_url(self.request.uri)

        if view == 'publish':
            path = os.path.join(os.path.dirname(__file__), 'market',
                                'market_insert.html')

        self.response.out.write(template.render(path, {
            'logo': logo,
            'next': next,
            'previous': previous,
            'ads': ads,
            'user': user,
            }))


import gzip
import StringIO
days = 150


class SiteMap(webapp2.RequestHandler):

    def get(self):
        days = 200
        url = (os.environ['HTTP_HOST'] if os.environ.get('HTTP_HOST'
               ) else os.environ['SERVER_NAME'])
        i = \
            '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" >'
        for ad in \
            Ad.gql('where published = True and modified >:1 order by modified desc'
                   , datetime.datetime.now() - timedelta(days=days)):
            i = \
                '%s<url><loc>http://%s/%d/%s</loc><lastmod>%s</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>' \
                % (i, url, ad.key().id(),
                   defaultfilters.slugify(ad.title), ad.modified.date())
        i = '%s</urlset>' % i
        self.response.headers['Content-Type'] = 'gzip'
        self.response.headers['Content-Length'] = str(len(i))
        self.response.out.write(compressBuf(i))


def compressBuf(buf):
    zbuf = StringIO.StringIO()
    zfile = gzip.GzipFile(None, 'wb', 9, zbuf)
    zfile.write(buf)
    zfile.close()
    return zbuf.getvalue()


class SiteMapModel(db.Model):

    owner = db.UserProperty(required=True)
    last_updated = db.DateTimeProperty(required=True, auto_now=True)
    zipfile = blobstore.BlobReferenceProperty(required=True)

    @property
    def url(self):
        return '%s.%s' % (self.key().name(), BASE_DOMAIN)


class GeoSiteMap(webapp2.RequestHandler):

    def get(self):
        from datetime import datetime, timedelta
        from django.template import defaultfilters
        start = datetime.now() - timedelta(days=200)
        ads = Ad.gql('where published = True and modified >:1', start)
        self.response.out.write('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:geo="http://www.google.com/geo/schemas/sitemap/1.0" >'
                                )
        for ad in ads:
            self.response.out.write('<url><loc>http://'
                                    + util.self.request.host + '/'
                                    + str(ad.key().id()) + '/'
                                    + defaultfilters.slugify(ad.title)
                                    + '</loc><lastmod>'
                                    + str(ad.modified.date())
                                    + '</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>'
                                    )
        self.response.out.write('</urlset>')


class CsrfException(Exception):

    pass


class RPCHandler(webapp2.RequestHandler):

    """ Allows the functions defined in the RPCMethods class to be RPCed."""

    def __init__(self):
        webapp2.RequestHandler.__init__(self)
        self.methods = RPCMethods()

    def get(self):
        func = None
        action = self.request.get('action')
        if action:
            if action[0] == '_':
                self.error(403)  # access denied
                return
            else:
                func = getattr(self.methods, action, None)

        if not func:
            self.error(404)  # file not found
            return

        args = ()
        while True:
            key = 'arg%d' % len(args)
            val = self.request.get(key)
            if val:
                args += (simplejson.loads(val), )
            else:
                break
        from datetime import datetime, timedelta
        limit = datetime.now() - timedelta(days=200)
        ads = Ad.all().filter('published =', True).filter('modified >',
                limit)
        L = []  # edit
        radius = 2
        for thing in ads:
            if thing.geopt:
                if thing.geopt.lat < radius + float(args[0]) \
                    and thing.geopt.lon < radius + float(args[1]) \
                    and thing.geopt.lat > float(args[0]) - radius \
                    and thing.geopt.lon > float(args[1]) - radius:
                    L.append(thing)
        ads = L
        result = len(ads)  # args[1]

        # result = Ad.all(),count()

        self.response.out.write(simplejson.dumps(result))


class RPCMethods:

    """ Defines the methods that can be RPCed.
    NOTE: Do not allow remote callers access to private/protected "_*" methods.
    """

    def Add(self, *args):

        # The JSON encoding may have encoded integers as strings.
        # Be sure to convert args to any mandatory type(s).

        ints = [int(arg) for arg in args]
        return sum(ints)


class GMT(tzinfo):

    def utcoffset(self, dt):
        return timedelta(hours=10)  # + self.dst(dt)

    def tzname(self, dt):
        return 'GMT'

    def dst(self, dt):
        return timedelta(0)


DELTA = timedelta(days=1)
DELTA_SECONDS = DELTA.days * 86400 + DELTA.seconds
gmt = GMT()
EXPIRATION_MASK = '%a, %d %b %Y %H:%M:%S %Z'


class KMLHandler(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        start = datetime.datetime.now() - timedelta(days=30)
        from google.appengine.api import memcache
        memcache_key = 'ads'
        data = memcache.get(memcache_key)
        if data is None:
            a = Ad.all().filter('modified >',
                                start).filter('published =',
                    True).order('-modified').fetch(1000)
            memcache.set('ads', a)
        else:
            a = data
        dispatch = 'templates/kml.html'
        template_values = {'a': a, 'request': self.request,
                           'host': os.environ.get('HTTP_HOST',
                           os.environ['SERVER_NAME'])}
        path = os.path.join(os.path.dirname(__file__), dispatch)
        output = template.render(path, template_values)
        self.response.headers['Content-Type'] = \
            'application/vnd.google-earth.kml+xml'
        self.response.headers['Content-Length'] = len(output)
        self.response.out.write(output)


class JSONHandler(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        start = datetime.datetime.now() - timedelta(days=182)
        from google.appengine.api import memcache
        memcache_key = 'ads'
        data = memcache.get(memcache_key)
        if data is None:
            a = Ad.all().filter('modified >',
                                start).filter('published =',
                    True).order('-modified').fetch(1000)
            memcache.set('ads', a)
        else:
            a = data
        dispatch = 'templates/json.html'
        template_values = {'ads': a, 'request': self.request,
                           'host': os.environ.get('HTTP_HOST',
                           os.environ['SERVER_NAME'])}
        path = os.path.join(os.path.dirname(__file__), dispatch)
        output = template.render(path, template_values)
        self.response.headers['Content-Type'] = \
            'application/vnd.google-earth.kml+xml'
        self.response.headers['Content-Length'] = len(output)
        self.response.out.write(output)


class GeoRSS(webapp2.RequestHandler):

    def get(self):
        start = datetime.datetime.now() - timedelta(days=182)
        count = (int(self.request.get('count'
                 )) if not self.request.get('count') == '' else 1000)
        try:
            ads = memcache.get('ads')
        except KeyError:
            ads = Ad.all().filter('modified >',
                                  start).filter('published =',
                    True).order('-modified').fetch(count)
        memcache.set('ads', ads)
        template_values = {'ads': ads, 'request': self.request,
                           'host': os.environ.get('HTTP_HOST',
                           os.environ['SERVER_NAME'])}
        dispatch = 'templates/georss.html'
        path = os.path.join(os.path.dirname(__file__), dispatch)
        output = template.render(path, template_values)
        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        self.response.headers['Content-Type'] = 'application/rss+xml'
        self.response.out.write(output)


class KMZHandler(webapp2.RequestHandler):

    def add_file(
        self,
        zip_file,
        url,
        file_name,
        ):
        """Fetch url, and add content as file_name to the zip file."""

        result = urlfetch.fetch(url)
        if not result.content:
            return
        zip_file.writestr(file_name, result.content)

    def get(self):
        """Attempt to create a zip file."""

        # you could set 'count' like this:
        # count = int(self.request.get('count', 1000))

        zipstream = StringIO.StringIO()
        zip_file = zipfile.ZipFile(zipstream, 'w')

        # repeat this for every URL that should be added to the zipfile

        url = 'http://montaoproject.appspot.com/list.kml'
        self.add_file(zip_file, url, 'list.kml')

        # we have finished with the zip so package it up and write the directory

        zip_file.close()

        # set the headers...

        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        self.response.headers['Content-Type'] = 'application/zip'
        self.response.headers['Content-Disposition'] = \
            'attachment;filename="list.kmz"'

        # create and return the output stream

        zipstream.seek(0)
        self.response.out.write(zipstream.read())
        zipstream.close()


class MontaoKMZHandler(webapp2.RequestHandler):

    def add_file(
        self,
        zip_file,
        url,
        file_name,
        ):
        """Fetch url, and add content as file_name to the zip file."""

        result = urlfetch.fetch(url)
        if not result.content:
            return
        zip_file.writestr(file_name, result.content)

    def get(self):
        """Attempt to create a zip file."""

        # you could set 'count' like this:
        # count = int(self.request.get('count', 1000))

        zipstream = StringIO.StringIO()
        zip_file = zipfile.ZipFile(zipstream, 'w')

        # repeat this for every URL that should be added to the zipfile

        url = 'http://montaoproject.appspot.com/montaolist.kml'
        self.add_file(zip_file, url, 'list.kml')

        # we have finished with the zip so package it up and write the directory

        zip_file.close()

        # set the headers...

        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        self.response.headers['Content-Type'] = 'application/zip'
        self.response.headers['Content-Disposition'] = \
            'attachment;filename="list.kmz"'

        # create and return the output stream

        zipstream.seek(0)
        self.response.out.write(zipstream.read())
        zipstream.close()


class MontaoKMLHandler(webapp2.RequestHandler):

    def get(self):
        start = datetime.datetime.now() - timedelta(days=182)
        host = os.environ.get('HTTP_HOST', os.environ['SERVER_NAME'])
        self.response.headers['Cache-Control'] = 'public,max-age=%s' \
            % 86400
        from google.appengine.api import memcache
        memcache_key = 'montao'
        data = memcache.get(memcache_key)
        if data is None:
            a = Ad.all().filter('modified >', start).filter('url IN',
                    ['www.montao.com.br', 'montao'
                    ]).filter('published =', True).order('-modified'
                    ).fetch(1000)
            memcache.set('montao', a)
        else:
            a = data
        dispatch = 'templates/montaokml.html'
        template_values = {'a': a, 'request': self.request,
                           'host': host}
        path = os.path.join(os.path.dirname(__file__), dispatch)
        self.response.headers['Content-Type'] = \
            'application/vnd.google-earth.kml+xml'
        self.response.out.write(template.render(path, template_values))


class I18NTestHandler(BaseHandler):

    def get(self, limit=60):
        self.response.out.write(_('Wanted'))  # custom translation
        self.response.out.write(_('All'))  # builtin translation

        query = Ad.all()
        query._keys_only = True
        self.response.out.write(query.count(100000000))

        from datetime import datetime, timedelta
        timeline = datetime.now() - timedelta(days=limit)
        self.response.out.write(' ' + str(Ad.all().filter('modified >',
                                timeline).filter('published =',
                                True).count(100000000)))


from paginator import Paginator, InvalidPage, EmptyPage
import paginator


class ContactHandler(webapp2.RequestHandler):  # works

    def get(self):
        dispatch = 'templates/contact.html'
        path = os.path.join(os.path.dirname(__file__), dispatch)
        self.response.out.write(template.render(path, template_values))


class FileUploadHandler(blobstore_handlers.BlobstoreUploadHandler):

    def post(self):
        logging.info('fileuploadhandler')
        try:
            upload_files = self.get_uploads('file')
            blob_info = upload_files[0]
            img = Image()
            img.primary_image = blob_info.key()
            img.put()
        except Exception, ex:
            self.response.write(str(ex))

        # self.redirect('/serve/%s' % blob_info.key())

        self.redirect('/file/%s' % img.key().id())


class CsrfException(Exception):

    pass


class FileBaseHandler(webapp2.RequestHandler):

    def render_template(self, file, template_args):
        path = os.path.join(os.path.dirname(__file__), 'templates',
                            file)
        self.response.out.write(template.render(path, template_args))


class FileInfo(db.Model):

    blob = blobstore.BlobReferenceProperty(required=True)
    uploaded_at = db.DateTimeProperty(required=True, auto_now_add=True)


class FileInfoHandler(NewBaseHandler):

    def get(self, file_id):
        logging.info('in filebasehandler')
        file_info = Image.get_by_id(long(file_id))
        if not file_info:
            self.error(404)
            return
        self.render_jinja('fileinfo', file_info=file_info,
                          logout_url=users.create_logout_url('/'))


class KMLFileHandler(blobstore_handlers.BlobstoreDownloadHandler):

    def get(self, file_id):
        logging.info('in KMLFileHandler')
        file_info = Image.get_by_id(long(file_id))
        resource = str(file_info.primary_image.key())
        logging.info('resource:' + resource)
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info)


class FileBaseHandler(webapp2.RequestHandler):

    def render_template(self, file, template_args):
        path = os.path.join(os.path.dirname(__file__), 'templates',
                            file)
        self.response.out.write(template.render(path, template_args))


def fb_request_decode(signed_request, fb_app_secret):
    s = [s.encode('ascii') for s in signed_request.split('.')]

    fb_sig = base64.urlsafe_b64decode(s[0] + '=')
    fb_data = json.loads(base64.urlsafe_b64decode(s[1]))
    fb_hash = hmac.new(fb_app_secret, s[1], hashlib.sha256).digest()

    sig_match = False
    if fb_sig == fb_hash:
        sig_match = True

    auth = False
    if 'user_id' in fb_data:
        auth = True

    return {
        'fb_sig': fb_sig,
        'fb_data': fb_data,
        'fb_hash': fb_hash,
        'sig_match': sig_match,
        'auth': auth,
        }


class BuscarHandler(BaseHandler):

    def get(self):
        self.render('buscar')


class QueryHandler(BaseHandler):

    def get(self):
        self.render('q')


class ManageHandler(BaseHandler):

    def get(self, id):
        self.render_jinja('manage_jinja', ad=Ad.get_by_id(long(id)))


class DeleteOrEditHandler(BaseHandler):

    csrf_protect = False

    def post(self, id):
        doc_index = search.Index(name=_INDEX_NAME)
        self.session['edit'] = None
        cmd = self.request.get('cmd')
        if cmd == 'delete':
            guser = users.get_current_user()
            ad = Ad.get_by_id(long(id))
            if not ad:
                self.error(404)
                return
            if ad.user is not None and ad.user == guser:
                ad.published = False
                ad.save()
                self.response.out.write('removed %s' % ad.key())
                return
            passwd = self.request.POST['passwd']
            if ad.check_password(passwd) \
                or users.is_current_user_admin():
                ad.published = False

                # self.response.out.write('deleting %s' % ad.title)

                query = 'adID = ' + str(ad.key().id())

                # self.response.out.write('.deleting %s' % ad.title)

                logging.info('query: ' + str(query))
                query_options = search.QueryOptions(limit=50)

                # self.response.out.write('..deleting %s' % ad.title)

                query_obj = search.Query(query_string=query,
                        options=query_options)

                # self.response.out.write('...deleting %s' % ad.title)

                result = \
                    search.Index(name=_INDEX_NAME).search(query=query_obj)
                self.response.out.write('....deleting %s' % ad.title)
                logging.info('result: ' + str(result))

                for r in result:
                    logging.info('r: ' + str(r))
                    self.response.out.write('....deleting from index %s'
                             % ad.title)
                    doc_index.delete(r.doc_id)
                    self.response.out.write('....deleted from index %s'
                            % ad.title)

                # doc_index.delete(result.0.doc_id)

                self.response.out.write('...deleted element %s'
                        % ad.title)

                # self.response.out.write('deleted %s' % ad.title)

                ad.save()

                # self.response.out.write('deleted %s' % ad.title)

                return
            self.response.out.write('wrong password ')
        elif cmd == 'edit':
            ad = Ad.get_by_id(long(id))
            if ad.check_password(self.request.POST['passwd']):
                self.session['edit'] = id
            self.redirect('/edit?id=%s' % id)


def process(entity):
    entity.small = None
    yield op.db.Put(entity)


def getblobs(entity):
    if entity.primary_image:
        try:
            entity.small = \
                blobstore.BlobReader(entity.primary_image.key()).read()
        except Exception, e:
            pass
    yield op.db.Put(entity)


def getblobnames(entity):
    if entity.primary_image:
        try:
            entity.name = entity.primary_image.filename
        except Exception, e:
            pass
    yield op.db.Put(entity)


def setmontaourl(entity):
    if entity.url:
        if entity.url.find('ntao') > 1:
            try:
                entity.url = 'www.montao.com.br'
                yield op.db.Put(entity)
            except Exception, e:
                logging.debug('There occurred exception:%s' % str(e))


def makethumbnails(entity):
    if entity.small:
        try:
            entity.thumb = images.resize(entity.small, 80, 100)
        except Exception, e:
            pass
    yield op.db.Put(entity)


def setblobs(entity):
    file_name = files.blobstore.create()
    with files.open(file_name, 'a') as f:
        f.write(entity.small)
        files.finalize(file_name)
        entity.primary_image = files.blobstore.get_blob_key(file_name)  # (?) this is the new reference from the info class to the blobstore blobs
        yield op.db.Put(entity)


def setprices(entity):
    if entity.price:
        try:
            entity.integer_price = int(entity.price)
            yield op.db.Put(entity)
        except Exception, e:
            logging.debug('There occurred exception:%s' % str(e))


import montaomodel


def index(entity):
    try:
        edge = datetime.datetime.now() - timedelta(days=182)
        if (entity.published == True and entity.modified > edge):
            city_entity = montaomodel.City.all().filter('name =',
                    entity.city).get()
            region_entity = montaomodel.Region.all().filter('name =',
                    entity.region).get()

            price = 0
            try:
                if entity.price:
  	            price = long(entity.price)               
            except (Exception), e:
	        price = 0
                logging.info('price conversion failed for entity %s', str(entity.key().id()) )

   	    mileage = -1
            try:
               if entity.mileage:
  	           mileage = int(entity.mileage)               
            except (Exception), e:
	       mileage = -1
               logging.info('mileage conversion failed for entity %s', str(entity.key().id()) )

	    regdate = -1
            try:
               if entity.regdate:
  	           regdate = int(entity.regdate)               
            except (Exception), e:
	       regdate = -1
               logging.info('regdate conversion failed for entity %s', str(entity.key().id()) )

            company_ad = 0
            if entity.company_ad:
  	        company_ad = 1 

            cityId = 0
            if city_entity:
  	        cityId = city_entity.key().id() 

            regionID = 0
            if region_entity:
  	        regionID = region_entity.key().id() 

            category = 0
            if entity.category:
  	        category = entity.category 

            doc = search.Document(doc_id=str(entity.key()), fields=[
                search.TextField(name='title', value=entity.title),
                search.TextField(name='text', value=entity.text),
                search.TextField(name='city', value=entity.city),
                search.TextField(name='region', value=entity.region),
                search.NumberField(name='cityID',
                                   value=int(cityId)),
                search.NumberField(name='regionID',
                                   value=int(regionID)),
                search.NumberField(name='category',
                                   value=int(category)),
                search.NumberField(name='constant', value=1),
                search.NumberField(name='adID',
                                   value=int(entity.key().id())),
                search.TextField(name='name', value=entity.name),
                search.DateField(name='date',
                                 value=entity.modified.date()),
                search.NumberField(name='price', value=long(price)),
                search.NumberField(name='mileage',
                                   value=int(mileage)),
                search.NumberField(name='regdate',
                                   value=int(regdate)),
                search.TextField(name='type', value=entity.type),
                search.TextField(name='currency', value=entity.currency),
                search.NumberField(name='company_ad',
                                   value=company_ad),
                search.NumberField(name='hour',
                                   value=entity.modified.hour),
                search.NumberField(name='minute',
                                   value=entity.modified.minute),
                ], language='en')
            yield search.Index(name='ads').put(doc)
    except Exception, e:
        logging.info('There occurred exception:%s' % str(e))


class PasswordResetComplete(NewBaseHandler):

    csrf_protect = False

    def get(self, token):
        """
............Updates password by token
........"""

        token = \
            auth_models.User.token_model.query(auth_models.User.token_model.token
                == token).get()
        if token is not None:
            path = os.path.join(os.path.dirname(__file__), 'templates',
                                'passwordreset.html')
            self.response.out.write(template.render(path, {'token'
                                    : token}))

    def post(self, token):
        token = \
            auth_models.User.token_model.query(auth_models.User.token_model.token
                == token).get()
        user = auth_models.User.get_by_id(int(token.user))
        if token and user:
            user.password = \
                security.generate_password_hash(self.request.get('password'
                    ), length=12)
            user.put()

            # Delete token

            token.key.delete()

            # Login User

            self.auth.get_user_by_password(user.auth_ids[0],
                    self.request.get('password'))
            return 'Password changed successfully'


class CreateAdHandler(BaseHandler):

    def post(self):
        ad = Ad.get_by_id(self.session.get('ad_id'))
        city_entity = montaomodel.City.all().filter('name =',
                ad.city).get()
        region_entity = montaomodel.Region.all().filter('name =',
                ad.region).get()
        form = PreviewAdForm(self.request.params)

        price = 0

        try:
            if ad.price:
                price = long(ad.price)
        except Exception, e:
            logging.info('price conversion failed')

        mileage = -1
        regdate = -1
        try:
            if ad.mileage:
                mileage = int(ad.mileage)
        except Exception, e:
            logging.info('mileage conversion failed')
        try:
            if ad.regdate:
                regdate = int(ad.regdate)
        except Exception, e:
            logging.info('regdate conversion failed')
        if form.validate():
            ad.set_password(self.request.get('password'))
            ad.published = True
            ad.put()
            company_ad = 0
            if ad.company_ad:
                company_ad = 1

            doc = search.Document(doc_id=str(ad.key()), fields=[
                search.TextField(name='title', value=ad.title),
                search.TextField(name='text', value=ad.text),
                search.TextField(name='city', value=ad.city),
                search.TextField(name='region', value=ad.region),
                search.NumberField(name='cityID',
                                   value=city_entity.key().id()),
                search.NumberField(name='regionID',
                                   value=region_entity.key().id()),
                search.NumberField(name='category',
                                   value=int(ad.category)),
                search.NumberField(name='constant', value=1),
                search.NumberField(name='adID', value=ad.key().id()),
                search.TextField(name='name', value=ad.name),
                search.DateField(name='date',
                                 value=datetime.datetime.now().date()),
                search.NumberField(name='price', value=price),
                search.NumberField(name='mileage', value=mileage),
                search.NumberField(name='regdate', value=regdate),
                search.TextField(name='type', value=ad.type),
                search.TextField(name='currency', value=ad.currency),
                search.NumberField(name='company_ad',
                                   value=company_ad),
                search.NumberField(name='hour',
                                   value=datetime.datetime.now().hour),
                search.NumberField(name='minute',
                                   value=datetime.datetime.now().minute),
                ], language='en')
            search.Index(name='ads').put(doc)

            message = mail.EmailMessage(sender=self.current_email,
                    subject=(ad.title if ad.title else 'Business'))
            if self.request.host != 'www.montao.com.br':
                message.body = 'Dear ' + ad.name \
                    + '\nThank you for registering with ' \
                    + self.request.host \
                    + '! To edit your ad, click edit from the menu. ' \
                    + self.request.host + '/vi/' + str(ad.key().id()) \
                    + '''.html
We invite you to visit our home page where you can find latest information on business and advertising.
If you like, you can also add us on Facebook: www.facebook.com/koolbusiness\nYou can follow us on www.twitter.com/koolwebapps '''
                message.to = ad.email
                message.bcc = 'niklasro@gmail.com'
                message.send()
            else:
                message.body = \
                    'Prezado %s\nObrigado por se registrar em %s! Para editar seu anúncio, clique em editar no menu. %s/vi/%s.html Convidamos a visitar nossa página, onde encontrará as últimas informações sobre novos anúncios de empresas. Lá você também poderá enviar e baixar videos, música e imagens.'.decode('utf-8'
                        ) % (ad.name, self.request.host,
                             self.request.host, str(ad.key().id()))
                message.to = ad.email
                message.bcc = \
                    'info@koolbusiness.com, kimo400@gmail.com, alex.hultmark@gmail.com, shankiboy@gmail.com'
                message.send()
            self.redirect('/vi/%d.html' % (ad.key().id(), ))
        else:
            logging.info('form did not validate')
            self.render_jinja('preview', form=form, ad=ad)


class FileDownloadHandler(blobstore_handlers.BlobstoreDownloadHandler):

    def get(self, file_id):
        file_info = FileInfo.get_by_id(long(file_id))
        if not file_info or not file_info.blob:
            self.error(404)
            return
        self.send_blob(file_info.blob, save_as=False)


class RegionHandler(BaseHandler):

    def get(self):
        if self.request.get('state') == '1':
            self.render_jinja('regions1')
        else:
            self.render_jinja('regions')


class GLogin(BaseHandler):

    def get(self):

       # todo: use self.request.uri to get back

        greeting = '<a href="%s">Sign in</a>.' \
            % users.create_login_url('/')

        self.response.out.write('<html><body>%s</body></html>'
                                % greeting)


class GLogout(BaseHandler):

    def get(self):

       # todo: use self.request.uri to get back

        greeting = '<a href="%s">Sign out</a>.' \
            % users.create_logout_url('/')

        self.response.out.write('<html><body>%s</body></html>'
                                % greeting)


class CitiesHandler(BaseHandler):

    def get(self):
        regionId = self.request.get('regionId')
        region = montaomodel.Region.get_by_id(long(regionId))
	
        cities = montaomodel.City.all().filter('region =',
                region.key()).order('-vieworder').order('name'
                ).fetch(999)
        self.render_jinja('cities', cities=cities)


class CitiesBrHandler(BaseHandler):

    def get(self):
        ddd = int(self.request.get('ddd'))
        cities = montaomodel.City.all().filter('areacode =',
                ddd).order('-vieworder').order('name').fetch(999)
        self.render_jinja('cities_br', cities=cities)


class CitiesInsertHandler(BaseHandler):

    def get(self):
        regionId = self.request.get('regionId')
        region = montaomodel.Region.get_by_id(long(regionId))
        cities = montaomodel.City.all().filter('region =',
                region.key()).order('-vieworder').order('name'
                ).fetch(999)
        self.render_jinja('citiesinsert', cities=cities)


class CitiesInsertBrHandler(BaseHandler):

    def get(self):
        ddd = int(self.request.get('ddd'))
        cities = montaomodel.City.all().filter('areacode =',
                ddd).order('-vieworder').order('name').fetch(999)
        self.render_jinja('citiesinsert', cities=cities)


class ViewCitiesHandler(BaseHandler):

    def get(self):
        self.response.out.write('<h4>DDD, city, estado</h4>')
        cities = montaomodel.City.all().filter('areacode >',
                0).order('areacode').order('-vieworder').order('name'
                ).fetch(999)
        for city in cities:
            region = montaomodel.Region.get(city.region.key())
            self.response.out.write(str(city.areacode) + ' '
                                    + city.name + ' (' + region.name
                                    + ')<br>')


class ViewAllCitiesHandler(BaseHandler):

    def get(self):
        self.response.out.write('<h4>Cities</h4>')
        cities = montaomodel.City.all().order('areacode'
                ).order('-vieworder').order('name').fetch(9999)
        for city in cities:
            region = montaomodel.Region.get(city.region.key())
            self.response.out.write('<a href="http://%s/%s/%s">%s, %s</a>%s'
                                     % (
                self.request.host,
                region.slugify_montao(),
                city.slugify_montao(),
                city.name,
                region.name,
                '<br>',
                ))


class CreateUserHandler(NewBaseHandler):

    def get(self):
        """
............Returns a simple HTML form for create a new user
........"""

        return """
                        <!DOCTYPE hml>
                        <html>
                                <head>
                                        <title>webapp2 auth example</title>
                                </head>
                                <body>
                                <form action="%s" method="post">
                                        <fieldset>
                                                <legend>Create user form</legend>


                                                <label>Email <input type="text" name="email" placeholder="Your email" /></label>
                                                <label>Password <input type="password" name="password" placeholder="Your password" /></label>
                                        </fieldset>
                                        <button>Create user</button>
                                </form>
                        </html>
                """ \
            % self.request.url

    def post(self):
        """
............username: Get the username from POST dict
............password: Get the password from POST dict
........"""

        logging.info('gettting email')
        email = self.request.POST.get('email')
        password = self.request.POST.get('password')

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL. If True ok, If False no new user is created

        user = self.auth.store.user_model.create_user(email,
                password_raw=password)
        logging.info('user: ' + str(user))

        # user.put()

        user[1].name = email
        user[1].email = email
        user[1].put()

        if not user[0]:  # user is a tuple
            return user[1]  # Error message
        else:

            # User is created, let's try redirecting to login page

            try:
                logging.info('redirect')
                logging.info('redirect to '
                             + self.auth_config['login_url'])
                self.redirect(self.auth_config['login_url'], abort=True)
            except (AttributeError, KeyError), e:

                # self.abort(403)

                self.response.out.write(str(e))


_INDEX_NAME2 = 'greeting'


class MainSearchPage(BaseHandler):

    """Handles search requests for comments."""

    def get(self):
        """Handles a get request with a query."""

        uri = urlparse(self.request.uri)
        query = ''
        if uri.query:
            query = parse_qs(uri.query)
            query = query['query'][0]

        # sort results by author descending

        expr_list = [search.SortExpression(expression='author',
                     default_value='',
                     direction=search.SortExpression.DESCENDING)]

        # construct the sort options

        sort_opts = search.SortOptions(expressions=expr_list)
        query_options = search.QueryOptions(limit=3,
                sort_options=sort_opts)
        query_obj = search.Query(query_string=query,
                                 options=query_options)
        results = \
            search.Index(name=_INDEX_NAME2).search(query=query_obj)
        if users.get_current_user():
            url = users.create_logout_url(self.request.uri)
            url_linktext = 'Logout'
        else:
            url = users.create_login_url(self.request.uri)
            url_linktext = 'Login'
        for r in results:
            logging.info('result: ' + str(r))
        template_values = {
            'results': results,
            'number_returned': len(results.results),
            'url': url,
            'url_linktext': url_linktext,
            }
        self.render_template('searchindex.html', template_values)


class googleb4b3b9748fe57cbf(BaseHandler):

    def get(self):
        logging.info('INFO')
        self.render_template('googleb4b3b9748fe57cbf.html', None)


def CreateSearchItem(author, content):
    """Creates a search.Document from content written by the author."""

    if author:
        nickname = author.nickname().split('@')[0]
    else:
        nickname = 'anonymous'

    # Let the search service supply the document id.

    return search.Document(fields=[search.TextField(name='author',
                           value=nickname),
                           search.TextField(name='comment',
                           value=content), search.DateField(name='date'
                           , value=datetime.datetime.now().date())])


class IndexComment(BaseHandler):

    """Handles requests to index comments."""

    def post(self):
        """Handles a post request."""

        author = None
        if users.get_current_user():
            author = users.get_current_user()

        content = self.request.get('content')
        query = self.request.get('search')
        if content:
            search.Index(name=_INDEX_NAME2).put(CreateSearchItem(author,
                    content))
        if query:
            self.redirect('/mainsearch?' + urllib.urlencode({'query'
                          : query.encode('utf-8')}))  # {'query': query}))
        else:
            self.redirect('/mainsearch')


import sys
if 'lib' not in sys.path:
    sys.path[0:0] = ['lib']
from secrets import SESSION_KEY
config = \
    {'webapp2_extras.sessions': {'cookie_name': '_simpleauth_sess',
     'secret_key': SESSION_KEY},
     'webapp2_extras.auth': {'user_attributes': []},
     'webapp2_extras.jinja2': {'template_path': 'templates',
     'filters': {
    'timesince': filters.timesince,
    'datetimeformat': filters.datetimeformat,
    'slugify_montao': filters.slugify_montao,
    'format_datetime_human': filters.format_datetime_human,
    'default_if_none': filters.default_if_none,
    'datetimeformat_viewad': filters.datetimeformat_viewad,
    'datetimeformat_jinja': filters.datetimeformat_jinja,
'format_date_human' : filters.format_date_human,
'displayimg': filters.displayimg,
'displayhour': filters.displayhour,
'displayminute': filters.displayminute,
'displaytime': filters.displaytime,
    }, 'environment_args': {'extensions': ['jinja2.ext.i18n',
                            'jinja2htmlcompress.SelectiveHTMLCompress'
                            ]}}}




app = webapp2.WSGIApplication([  # ('/oldlist.kml', KMLHandler),
                                 # ('/list.kml', KMLHandler),
                                 # ('/list.kmz', KMZHandler),
                                 # ('/file/([0-9]+)', FileInfoHandler),
    webapp2.Route(r'/createnewad', handler=CreateAdHandler,
                  name='createadhandler'),
    ('/file/([0-9]+)', FileInfoHandler),
    ('/kmlfile/([0-9]+)', KMLFileHandler),
    ('/upload_form', AdLister),
    ('/rpc', RPCHandler),
    ('/edit', EditAdPage),
    ('/([0-9]*)/submit', PreviewForm),
    ('/preview/([^/]*)', PreviewForm),
    ('/(publish)/([0-9]*)', PublishAdById),
    ('(/market)', AdLister),
    ('/addimage', AddImage),
    ('/removeimage([^/]*)', RemoveImageById),
    ('/thankyou.html([^/]*)', AdLister),
    ('/thanks.html([^/]*)', AdLister),
    ('/previewform([^/]*)', PreviewForm),
    ('/images/([^_]*)(_small\.|_full\.|_out\.|_o\.|\.)(jpg|jpeg|ico|bmp|png|tif|tiff|gif)'
     , ServeImageById),
    ('/market/([^/]*)/recommend', Recommend),
    ('/market/([^/]*)/remove', RemoveAd),
    ('/market/([^/]*)/renew', RenewAd),
    ('/market/([^/]*)/newpasswd', NewPassword),
    ('/market/([^/]*)/(mailc2c|fullmail)', SendMail),
    ('/sitemap.xml.gz', SiteMap),
    ('/georss', GeoRSS),
    ('/montaolist.kmz', MontaoKMZHandler),
    ('/montaolist.kml', MontaoKMLHandler),
    ('/serve/([^/]+)?', ServeHandler),
    ('/vi/(\d+)(\.html?)?', NewAdHandler),
    ('/vi/([^/]+)?', NewAdHandler),
    ('/post/([^/]+)?', PostKeyHandler),
    ('/upload', FileUploadFormHandler),
    ('/buscar', BuscarHandler),
    ('/manage', ManageHandler),
    ('/manage/([^/]+)?', ManageHandler),
    ('/fileupload', FileUploadHandler),
    ('/faleconosco', FileUploadFormHandler),
    ('/contactfileupload', ContactFileUploadHandler),
    ('/id2blob/([^/]+)?', BlobHandler),
    ('/i18ntest', I18NTestHandler),
    ('/remove', RemoveHandler),
    ('/resetpassword', ResetPassword),
    ('/credit', CreditHandler),
    ('/customer_service.htm', FileUploadFormHandler),
    ('/about.htm', AboutHandler),
    ('/rules.htm', RulesHandler),
    ('/action/([0-9]+)', DeleteOrEditHandler),
    ('/security/index.htm', SecurityHandler),
    ('/output.data', JSONHandler),
    ('/home', Home),
    ('/sell', Sell),
    ('/sell/(.*)/', Sell),
    ('/buy/(.*)/return/(.*)/(.*)/', BuyReturn),
    ('/buy/(.*)/cancel/(.*)/', BuyCancel),
    ('/buy/(.*)/', Buy),
    ('/image/(.*)/', PPImage),
    ('/file/([0-9]+)/download', FileDownloadHandler),
    webapp2.Route(r'/ads/<ad_id:\d+>', handler=CurrentAdHandler,
                  name='ad'),
    webapp2.Route('/passwdresetcomplete/<token>',
                  handler=PasswordResetComplete,
                  name='passwordresetcomplete'),
    webapp2.Route(r'/adwatch/', handler=AdWatch, name='adwatch'),
    webapp2.Route(r'/createkml/', handler=CreateKMLHandler,
                  name='createkml'),
    webapp2.Route(r'/createkmltask/', handler=CreateKMLTask,
                  name='createkmltask'),
    webapp2.Route(r'/adwatch/watch_ad', handler=WatchAdHandler,
                  name='watchad'),
    webapp2.Route(r'/passwordreset/', handler=Passwordreset,
                  name='passwordreset'),
    ('/taps/(.*)', Ad3tapsHandler),
    webapp2.Route(r'/syncwithfacebook/', handler=SyncwithFacebook,
                  name='syncwithfacebook'),
    webapp2.Route(r'/login/', handler=NewLoginHandler, name='login'),
    webapp2.Route(r'/q/', handler=QueryHandler, name='query'),
    webapp2.Route(r'/logout/', handler=NewLogoutHandler, name='logout'
                  ),
    webapp2.Route(r'/secure/', handler=SecureRequestHandler,
                  name='secure'),
    webapp2.Route(r'/create/', handler=CreateUserHandler,
                  name='create-user'),
    webapp2.Route(r'/register', handler=CreateUserHandler,
                  name='register'),
    webapp2.Route(r'/addregions', handler=AddregionsHandler,
                  name='addregions'),
    webapp2.Route(r'/addcity', handler=AddCityHandler, name='addcity'),
    webapp2.Route(r'/addcity_by_ddd', handler=AddCityByDDDHandler,
                  name='addcity_by_ddd'),
    webapp2.Route(r'/addddd_by_region', handler=AddDDDByRegionHandler,
                  name='addddd_by_region'),
    webapp2.Route(r'/templates/common/regions.html',
                  handler=RegionHandler, name='regions'),
    webapp2.Route('/auth', handler='authhandlers.RootHandler'),
    webapp2.Route('/profile', handler='authhandlers.ProfileHandler',
                  name='profile'),
    webapp2.Route('/auth/<provider>',
                  handler='authhandlers.AuthHandler:_simple_auth',
                  name='auth_login'),
    webapp2.Route('/auth/<provider>/callback',
                  handler='authhandlers.AuthHandler:_auth_callback',
                  name='auth_callback'),
    webapp2.Route('/logout', handler='auth-handlers.AuthHandler:logout'
                  , name='logout'),
    webapp2.Route(r'/cities', handler=CitiesHandler, name='cities'),
    webapp2.Route(r'/citiesinsert', handler=CitiesInsertHandler,
                  name='citiesinsert'),
    webapp2.Route(r'/citiesinsert_br', handler=CitiesInsertBrHandler,
                  name='citiesinsert_br'),
    webapp2.Route(r'/cities_br', handler=CitiesBrHandler,
                  name='citiesinsert_br'),
    webapp2.Route(r'/viewcities_br', handler=ViewCitiesHandler,
                  name='viewcities_br'),
    webapp2.Route(r'/viewallcities', handler=ViewAllCitiesHandler,
                  name='viewallcities'),
    webapp2.Route(r'/googlogin', handler=GLogin, name='gglogin'),
    webapp2.Route(r'/googlogout', handler=GLogout, name='gglogout'),
    ('/searchapi', SearchAPI),
    ('/searchapisign', Comment),
    ('/mainsearch', MainSearchPage),
    ('/sign', IndexComment),
    ('/googleb4b3b9748fe57cbf.html', googleb4b3b9748fe57cbf),
    ], config=config, debug=False)