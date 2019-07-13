"""
opengxp.org
Copyright (C) 2019  Henrik Baran

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# django imports
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX
from urp.backends.ldap import init_server, connect, search
from urp.crypto import decrypt
from urp.validators import validate_only_positive_numbers
from urp.models.users import Users


# log manager
class LDAPLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('host',
                       'port',
                       'ssl_tls',
                       'bindDN',
                       'base',
                       'filter',
                       'attr_username',
                       'attr_email',
                       'attr_surname',
                       'attr_forename',
                       'priority',)


# log table
class LDAPLog(GlobalModel):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT)
    port = models.IntegerField(_('Port'))
    ssl_tls = models.BooleanField(_('SSL'))
    bindDN = models.CharField(_('BindDN'), max_length=CHAR_DEFAULT)
    base = models.CharField(_('Base'), max_length=CHAR_DEFAULT)
    filter = models.CharField(_('Filter'), max_length=CHAR_DEFAULT)
    attr_username = models.CharField(_('Attr Username'), max_length=CHAR_DEFAULT)
    attr_email = models.CharField(_('Attr Email'), max_length=CHAR_DEFAULT, blank=True)
    attr_surname = models.CharField(_('Attr Surname'), max_length=CHAR_DEFAULT, blank=True)
    attr_forename = models.CharField(_('Attr Forename'), max_length=CHAR_DEFAULT, blank=True)
    priority = models.IntegerField(_('Priority'), validators=[validate_only_positive_numbers])
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = LDAPLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};ssl_tls:{};bindDN:{};base:{};filter:{};attr_username:{};' \
                          'attr_email:{};attr_surname:{};attr_forename:{};priority:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.host, self.port, self.ssl_tls, self.bindDN, self.base, self.filter,
                   self.attr_username, self.attr_email, self.attr_surname, self.attr_forename, self.priority,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['host', 'port', 'ssl_tls', 'bindDN', 'base', 'filter', 'attr_username',
                     'attr_email', 'attr_surname', 'attr_forename', 'priority'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '12'
    MODEL_CONTEXT = 'LDAPLog'
    perms = {
        '01': 'read',
    }


class LDAPManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = LDAPLog

    # meta
    GET_MODEL_ORDER = ('host',
                       'port',
                       'ssl_tls',
                       'bindDN',
                       'password',
                       'base',
                       'filter',
                       'attr_username',
                       'attr_email',
                       'attr_surname',
                       'attr_forename',
                       'priority',)

    def _server(self):
        query = self.order_by('-priority').all()
        if not query:
            raise ValidationError('No LDAP server configured.')
        return query

    def search(self, data):
        query = self._server()
        error = dict()
        for server in query:
            # try to connect to server
            try:
                ser = init_server(host=server.host, port=server.port, use_ssl=server.ssl_tls)
            except ValidationError as e:
                error[server.host] = e
            else:
                if ser.check_availability():
                    # decrypt password before usage
                    password = decrypt(server.password)
                    con = connect(server=ser, bind_dn=server.bindDN, password=password)
                    if con.bind():
                        attributes = [server.attr_username]
                        if server.attr_email:
                            attributes.append(server.attr_email)
                        if server.attr_surname:
                            attributes.append(server.attr_surname)
                        if server.attr_forename:
                            attributes.append(server.attr_forename)
                        # build filter
                        ldap_filter = '(&{}({}={}))'.format(server.filter, server.attr_username, data['username'])
                        try:
                            search(con=con, base=server.base, attributes=attributes, ldap_filter=ldap_filter)
                        except ValidationError as e:
                            error[server.host] = e
                        else:
                            # check if search was successful as specified in RFC4511
                            if con.response and con.result['description'] == 'success':
                                response_attributes = con.response[0]['attributes']
                                for attr in response_attributes:
                                    if attr == server.attr_email:
                                        data[Users.EMAIL_FIELD] = response_attributes[attr][0]
                                    if attr == server.attr_forename:
                                        data['first_name'] = response_attributes[attr][0]
                                    if attr == server.attr_surname:
                                        data['last_name'] = response_attributes[attr][0]
                                return
                            else:
                                error[server.host] = ('Username "{}" does not exist on LDAP host "{}".'
                                                      .format(data['username'], server.host))
                    else:
                        error[server.host] = 'LDAP connection failed. False credentials and / or false bind.'
                else:
                    error[server.host] = 'LDAP server <{}> not available at port <{}>.'.format(server.host, server.port)
        raise ValidationError(error)

    def bind(self, username, password):
        query = self._server()
        for server in query:
            ser = init_server(host=server.host, port=server.port, use_ssl=server.ssl_tls)
            bind_dn = '{}={},{}'.format(server.attr_username, username, server.base)
            # auto bind using tls is active, therefore no additional manual bind required
            try:
                connect(server=ser, bind_dn=bind_dn, password=password)
            except ValidationError:
                return False
            return True


# table
class LDAP(GlobalModel):
    # custom fields
    host = models.CharField(
        _('Host'),
        max_length=CHAR_DEFAULT,
        unique=True)
    port = models.IntegerField(
        _('Port'))
    ssl_tls = models.BooleanField(
        _('SSL'))
    bindDN = models.CharField(
        _('BindDN'),
        max_length=CHAR_DEFAULT)
    password = models.CharField(
        _('Password'),
        max_length=CHAR_MAX)
    base = models.CharField(
        _('Base'),
        max_length=CHAR_DEFAULT)
    filter = models.CharField(
        _('Filter'),
        max_length=CHAR_DEFAULT)
    attr_username = models.CharField(
        _('Attr Username'),
        max_length=CHAR_DEFAULT)
    attr_email = models.CharField(
        _('Attr Email'),
        max_length=CHAR_DEFAULT,
        blank=True)
    attr_surname = models.CharField(
        _('Attr Surname'),
        max_length=CHAR_DEFAULT,
        blank=True)
    attr_forename = models.CharField(
        _('Attr Forename'),
        max_length=CHAR_DEFAULT,
        blank=True)
    priority = models.IntegerField(
        _('Priority'),
        validators=[validate_only_positive_numbers],
        unique=True)

    # manager
    objects = LDAPManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};ssl_tls:{};bindDN:{};password:{};base:{};filter:{};attr_username:{};' \
                          'attr_email:{};attr_surname:{};attr_forename:{};priority:{};'. \
            format(self.host, self.port, self.ssl_tls, self.bindDN, self.password, self.base, self.filter,
                   self.attr_username, self.attr_email, self.attr_surname, self.attr_forename, self.priority)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['host', 'port', 'ssl_tls', 'bindDN', 'password', 'base', 'filter', 'attr_username',
                     'attr_email', 'attr_surname', 'attr_forename', 'priority']

    # permissions
    MODEL_ID = '11'
    MODEL_CONTEXT = 'LDAP'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
    }

    # unique field
    UNIQUE = 'host'
