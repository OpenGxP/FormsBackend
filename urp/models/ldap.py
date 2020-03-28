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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX, GlobalModelLog
from urp.backends.ldap import init_server, connect, search
from urp.crypto import decrypt
from urp.validators import validate_only_positive_numbers
from urp.models.users import Users


# log manager
class LDAPLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('host',
                       'port',
                       'ssl_tls',
                       'bindDN',
                       'base_user',
                       'filter_user',
                       'filter_group',
                       'attr_username',
                       'attr_group',
                       'attr_email',
                       'attr_surname',
                       'attr_forename',
                       'priority',)


# log table
class LDAPLog(GlobalModelLog):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT)
    port = models.IntegerField(_('Port'))
    ssl_tls = models.BooleanField(_('SSL'))
    bindDN = models.CharField(_('BindDN'), max_length=CHAR_DEFAULT)
    base_user = models.CharField(_('Base User'), max_length=CHAR_DEFAULT)
    base_group = models.CharField(_('Base Group'), max_length=CHAR_DEFAULT, blank=True)
    filter_user = models.CharField(_('Filter User'), max_length=CHAR_DEFAULT)
    filter_group = models.CharField(_('Filter Groups'), max_length=CHAR_DEFAULT, blank=True)
    attr_username = models.CharField(_('Attr Username'), max_length=CHAR_DEFAULT)
    attr_group = models.CharField(_('Attr Group'), max_length=CHAR_DEFAULT, blank=True)
    attr_email = models.CharField(_('Attr Email'), max_length=CHAR_DEFAULT, blank=True)
    attr_surname = models.CharField(_('Attr Surname'), max_length=CHAR_DEFAULT, blank=True)
    attr_forename = models.CharField(_('Attr Forename'), max_length=CHAR_DEFAULT, blank=True)
    priority = models.IntegerField(_('Priority'), validators=[validate_only_positive_numbers])

    # manager
    objects = LDAPLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};ssl_tls:{};bindDN:{};base_user:{};base_group:{};filter_user:{};' \
                          'filter_group:{};attr_username:{};attr_group:{};attr_email:{};attr_surname:{};' \
                          'attr_forename:{};priority:{};'. \
            format(self.host, self.port, self.ssl_tls, self.bindDN, self.base_user, self.base_group, self.filter_user,
                   self.filter_group, self.attr_username, self.attr_group, self.attr_email, self.attr_surname,
                   self.attr_forename, self.priority)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['host', 'port', 'ssl_tls', 'bindDN', 'base_user', 'base_group', 'filter_user',
                                         'filter_group', 'attr_username', 'attr_group', 'attr_email', 'attr_surname',
                                         'attr_forename', 'priority']

    # permissions
    MODEL_ID = '12'
    MODEL_CONTEXT = 'LDAPLog'


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
                       'base_user',
                       'base_group',
                       'filter_user',
                       'filter_group',
                       'attr_username',
                       'attr_group',
                       'attr_email',
                       'attr_surname',
                       'attr_forename',
                       'priority',)

    def meta(self, data):
        # add field for certificate
        data['post']['certificate'] = {'verbose_name': 'Certificate',
                                       'help_text': 'For ssl/tls connections add a certificate file in PEM format.',
                                       'max_length': None,
                                       'data_type': 'CharField',
                                       'required': False,
                                       'unique': False,
                                       'lookup': None,
                                       'editable': True}

    def _server(self):
        query = self.order_by('-priority').all()
        if not query:
            raise ValidationError('No LDAP server configured.')
        return query

    def search_user(self, data):
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
                        ldap_filter = '(&{}({}={}))'.format(server.filter_user, server.attr_username, data['username'])
                        try:
                            search(con=con, base=server.base_user, attributes=attributes, ldap_filter=ldap_filter)
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
            bind_dn = '{}={},{}'.format(server.attr_username, username, server.base_user)
            # auto bind using tls is active, therefore no additional manual bind required
            try:
                connect(server=ser, bind_dn=bind_dn, password=password)
            except ValidationError:
                return False
            return True

    def search_groups(self):
        # lowest priority ldap server is used for groups
        priority_min = self.all().aggregate(models.Min('priority'))
        try:
            server = self.filter(priority=priority_min['priority__min']).get()
        except self.model.DoesNotExist:
            raise ValidationError('No LDAP server configured.')
        groups = []
        # connect to server
        _server = init_server(host=server.host, port=server.port, use_ssl=server.ssl_tls)
        if _server.check_availability():
            # decrypt password before usage
            password = decrypt(server.password)
            con = connect(server=_server, bind_dn=server.bindDN, password=password)
            if con.bind():
                search(con=con, base=server.base_group, attributes=[server.attr_group], ldap_filter=server.filter_group)
                # check if search was successful as specified in RFC4511
                if con.response and con.result['description'] == 'success':
                    for x in con.response:
                        groups.append(x['attributes'][server.attr_group][0])
                    return groups


# table
class LDAP(GlobalModel):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT, unique=True)
    port = models.IntegerField(_('Port'))
    ssl_tls = models.BooleanField(_('SSL'))
    bindDN = models.CharField(_('BindDN'), max_length=CHAR_DEFAULT)
    password = models.CharField(_('Password'), max_length=CHAR_MAX)
    base_user = models.CharField(_('Base User'), max_length=CHAR_DEFAULT)
    base_group = models.CharField(_('Base Group'), max_length=CHAR_DEFAULT, blank=True)
    filter_user = models.CharField(_('Filter User'), max_length=CHAR_DEFAULT)
    filter_group = models.CharField(_('Filter Groups'), max_length=CHAR_DEFAULT, blank=True)
    attr_username = models.CharField(_('Attr Username'), max_length=CHAR_DEFAULT)
    attr_group = models.CharField(_('Attr Group'), max_length=CHAR_DEFAULT, blank=True)
    attr_email = models.CharField(_('Attr Email'), max_length=CHAR_DEFAULT, blank=True)
    attr_surname = models.CharField(_('Attr Surname'), max_length=CHAR_DEFAULT, blank=True)
    attr_forename = models.CharField(_('Attr Forename'), max_length=CHAR_DEFAULT, blank=True)
    priority = models.IntegerField(_('Priority'), validators=[validate_only_positive_numbers], unique=True)

    # manager
    objects = LDAPManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};ssl_tls:{};bindDN:{};password:{};base_user:{};base_group:{};' \
                          'filter_user:{};filter_group:{};attr_username:{};attr_group:{};attr_email:{};' \
                          'attr_surname:{};attr_forename:{};priority:{};'. \
            format(self.host, self.port, self.ssl_tls, self.bindDN, self.password, self.base_user, self.base_group,
                   self.filter_user, self.filter_group, self.attr_username, self.attr_group, self.attr_email,
                   self.attr_surname, self.attr_forename, self.priority)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['host', 'port', 'ssl_tls', 'bindDN', 'password', 'base_user', 'base_group', 'filter_user',
                     'filter_group', 'attr_username', 'attr_group', 'attr_email', 'attr_surname', 'attr_forename',
                     'priority']

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
