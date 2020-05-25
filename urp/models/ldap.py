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

# rest imports
from rest_framework.serializers import ValidationError as SerializerValidationError

# django imports
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX, GlobalModelLog
from urp.backends.ldap import init_server, connect, search
from urp.crypto import decrypt
from urp.validators import validate_only_positive_numbers


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
        data['post']['certificate'] = {'verbose_name': _('Certificate'),
                                       'help_text': _('For SSL/TLS connections add a certificate file in PEM format.'),
                                       'max_length': None,
                                       'data_type': 'CharField',
                                       'required': False,
                                       'unique': False,
                                       'lookup': None,
                                       'editable': True}

    @property
    def _server(self):
        query = self.order_by('-priority').all()
        if not query:
            # FO-283: change error type to django rest framework
            raise SerializerValidationError('No LDAP server configured.')
        return query

    @property
    def _cache_server_con(self):
        server, con = self._base_server_con()
        return server, con

    @property
    def _cache_server(self):
        # try to get from cache
        server, _server = self._base_server_con(only_server=True)
        return server, _server

    def _base_server_con(self, only_server=None):
        query = self._server
        error = {}
        for server in query:
            try:
                _server = init_server(host=server.host, port=server.port, use_ssl=server.ssl_tls)
            except ValidationError as e:
                error[server.host] = e
            else:
                if _server.check_availability():
                    if only_server:
                        return server, _server
                    # decrypt password before usage
                    password = decrypt(server.password)
                    # auto bind using tls is active, therefore no additional manual bind required
                    try:
                        con = connect(server=_server, bind_dn=server.bindDN, password=password)
                    except ValidationError as e:
                        error[server.host] = e
                    else:
                        return server, con
                error[server.host] = 'LDAP server <{}> not available at port <{}>.'.format(server.host, server.port)
        raise ValidationError(error)

    def base_search_user(self, username):
        # get server and connection
        server, con = self._cache_server_con
        # build filter
        ldap_filter = '(&{}({}={}))'.format(server.filter_user, server.attr_username, username)
        search(con=con, base=server.base_user, ldap_filter=ldap_filter, attributes=server.attr_username)
        # check if search was successful as specified in RFC4511
        if con.response and con.result['description'] == 'success':
            return True
        return False

    def search_user(self, data):
        # get server and connection
        server, con = self._cache_server_con
        # build filter
        attributes = [server.attr_username]
        if server.attr_email:
            attributes.append(server.attr_email)
        if server.attr_surname:
            attributes.append(server.attr_surname)
        if server.attr_forename:
            attributes.append(server.attr_forename)
        # build filter
        ldap_filter = '(&{}({}={}))'.format(server.filter_user, server.attr_username, data['username'])
        search(con=con, base=server.base_user, attributes=attributes, ldap_filter=ldap_filter)
        if con.response and con.result['description'] == 'success':
            response_attributes = con.response[0]['attributes']
            for attr in response_attributes:
                if attr == server.attr_email:
                    data['email'] = response_attributes[attr][0]
                if attr == server.attr_forename:
                    data['first_name'] = response_attributes[attr][0]
                if attr == server.attr_surname:
                    data['last_name'] = response_attributes[attr][0]

    def bind(self, username, password):
        # get server
        server, _server = self._cache_server
        bind_dn = '{}={},{}'.format(server.attr_username, username, server.base_user)
        # auto bind using tls is active, therefore no additional manual bind required
        try:
            con = connect(server=_server, bind_dn=bind_dn, password=password)
        except ValidationError:
            return False
        else:
            # immediately unbind again to close connection
            con.unbind()
        return True

    @property
    def search_groups(self):
        # get server and connection
        server, con = self._cache_server_con
        groups = []
        search(con=con, base=server.base_group, attributes=[server.attr_group], ldap_filter=server.filter_group)
        # check if search was successful as specified in RFC4511
        if con.response and con.result['description'] == 'success':
            for item in con.response:
                groups.append(item['attributes'][server.attr_group][0])
        return groups

    def get_group_membership(self, username):
        groups = []
        # get server and connection
        server, con = self._cache_server_con
        # build filter
        ldap_filter = '(&{}(memberUid={}))'.format(server.filter_group, username)
        search(con=con, base=server.base_group, ldap_filter=ldap_filter, attributes=server.attr_group)
        # check if search was successful as specified in RFC4511
        if con.response and con.result['description'] == 'success':
            for item in con.response:
                groups.append(item['attributes'][server.attr_group][0])
            return groups
        return groups


# table
class LDAP(GlobalModel):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT, unique=True, help_text=_('Provide ldap host.'))
    port = models.IntegerField(_('Port'), validators=[validate_only_positive_numbers],
                               help_text=_('Provide ldap host port, only positive numbers are allowed.'))
    ssl_tls = models.BooleanField(_('SSL'), help_text=_('Specify if SSL/TLS connection is used.'))
    bindDN = models.CharField(_('BindDN'), max_length=CHAR_DEFAULT,
                              help_text=_('BindDN to authenticate against ldap server. '
                                          'Example: cn=userxy,dc=example,dc=com'))
    password = models.CharField(_('Password'), max_length=CHAR_MAX,
                                help_text=_('Password for ldap BindDN authentication.'))
    base_user = models.CharField(_('Base User'), max_length=CHAR_DEFAULT,
                                 help_text=_('Base for user operations. Example: ou=users,dc=example,dc=com'))
    base_group = models.CharField(_('Base Group'), max_length=CHAR_DEFAULT, blank=True,
                                  help_text=_('Base for group operations. Example: ou=groups,dc=example,dc=com'))
    filter_user = models.CharField(_('Filter User'), max_length=CHAR_DEFAULT,
                                   help_text=_('Filter for user operations. Example: (objectClass=inetOrgPerson)'))
    filter_group = models.CharField(_('Filter Groups'), max_length=CHAR_DEFAULT, blank=True,
                                    help_text=_('Filter for group operations. Example: (objectClass=posixGroup)'))
    attr_username = models.CharField(_('Attr Username'), max_length=CHAR_DEFAULT,
                                     help_text=_('Unique attribute of users in external ldap server. Example: cn/uid'))
    attr_group = models.CharField(_('Attr Group'), max_length=CHAR_DEFAULT, blank=True,
                                  help_text=_('Attribute of groups in external ldap server. Example: cn'))
    attr_email = models.CharField(_('Attr Email'), max_length=CHAR_DEFAULT, blank=True,
                                  help_text=_('Attribute of user email field. Example: mail'))
    attr_surname = models.CharField(_('Attr Surname'), max_length=CHAR_DEFAULT, blank=True,
                                    help_text=_('Attribute of user surname field. Example: sn'))
    attr_forename = models.CharField(_('Attr Forename'), max_length=CHAR_DEFAULT, blank=True,
                                     help_text=_('Attribute of user forename field. Example: givenName'))
    priority = models.IntegerField(_('Priority'), validators=[validate_only_positive_numbers], unique=True,
                                   help_text=_('Provide priority, only positive numbers are allowed.'))

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
