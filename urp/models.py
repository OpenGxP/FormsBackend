"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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


# python import
import string

# django imports
from django.db import models
from django.utils import timezone
from django.db.models import Q
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

# app imports
from .validators import validate_no_space, validate_no_specials, validate_no_specials_reduced, SPECIALS_REDUCED, \
    validate_no_numbers, validate_only_ascii, validate_only_positive_numbers
from .custom import create_log_record
from basics.custom import generate_checksum, generate_to_hash
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, CHAR_MAX, FIELD_VERSION, Status, LOG_HASH_SEQUENCE
from .ldap import init_server, connect, search


###############
# PERMISSIONS #
###############

# log manager
class PermissionsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# log table
class PermissionsLog(GlobalModel):
    # custom fields
    key = models.CharField(_('key'), max_length=CHAR_DEFAULT)
    model = models.CharField(_('model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('permission'), max_length=CHAR_DEFAULT)
    # log specific fields
    user = models.CharField(_('user'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('action'), max_length=CHAR_DEFAULT)

    # manager
    objects = PermissionsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};model:{};permission:{};user:{};timestamp:{};action:{};' \
            .format(self.key, self.model, self.permission, self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'model', 'permission'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '08'
    perms = {
            '01': 'read',
        }


# manager
class PermissionsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = PermissionsLog

    @property
    def all_comma_separated_list(self):
        comma_list = ''
        query = self.all()
        for perm in query:
            comma_list += '{},'.format(perm.key)
        return comma_list[:-1]


# table
class Permissions(GlobalModel):
    # custom fields
    key = models.CharField(_('key'), max_length=CHAR_DEFAULT, unique=True)
    model = models.CharField(_('model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('permission'), max_length=CHAR_DEFAULT)

    # manager
    objects = PermissionsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};model:{};permission:{};'.format(self.key, self.model, self.permission)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'model', 'permission']

    # permissions
    MODEL_ID = '02'
    MODEL_CONTEXT = 'Permissions'
    perms = {
        '01': 'read',
    }

    # unique field
    UNIQUE = 'key'


#############
# ACCESSLOG #
#############

# manager
class AccessLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    def latest_record(self, username):
        try:
            return self.filter(user=username).filter(Q(action='attempt') | Q(action='login')).order_by('-timestamp')[0]
        except IndexError:
            return None


# table
class AccessLog(GlobalModel):
    # custom fields
    user = models.CharField(_('user'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('action'), max_length=CHAR_DEFAULT)
    mode = models.CharField(_('mode'), max_length=CHAR_DEFAULT)
    method = models.CharField(_('method'), max_length=CHAR_DEFAULT)
    attempt = models.CharField(_('attempt'), max_length=CHAR_DEFAULT)
    active = models.CharField(_('mode'), max_length=CHAR_DEFAULT)

    # manager
    objects = AccessLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'user:{};timestamp:{};action:{};mode:{};method:{};attempt:{};active:{};' \
            .format(self.user, self.timestamp, self.action, self.mode, self.method, self.attempt, self.active)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['user', 'timestamp', 'action', 'mode', 'method', 'attempt', 'active']

    # permissions
    MODEL_ID = '05'
    MODEL_CONTEXT = 'Authentication'
    perms = {
        '01': 'read',
    }


#########
# ROLES #
#########

# log manager
class RolesLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# log table
class RolesLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    role = models.CharField(_('role'), max_length=CHAR_DEFAULT)
    permissions = models.CharField(_('permissions'), max_length=CHAR_MAX, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('user'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('action'), max_length=CHAR_DEFAULT)

    # manager
    objects = RolesLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'role:{};status_id:{};version:{};valid_from:{};valid_to:{};permissions:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.role, self.status_id, self.version, self.valid_from, self.valid_to, self.permissions,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['role', 'status_id', 'version', 'valid_from', 'valid_to', 'permissions'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '09'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class RolesManager(GlobalManager):
    # flags
    LOG_TABLE = RolesLog

    def find_permission_in_roles(self, roles, permission):
        for role in roles.split(','):
            # query all versions of each role that is in status "productive" or "inactive"
            query = self.filter(role=role).filter(Q(status=Status.objects.productive) |
                                                  Q(status=Status.objects.inactive)).all()
            for obj in query:
                # get the valid role (only one version of all returned versions can be valid!)
                if obj.verify_validity_range:
                    # check each role for the requested permission
                    if permission in obj.permissions.split(','):
                        return True

    def casl(self, roles):
        permissions = list()
        # check all roles of valid user
        for role in roles:
            # get all productive versions of each role
            prod_roles = self.get_by_natural_key_productive(role)
            # catch the valid version
            for valid_prod_role in prod_roles:
                if valid_prod_role.verify_validity_range:
                    # merge permissions of valid role into permission list
                    permissions = list(set(permissions + valid_prod_role.permissions.split(',')))
        casl = list()
        # iterate merges permissions to build casl response
        for perm in permissions:
            perm_obj = Permissions.objects.filter(key=perm).get()
            append = None
            # check if subject exists and add if yes
            for item in casl:
                if item['subject'][0] == perm_obj.model:
                    item['actions'].append(perm_obj.permission)
                    append = True
            if not append:
                # append permission to new subject
                casl.append({'subject': [perm_obj.model],
                             'actions': [perm_obj.permission]})
        return casl


# table
class Roles(GlobalModel):
    # custom fields
    role = models.CharField(
        _('role'),
        max_length=CHAR_DEFAULT,
        help_text=_('Unique and required. {} characters or fewer. Special characters "{}" are not permitted. '
                    'No whitespaces.'
                    .format(CHAR_DEFAULT, SPECIALS_REDUCED)),
        validators=[validate_no_specials_reduced,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii])
    permissions = models.CharField(_('permissions'), max_length=CHAR_MAX, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'role:{};status_id:{};version:{};valid_from:{};valid_to:{};permissions:{};'. \
            format(self.role, self.status_id, self.version, self.valid_from, self.valid_to, self.permissions)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # manager
    objects = RolesManager()

    # hashing
    HASH_SEQUENCE = ['role', 'status_id', 'version', 'valid_from', 'valid_to', 'permissions']

    # permissions
    MODEL_ID = '03'
    MODEL_CONTEXT = 'Roles'

    # unique field
    UNIQUE = 'role'

    class Meta:
        unique_together = ('lifecycle_id', 'version')


########
# LDAP #
########

# log manager
class LDAPLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# log table
class LDAPLog(GlobalModel):
    # custom fields
    host = models.CharField(_('host'), max_length=CHAR_DEFAULT)
    port = models.IntegerField(_('port'))
    ssl_tls = models.BooleanField(_('ssl_tls'))
    bindDN = models.CharField(_('bindDN'), max_length=CHAR_DEFAULT)
    password = models.CharField(_('password'), max_length=CHAR_MAX)
    base = models.CharField(_('base'), max_length=CHAR_DEFAULT)
    filter = models.CharField(_('filter'), max_length=CHAR_DEFAULT)
    attr_username = models.CharField(_('attr_username'), max_length=CHAR_DEFAULT)
    attr_email = models.CharField(_('attr_email'), max_length=CHAR_DEFAULT, blank=True)
    attr_surname = models.CharField(_('attr_surname'), max_length=CHAR_DEFAULT, blank=True)
    attr_forename = models.CharField(_('attr_forename'), max_length=CHAR_DEFAULT, blank=True)
    priority = models.IntegerField(_('priority'), validators=[validate_only_positive_numbers])
    # log specific fields
    user = models.CharField(_('user'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('action'), max_length=CHAR_DEFAULT)

    # manager
    objects = LDAPLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};ssl_tls:{};bindDN:{};password:{};base:{};filter:{};attr_username:{};' \
                          'attr_email:{};attr_surname:{};attr_forename:{};priority:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.host, self.port, self.ssl_tls, self.bindDN, self.password, self.base, self.filter,
                   self.attr_username, self.attr_email, self.attr_surname, self.attr_forename, self.priority,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['host', 'port', 'ssl_tls', 'bindDN', 'password', 'base', 'filter', 'attr_username',
                     'attr_email', 'attr_surname', 'attr_forename', 'priority'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '12'
    perms = {
        '01': 'read',
    }


class LDAPManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = LDAPLog

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
                    con = connect(server=ser, bind_dn=server.bindDN, password=server.password)
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
            con = connect(server=ser, bind_dn=bind_dn, password=password)
            return con.bind()


# table
class LDAP(GlobalModel):
    # custom fields
    host = models.CharField(_('host'), max_length=CHAR_DEFAULT, unique=True)
    port = models.IntegerField(_('port'))
    ssl_tls = models.BooleanField(_('ssl_tls'))
    bindDN = models.CharField(_('bindDN'), max_length=CHAR_DEFAULT)
    password = models.CharField(_('password'), max_length=CHAR_MAX)
    base = models.CharField(_('base'), max_length=CHAR_DEFAULT)
    filter = models.CharField(_('filter'), max_length=CHAR_DEFAULT)
    attr_username = models.CharField(_('attr_username'), max_length=CHAR_DEFAULT)
    attr_email = models.CharField(_('attr_email'), max_length=CHAR_DEFAULT, blank=True)
    attr_surname = models.CharField(_('attr_surname'), max_length=CHAR_DEFAULT, blank=True)
    attr_forename = models.CharField(_('attr_forename'), max_length=CHAR_DEFAULT, blank=True)
    priority = models.IntegerField(_('priority'), validators=[validate_only_positive_numbers], unique=True)

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


#########
# USERS #
#########

# log manager
class UsersLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# log table
class UsersLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    username = models.CharField(_('username'), max_length=CHAR_DEFAULT)
    email = models.EmailField(_('email'), max_length=CHAR_MAX, blank=True)
    first_name = models.CharField(_('first name'), max_length=CHAR_DEFAULT, blank=True)
    last_name = models.CharField(_('last name'), max_length=CHAR_DEFAULT, blank=True)
    initial_password = models.BooleanField(_('initial password'))
    ldap = models.BooleanField(_('ldap'))
    roles = models.CharField(_('roles'), max_length=CHAR_DEFAULT)
    is_active = models.BooleanField(_('is_active'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('user'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('action'), max_length=CHAR_DEFAULT)

    # manager
    objects = UsersLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};initial_password:{};' \
                          'status_id:{};version:{};valid_from:{};valid_to:{};ldap:{};roles:{};' \
                          'user:{};timestamp:{};action:{};' \
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.status_id, self.version, self.valid_from, self.valid_to, self.ldap, self.roles,
                    self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active', 'initial_password',
                     'status_id', 'version', 'valid_from', 'valid_to', 'ldap', 'roles'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '10'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class UsersManager(BaseUserManager, GlobalManager):
    # flags
    LOG_TABLE = UsersLog

    # form
    MODEL_EXCLUDE = ('initial_password', 'is_active')

    @property
    def existing_users(self):
        return self.all().values_list('username', flat=True)

    def exist(self, username):
        return self.filter(username=username).exists()

    # superuser function for createsuperuser
    def create_superuser(self, username, password, role, email):
        # initial status "Effective" to immediately user superuser
        now = timezone.now()
        status_id = Status.objects.productive
        fields = {'username': username,
                  'first_name': username,
                  'last_name': username,
                  'version': 1,
                  'is_active': True,
                  'valid_from': now,
                  'initial_password': True,
                  'email': email,
                  'status_id': status_id,
                  'ldap': False,
                  'roles': role}
        user = self.model(**fields)
        user.set_password(password)
        fields['password'] = user.password
        # build string with row id to generate hash
        to_hash = generate_to_hash(fields, hash_sequence=user.HASH_SEQUENCE, unique_id=user.id,
                                   lifecycle_id=user.lifecycle_id)
        user.checksum = generate_checksum(to_hash)
        try:
            user.full_clean()
        except ValidationError as e:
            raise e
        else:
            user.save()
        # log record
        del fields['password']
        context = dict()
        context['function'] = 'init'
        create_log_record(model=self.model, context=context, obj=user,
                          validated_data=fields, action=settings.DEFAULT_LOG_CREATE)
        return user


# table
class Users(AbstractBaseUser, GlobalModel):
    # custom fields
    username = models.CharField(_('username'), max_length=CHAR_DEFAULT)
    email = models.EmailField(_('email'), max_length=CHAR_MAX, blank=True)
    first_name = models.CharField(
        _('first name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii], blank=True)
    last_name = models.CharField(
        _('last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii], blank=True)
    initial_password = models.BooleanField(_('initial password'))
    password = models.CharField(_('password'), max_length=CHAR_MAX)
    ldap = models.BooleanField(_('ldap'))
    roles = models.CharField(_('roles'), max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};initial_password:{};' \
                          'password:{};status_id:{};version:{};valid_from:{};valid_to:{};ldap:{};roles:{};'\
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.password, self.status_id, self.version, self.valid_from, self.valid_to, self.ldap, self.roles)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    def permission(self, value):
        return Roles.objects.find_permission_in_roles(roles=self.roles, permission=value)

    # references
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    last_login = None
    is_active = models.BooleanField(_('is_active'))

    # unique field
    UNIQUE = 'username'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active', 'initial_password', 'password',
                     'status_id', 'version', 'valid_from', 'valid_to', 'ldap', 'roles']

    # permissions
    MODEL_ID = '04'
    MODEL_CONTEXT = 'Users'

    def get_full_name(self):
        return _('{} - {} {}').format(self.username, self.first_name, self.last_name)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)
