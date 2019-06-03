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
import itertools

# django imports
from django.db import models
from django.utils import timezone
from django.db.models import Q
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.password_validation import password_validators_help_texts, validate_password
from django.contrib.auth.hashers import make_password, check_password

# app imports
from .validators import validate_no_space, validate_no_specials, validate_no_specials_reduced, SPECIALS_REDUCED, \
    validate_no_numbers, validate_only_ascii, validate_only_positive_numbers
from .custom import create_log_record
from basics.custom import generate_checksum, generate_to_hash, decrypt
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, CHAR_MAX, FIELD_VERSION, Status, \
    LOG_HASH_SEQUENCE, CHAR_BIG
from .ldap import init_server, connect, search


###############
# PERMISSIONS #
###############

# log manager
class PermissionsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('key',
                       'model',
                       'permission',)


# log table
class PermissionsLog(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    model = models.CharField(_('Model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('Permission'), max_length=CHAR_DEFAULT)
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

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
    MODEL_CONTEXT = 'PermissionsLog'
    perms = {
            '01': 'read',
        }


# manager
class PermissionsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = PermissionsLog

    # meta
    GET_MODEL_ORDER = PermissionsLogManager.GET_MODEL_ORDER


# table
class Permissions(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT, unique=True)
    model = models.CharField(_('Model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('Permission'), max_length=CHAR_DEFAULT)

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

    # meta
    GET_MODEL_ORDER = ('user',
                       'action',
                       'timestamp',
                       'mode',
                       'method',
                       'attempt',
                       'active',)

    def latest_record(self, username):
        try:
            return self.filter(user=username).filter(Q(action='attempt') | Q(action='login')).order_by('-timestamp')[0]
        except IndexError:
            return None


# table
class AccessLog(GlobalModel):
    # custom fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)
    mode = models.CharField(_('Mode'), max_length=CHAR_DEFAULT)
    method = models.CharField(_('Method'), max_length=CHAR_DEFAULT)
    attempt = models.CharField(_('Attempt'), max_length=CHAR_DEFAULT)
    active = models.CharField(_('Active'), max_length=CHAR_DEFAULT)

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
    MODEL_CONTEXT = 'AccessLog'
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

    # meta
    GET_MODEL_ORDER = ('role',
                       'permissions')


# log table
class RolesLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT)
    permissions = models.CharField(_('Permissions'), max_length=CHAR_BIG, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

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
    MODEL_CONTEXT = 'RolesLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class RolesManager(GlobalManager):
    # flags
    LOG_TABLE = RolesLog

    # meta
    GET_MODEL_ORDER = RolesLogManager.GET_MODEL_ORDER

    def find_permission_in_roles(self, roles, permission):
        for role in roles.split(','):
            # query all versions of each role that is in status "productive" or "inactive"
            query = self.filter(role=role).filter(Q(status=Status.objects.productive) |
                                                  Q(status=Status.objects.inactive)).all()
            for obj in query:
                # get the valid role (only one version of all returned versions can be valid!)
                if obj.verify_validity_range:
                    # check each role for the requested permission
                    if any(perm in obj.permissions.split(',') for perm in [permission, settings.ALL_PERMISSIONS]):
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
        _('Role'),
        max_length=CHAR_DEFAULT,
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(SPECIALS_REDUCED)),
        validators=[validate_no_specials_reduced,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii])
    permissions = models.CharField(
        _('Permissions'),
        help_text='Provide comma separated permission keys.',
        max_length=CHAR_BIG,
        blank=True)
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
    GET_MODEL_EXCLUDE = ('password',)
    GET_MODEL_ORDER = LDAPLogManager.GET_MODEL_ORDER

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
            con = connect(server=ser, bind_dn=bind_dn, password=password)
            return con.bind()


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


#########
# VAULT #
#########

# vault manager
class VaultManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_EXCLUDE = ('password',
                         'question_one',
                         'question_two',
                         'question_three',
                         'answer_one',
                         'answer_two',
                         'answer_three',)
    GET_MODEL_ORDER = ('username',
                       'initial_password',)


class Vault(GlobalModel):
    # custom fields
    username = models.CharField(max_length=CHAR_DEFAULT, unique=True)
    initial_password = models.BooleanField()
    password = models.CharField(max_length=CHAR_MAX)
    question_one = models.CharField(max_length=CHAR_MAX, blank=True)
    question_two = models.CharField(max_length=CHAR_MAX, blank=True)
    question_three = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_one = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_two = models.CharField(max_length=CHAR_MAX, blank=True)
    answer_three = models.CharField(max_length=CHAR_MAX, blank=True)

    # manager
    objects = VaultManager()

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['username', 'initial_password', 'password', 'question_one', 'question_two',
                     'question_three', 'answer_one', 'answer_two', 'answer_three']

    # permissions
    MODEL_ID = '17'
    MODEL_CONTEXT = 'users_password'
    perms = {
        '01': 'read',
        '13': 'change_password',
    }

    # unique field
    UNIQUE = 'username'

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};initial_password:{};password:{};question_one:{};question_two:{};' \
                          'question_three:{};answer_one:{};answer_two:{};answer_three:{};' \
            .format(self.username, self.initial_password, self.password, self.question_one, self.question_two,
                    self.question_three, self.answer_one, self.answer_two, self.answer_three)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["password"])
        return check_password(raw_password, self.password, setter)

    @staticmethod
    def question_answers_fields():
        return {'question_one': 'answer_one',
                'question_two': 'answer_two',
                'question_three': 'answer_three'}


#########
# USERS #
#########

# log manager
class UsersLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_EXCLUDE = ('is_active',)
    GET_MODEL_ORDER = ('username',
                       'first_name',
                       'last_name',
                       'password',
                       'email',
                       'roles',
                       'ldap',
                       'initial_password',)
    GET_MODEL_ORDER_NO_PW = ('username',
                             'first_name',
                             'last_name',
                             'email',
                             'roles',
                             'ldap',
                             'initial_password',)


# log table
class UsersLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    email = models.EmailField(_('Email'), max_length=CHAR_MAX, blank=True)
    first_name = models.CharField(_('First name'), max_length=CHAR_DEFAULT, blank=True)
    last_name = models.CharField(_('Last name'), max_length=CHAR_DEFAULT, blank=True)
    initial_password = models.BooleanField(_('Initial password'))
    ldap = models.BooleanField(_('Ldap'))
    roles = models.CharField(_('Roles'), max_length=CHAR_DEFAULT)
    is_active = models.BooleanField(_('Is_active'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

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
    MODEL_CONTEXT = 'UsersLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class UsersManager(BaseUserManager, GlobalManager):
    # flags
    LOG_TABLE = UsersLog

    # meta
    GET_MODEL_EXCLUDE = ('is_active', 'password')
    GET_MODEL_ORDER = UsersLogManager.GET_MODEL_ORDER
    GET_MODEL_ORDER_NO_PW = UsersLogManager.GET_MODEL_ORDER_NO_PW
    POST_MODEL_EXCLUDE = ('initial_password', 'is_active')

    @property
    def existing_users(self):
        return self.all().values_list('username', flat=True)

    def exist(self, username):
        return self.filter(username=username).exists()

    # superuser function for createsuperuser
    def create_superuser(self, username, password, role, email, initial_password=True):
        # initial status "Effective" to immediately user superuser
        now = timezone.now()
        status_id = Status.objects.productive
        fields = {'username': username,
                  'first_name': username,
                  'last_name': username,
                  'version': 1,
                  'is_active': True,
                  'valid_from': now,
                  'email': email,
                  'status_id': status_id,
                  'ldap': False,
                  'roles': role}
        user = self.model(**fields)
        # set random password for user object because required
        user.set_password(self.make_random_password())
        vault_fields = {
            'username': username,
            'initial_password': initial_password
        }
        vault = Vault(**vault_fields)
        vault.set_password(password)
        vault_fields['password'] = vault.password

        # build string with row id to generate hash for user
        to_hash = generate_to_hash(fields, hash_sequence=user.HASH_SEQUENCE, unique_id=user.id,
                                   lifecycle_id=user.lifecycle_id)
        user.checksum = generate_checksum(to_hash)

        # build string with row id to generate hash for vault
        to_hash = generate_to_hash(vault_fields, hash_sequence=vault.HASH_SEQUENCE, unique_id=vault.id)
        vault.checksum = generate_checksum(to_hash)
        try:
            user.full_clean()
            vault.full_clean()
        except ValidationError as e:
            raise e
        else:
            user.save()
            vault.save()
        # log record
        context = dict()
        context['function'] = 'init'
        fields['initial_password'] = initial_password
        create_log_record(model=self.model, context=context, obj=user,
                          validated_data=fields, action=settings.DEFAULT_LOG_CREATE)
        return user


# table
class Users(AbstractBaseUser, GlobalModel):
    # custom fields
    username = models.CharField(
        _('Username'),
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        max_length=CHAR_DEFAULT,
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii])
    email = models.EmailField(
        _('Email'),
        help_text='Email must be provided in format example@example.com.',
        max_length=CHAR_MAX)
    first_name = models.CharField(
        _('First name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii],
        blank=True)
    last_name = models.CharField(
        _('Last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                    .format(string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii],
        blank=True)
    ldap = models.BooleanField(
        _('LDAP'),
        help_text=_('Specify if user is manually or LDAP manged.'))
    roles = models.CharField(
        _('Roles'),
        help_text='Provide comma separated roles. Roles must exist in status "productive".',
        max_length=CHAR_DEFAULT)
    password = models.CharField(
        _('Password'),
        help_text='{}'.format(password_validators_help_texts()),
        max_length=CHAR_MAX,
        validators=[validate_password]
    )
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};' \
                          'status_id:{};version:{};valid_from:{};valid_to:{};ldap:{};roles:{};'\
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active,
                    self.status_id, self.version, self.valid_from, self.valid_to, self.ldap, self.roles)
        user = self._verify_checksum(to_hash_payload=to_hash_payload)
        if not self.ldap:
            vault = Vault.objects.filter(username=self.username).get()
            user_ext = vault.verify_checksum()
            if user and user_ext:
                return True
        else:
            return user

    @property
    def get_status(self):
        return self.status.status

    def permission(self, value):
        return Roles.objects.find_permission_in_roles(roles=self.roles, permission=value)

    # FO-123: new check to verify is any assigned role is productive and valid
    @property
    def verify_valid_roles(self):
        # determine assigned roles by splitting string
        assigned_roles = self.roles.split(',')
        # parse roles
        for assigned_role in assigned_roles:
            # try to get productive versions of each role
            try:
                productive_roles = Roles.objects.get_by_natural_key_productive(assigned_role)
            # in case no productive roles, do nothing
            except Roles.DoesNotExist:
                pass
            # if productive role exists, parse if any of them is valid
            else:
                for role in productive_roles:
                    if role.verify_validity_range:
                        return True
        # if no assigned roles is prod and valid, return none

    @property
    def verify_sod(self):
        # determine pairs of assigned roles
        combinations = itertools.combinations(self.roles.split(','), 2)
        status_effective_id = Status.objects.productive
        # parse combinations
        for a, b in combinations:
            # look for productive sod records
            query = SoD.objects.filter(Q(base=a, conflict=b, status__id=status_effective_id) |
                                       Q(base=b, conflict=a, status__id=status_effective_id)).all()
            # check if records are valid
            for record in query:
                if record.verify_validity_range:
                    return False
        return True

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
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active',
                     'status_id', 'version', 'valid_from', 'valid_to', 'ldap', 'roles']

    # permissions
    MODEL_ID = '04'
    MODEL_CONTEXT = 'Users'

    def get_full_name(self):
        return _('{} - {} {}').format(self.username, self.first_name, self.last_name)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)

    def check_password(self, raw_password):
        """
        direct password check to vault
        """
        user = Vault.objects.filter(username=self.username).get()
        return user.check_password(raw_password)

    @property
    def initial_password(self):
        if not self.ldap:
            user = Vault.objects.filter(username=self.username).get()
            return user.initial_password
        else:
            return False


########
# SOD #
########

# log manager
class SoDLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('base',
                       'conflict',)


# log table
class SoDLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    base = models.CharField(_('Base'), max_length=CHAR_DEFAULT)
    conflict = models.CharField(_('Conflict'), max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = SoDLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'base:{};conflict:{};status_id:{};version:{};valid_from:{};valid_to:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.base, self.conflict, self.status_id, self.version, self.valid_from, self.valid_to,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['base', 'conflict', 'status_id', 'version', 'valid_from', 'valid_to'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '16'
    MODEL_CONTEXT = 'SoDLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class SoDManager(GlobalManager):
    # flags
    LOG_TABLE = SoDLog

    # meta
    GET_MODEL_ORDER = SoDLogManager.GET_MODEL_ORDER


# table
class SoD(GlobalModel):
    # custom fields
    base = models.CharField(
        verbose_name=_('Base'),
        help_text=_('Select base role.'),
        max_length=CHAR_DEFAULT)
    conflict = models.CharField(
        verbose_name=_('Conflict'),
        help_text=_('Select one conflict role.'),
        max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'base:{};conflict:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.base, self.conflict, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # manager
    objects = SoDManager()

    # hashing
    HASH_SEQUENCE = ['base', 'conflict', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '15'
    MODEL_CONTEXT = 'SoD'

    # unique fields
    UNIQUE = ['base', 'conflict']

    class Meta:
        unique_together = ('lifecycle_id', 'version')
