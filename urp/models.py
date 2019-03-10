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
    validate_no_numbers, validate_only_ascii
from .custom import create_log_record, create_central_log_record
from basics.custom import generate_checksum, generate_to_hash
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, CHAR_MAX, FIELD_VERSION, Status, LOG_HASH_SEQUENCE


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
    attempt = models.PositiveIntegerField()
    active = models.CharField(_('mode'), max_length=CHAR_DEFAULT)

    # manager
    objects = AccessLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'user:{};timestamp:{};action:{};mode:{};attempt:{};active:{};'\
            .format(self.user, self.timestamp, self.action, self.mode, self.attempt, self.active)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['user', 'timestamp', 'action', 'mode', 'attempt', 'active']

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
    first_name = models.CharField(_('first name'), max_length=CHAR_DEFAULT)
    last_name = models.CharField(_('last name'), max_length=CHAR_DEFAULT)
    initial_password = models.BooleanField(_('initial password'))
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
                          'status_id:{};version:{};valid_from:{};valid_to:{};roles:{};' \
                          'user:{};timestamp:{};action:{};' \
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.status_id, self.version, self.valid_from, self.valid_to, self.roles,
                    self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['username', 'email', 'first_name', 'last_name', 'is_active', 'initial_password',
                     'status_id', 'version', 'valid_from', 'valid_to', 'roles'] + LOG_HASH_SEQUENCE

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

    def get_by_natural_key_productive(self, username):
        status_effective_id = Status.objects.productive
        users = self.filter(status__id=status_effective_id).filter(**{self.model.USERNAME_FIELD: username}).all()
        if not users:
            raise self.model.DoesNotExist
        else:
            return users

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
                    validate_only_ascii])
    last_name = models.CharField(
        _('last name'),
        max_length=CHAR_DEFAULT,
        help_text=_('Required. {} characters or fewer. Special characters "{}" are not permitted. No whitespaces.'
                    .format(CHAR_DEFAULT, string.punctuation)),
        validators=[validate_no_specials,
                    validate_no_space,
                    validate_no_numbers,
                    validate_only_ascii])
    initial_password = models.BooleanField(_('initial password'))
    password = models.CharField(_('password'), max_length=CHAR_MAX)
    roles = models.CharField(_('roles'), max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = UsersManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};first_name:{};last_name:{};is_active:{};initial_password:{};' \
                          'password:{};status_id:{};version:{};valid_from:{};valid_to:{};roles:{};'\
            .format(self.username, self.email, self.first_name, self.last_name, self.is_active, self.initial_password,
                    self.password, self.status_id, self.version, self.valid_from, self.valid_to, self.roles)
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
                     'status_id', 'version', 'valid_from', 'valid_to', 'roles']

    # permissions
    MODEL_ID = '04'
    MODEL_CONTEXT = 'Users'

    def get_full_name(self):
        return _('{} - {} {}').format(self.username, self.first_name, self.last_name)

    def get_short_name(self):
        return _('{} - {} {}').format(self.username)
