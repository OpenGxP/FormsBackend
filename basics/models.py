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


# python imports
import uuid as python_uuid

# django imports
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

# app imports
from .custom import HASH_ALGORITHM


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255
CHAR_BIG = 1000

# default fields
FIELD_VERSION = models.IntegerField(_('Version'))

AVAILABLE_STATUS = ['draft', 'circulation', 'productive', 'blocked', 'inactive', 'archived']
LOG_HASH_SEQUENCE = ['user', 'timestamp', 'action']


class GlobalManager(models.Manager):
    # flags
    HAS_VERSION = True
    HAS_STATUS = True
    LOG_TABLE = None

    # meta information for get and post
    # get
    GET_BASE_EXCLUDE = ('id', 'checksum')
    GET_MODEL_EXCLUDE = tuple()
    GET_BASE_NOT_RENDER = ('lifecycle_id', )
    GET_MODEL_NOT_RENDER = tuple()
    GET_BASE_ORDER_STATUS_MANAGED = ('valid_from',
                                     'valid_to',
                                     'status',
                                     'version',
                                     'lifecycle_id',)
    GET_BASE_ORDER_LOG = ('user',
                          'action',
                          'timestamp',)
    GET_BASE_CALCULATED = ('valid',
                           'unique',)
    GET_MODEL_ORDER = dict()
    # post
    POST_BASE_EXCLUDE = ('id', 'lifecycle_id', 'checksum', 'status', 'version')
    POST_MODEL_EXCLUDE = tuple()

    def get_previous_version(self, instance):
        try:
            version = instance.version - 1
            return self.filter(lifecycle_id=instance.lifecycle_id, version=version).get()
        except self.model.DoesNotExist:
            return None

    def get_by_natural_key_productive(self, key):
        status_effective_id = Status.objects.productive
        query = self.filter(status__id=status_effective_id).filter(**{self.model.UNIQUE: key}).all()
        if not query:
            raise self.model.DoesNotExist
        else:
            return query

    def get_circulation_user_for_sod(self, instance):
        status_circulation_id = Status.objects.circulation
        try:
            # FO-122: order log record by timestamp and take last record
            query = self.filter(action='status', status=status_circulation_id, version=instance.version,
                                lifecycle_id=instance.lifecycle_id).order_by('-timestamp').all()[0]
            return query.user
        except self.model.DoesNotExist:
            return None

    # FO-121: new method to determine status and validity at the same time
    def verify_prod_valid(self, key):
        try:
            query = self.get_by_natural_key_productive(key=key)
        except self.model.DoesNotExist:
            return
        for record in query:
            if record.verify_validity_range:
                return True

    def last_record(self, filter_dict=None, order_str=None):
        if not filter_dict and not order_str:
            return self.last()
        if not filter_dict and order_str:
            return self.order_by(order_str).last()
        if filter_dict and not order_str:
            return self.filter(**filter_dict).last()
        return self.filter(**filter_dict).order_by(order_str).last()


class GlobalModel(models.Model):
    # id
    id = models.UUIDField(primary_key=True, default=python_uuid.uuid4)
    lifecycle_id = models.UUIDField(default=python_uuid.uuid4)
    checksum = models.CharField(_('checksum'), max_length=CHAR_MAX)
    valid_from = models.DateTimeField(
        _('Valid from'),
        help_text='Provide valid from in format yyyy-mm-dd hh:mm:ss',
        blank=True,
        null=True)
    valid_to = models.DateTimeField(
        _('Valid to'),
        help_text='Provide valid to in format yyyy-mm-dd hh:mm:ss',
        blank=True,
        null=True)

    class Meta:
        abstract = True

    HASH_SEQUENCE = []
    UNIQUE = None

    def unique_id(self):
        if self.lifecycle_id:
            return '{}_{}'.format(self.lifecycle_id, self.version)
        else:
            if self.UNIQUE:
                return getattr(self, self.UNIQUE)
        return

    def _verify_checksum(self, to_hash_payload):
        if not self.lifecycle_id:
            to_hash = 'id:{};'.format(self.id)
        else:
            to_hash = 'id:{};lifecycle_id:{};'.format(self.id, self.lifecycle_id)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_HASH_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    @property
    def verify_validity_range(self):
        now = timezone.now()
        if self.valid_from < now:
            if now > self.valid_from and self.valid_to is None:
                return True
            if self.valid_to > now > self.valid_from:
                return True

    # default permissions for every status and version managed dialog
    MODEL_ID = None
    MODEL_CONTEXT = None
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
        '05': 'circulation',
        '06': 'reject',
        '07': 'productive',
        '08': 'block',
        '09': 'archive',
        '10': 'inactivate',
        '11': 'version',
        '12': 'version_archived'
    }


##########
# STATUS #
##########

# log manager
class StatusLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('status',)


# log table
class StatusLog(GlobalModel):
    # custom fields
    status = models.CharField(_('Status'), max_length=CHAR_DEFAULT)
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = StatusLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'status:{};user:{};timestamp:{};action:{};' \
            .format(self.status, self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['status'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '07'
    perms = {
            '01': 'read',
        }


# manager
class StatusManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = StatusLog

    # meta
    GET_MODEL_ORDER = StatusLogManager.GET_MODEL_ORDER

    def status_by_text(self, value):
        try:
            if self.filter(status=value).exists():
                return self.filter(status=value).get().id
            else:
                return False
        except IndexError:
            return False

    @property
    def draft(self):
        return self.filter(status='draft').get().id

    @property
    def circulation(self):
        return self.filter(status='circulation').get().id

    @property
    def productive(self):
        return self.filter(status='productive').get().id

    @property
    def blocked(self):
        return self.filter(status='blocked').get().id

    @property
    def inactive(self):
        return self.filter(status='inactive').get().id

    @property
    def archived(self):
        return self.filter(status='archived').get().id


# table
class Status(GlobalModel):
    # custom fields
    status = models.CharField(_('Status'), max_length=CHAR_DEFAULT, unique=True)

    # manager
    objects = StatusManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'status:{};'.format(self.status)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['status']

    # permissions
    MODEL_ID = '01'
    MODEL_CONTEXT = 'Status'
    perms = {
        '01': 'read',
    }


##############
# CENTRALLOG #
##############

# manager
class CentralLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_NOT_RENDER = ('log_id',)
    GET_MODEL_ORDER = ('log_id',
                       'context',)


# table
class CentralLog(GlobalModel):
    # custom fields
    log_id = models.UUIDField(_('LogID'))
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)
    context = models.CharField(_('Context'), max_length=CHAR_DEFAULT)

    # manager
    objects = CentralLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'log_id:{};user:{};timestamp:{};action:{};context:{};'\
            .format(self.log_id, self.user, self.timestamp, self.action, self.context)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['log_id', 'user', 'timestamp', 'action', 'context']

    # permissions
    MODEL_ID = '06'
    MODEL_CONTEXT = 'CentralLog'
    perms = {
        '01': 'read',
    }


############
# SETTINGS #
############

# log manager
class SettingsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('key',
                       'default',
                       'value',)


# log table
class SettingsLog(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = SettingsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};default:{};value:{};user:{};timestamp:{};action:{};' \
            .format(self.key, self.default, self.value, self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'default', 'value'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '14'
    MODEL_CONTEXT = 'SettingsLog'
    perms = {
            '01': 'read',
        }


# manager
class SettingsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = SettingsLog

    # meta
    GET_MODEL_ORDER = SettingsLogManager.GET_MODEL_ORDER
    POST_MODEL_EXCLUDE = ('key', 'default')

    @property
    def auth_maxloginattempts(self):
        try:
            return int(self.filter(key='auth.max_login_attempts').get().value)
        except self.model.DoesNotExist:
            return settings.MAX_LOGIN_ATTEMPTS

    @property
    def core_devalue(self):
        try:
            return self.filter(key='core.devalue').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_SYSTEM_DEVALUE

    @property
    def core_system_username(self):
        try:
            return self.filter(key='core.system_username').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_SYSTEM_USER

    @property
    def core_timestamp_format(self):
        try:
            return self.filter(key='core.timestamp_format').get().value
        except self.model.DoesNotExist:
            return settings.DEFAULT_FRONT_TIMESTAMP

    @property
    def core_auto_logout(self):
        try:
            return int(self.filter(key='core.auto_logout').get().value)
        except self.model.DoesNotExist:
            return settings.DEFAULT_AUTO_LOGOUT


# table
class Settings(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT, unique=True)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)

    # manager
    objects = SettingsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};default:{};value:{};'.format(self.key, self.default, self.value)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'default', 'value']

    # permissions
    MODEL_ID = '13'
    MODEL_CONTEXT = 'Settings'
    perms = {
        '01': 'read',
        '03': 'edit',
    }

    UNIQUE = 'key'
