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
    GET_BASE_ORDER_STATUS_MANAGED = {'valid_from': 76,
                                     'valid_to': 77,
                                     'status': 78,
                                     'version': 79,
                                     'lifecycle_id': 8000}
    GET_BASE_ORDER_LOG = {'user': 97,
                          'action': 98,
                          'timestamp': 99}
    GET_MODEL_ORDER = dict()
    # post
    POST_BASE_EXCLUDE = ('id', 'lifecycle_id', 'checksum', 'status', 'version')
    POST_MODEL_EXCLUDE = tuple()

    def validate_unique(self, instance):
        model_unique = self.model.UNIQUE
        unique = getattr(instance, self.model.UNIQUE)
        _filter = {model_unique: unique}
        try:
            query = self.filter(**_filter).filter(~Q(lifecycle_id=getattr(instance, 'lifecycle_id'))).\
                filter(Q(status=Status.objects.circulation) | Q(status=Status.objects.productive)).all()
            for item in query:
                return (_('{} "{}" does already exist in status "{}" and version "{}".'.format(
                    model_unique.capitalize(), unique, item.status.status, item.version)))
        except self.model.DoesNotExist:
            return None

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
    GET_MODEL_ORDER = {'status': 0}


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
    GET_MODEL_ORDER = {'log_id': 0,
                       'context': 1}


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
