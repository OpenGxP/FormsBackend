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
from passlib.hash import sha256_crypt

# django imports
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

# app imports
from .custom import HASH_ALGORITHM, generate_checksum, generate_to_hash, str_list_change, meta_lookup


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255
CHAR_BIG = 1000

# default fields
FIELD_VERSION = models.IntegerField(_('Version'))

AVAILABLE_STATUS = ['draft', 'circulation', 'productive', 'blocked', 'inactive', 'archived'] + \
                   ['created', 'started', 'canceled', 'complete']
LOG_HASH_SEQUENCE = ['user', 'timestamp', 'action', 'comment', 'way']


class GlobalManager(models.Manager):
    # flags
    HAS_VERSION = True
    HAS_STATUS = True
    LOG_TABLE = None
    IS_LOG = False
    WF_MGMT = False
    COM_SIG_SETTINGS = True
    NO_PERMISSIONS = False
    IS_RT = False

    @staticmethod
    def create_sub_record(obj, validated_data, key, sub_model, new_version=None, instance=None):
        if key in validated_data:
            for record in validated_data[key]:
                record['version'] = validated_data['version']
                if new_version:
                    record['version'] = instance.version + 1
                    # for new version make predecessors a list, because internal value
                    record = str_list_change(data=record, key='predecessors', target=list)
                sub_record = sub_model()
                sub_record_hash_sequence = sub_record.HASH_SEQUENCE
                setattr(sub_record, 'lifecycle_id', obj.lifecycle_id)
                # passed keys
                keys = record.keys()
                # set attributes of validated data
                for attr in sub_record_hash_sequence:
                    if attr in keys:
                        setattr(sub_record, attr, record[attr])
                # for hashing make predecessors comma separated string
                fields = record.copy()
                fields = str_list_change(data=fields, key='predecessors', target=str)
                # generate hash
                to_hash = generate_to_hash(fields=fields, hash_sequence=sub_record_hash_sequence,
                                           unique_id=sub_record.id, lifecycle_id=sub_record.lifecycle_id)
                sub_record.checksum = generate_checksum(to_hash)
                sub_record.full_clean()
                sub_record.save()

    # meta information for get and post
    # get
    GET_BASE_EXCLUDE = ('id', 'checksum')
    GET_MODEL_EXCLUDE = tuple()
    GET_BASE_NOT_RENDER = ('lifecycle_id', 'timestamp', 'valid_from', 'valid_to',)
    GET_MODEL_NOT_RENDER = tuple()
    GET_BASE_ORDER_STATUS_MANAGED = ('valid_from',
                                     'valid_from_local',
                                     'valid_to',
                                     'valid_to_local',
                                     'status',
                                     'version',
                                     'lifecycle_id',)
    GET_BASE_ORDER_SUB = ('version',
                          'lifecycle_id',)
    GET_BASE_ORDER_LOG = ('user',
                          'action',
                          'comment',
                          'timestamp',
                          'timestamp_local',
                          'way',)
    GET_BASE_CALCULATED = ('valid',
                           'unique',)
    GET_MODEL_ORDER = dict()
    # post
    POST_BASE_EXCLUDE = ('id', 'lifecycle_id', 'checksum', 'status', 'version')
    POST_MODEL_EXCLUDE = tuple()

    # comments an electronic signatures
    COMMENT_SIGNATURE = ('com', 'sig_user', 'sig_pw',)

    # generic method to add model specific meta information
    def meta(self, data):
        pass

    def meta_sub(self, data):
        sub_models = self.model.sub_tables()
        for model in sub_models:
            exclude = model.objects.POST_BASE_EXCLUDE + model.objects.POST_MODEL_EXCLUDE
            fields = [i for i in model._meta.get_fields() if i.name not in exclude]
            table_field = sub_models[model].replace('linked_', '')
            data['post'][table_field] = {}
            for f in fields:
                data['post'][table_field][f.name] = {'verbose_name': f.verbose_name,
                                                     'help_text': f.help_text,
                                                     'max_length': f.max_length,
                                                     'data_type': f.get_internal_type(),
                                                     'required': not f.blank,
                                                     'unique': f.unique,
                                                     'lookup': None,
                                                     'editable': True}

                if f.name == model.UNIQUE:
                    data['post'][table_field][f.name]['unique'] = True

                # create lookup data
                meta_lookup(data=data, model=model, f_name=f.name, sub=table_field)

    def meta_field(self, data, f_name):
        pass

    def get_previous_version(self, instance):
        try:
            version = instance.version - 1
            return self.filter(lifecycle_id=instance.lifecycle_id, version=version).get()
        except self.model.DoesNotExist:
            return None

    def get_by_natural_key_productive(self, key, opt_filter=None):
        if not opt_filter:
            opt_filter = {}
        status_effective_id = Status.objects.productive
        query = self.filter(status__id=status_effective_id).filter(**{self.model.UNIQUE: key}).filter(**opt_filter) \
            .all()
        if not query:
            raise self.model.DoesNotExist
        else:
            return query

    def get_by_natural_key_productive_list(self, key):
        status_effective_id = Status.objects.productive
        if self.HAS_STATUS:
            query = self.filter(status__id=status_effective_id).order_by(key).values_list(key, flat=True).distinct()
        else:
            query = self.order_by(key).values_list(key, flat=True).distinct()
        if not query:
            return []
        return query

    def get_by_natural_key_not_draft(self, key):
        status_draft_id = Status.objects.draft
        query = self.filter(~Q(status__id=status_draft_id)).filter(**{self.model.UNIQUE: key}).all()
        if not query:
            raise self.model.DoesNotExist
        return query

    def get_valid_by_key(self, key):
        query = self.filter(**{self.model.UNIQUE: key}).all()
        if not query:
            return
        for record in query:
            if record.verify_validity_range():
                return record
        return

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
    def verify_prod_valid(self, key, opt_filter=None, now=None):
        try:
            query = self.get_by_natural_key_productive(key=key, opt_filter=opt_filter)
        except self.model.DoesNotExist:
            return
        for record in query:
            if record.verify_validity_range(now=now):
                return record

    def prod_val_with_errors(self, key, opt_filter=None, now=None):
        # add filter is passed from outside
        if not opt_filter:
            opt_filter = {}

        # get all records despite of status or validity range
        all_records = self.filter(**{self.model.UNIQUE: key}).filter(**opt_filter).all()
        # if no records at all, return None and error message
        if not all_records:
            return None, settings.ERROR_NO_RECORD

        # if records exist filter them for status productive
        status_effective_id = Status.objects.productive
        prod_records = self.filter(status__id=status_effective_id).filter(**{self.model.UNIQUE: key}) \
            .filter(**opt_filter).all()
        # if no record in status productive exist, return None and error message
        if not prod_records:
            return None, settings.ERROR_NO_RECORD_PROD

        # loop over productive records to identify a valid record
        for item in prod_records:
            if item.verify_validity_range(now=now):
                return item, None
        # if no valid record was found, return None and error message
        return None, settings.ERROR_NO_RECORD_PROD_VALID

    def last_record(self, filter_dict=None, order_str=None):
        if not filter_dict and not order_str:
            return self.last()
        if not filter_dict and order_str:
            return self.order_by(order_str).last()
        if filter_dict and not order_str:
            return self.filter(**filter_dict).last()
        return self.filter(**filter_dict).order_by(order_str).last()

    def get_prod_valid_list(self, opt_filter=None, now=None):
        if not opt_filter:
            opt_filter = {}
        prod_valid_records = []
        status_effective_id = Status.objects.productive
        query = self.filter(status__id=status_effective_id).filter(**opt_filter).all()
        for record in query:
            if record.verify_validity_range(now=now):
                prod_valid_records.append(record)
        return prod_valid_records


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
    NO_UPDATE = ['version']

    @staticmethod
    def sub_tables():
        return {}

    def unique_id(self):
        if not self.UNIQUE:
            return sha256_crypt.using(rounds=1000, salt='salt').hash(str(self.id))
        if self.lifecycle_id and hasattr(self, 'version'):
            return '{}_{}'.format(self.lifecycle_id, getattr(self, 'version'))
        return getattr(self, self.UNIQUE)

    def _verify_checksum(self, to_hash_payload):
        if not self.lifecycle_id:
            to_hash = 'id:{};'.format(self.id)
        else:
            to_hash = 'id:{};lifecycle_id:{};'.format(self.id, self.lifecycle_id)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    def verify_validity_range(self, now=None):
        if not now:
            now = timezone.now()
        if self.valid_from < now:
            if now > self.valid_from and self.valid_to is None:
                return True
            if self.valid_to > now > self.valid_from:
                return True

    def delete_me(self):
        self.delete()

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

    # lookup fields
    LOOKUP = {}


class GlobalModelLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)
    comment = models.CharField(_('Comment'), max_length=CHAR_DEFAULT, blank=True)
    way = models.CharField(_('Way'), max_length=CHAR_DEFAULT)

    def _verify_checksum(self, to_hash_payload):
        if not self.lifecycle_id:
            to_hash = 'id:{};user:{};timestamp:{};action:{};comment:{};way:{};' \
                .format(self.id, self.user, self.timestamp, self.action, self.comment, self.way)
        else:
            to_hash = 'id:{};lifecycle_id:{};user:{};timestamp:{};action:{};comment:{};way:{};' \
                .format(self.id, self.lifecycle_id, self.user, self.timestamp, self.action, self.comment, self.way)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    # permissions
    perms = {
        '01': 'read',
    }

    class Meta:
        abstract = True


##########
# STATUS #
##########

# log manager
class StatusLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True
    NO_PERMISSIONS = True

    # meta
    GET_MODEL_ORDER = ('status',)


# log table
class StatusLog(GlobalModelLog):
    # custom fields
    status = models.CharField(_('Status'), max_length=CHAR_DEFAULT)

    # manager
    objects = StatusLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'status:{};'.format(self.status)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['status']

    # permissions
    MODEL_ID = '07'


# manager
class StatusManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    NO_PERMISSIONS = True
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

    # runtime status
    @property
    def created(self):
        return self.filter(status='created').get().id

    @property
    def started(self):
        return self.filter(status='started').get().id

    @property
    def canceled(self):
        return self.filter(status='canceled').get().id

    @property
    def complete(self):
        return self.filter(status='complete').get().id


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
    # FO-276: added UNIQUE to find unique field
    UNIQUE = 'status'

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
    IS_LOG = True

    # meta
    GET_MODEL_NOT_RENDER = ('log_id',)
    GET_MODEL_ORDER = ('log_id',
                       'context',
                       'user',
                       'action',
                       'timestamp',
                       'timestamp_local',)


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
