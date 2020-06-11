"""
opengxp.org
Copyright (C) 2020  Henrik Baran

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
from rest_framework import serializers

# python imports
from itertools import chain

# django imports
from django.db import models
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, GlobalModelLog, LOG_HASH_SEQUENCE
from urp.models.forms.forms import Forms
from urp.models.execution.sub.text_fields import ExecutionTextFields
from urp.models.execution.sub.bool_fields import ExecutionBoolFields
from urp.models.forms.sub.sections import FormsSections
from urp.validators import validate_last_execution_value


# log manager
class ExecutionLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('number',
                       'form',
                       'tag',
                       'lifecycle_id',
                       'version',)
    # FO-215: removed version from not render to indicate what form object + version the execution object is inherited
    GET_MODEL_NOT_RENDER = ('tag',)


# log table
class ExecutionLog(GlobalModelLog):
    # runtime fields
    number = models.IntegerField(_('Number'))
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    # FO-215: changed version verbose name to indicate version belongs to form, not execution object
    version = models.IntegerField(_('Form version'))

    lifecycle_id = models.UUIDField()
    valid_from = None
    valid_to = None

    # manager
    objects = ExecutionLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};form:{};tag:{};status_id:{};version:{};'. \
            format(self.number, self.form, self.tag, self.status_id, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['number', 'form', 'tag', 'status_id', 'version']

    # permissions
    MODEL_ID = '41'
    MODEL_CONTEXT = 'ExecutionLog'


# manager
class ExecutionManager(GlobalManager):
    # flags
    LOG_TABLE = ExecutionLog
    HAS_VERSION = False
    IS_RT = True

    # meta
    GET_MODEL_ORDER = ('number',
                       'form',
                       'tag',
                       'lifecycle_id',
                       'version',)

    # FO-215: removed version from not render to indicate what form object + version the execution object is inherited
    GET_MODEL_NOT_RENDER = ('tag',)
    POST_MODEL_EXCLUDE = ('number',
                          'tag',)

    @property
    def next_number(self):
        latest = ExecutionLog.objects.all().aggregate(models.Max('number'))['number__max']
        if latest:
            return latest + 1
        return 1


# table
class Execution(GlobalModel):
    # runtime fields
    number = models.IntegerField(_('Number'), unique=True)
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT, help_text=_('Select form.'))
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    # FO-215: changed version verbose name to indicate version belongs to form, not execution object
    version = models.IntegerField(_('Form version'))

    lifecycle_id = models.UUIDField()
    valid_from = None
    valid_to = None

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};form:{};tag:{};status_id:{};version:{};'. \
            format(self.number, self.form, self.tag, self.status_id, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = ExecutionManager()

    # hashing
    HASH_SEQUENCE = ['number', 'form', 'tag', 'status_id', 'version']

    # permissions
    MODEL_ID = '40'
    MODEL_CONTEXT = 'Execution'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
        '05': 'start',
        '06': 'cancel',
        '07': 'complete',
        '08': 'correct'
    }

    # unique field
    UNIQUE = 'number'

    # lookup fields
    LOOKUP = {'form': {'model': Forms,
                       'key': 'form',
                       'multi': False,
                       'method': 'select'}}

    @property
    def get_status(self):
        return self.status.status

    @property
    def linked_fields_values(self):
        return list(chain(ExecutionTextFields.objects.filter(number__exact=self.number).all(),
                          ExecutionBoolFields.objects.filter(number__exact=self.number).all()))

    @property
    def actual_values(self):
        return list(chain(ExecutionTextFields.objects.filter(number=self.number).values('value'),
                          ExecutionBoolFields.objects.filter(number=self.number).values('value')))

    @property
    def linked_sections(self):
        return FormsSections.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    @staticmethod
    def last_value(number, section):
        actual_values = list(chain(ExecutionTextFields.objects.filter(number=number, section=section).values('value'),
                                   ExecutionBoolFields.objects.filter(number=number, section=section).values('value')))
        try:
            validate_last_execution_value(actual_values)
        except serializers.ValidationError:
            return False
        return True

    def delete_me(self):
        self.delete()

    # FO-214: changed unique id of execution object to number
    def unique_id(self):
        return self.number
