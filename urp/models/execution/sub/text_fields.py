"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import CHAR_DEFAULT
from urp.models.execution.fields import ExecutionFields, ExecutionFieldsManager, ExecutionFieldsLog, \
    ExecutionFieldsLogManager, FIELDS_HASH_SEQUENCE, FIELDS_GET_MODEL_ORDER, FIELDS_LOG_HASH_SEQUENCE


# log manager
class ExecutionTextFieldsLogManager(ExecutionFieldsLogManager):
    # meta
    GET_MODEL_ORDER = FIELDS_GET_MODEL_ORDER + ('default', 'value',)


# log table
class ExecutionTextFieldsLog(ExecutionFieldsLog):
    # rtd data
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT, blank=True)
    # static data
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionTextFieldsLogManager()

    # integrity check
    @property
    def sub_verify_checksum(self):
        return 'value:{};default:{};'.format(self.value, self.default)

    # hashing
    HASH_SEQUENCE = FIELDS_LOG_HASH_SEQUENCE + ['value', 'default']

    # permissions
    MODEL_ID = '61'
    MODEL_CONTEXT = 'ExecutionTextFieldsLog'

    class Meta:
        unique_together = None


# log manager
class ExecutionTextFieldsManager(ExecutionFieldsManager):
    # flags
    LOG_TABLE = ExecutionTextFieldsLog


# log table
class ExecutionTextFields(ExecutionFields):
    # rtd data
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT, blank=True)
    # static data
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionTextFieldsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'value:{};default:{};'.format(self.value, self.default)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # hashing
    HASH_SEQUENCE = FIELDS_HASH_SEQUENCE + ['value', 'default']

    # permissions
    MODEL_CONTEXT = 'ExecutionTextFields'

    class Meta:
        unique_together = ('number', 'section', 'field')
