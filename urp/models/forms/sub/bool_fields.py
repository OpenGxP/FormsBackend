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
from django.utils.translation import gettext_lazy as _

# app imports
from urp.models.forms.fields import FormsFieldsManager, FormsFields, FIELDS_HASH_SEQUENCE, FormsFieldsLogManager, \
    FormsFieldsLog, FIELDS_GET_MODEL_ORDER, FIELDS_LOG_HASH_SEQUENCE


# log manager
class FormsBoolFieldsLogManager(FormsFieldsLogManager):
    # meta
    GET_MODEL_ORDER = FIELDS_GET_MODEL_ORDER + ('default',)


# log table
class FormsBoolFieldsLog(FormsFieldsLog):
    default = models.BooleanField(_('Default'), blank=True, null=True)

    # integrity check
    @property
    def sub_verify_checksum(self):
        return 'default:{};'.format(self.default)

    # manager
    objects = FormsBoolFieldsLogManager()

    # hashing
    HASH_SEQUENCE = FIELDS_LOG_HASH_SEQUENCE + ['default']

    # permissions
    MODEL_ID = '33'
    MODEL_CONTEXT = 'FormsBoolFieldsLog'

    class Meta:
        unique_together = None


# manager
class FormsBoolFieldsManager(FormsFieldsManager):
    LOG_TABLE = FormsBoolFieldsLog


# table
class FormsBoolFields(FormsFields):
    default = models.BooleanField(_('Default'), blank=True, null=True)

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'default:{};'.format(self.default)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = FormsBoolFieldsManager()

    # permissions
    MODEL_CONTEXT = 'FormsBoolFields'

    # hashing
    HASH_SEQUENCE = FIELDS_HASH_SEQUENCE + ['default']

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'section', 'field')
