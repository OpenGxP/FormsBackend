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
from basics.models import CHAR_DEFAULT
from urp.models.forms.fields import FormsFieldsManager, FormsFields, FIELDS_HASH_SEQUENCE, FormsFieldsLogManager, \
    FormsFieldsLog, FIELDS_GET_MODEL_ORDER, FIELDS_LOG_HASH_SEQUENCE


# log manager
class FormsTextFieldsLogManager(FormsFieldsLogManager):
    # meta
    GET_MODEL_ORDER = FIELDS_GET_MODEL_ORDER + ('default',)


# log table
class FormsTextFieldsLog(FormsFieldsLog):
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT, blank=True, help_text=_('Enter default value.'))

    # integrity check
    @property
    def sub_verify_checksum(self):
        return 'default:{};'.format(self.default)

    # manager
    objects = FormsTextFieldsLogManager()

    # hashing
    HASH_SEQUENCE = FIELDS_LOG_HASH_SEQUENCE + ['default']

    # permissions
    MODEL_ID = '32'
    MODEL_CONTEXT = 'FormsTextFieldsLog'

    class Meta:
        unique_together = None


# manager
class FormsTextFieldsManager(FormsFieldsManager):
    LOG_TABLE = FormsTextFieldsLog


# table
class FormsTextFields(FormsFields):
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT, blank=True)

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'default:{};'.format(self.default)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = FormsTextFieldsManager()

    # permissions
    MODEL_CONTEXT = 'FormsTextFields'

    # hashing
    HASH_SEQUENCE = FIELDS_HASH_SEQUENCE + ['default']

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'section', 'field')
