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

# django imports
from django.db import models
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, GlobalModelLog, LOG_HASH_SEQUENCE


# log manager
class ExecutionFieldsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('number',
                       'value',
                       'section',
                       'field',)


# log table
class ExecutionFieldsLog(GlobalModelLog):
    # rtd data
    number = models.IntegerField(_('Number'))
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT, blank=True)
    # static data
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionFieldsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};section:{};field:{};value:{};tag:{};'. \
            format(self.number, self.section, self.field, self.value, self.tag)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['number', 'section', 'field', 'value', 'tag']

    lifecycle_id = None
    valid_to = None
    valid_from = None

    # permissions
    MODEL_ID = '61'
    MODEL_CONTEXT = 'ExecutionFieldsLog'

    class Meta:
        unique_together = None


# log manager
class ExecutionFieldsManager(GlobalManager):
    # flags
    LOG_TABLE = ExecutionFieldsLog
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True
    IS_RT = True

    # meta
    GET_MODEL_ORDER = ('number',
                       'section',
                       'field',
                       'value',)


# log table
class ExecutionFields(GlobalModel):
    # rtd data
    number = models.IntegerField(_('Number'))
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT, blank=True)
    # static data
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionFieldsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};section:{};field:{};value:{};tag:{};'. \
            format(self.number, self.section, self.field, self.value, self.tag)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_to = None
    valid_from = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['number', 'section', 'field', 'value', 'tag']

    # permissions
    # FO-215: corrected context to individual string to avoid false mixing for meta view
    MODEL_CONTEXT = 'ExecutionFields'
    perms = None

    class Meta:
        unique_together = ('number', 'section', 'field')

    @property
    def user_correction(self):
        query = ExecutionFieldsLog.objects.filter(number__exact=self.number, field__exact=self.field,
                                                  section__exact=self.section).order_by('-timestamp').all()
        if not query:
            return '', False
        if len(query) > 1:
            return query[0].user, True
        return query[0].user, False
