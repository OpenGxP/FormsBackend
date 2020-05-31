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
from django.conf import settings

# app imports
from basics.custom import HASH_ALGORITHM
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, GlobalModelLog, LOG_HASH_SEQUENCE, CHAR_BIG


# variables
FIELDS_HASH_SEQUENCE = ['number', 'section', 'field', 'tag', 'instruction', 'mandatory', 'data_type']
FIELDS_LOG_HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['number', 'section', 'field', 'tag', 'instruction', 'mandatory',
                                                'data_type']
FIELDS_GET_MODEL_ORDER = ('number', 'section', 'field', 'tag', 'mandatory', 'data_type',)


# log manager
class ExecutionFieldsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    GET_MODEL_NOT_RENDER = ('data_type',)


# log table
class ExecutionFieldsLog(GlobalModelLog):
    # rtd data
    number = models.IntegerField(_('Number'))
    # static data
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    instruction = models.CharField(_('Instruction'), max_length=CHAR_BIG, blank=True)
    mandatory = models.BooleanField(_('Mandatory'))
    data_type = models.CharField(_('Data Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionFieldsLogManager()

    @property
    def sub_verify_checksum(self):
        return ''

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};section:{};field:{};tag:{};instruction:{};mandatory:{};data_type:{};' \
            .format(self.number, self.section, self.field, self.tag, self.instruction, self.mandatory, self.data_type)
        to_hash_payload += self.sub_verify_checksum
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    lifecycle_id = None
    valid_to = None
    valid_from = None

    class Meta:
        abstract = True
        unique_together = None


# log manager
class ExecutionFieldsManager(GlobalManager):
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True
    IS_RT = True


# log table
class ExecutionFields(GlobalModel):
    # rtd data
    number = models.IntegerField(_('Number'))
    # static data
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    instruction = models.CharField(_('Instruction'), max_length=CHAR_BIG, blank=True)
    mandatory = models.BooleanField(_('Mandatory'))
    data_type = models.CharField(_('Data Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionFieldsManager()

    # integrity check
    def _verify_checksum(self, to_hash_payload):
        to_hash = 'id:{};number:{};section:{};field:{};tag:{};instruction:{};mandatory:{};data_type:{};' \
            .format(self.id, self.number, self.section, self.field, self.tag, self.instruction,
                    self.mandatory, self.data_type)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    valid_to = None
    valid_from = None
    lifecycle_id = None

    # permissions
    # FO-215: corrected context to individual string to avoid false mixing for meta view
    perms = None

    class Meta:
        abstract = True

    def _user_correction(self, model):
        query = model.objects.LOG_TABLE.objects.filter(number__exact=self.number, field__exact=self.field,
                                                       section__exact=self.section).order_by('-timestamp').all()
        if not query:
            return '', False
        if len(query) > 1:
            return query[0].user, True
        return query[0].user, False
