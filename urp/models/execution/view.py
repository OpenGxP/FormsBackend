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
from basics.models import GlobalManager, CHAR_DEFAULT, GlobalModelLog, CHAR_BIG
from urp.models.execution.sub.bool_fields import ExecutionBoolFields
from urp.models.execution.sub.text_fields import ExecutionTextFields

# variables
FIELDS_GET_MODEL_ORDER = ('number', 'section', 'field', 'tag', 'mandatory', 'data_type',)


class ExecutionActualValuesLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    GET_MODEL_ORDER = FIELDS_GET_MODEL_ORDER + ('value', 'default',)
    GET_MODEL_NOT_RENDER = ('data_type',)

    def meta_get(self, data):
        data['get']['value'] = {'verbose_name': 'Value',
                                'data_type': None,
                                'render': True}
        data['get']['default'] = {'verbose_name': 'Default',
                                  'data_type': None,
                                  'render': True}


# log table
class ExecutionActualValuesLog(GlobalModelLog):
    # rtd data
    number = models.IntegerField(_('Number'))
    # static data
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    instruction = models.CharField(_('Instruction'), max_length=CHAR_BIG, blank=True)
    mandatory = models.BooleanField(_('Mandatory'))
    data_type = models.CharField(_('Data Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    @property
    def get_value(self):
        model = None
        if self.data_type == 'BooleanField':
            model = ExecutionBoolFields
        elif self.data_type == 'CharField':
            model = ExecutionTextFields
        return model.objects.filter(number=self.number, section=self.section, field=self.field) \
            .values('value')[0]['value']

    @property
    def get_default(self):
        model = None
        if self.data_type == 'BooleanField':
            model = ExecutionBoolFields
        elif self.data_type == 'CharField':
            model = ExecutionTextFields
        return model.objects.filter(number=self.number, section=self.section, field=self.field) \
            .values('default')[0]['default']

        # manager
    objects = ExecutionActualValuesLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};section:{};field:{};tag:{};instruction:{};mandatory:{};data_type:{};' \
            .format(self.number, self.section, self.field, self.tag, self.instruction, self.mandatory, self.data_type)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    lifecycle_id = None
    valid_to = None
    valid_from = None

    # permissions
    MODEL_ID = '61'
    MODEL_CONTEXT = 'ExecutionActualValuesLog'

    class Meta:
        managed = False
        db_table = 'urp_executionactualvalueslog'
