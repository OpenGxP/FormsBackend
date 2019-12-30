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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, LOG_HASH_SEQUENCE, FIELD_VERSION, \
    CHAR_BIG, GlobalModelLog
from urp.models.roles import Roles
from urp.fields import LookupField


# log manager
class WorkflowsStepsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('step',
                       'role',
                       'predecessors',
                       'text',
                       'sequence',
                       'version')

    GET_MODEL_NOT_RENDER = ('sequence',)


# log table
class WorkflowsStepsLog(GlobalModelLog):
    step = models.CharField(_('Step'), max_length=CHAR_DEFAULT)
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT)
    predecessors = LookupField(_('Predecessors'), max_length=CHAR_BIG, blank=True)
    text = models.CharField(_('Text'), max_length=CHAR_BIG, blank=True)
    sequence = models.IntegerField(_('Sequence'))
    version = FIELD_VERSION

    # manager
    objects = WorkflowsStepsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'step:{};role:{};predecessors:{};text:{};sequence:{};version:{}'. \
            format(self.step, self.role, self.predecessors, self.text, self.sequence, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['step', 'role', 'predecessors', 'text', 'sequence', 'version']

    # permissions
    MODEL_ID = '34'
    MODEL_CONTEXT = 'WorkflowsStepsLog'

    valid_to = None
    valid_from = None

    class Meta:
        unique_together = None


# manager
class WorkflowsStepsManager(GlobalManager):
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True
    LOG_TABLE = WorkflowsStepsLog


# sub table
class WorkflowsSteps(GlobalModel):
    step = models.CharField(_('Step'), max_length=CHAR_DEFAULT)
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT)
    predecessors = LookupField(_('Predecessors'), max_length=CHAR_BIG, blank=True)
    text = models.CharField(_('Text'), max_length=CHAR_BIG, blank=True)
    sequence = models.IntegerField(_('Sequence'))
    # defaults
    version = FIELD_VERSION

    valid_to = None
    valid_from = None

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'step:{};role:{};predecessors:{};text:{};sequence:{};version:{};'.\
            format(self.step, self.role, self.predecessors, self.text, self.sequence, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = WorkflowsStepsManager()

    # permissions
    perms = None
    MODEL_CONTEXT = 'WorkflowsSteps'

    # unique field
    UNIQUE = 'step'

    # hashing
    HASH_SEQUENCE = ['step', 'role', 'predecessors', 'text', 'sequence', 'version']

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'step')

    # lookup fields
    LOOKUP = {'role': {'model': Roles,
                       'key': 'role',
                       'multi': False,
                       'method': 'select'}}
