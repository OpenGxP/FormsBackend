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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, LOG_HASH_SEQUENCE, FIELD_VERSION, CHAR_BIG
from urp.models.tags import Tags
from urp.models.roles import Roles
from urp.fields import LookupField
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii


# log manager
class WorkflowsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('workflow',
                       'tag',
                       'step',
                       'role',
                       'predecessors',
                       'text',
                       'sequence')


# log table
class WorkflowsLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # step fields
    step = models.CharField(_('Step'), max_length=CHAR_DEFAULT)
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT)
    # FO-187: changed log field to char field because lookup field to python was already called on main object
    predecessors = models.CharField(_('Predecessors'), max_length=CHAR_BIG, blank=True)
    text = models.CharField(_('Text'), max_length=CHAR_BIG, blank=True)
    sequence = models.IntegerField(_('Sequence'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = WorkflowsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'workflow:{};tag:{};step:{};role:{};predecessors:{};text:{};sequence:{};' \
                          'status_id:{};version:{};valid_from:{};valid_to:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.workflow, self.tag, self.step, self.role, self.predecessors, self.text, self.sequence,
                   self.status_id, self.version, self.valid_from, self.valid_to,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['workflow', 'tag', 'step', 'role', 'predecessors', 'text', 'sequence', 'status_id', 'version',
                     'valid_from', 'valid_to'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '27'
    MODEL_CONTEXT = 'WorkflowsLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class WorkflowsManager(GlobalManager):
    # flags
    LOG_TABLE = WorkflowsLog

    # meta
    GET_MODEL_ORDER = ('workflow',
                       'tag')


# table
class Workflows(GlobalModel):
    # custom fields
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT, help_text=_('tbd'),
                                validators=[validate_no_specials_reduced,
                                            validate_no_space,
                                            validate_no_numbers,
                                            validate_only_ascii])
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    @property
    def linked_steps(self):
        return WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    # manager
    objects = WorkflowsManager()

    # hashing
    HASH_SEQUENCE = ['workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '26'
    MODEL_CONTEXT = 'Workflows'

    # unique field
    UNIQUE = 'workflow'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'}}


# manager
class WorkflowsStepsManager(GlobalManager):
    pass


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

    # hashing
    HASH_SEQUENCE = ['step', 'role', 'predecessors', 'text', 'sequence', 'version']

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'step')

    # lookup fields
    LOOKUP = {'role': {'model': Roles,
                       'key': 'role',
                       'multi': False,
                       'method': 'select'}}
