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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT


# manager
class SignaturesLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('user',
                       'timestamp',
                       'timestamp_local',  # because can not use global GET_BASE_ORDER_LOG
                       'context',
                       'object',
                       'object_version',
                       'workflow',
                       'workflow_version',
                       'step',
                       'action',
                       'cycle',)


# table
class SignaturesLog(GlobalModel):
    # custom fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    context = models.CharField(_('Context'), max_length=CHAR_DEFAULT)
    object = models.CharField(_('Object'), max_length=CHAR_DEFAULT)
    object_lifecycle_id = models.UUIDField()
    object_version = models.IntegerField(_('Object version'))
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    workflow_lifecycle_id = models.UUIDField()
    workflow_version = models.IntegerField(_('Workflow version'))
    step = models.CharField(_('Step'), max_length=CHAR_DEFAULT)
    sequence = models.CharField(_('Sequence'), max_length=CHAR_DEFAULT)
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)
    cycle = models.IntegerField(_('Cycle'))

    # manager
    objects = SignaturesLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'user:{};timestamp:{};context:{};object:{};object_lifecycle_id:{};object_version:{};' \
                          'workflow:{};workflow_lifecycle_id:{};workflow_version:{};step:{};sequence:{};action:{};' \
                          'cycle:{};' \
            .format(self.user, self.timestamp, self.context, self.object, self.object_lifecycle_id, self.object_version,
                    self.workflow, self.workflow_lifecycle_id, self.workflow_version, self.step, self.sequence,
                    self.action, self.cycle)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None

    # hashing
    HASH_SEQUENCE = ['user', 'timestamp', 'context', 'object', 'object_lifecycle_id', 'object_version',
                     'workflow', 'workflow_lifecycle_id', 'workflow_version', 'step', 'sequence', 'action', 'cycle']

    # permissions
    MODEL_ID = '30'
    MODEL_CONTEXT = 'SignaturesLog'
    perms = {
        '01': 'read',
    }
