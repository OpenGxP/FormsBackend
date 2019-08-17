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
from urp.models.workflows import Workflows
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii


# log manager
class FormsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('form',
                       'workflow',
                       'tag',)


# log table
class FormsLog(GlobalModel):
    # id field
    lifecycle_id = models.UUIDField()
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT)
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = FormsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'form:{};workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.form, self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to,
                   self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['form', 'workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '29'
    MODEL_CONTEXT = 'FormsLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class FormsManager(GlobalManager):
    # flags
    LOG_TABLE = FormsLog

    # meta
    GET_MODEL_ORDER = ('form',
                       'workflow',
                       'tag')


# table
class Forms(GlobalModel):
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT, validators=[validate_no_specials_reduced,
                                                                            validate_no_space,
                                                                            validate_no_numbers,
                                                                            validate_only_ascii])
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'form:{};workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.form, self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # manager
    objects = FormsManager()

    # hashing
    HASH_SEQUENCE = ['form', 'workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '28'
    MODEL_CONTEXT = 'Forms'

    # unique field
    UNIQUE = 'form'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'},
              'workflow': {'model': Workflows,
                           'key': 'workflow',
                           'multi': False,
                           'method': 'select'}}
