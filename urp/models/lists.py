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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, FIELD_VERSION, CHAR_BIG
from urp.models.tags import Tags
from urp.fields import LookupField
from basics.models import Status


# log manager
class ListsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('list',
                       'type',
                       'tag',
                       'elements')


# log table
class ListsLog(GlobalModel):
    # custom fields
    list = models.CharField(_('List'), max_length=CHAR_DEFAULT)
    type = models.CharField(_('Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT)
    elements = models.CharField(_('Elements'), max_length=CHAR_BIG)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = ListsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'list:{};type:{};tag:{};elements:{};status_id:{};version:{};valid_from:{};valid_to:{};' \
                          'user:{};timestamp:{};action:{};'. \
            format(self.list, self.type, self.tag, self.elements, self.status_id, self.version, self.valid_from,
                   self.valid_to, self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['list', 'type', 'tag', 'elements', 'status_id', 'version', 'valid_from',
                     'valid_to'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '25'
    MODEL_CONTEXT = 'ListsLog'
    perms = {
            '01': 'read',
        }

    class Meta:
        unique_together = None


# manager
class ListsManager(GlobalManager):
    # flags
    LOG_TABLE = ListsLog

    # meta
    GET_MODEL_ORDER = ListsLogManager.GET_MODEL_ORDER


# table
class Lists(GlobalModel):
    # custom fields
    list = models.CharField(_('List'), max_length=CHAR_DEFAULT)
    type = models.CharField(_('Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT)
    elements = LookupField(_('Elements'), max_length=CHAR_BIG)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = ListsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'list:{};type:{};tag:{};elements:{};status_id:{};version:{};valid_from:{};valid_to:{};'.\
            format(self.list, self.type, self.tag, self.elements, self.status_id, self.version, self.valid_from,
                   self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['list', 'type', 'tag', 'elements', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '24'
    MODEL_CONTEXT = 'Lists'

    # unique field
    UNIQUE = 'list'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'},
              'type': {'model': ['copy', 'reference'],  # static select
                       'key': None,
                       'multi': False,
                       'method': 'select'},
              'elements': {'model': [],
                           'key': None,
                           'multi': True,
                           'method': 'new'}}
