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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, GlobalModelLog


# log manager
class TagsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('tag',)


# log table
class TagsLog(GlobalModelLog):
    # custom fields
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT)

    # manager
    objects = TagsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'tag:{};'.format(self.tag)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['tag']

    # permissions
    MODEL_ID = '21'
    MODEL_CONTEXT = 'TagsLog'


# manager
class TagsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = TagsLog

    # meta
    GET_MODEL_ORDER = TagsLogManager.GET_MODEL_ORDER


# table
class Tags(GlobalModel):
    # custom fields
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, unique=True)

    # manager
    objects = TagsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'tag:{};'.format(self.tag)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['tag']

    # permissions
    MODEL_ID = '20'
    MODEL_CONTEXT = 'Tags'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
    }

    # unique field
    UNIQUE = 'tag'
