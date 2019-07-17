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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_BIG
from urp.models.tags import Tags
from urp.models.users import Users
from urp.fields import LookupField


# log manager
class SpacesLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('space',
                       'users',
                       'tags')


# log table
class SpacesLog(GlobalModel):
    # custom fields
    space = models.CharField(_('Space'), max_length=CHAR_DEFAULT)
    users = models.CharField(_('Users'), max_length=CHAR_BIG)
    tags = models.CharField(_('Tags'), max_length=CHAR_BIG)
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = SpacesLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'space:{};users:{};tags:{};user:{};timestamp:{};action:{};' \
            .format(self.space, self.users, self.tags, self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['space', 'users', 'tags'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '23'
    MODEL_CONTEXT = 'SpacesLog'
    perms = {
            '01': 'read',
        }


# manager
class SpacesManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = SpacesLog

    # meta
    GET_MODEL_ORDER = SpacesLogManager.GET_MODEL_ORDER


# table
class Spaces(GlobalModel):
    # custom fields
    space = models.CharField(_('Space'), max_length=CHAR_DEFAULT, unique=True)
    users = LookupField(_('Users'), max_length=CHAR_BIG)
    tags = LookupField(_('Tags'), max_length=CHAR_BIG)

    # manager
    objects = SpacesManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'space:{};users:{};tags:{};'.format(self.space, self.users, self.tags)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['space', 'users', 'tags']

    # permissions
    MODEL_ID = '22'
    MODEL_CONTEXT = 'Spaces'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
    }

    # unique field
    UNIQUE = 'space'

    # lookup fields
    LOOKUP = {'tags': {'model': Tags,
                       'key': 'tag',
                       'multi': True,
                       'method': 'select'},
              'users': {'model': Users,
                        'key': 'username',
                        'multi': True,
                        'method': 'select'}}
