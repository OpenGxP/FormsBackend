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
class PermissionsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True
    NO_PERMISSIONS = True

    # meta
    GET_MODEL_ORDER = ('key',
                       'model',
                       'permission',)


# log table
class PermissionsLog(GlobalModelLog):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    model = models.CharField(_('Model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('Permission'), max_length=CHAR_DEFAULT)

    # manager
    objects = PermissionsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};model:{};permission:{};'.format(self.key, self.model, self.permission)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['key', 'model', 'permission']

    # permissions
    MODEL_ID = '08'
    MODEL_CONTEXT = 'PermissionsLog'


# manager
class PermissionsManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True
    LOG_TABLE = PermissionsLog

    # meta
    GET_MODEL_ORDER = PermissionsLogManager.GET_MODEL_ORDER


# table
class Permissions(GlobalModel):
    # custom fields
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT, unique=True)
    model = models.CharField(_('Model'), max_length=CHAR_DEFAULT)
    permission = models.CharField(_('Permission'), max_length=CHAR_DEFAULT)

    # manager
    objects = PermissionsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};model:{};permission:{};'.format(self.key, self.model, self.permission)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'model', 'permission']

    # permissions
    MODEL_ID = '02'
    MODEL_CONTEXT = 'Permissions'
    perms = {
        '01': 'read',
    }

    # unique field
    UNIQUE = 'key'
