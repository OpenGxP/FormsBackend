"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from urp.crypto import decrypt
from urp.models.users import Users
from basics.models import GlobalModel, GlobalManager, CHAR_MAX, LOG_HASH_SEQUENCE, GlobalModelLog, CHAR_DEFAULT


# log manager
class SecurityKeysLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('username',
                       'security_key')


# log table
class SecurityKeysLog(GlobalModelLog):
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT, help_text=_('Select username.'))
    security_key = models.CharField(_('Security Key'), max_length=CHAR_MAX)

    # manager
    objects = SecurityKeysLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};security_key:{};'.format(self.username, self.security_key)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    @property
    def get_security_keys(self):
        return decrypt(self.security_key)

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['username', 'security_key']

    # permissions
    MODEL_ID = '56'
    MODEL_CONTEXT = 'SecurityKeysLog'


# manager
class SecurityKeysManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = SecurityKeysLog

    # meta
    GET_MODEL_ORDER = SecurityKeysLogManager.GET_MODEL_ORDER
    POST_MODEL_EXCLUDE = ('security_key',)


# table
class SecurityKeys(GlobalModel):
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT, help_text=_('Select username.'))
    security_key = models.CharField(_('Security Key'), max_length=CHAR_MAX, unique=True)

    # manager
    objects = SecurityKeysManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};security_key:{};'.format(self.username, self.security_key)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    @property
    def get_security_keys(self):
        return decrypt(self.security_key)

    # hashing
    HASH_SEQUENCE = ['username', 'security_key']

    # permissions
    MODEL_ID = '55'
    MODEL_CONTEXT = 'SecurityKeys'
    perms = {
        '01': 'read',
        '02': 'add',
        '04': 'delete',
    }

    # unique field
    UNIQUE = 'security_key'

    # lookup fields
    LOOKUP = {'username': {'model': Users,
                           'key': 'username',
                           'multi': False,
                           'method': 'select'}}
