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

# python imports
import uuid as python_uuid

# django imports
from django.db import models
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX, GlobalModelLog, \
    CHAR_BIG


# log manager
class WebHooksMonitorLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('key',
                       'url',
                       'payload',
                       'status_code',
                       'response')


# log table
class WebHooksMonitorLog(GlobalModelLog):
    # custom fields
    key = models.UUIDField(_('Key'), default=python_uuid.uuid4)
    url = models.CharField(_('Url'), max_length=CHAR_MAX)
    payload = models.CharField(_('Payload'), max_length=CHAR_BIG)
    status_code = models.CharField(_('Status code'), max_length=CHAR_DEFAULT)
    response = models.TextField(_('Response'))

    # manager
    objects = WebHooksMonitorLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};url:{};payload:{};status_code:{};response:{};'. \
            format(self.key, self.url, self.payload, self.status_code, self.response)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['key', 'url', 'payload', 'status_code', 'response']

    # permissions
    MODEL_ID = '53'
    MODEL_CONTEXT = 'WebHooksMonitorLog'


# manager
class WebHooksMonitorManager(GlobalManager):
    # flags
    LOG_TABLE = WebHooksMonitorLog

    # meta
    GET_MODEL_ORDER = WebHooksMonitorLogManager.GET_MODEL_ORDER


# table
class WebHooksMonitor(GlobalModel):
    # custom fields
    key = models.UUIDField(_('key'), default=python_uuid.uuid4)
    url = models.CharField(_('Url'), max_length=CHAR_MAX)
    payload = models.CharField(_('Payload'), max_length=CHAR_BIG)
    status_code = models.CharField(_('Status code'), max_length=CHAR_DEFAULT)
    response = models.TextField(_('Response'))

    # manager
    objects = WebHooksMonitorManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'key:{};url:{};payload:{};status_code:{};response:{};'. \
            format(self.key, self.url, self.payload, self.status_code, self.response)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['key', 'url', 'payload', 'status_code', 'response']

    # permissions
    MODEL_ID = '52'
    MODEL_CONTEXT = 'WebHooksMonitor'
    perms = {
        '01': 'read',
        '20': 'retry',
        '21': 'cancel',
    }

    # unique field
    UNIQUE = 'key'
