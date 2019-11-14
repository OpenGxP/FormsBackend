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
from django.conf import settings
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT


# manager
class AccessLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('user',
                       'action',
                       'timestamp',
                       'timestamp_local',
                       'mode',
                       'method',
                       'attempt',
                       'active',)

    def latest_record(self, username):
        try:
            return self.filter(user=username).filter(Q(action=settings.DEFAULT_LOG_ATTEMPT) |
                                                     Q(action=settings.DEFAULT_LOG_LOGIN) |
                                                     Q(action=settings.DEFAULT_LOG_SIGNATURE) |
                                                     Q(action=settings.DEFAULT_LOG_PASSWORD)).order_by('-timestamp')[0]
        except IndexError:
            return None


# table
class AccessLog(GlobalModel):
    # custom fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)
    mode = models.CharField(_('Mode'), max_length=CHAR_DEFAULT)
    method = models.CharField(_('Method'), max_length=CHAR_DEFAULT)
    attempt = models.CharField(_('Attempt'), max_length=CHAR_DEFAULT)
    active = models.CharField(_('Active'), max_length=CHAR_DEFAULT)

    # manager
    objects = AccessLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'user:{};timestamp:{};action:{};mode:{};method:{};attempt:{};active:{};' \
            .format(self.user, self.timestamp, self.action, self.mode, self.method, self.attempt, self.active)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['user', 'timestamp', 'action', 'mode', 'method', 'attempt', 'active']

    # permissions
    MODEL_ID = '05'
    MODEL_CONTEXT = 'AccessLog'
    perms = {
        '01': 'read',
    }
