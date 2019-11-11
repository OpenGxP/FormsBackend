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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, LOG_HASH_SEQUENCE, FIELD_VERSION, \
    GlobalModelLog
from urp.models.roles import Roles


# log manager
class SoDLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('base',
                       'conflict',)


# log table
class SoDLog(GlobalModelLog):
    # custom fields
    base = models.CharField(_('Base'), max_length=CHAR_DEFAULT)
    conflict = models.CharField(_('Conflict'), max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = SoDLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'base:{};conflict:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.base, self.conflict, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['base', 'conflict', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '16'
    MODEL_CONTEXT = 'SoDLog'

    class Meta:
        unique_together = None


# manager
class SoDManager(GlobalManager):
    # flags
    LOG_TABLE = SoDLog

    # meta
    GET_MODEL_ORDER = SoDLogManager.GET_MODEL_ORDER


# table
class SoD(GlobalModel):
    # custom fields
    base = models.CharField(
        verbose_name=_('Base'),
        help_text=_('Select base role.'),
        max_length=CHAR_DEFAULT)
    conflict = models.CharField(
        verbose_name=_('Conflict'),
        help_text=_('Select one conflict role.'),
        max_length=CHAR_DEFAULT)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'base:{};conflict:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.base, self.conflict, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # manager
    objects = SoDManager()

    # hashing
    HASH_SEQUENCE = ['base', 'conflict', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '15'
    MODEL_CONTEXT = 'SoD'

    # unique fields
    UNIQUE = ['base', 'conflict']

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'base': {'model': Roles,
                       'key': 'role',
                       'multi': False,
                       'method': 'select'},
              'conflict': {'model': Roles,
                           'key': 'role',
                           'multi': False,
                           'method': 'select'}}
