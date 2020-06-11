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
from basics.models import GlobalModelLog, GlobalManager, LOG_HASH_SEQUENCE, CHAR_DEFAULT


# manager
class ExecutionSectionsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('number',
                       'section',
                       'tag',)


# table
class ExecutionSectionsLog(GlobalModelLog):
    # custom fields
    number = models.BigIntegerField(_('Number'))
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)

    # manager
    objects = ExecutionSectionsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'number:{};section:{};tag:{};'.format(self.number, self.section, self.tag)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['number', 'section', 'tag']

    # permissions
    MODEL_ID = '62'
    MODEL_CONTEXT = 'ExecutionSectionsLog'

    class Meta:
        unique_together = None
