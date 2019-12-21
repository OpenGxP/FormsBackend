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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, FIELD_VERSION, CHAR_BIG
from basics.custom import generate_checksum, generate_to_hash


# inbox manager
class InboxManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True
    NO_PERMISSIONS = True

    # meta
    GET_MODEL_ORDER = ('context',
                       'object',
                       'lifecycle_id',
                       'version',)

    def create(self, data):
        # build comma separated string from users list
        data['users'] = ','.join(data['users'])

        record = self.model(**data)
        # generate hash
        to_hash = generate_to_hash(data, hash_sequence=self.model.HASH_SEQUENCE, unique_id=record.id,
                                   lifecycle_id=record.lifecycle_id)
        record.checksum = generate_checksum(to_hash)
        record.save()

    def delete(self, lifecycle_id, version):
        self.filter(lifecycle_id=lifecycle_id, version=version).delete()


# inbox model
class Inbox(GlobalModel):
    # custom fields
    context = models.CharField(_('Context'), max_length=CHAR_DEFAULT)
    object = models.CharField(_('Object'), max_length=CHAR_DEFAULT)
    version = FIELD_VERSION
    users = models.CharField(max_length=CHAR_BIG)

    # manager
    objects = InboxManager()

    valid_from = None
    valid_to = None

    # hashing
    HASH_SEQUENCE = ['context', 'object', 'version', 'users']

    # permissions
    MODEL_ID = '33'
    MODEL_CONTEXT = 'Inbox'
    perms = None

    # unique field
    UNIQUE = 'object'

    class Meta:
        unique_together = ('context', 'object')

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'context:{};object:{};version:{};users:{};' \
            .format(self.context, self.object, self.version, self.users)
        return self._verify_checksum(to_hash_payload=to_hash_payload)
