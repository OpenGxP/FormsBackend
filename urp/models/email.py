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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, CHAR_MAX, GlobalModelLog
from urp.validators import validate_only_positive_numbers


# log manager
class EmailLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('host',
                       'port',
                       'username',
                       'use_ssl',
                       'priority',)


# log table
class EmailLog(GlobalModelLog):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT)
    port = models.IntegerField(_('Port'))
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    use_ssl = models.BooleanField(_('SSL'))
    priority = models.IntegerField(_('Priority'))

    # manager
    objects = EmailLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};username:{};use_ssl:{};priority:{};'.format(self.host, self.port,
                                                                                       self.username, self.use_ssl,
                                                                                       self.priority)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['host', 'port', 'username', 'use_ssl', 'priority']

    # permissions
    MODEL_ID = '19'
    MODEL_CONTEXT = 'EmailLog'


class EmailManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = EmailLog

    # meta
    GET_MODEL_ORDER = ('host',
                       'port',
                       'username',
                       'password',
                       'use_ssl',
                       'priority',)
    GET_MODEL_EXCLUDE = ('password', )

    # get configured hosts
    def get_hosts(self):
        return self.all().order_by('priority')


# table
class Email(GlobalModel):
    # custom fields
    host = models.CharField(_('Host'), max_length=CHAR_DEFAULT, unique=True)
    port = models.IntegerField(_('Port'))
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    password = models.CharField(_('Password'), max_length=CHAR_MAX)
    use_ssl = models.BooleanField(_('SSL'))
    priority = models.IntegerField(_('Priority'), validators=[validate_only_positive_numbers], unique=True)

    # manager
    objects = EmailManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'host:{};port:{};username:{};password:{};use_ssl:{};priority:{};'. \
            format(self.host, self.port, self.username, self.password, self.use_ssl, self.priority)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['host', 'port', 'username', 'password', 'use_ssl', 'priority']

    # permissions
    MODEL_ID = '18'
    MODEL_CONTEXT = 'Email'
    perms = {
        '01': 'read',
        '02': 'add',
        '03': 'edit',
        '04': 'delete',
    }

    # unique field
    UNIQUE = 'host'
