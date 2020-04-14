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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, FIELD_VERSION, CHAR_BIG, \
    GlobalModelLog
from urp.models.tags import Tags
from urp.fields import LookupField
from basics.models import Status
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED


# log manager
class ListsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('list',
                       'type',
                       'tag',
                       'elements')


# log table
class ListsLog(GlobalModelLog):
    # custom fields
    list = models.CharField(_('List'), max_length=CHAR_DEFAULT)
    type = models.CharField(_('Type'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    elements = models.CharField(_('Elements'), max_length=CHAR_BIG)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # manager
    objects = ListsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'list:{};type:{};tag:{};elements:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.list, self.type, self.tag, self.elements, self.status_id, self.version, self.valid_from,
                   self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['list', 'type', 'tag', 'elements', 'status_id', 'version', 'valid_from',
                                         'valid_to']

    # permissions
    MODEL_ID = '25'
    MODEL_CONTEXT = 'ListsLog'

    class Meta:
        unique_together = None


# manager
class ListsManager(GlobalManager):
    # flags
    LOG_TABLE = ListsLog

    # meta
    GET_MODEL_ORDER = ListsLogManager.GET_MODEL_ORDER


# table
class Lists(GlobalModel):
    # custom fields
    list = models.CharField(_('List'), max_length=CHAR_DEFAULT, help_text=_('Special characters "{}" are not '
                                                                            'permitted. No whitespaces and numbers.'
                                                                            .format(SPECIALS_REDUCED)),
                            validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                        validate_only_ascii])
    type = models.CharField(_('Type'), max_length=CHAR_DEFAULT, help_text=_('Select type.'))
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True, help_text=_('Select tag.'))
    elements = LookupField(_('Elements'), max_length=CHAR_BIG, help_text=_('Provide elements of this list.'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # manager
    objects = ListsManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'list:{};type:{};tag:{};elements:{};status_id:{};version:{};valid_from:{};valid_to:{};'.\
            format(self.list, self.type, self.tag, self.elements, self.status_id, self.version, self.valid_from,
                   self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = ['list', 'type', 'tag', 'elements', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '24'
    MODEL_CONTEXT = 'Lists'

    # unique field
    UNIQUE = 'list'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'},
              'type': {'model': ['copy', 'reference'],  # static select
                       'key': None,
                       'multi': False,
                       'method': 'select'},
              'elements': {'model': [],
                           'key': None,
                           'multi': True,
                           'method': 'new'}}
