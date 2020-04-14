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
from django.conf import settings

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE, FIELD_VERSION, GlobalModelLog, \
    CHAR_BIG
from urp.models.roles import Roles
from urp.fields import LookupField
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED


# log manager
class FormsSectionsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('section',
                       'role',
                       'predecessors',
                       'sequence',
                       'confirmation',)

    GET_MODEL_NOT_RENDER = ('sequence',)


# log table
class FormsSectionsLog(GlobalModelLog):
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT, blank=True)
    predecessors = LookupField(_('Predecessors'), max_length=CHAR_BIG, blank=True)
    sequence = models.IntegerField(_('Sequence'))  # only for graphic ordering
    confirmation = models.CharField(_('Confirmation'), max_length=CHAR_DEFAULT)

    # defaults
    version = FIELD_VERSION

    # manager
    objects = FormsSectionsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'section:{};role:{};predecessors:{};sequence:{};confirmation:{};version:{};'.\
            format(self.section, self.role, self.predecessors, self.sequence, self.confirmation, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['section', 'role', 'predecessors', 'sequence', 'confirmation', 'version']

    # permissions
    MODEL_ID = '31'
    MODEL_CONTEXT = 'FormsSectionsLog'

    valid_to = None
    valid_from = None

    class Meta:
        unique_together = None


# manager
class FormsSectionsManager(GlobalManager):
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True
    LOG_TABLE = FormsSectionsLog


# table
class FormsSections(GlobalModel):
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT,
                               help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                                           .format(SPECIALS_REDUCED)),
                               validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                           validate_only_ascii])
    role = models.CharField(_('Role'), max_length=CHAR_DEFAULT, blank=True, help_text=_('Select role.'))
    predecessors = LookupField(_('Predecessors'), max_length=CHAR_BIG, blank=True,
                               help_text=_('Select predecessor(s).'))
    sequence = models.IntegerField(_('Sequence'))  # only for graphic ordering
    confirmation = models.CharField(_('Confirmation'), max_length=CHAR_DEFAULT,
                                    help_text=_('Select confirmation type.'))

    # defaults
    version = FIELD_VERSION

    # permissions
    perms = None
    MODEL_CONTEXT = 'FormsSections'

    valid_to = None
    valid_from = None

    # unique field
    UNIQUE = 'section'

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'section:{};role:{};predecessors:{};sequence:{};confirmation:{};version:{};'.\
            format(self.section, self.role, self.predecessors, self.sequence, self.confirmation, self.version)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = FormsSectionsManager()

    # hashing
    HASH_SEQUENCE = ['section', 'role', 'predecessors', 'sequence', 'confirmation', 'version']

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'section')

    # lookup fields
    LOOKUP = {'role': {'model': Roles,
                       'key': 'role',
                       'multi': False,
                       'method': 'select'},
              'confirmation': {'model': settings.DEFAULT_LOG_CONFIRMATIONS,
                               'key': None,
                               'multi': False,
                               'method': 'select'}}
