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
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, FIELD_VERSION, GlobalModelLog, LOG_HASH_SEQUENCE
from basics.custom import HASH_ALGORITHM
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED
from urp.models.forms.sub.sections import FormsSections


# variables
FIELDS_HASH_SEQUENCE = ['section', 'field', 'instruction', 'mandatory', 'sequence', 'version']
FIELDS_LOG_HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['section', 'field', 'instruction', 'mandatory', 'sequence', 'version']
FIELDS_GET_MODEL_ORDER = ('section', 'field', 'instruction', 'mandatory', 'sequence', 'version',)


# log manager
class FormsFieldsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('section',
                       'field',
                       'instruction',
                       'mandatory',
                       'sequence',
                       'version',)

    GET_MODEL_NOT_RENDER = ('sequence',)


# log table
class FormsFieldsLog(GlobalModelLog):
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT)
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT)
    instruction = models.CharField(_('Instruction'), max_length=CHAR_DEFAULT, blank=True)
    mandatory = models.BooleanField(_('Mandatory'))
    sequence = models.IntegerField(_('Sequence'))  # only for graphic ordering
    version = FIELD_VERSION

    # manager
    objects = FormsFieldsLogManager()

    @property
    def sub_verify_checksum(self):
        return ''

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'section:{};field:{};instruction:{};mandatory:{};sequence:{};version:{};'.\
            format(self.section, self.field, self.instruction, self.mandatory, self.sequence, self.version)
        to_hash_payload += self.sub_verify_checksum
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['section', 'field', 'instruction', 'mandatory', 'sequence', 'version']

    valid_to = None
    valid_from = None

    class Meta:
        abstract = True
        unique_together = None


# manager
class FormsFieldsManager(GlobalManager):
    COM_SIG_SETTINGS = False
    NO_PERMISSIONS = True


# table
class FormsFields(GlobalModel):
    section = models.CharField(_('Section'), max_length=CHAR_DEFAULT,
                               help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                                           .format(SPECIALS_REDUCED)),
                               validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                           validate_only_ascii])
    field = models.CharField(_('Field'), max_length=CHAR_DEFAULT,
                             help_text=_('Special characters "{}" are not permitted. No whitespaces and numbers.'
                                         .format(SPECIALS_REDUCED)),
                             validators=[validate_no_specials_reduced, validate_no_space, validate_no_numbers,
                                         validate_only_ascii])
    instruction = models.CharField(_('Instruction'), max_length=CHAR_DEFAULT, blank=True,
                                   help_text=_('Enter instruction text'))
    mandatory = models.BooleanField(_('Mandatory'), help_text=_('Specify if field is mandatory.'))
    sequence = models.IntegerField(_('Sequence'))  # only for graphic ordering
    version = FIELD_VERSION

    valid_to = None
    valid_from = None

    # permissions
    perms = None

    # unique field
    UNIQUE = 'field'

    # integrity check
    def _verify_checksum(self, to_hash_payload):
        to_hash = 'id:{};lifecycle_id:{};section:{};field:{};instruction:{};mandatory:{};sequence:{};version:{};' \
            .format(self.id, self.lifecycle_id, self.section, self.field, self.instruction, self.mandatory,
                    self.sequence, self.version)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_HASH_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    # manager
    objects = FormsFieldsManager()

    class Meta:
        abstract = True
