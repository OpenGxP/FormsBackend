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
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii


# select field manager
class FormsSelectFieldsManager(FormsFieldsManager):
    pass


# sub table for select fields
class FormsSelectFields(FormsFields):
    options = models.CharField(_('Section'), max_length=CHAR_BIG)
    type =
    elements = LookupField(_('Elements'), max_length=CHAR_BIG, blank=True)

    # integrity check
    def verify_checksum(self):
        to_hash_payload = ''
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # manager
    objects = FormsSelectFieldsManager()

    # hashing
    HASH_SEQUENCE = FORMS_HASH_SEQUENCE + []

    class Meta:
        unique_together = ('lifecycle_id', 'version', 'section', 'field')

    # lookup fields
    LOOKUP = {'type': {'model': ['copy', 'reference'],  # static select
                       'key': None,
                       'multi': False,
                       'method': 'select'},
              'elements': {'model': [],
                           'key': None,
                           'multi': True,
                           'method': 'new'}}
"""
