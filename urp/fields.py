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
from django.core.exceptions import ValidationError


class LookupField(models.Field):
    description = 'CharField that accepts arrays and transform them to comma separated string.'

    def get_internal_type(self):
        return 'CharField'

    def to_python(self, value):
        if not isinstance(value, list):
            raise ValidationError(_('Not a valid array.'))
        if not value:
            raise ValidationError(_('This field is required.'))
        string_value = ''
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(_('Value of array not a valid string.'))
            string_value += '{},'.format(item)
        return string_value[:-1]
