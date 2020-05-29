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

# rest imports
from rest_framework import serializers


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


class StepsField(serializers.Field):
    def to_representation(self, value):
        steps = []
        for record in value:
            # FO-250: if no predecessors, return empty array [], not split empty string which is ['']
            if not record.predecessors:
                predecessors = []
            else:
                predecessors = record.predecessors.split(',')
            steps.append({'step': record.step,
                          'role': record.role,
                          # FO-250: use variable from above
                          'predecessors': predecessors,
                          'text': record.text,
                          'sequence': record.sequence})
        return steps

    def to_internal_value(self, data):
        if not isinstance(data, list):
            raise serializers.ValidationError(_('Not a valid array.'))
        for item in data:
            if not isinstance(item, dict):
                raise serializers.ValidationError(_('Value of array not a valid object.'))
        return data


class ExecutionValuesField(serializers.Field):
    def to_representation(self, value):
        values = []
        for record in value:
            if record.default == 'False':
                default = False
            elif record.default == 'True':
                default = True
            else:
                default = record.default
            user, correction = record.user_correction
            values.append({'section': record.section,
                           'field': record.field,
                           'value': record.value,
                           'mandatory': record.mandatory,
                           'instruction': record.instruction,
                           'data_type': record.data_type,
                           'default': default,
                           'user': user,
                           'correction': correction})
        return values

    def to_internal_value(self, data):
        return data


class SectionsField(serializers.Field):
    def to_representation(self, value):
        sections = []
        for record in value:
            # FO-250: if no predecessors, return empty array [], not split empty string which is ['']
            if not record.predecessors:
                predecessors = []
            else:
                predecessors = record.predecessors.split(',')
            sections.append({'section': record.section,
                             'role': record.role,
                             # FO-250: use variable from above
                             'predecessors': predecessors,
                             'confirmation': record.confirmation,
                             'sequence': record.sequence})
        return sections

    def to_internal_value(self, data):
        if not isinstance(data, list):
            raise serializers.ValidationError(_('Not a valid array.'))
        for item in data:
            if not isinstance(item, dict):
                raise serializers.ValidationError(_('Value of array not a valid object.'))
        return data


class FormsFieldBase(serializers.Field):
    @property
    def fields(self):
        return []

    def to_representation(self, value):
        values = []
        for record in value:
            _dict = {'section': record.section,
                     'field': record.field,
                     'instruction': record.instruction,
                     'mandatory': record.mandatory,
                     'sequence': record.sequence}

            for i in self.fields:
                _dict[i] = getattr(record, i)

            values.append(_dict)
        return values

    def to_internal_value(self, data):
        if not isinstance(data, list):
            raise serializers.ValidationError(_('Not a valid array.'))
        for item in data:
            if not isinstance(item, dict):
                raise serializers.ValidationError(_('Value of array not a valid object.'))
        return data


class TextField(FormsFieldBase):
    @property
    def fields(self):
        return ['default']


class BoolField(FormsFieldBase):
    @property
    def fields(self):
        return ['default']
