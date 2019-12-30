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

# rest imports
from rest_framework import serializers

# django imports
from django.conf import settings

# app imports
from basics.models import CHAR_DEFAULT
from urp.models.forms.forms import Forms, FormsLog
from urp.models.tags import Tags
from urp.fields import SectionsField, TextField, BoolField
from urp.models.workflows.workflows import Workflows
from urp.models.roles import Roles
from urp.serializers import GlobalReadWriteSerializer


FORM_FIELDS = ('sections', 'fields_text', 'fields_bool', )


# read / add / edit
class FormsReadWriteSerializer(GlobalReadWriteSerializer):
    sections = SectionsField(source='linked_sections')
    fields_text = TextField(source='linked_fields_text')
    fields_bool = BoolField(source='linked_fields_bool')

    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + FORM_FIELDS + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def validate_tag(self, value):
        if value:
            allowed = Tags.objects.get_by_natural_key_productive_list('tag')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_workflow(self, value):
        if value:
            allowed = Workflows.objects.get_by_natural_key_productive_list('workflow')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_sections(self, value):
        value = self.validate_sub(value, key='section', sequence=True, predecessors=True, parent=True)
        allowed_roles = Roles.objects.get_by_natural_key_productive_list('role')

        for item in value:
            # validate role field
            if 'role' not in item.keys():
                raise serializers.ValidationError('Role ist required.')
            if not isinstance(item['role'], str):
                raise serializers.ValidationError('Role field must be string.')
            if item['role'] not in allowed_roles:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item['role']))

            # validate confirmation field
            if 'confirmation' not in item.keys():
                raise serializers.ValidationError('Confirmation ist required.')
            if item['confirmation'] not in settings.DEFAULT_LOG_CONFIRMATIONS:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item['confirmation']))

        return value

    def validate_fields_text(self, value):
        value = self.validate_sub(value, key='field', sequence=True)
        value = self.validated_form_fields(value)

        for item in value:
            # validate default field
            if 'default' in item.keys():
                if not isinstance(item['default'], str):
                    raise serializers.ValidationError('Default field must be string.')
                if len(item['default']) > CHAR_DEFAULT:
                    raise serializers.ValidationError('Instruction must not be longer than {} characters.'
                                                      .format(CHAR_DEFAULT))

        return value

    def validate_fields_bool(self, value):
        value = self.validate_sub(value, key='field', sequence=True)
        value = self.validated_form_fields(value)

        for item in value:
            # validate default field
            if 'default' in item.keys():
                if not isinstance(item['default'], bool):
                    raise serializers.ValidationError('Default field must be boolean.')

        return value


# new version / status
class FormsNewVersionStatusSerializer(GlobalReadWriteSerializer):
    sections = SectionsField(source='linked_sections', read_only=True)
    fields_text = TextField(source='linked_fields_text', read_only=True)
    fields_bool = BoolField(source='linked_fields_bool', read_only=True)
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False},
                        'form': {'required': False},
                        'workflow': {'required': False},
                        'tag': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + FORM_FIELDS + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class FormsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Forms
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class FormsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = FormsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
