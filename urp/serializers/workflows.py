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

# app imports
from urp.models.workflows.workflows import Workflows, WorkflowsLog
from urp.models.tags import Tags
from urp.serializers import GlobalReadWriteSerializer
from urp.fields import StepsField
from urp.models.roles import Roles
from basics.models import CHAR_BIG


# read / add / edit
class WorkflowsReadWriteSerializer(GlobalReadWriteSerializer):
    # step fields
    steps = StepsField(source='linked_steps')
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Workflows
        extra_kwargs = {'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('steps', ) + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def validate_tag(self, value):
        if value:
            allowed = Tags.objects.get_by_natural_key_productive_list('tag')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_steps(self, value):
        value = self.validate_sub(value, key='step', sequence=True, predecessors=True)
        allowed_roles = Roles.objects.get_by_natural_key_productive_list('role')

        for item in value:
            # validate role field
            if 'role' not in item.keys():
                raise serializers.ValidationError('Role ist required.')
            if not isinstance(item['role'], str):
                raise serializers.ValidationError('Role field must be string.')
            if item['role'] not in allowed_roles:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item['role']))

            # validate text
            if 'text' in item.keys():
                if not isinstance(item['text'], str):
                    raise serializers.ValidationError('Text field must be string.')
                if len(item['text']) > CHAR_BIG:
                    raise serializers.ValidationError('Text must not be longer than {} characters.'.format(CHAR_BIG))

        return value


# new version / status
class WorkflowsNewVersionStatusSerializer(GlobalReadWriteSerializer):
    steps = StepsField(source='linked_steps', read_only=True)
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Workflows
        extra_kwargs = {'version': {'required': False},
                        'workflow': {'required': False},
                        'tag': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('steps', ) + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class WorkflowsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Workflows
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class WorkflowsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WorkflowsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
