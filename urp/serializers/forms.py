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
from urp.models.forms import Forms, FormsLog
from urp.models.tags import Tags
from urp.models.workflows import Workflows
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class FormsReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED

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


# new version / status
class FormsNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False},
                        'form': {'required': False},
                        'workflow': {'required': False},
                        'tag': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED


# delete
class FormsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Forms
        fields = ()


# read logs
class FormsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = FormsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
