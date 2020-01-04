"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from basics.models import Status
from urp.serializers import GlobalReadWriteSerializer
from urp.models.forms.forms import Forms
from urp.models.execution.execution import Execution, ExecutionLog


# read / add / edit
class ExecutionReadWriteSerializer(GlobalReadWriteSerializer):
    def __init__(self, *args, **kwargs):
        GlobalReadWriteSerializer.__init__(self, *args, **kwargs)
        self.form = None

    # status field
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Execution
        extra_kwargs = {'number': {'read_only': True},
                        'tag': {'read_only': True}}
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE

    def validate_form(self, value):
        if value:
            form = Forms.objects.verify_prod_valid(key=value)
            if not form:
                raise serializers.ValidationError('Referenced form "{}" is not valid.'.format(value))
            self.form = form
        return value

    def validate_post_specific(self):
        pass

    def create_specific(self, validated_data, obj):
        validated_data['status_id'] = Status.objects.created
        validated_data['number'] = Execution.objects.next_number

        if self.form:
            validated_data['tag'] = self.form.tag

        return validated_data, obj


# new status
class ExecutionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Execution
        extra_kwargs = {'number': {'required': False},
                        'form': {'required': False},
                        'tag': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE


# delete
class ExecutionDeleteSerializer(GlobalReadWriteSerializer):
    def validate_delete_specific(self):
        if self.instance.status.id != Status.objects.created:
            raise serializers.ValidationError('Delete is only permitted in status created.')

    class Meta:
        model = Execution
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class ExecutionLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = ExecutionLog
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_ORDER_LOG + \
            model.objects.GET_BASE_CALCULATED
