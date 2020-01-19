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
from urp.decorators import require_status
from urp.models.execution.fields import ExecutionFields
from basics.custom import generate_checksum, generate_to_hash


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
                        'tag': {'read_only': True},
                        'lifecycle_id': {'required': False},
                        'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE

    def validate_form(self, value):
        if value:
            form = Forms.objects.verify_prod_valid(key=value)
            if not form:
                raise serializers.ValidationError('Referenced form "{}" is not valid.'.format(value))
            self.form = form
        return value

    def validate_patch_specific(self, data):
        raise serializers.ValidationError('Patch is not supported yet.')

    def create_specific(self, validated_data, obj):
        number = Execution.objects.next_number
        validated_data['status_id'] = Status.objects.created
        validated_data['number'] = number

        if self.form:
            validated_data['tag'] = self.form.tag
            validated_data['lifecycle_id'] = self.form.lifecycle_id
            setattr(obj, 'lifecycle_id', self.form.lifecycle_id)
            validated_data['version'] = self.form.version

        # ad fields execution records for values
        for fields_set in self.form.fields_execution():
            for data in fields_set:
                data['number'] = number
                value_obj = ExecutionFields()

                hash_sequence = ExecutionFields.HASH_SEQUENCE

                for attr in hash_sequence:
                    if attr in data.keys():
                        setattr(value_obj, attr, data[attr])
                # generate hash
                to_hash = generate_to_hash(fields=data, hash_sequence=hash_sequence, unique_id=value_obj.id)
                value_obj.checksum = generate_checksum(to_hash)
                value_obj.save()

        return validated_data, obj


# new status
class ExecutionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Execution
        extra_kwargs = {'number': {'required': False},
                        'form': {'required': False},
                        'tag': {'required': False},
                        'lifecycle_id': {'required': False},
                        'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE

    def validate_patch_specific(self, data):
        require_created = require_status(Status.objects.created)
        require_started = require_status(Status.objects.started)
        require_canceled = require_status(Status.objects.canceled)
        require_complete = require_status(Status.objects.complete)

        class Patch(self.Validate):
            @require_created
            def validate_created(self):
                if self.context['status'] != 'started':
                    raise serializers.ValidationError('Start can only be executed from status created.')

            @require_started
            def validate_started(self):
                if self.context['status'] not in ['canceled', 'complete']:
                    raise serializers.ValidationError('From started only canceled and complete are allowed.')

            @require_canceled
            def validate_canceled(self):
                raise serializers.ValidationError('Canceled is a final state.')

            @require_complete
            def validate_complete(self):
                raise serializers.ValidationError('Complete is a final state.')

        Patch(self)


# delete
class ExecutionDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Execution
        fields = model.objects.COMMENT_SIGNATURE

    def validate_delete_specific(self, data):
        if self.instance.status.id != Status.objects.created:
            raise serializers.ValidationError('Delete is only permitted in status created.')


# read logs
class ExecutionLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = ExecutionLog
        fields = model.objects.GET_MODEL_ORDER + ('status', ) + model.objects.GET_BASE_ORDER_LOG + \
            model.objects.GET_BASE_CALCULATED
