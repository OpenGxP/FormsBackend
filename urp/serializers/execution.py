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

# python imports
import requests
import json

# rest imports
from rest_framework import serializers

# django imports
from django.conf import settings

# app imports
from basics.models import Status
from urp.serializers import GlobalReadWriteSerializer
from urp.models.forms.forms import Forms
from urp.models.forms.sub.sections import FormsSections
from urp.models.execution.execution import Execution, ExecutionLog
from urp.decorators import require_status
from urp.models.execution.view import ExecutionActualValuesLog
from urp.models.execution.sub.text_fields import ExecutionTextFields
from urp.models.execution.sub.bool_fields import ExecutionBoolFields
from basics.custom import generate_checksum, generate_to_hash
from urp.custom import validate_comment, validate_signature
from urp.fields import ExecutionValuesField, ExecutionGenericField
from urp.decorators import require_STATUS_CHANGE
from urp.models.webhooks import WebHooks


# read / add / edit
class ExecutionReadWriteSerializer(GlobalReadWriteSerializer):
    def __init__(self, *args, **kwargs):
        GlobalReadWriteSerializer.__init__(self, *args, **kwargs)
        self.form = None
        self.number = None

    # status field
    status = serializers.CharField(source='get_status', read_only=True)
    fields_values = ExecutionValuesField(source='linked_fields_values', read_only=True)

    class Meta:
        model = Execution
        extra_kwargs = {'number': {'read_only': True},
                        'tag': {'read_only': True},
                        'lifecycle_id': {'required': False},
                        'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + ('status', 'fields_values', ) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE

    def validate_form(self, value):
        if value:
            form = Forms.objects.verify_prod_valid(key=value)
            if not form:
                raise serializers.ValidationError('Referenced form "{}" is not valid.'.format(value))
            self.form = form
        return value

    def _build(self, hash_sequence, record, model):
        data = {}
        obj = model()
        setattr(obj, 'number', self.number)
        data['number'] = self.number
        setattr(obj, 'tag', self.form.tag)
        data['tag'] = self.form.tag

        for attr in hash_sequence:
            if attr in ['number', 'tag']:
                continue
            elif attr == 'value':
                # value for bool is initially always None / Null
                if isinstance(obj, ExecutionBoolFields):
                    setattr(obj, attr, None)
                    data[attr] = None
                continue
            elif attr == 'section':
                query = FormsSections.objects.filter(lifecycle_id=self.form.lifecycle_id,
                                                     version=self.form.version,
                                                     sequence=getattr(record, 'section')).get()
                setattr(obj, attr, query.section)
                data['section'] = query.section
                continue
            setattr(obj, attr, getattr(record, attr))
            data[attr] = getattr(record, attr)

        # generate hash
        to_hash = generate_to_hash(fields=data, hash_sequence=hash_sequence, unique_id=obj.id)
        obj.checksum = generate_checksum(to_hash)
        obj.save()

    def create_specific(self, validated_data, obj):
        self.number = Execution.objects.next_number
        validated_data['status_id'] = Status.objects.created
        validated_data['number'] = self.number

        if self.form:
            validated_data['tag'] = self.form.tag
            validated_data['lifecycle_id'] = self.form.lifecycle_id
            setattr(obj, 'lifecycle_id', self.form.lifecycle_id)
            validated_data['version'] = self.form.version

        # ad fields execution records for values

        # add text fields
        for record in self.form.linked_fields_text:
            model = ExecutionTextFields
            hash_sequence = model.HASH_SEQUENCE
            self._build(hash_sequence=hash_sequence, record=record, model=model)

        for record in self.form.linked_fields_bool:
            model = ExecutionBoolFields
            hash_sequence = model.HASH_SEQUENCE
            self._build(hash_sequence=hash_sequence, record=record, model=model)

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

    # add decorator to only execute when status change
    @require_STATUS_CHANGE
    def update_specific(self, validated_data, instance, self_call=None):
        if self.context['status'] == 'complete':
            headers = {'Accept': 'application/json',
                       'Content-Type': 'application/json',
                       'Authorization': ''}

            payload = {}

            field_values = self.instance.linked_fields_values
            for record in field_values:
                payload[record.field] = record.value

            hooks = WebHooks.objects.get_prod_valid_list({'form': self.instance.form})
            for hook in hooks:
                headers['Authorization'] = '{} {}'.format(hook.header_token, hook.decrypt_token)
                requests.post(url=hook.url, headers=headers, data=json.dumps(payload))

        return validated_data, instance

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

            @require_started
            def validate_complete_record(self):
                values = Execution.actual_values(number=self.instance.number)
                for i in values:
                    if not i['value']:
                        raise serializers.ValidationError('Not all actual values are completed.')

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


# fields execution
class ExecutionFieldsWriteSerializer(GlobalReadWriteSerializer):
    def _validate_specific(self, data):
        pass

    def update_specific(self, validated_data, instance, self_call=None):
        if not getattr(instance, 'value'):
            self.action = settings.DEFAULT_LOG_CREATE

        return validated_data, instance

    def validate_patch_specific(self, data):
        if Execution.objects.get(number=self.instance.number).status.id != Status.objects.started:
            raise serializers.ValidationError('Updates are only permitted in status started.')

        if self.my_errors:
            raise serializers.ValidationError(self.my_errors['value'])

        if 'value' not in data:
            raise serializers.ValidationError('Field value is required.')

        self._validate_specific(data)

        # validate if allowed to update value
        exec_obj = Execution.objects.get(number=self.instance.number)
        allowed_role = FormsSections.objects.get(lifecycle_id=exec_obj.lifecycle_id, version=exec_obj.version,
                                                 section=self.instance.section).role
        if allowed_role and not self.context['request'].user.has_role(allowed_role):
            raise serializers.ValidationError('You are not allowed to update that value.')
        # validate if record has value, then apply correction settings for sig and comment
        if getattr(self.instance, 'value'):
            dialog = Execution.MODEL_CONTEXT.lower()
            validate_comment(dialog=dialog, data=data, perm='correct')
            self.signature = validate_signature(logged_in_user=self.user, dialog=dialog, data=data, perm='correct',
                                                request=self.request)


# fields text execution
class ExecutionTextFieldsWriteSerializer(ExecutionFieldsWriteSerializer):
    def _validate_specific(self, data):
        if not data['value']:
            raise serializers.ValidationError('Actual value is required.')

    class Meta:
        model = ExecutionTextFields
        fields = ('value',) + model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# fields bool execution
class ExecutionBoolFieldsWriteSerializer(ExecutionFieldsWriteSerializer):
    class Meta:
        model = ExecutionBoolFields
        fields = ('value',) + model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# read field logs
class ExecutionFieldsLogReadSerializer(GlobalReadWriteSerializer):
    value = ExecutionGenericField(source='get_value', read_only=True)
    default = ExecutionGenericField(source='get_default', read_only=True)

    class Meta:
        model = ExecutionActualValuesLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
