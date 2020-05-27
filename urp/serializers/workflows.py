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
from urp.models.workflows.sub.steps import WorkflowsStepsLog
from urp.models.tags import Tags
from urp.serializers import GlobalReadWriteSerializer
from urp.fields import StepsField
from urp.models.roles import Roles
from basics.models import CHAR_BIG, Status
from urp.custom import create_log_record

# django imports
from django.conf import settings


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
        error_dict = {}
        # FO-229: validate that steps are not empty
        if not value:
            raise serializers.ValidationError('At least one step ist required.')
        self.validate_sequence_plain(value)
        try:
            # FO-239: validate_sub must control error_key, use "sequence" for workflows
            value = self.validate_sub(value, key='step', parent=True, error_key='sequence')
        except serializers.ValidationError as e:
            error_dict.update(e.detail)
        try:
            self.validate_predecessors(value, key='step')
        except serializers.ValidationError as e:
            error_dict.update(e.detail)
        allowed_roles = Roles.objects.get_by_natural_key_productive_list('role')

        for item in value:
            # validate role field
            if 'role' not in item.keys():
                self.create_update_record(error_dict=error_dict, item=item, value={'role': ['This field is required.']})
            elif not item['role']:
                self.create_update_record(error_dict=error_dict, item=item, value={'role': ['This field is required.']})
            elif not isinstance(item['role'], str):
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'role': ['This field requires data type string.']})
            elif item['role'] not in allowed_roles:
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'role': ['Not allowed to use "{}".'.format(item['role'])]})

            # validate text
            if 'text' in item.keys():
                if not isinstance(item['text'], str):
                    self.create_update_record(error_dict=error_dict, item=item,
                                              value={'role': ['This field requires data type string.']})
                elif len(item['text']) > CHAR_BIG:
                    self.create_update_record(error_dict=error_dict, item=item,
                                              value={'text': ['This field must not be longer than {} characters.'
                                                     .format(CHAR_BIG)]})

        if error_dict:
            raise serializers.ValidationError(error_dict)

        return value

    def create_specific(self, validated_data, obj):
        for table, key in obj.sub_tables().items():
            self.model.objects.create_sub_record(obj=obj, validated_data=validated_data, key=key,
                                                 sub_model=table)
        return validated_data, obj

    # FO-251: route self_call
    def update_specific(self, validated_data, instance, self_call=None):
        self.update_sub(validated_data, instance)
        return validated_data, instance


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

    def create_specific(self, validated_data, obj):
        for table, key in obj.sub_tables().items():
            validated_data[key] = getattr(self.instance, '{}_values'.format(key))
            self.model.objects.create_sub_record(obj=obj, validated_data=validated_data, key=key,
                                                 sub_model=table, new_version=True, instance=self.instance)
        return validated_data, obj

    def validate_patch_specific(self, data):
        # FO-229: validate that steps are not empty
        if self.instance.status.id == Status.objects.draft:
            if not self.instance.linked_steps:
                raise serializers.ValidationError('Steps field must not be empty.')


# delete
class WorkflowsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Workflows
        fields = model.objects.COMMENT_SIGNATURE

    def delete_specific(self, fields):
        for table, key in self.instance.sub_tables().items():
            linked_records = getattr(self.instance, '{}_values'.format(key))
            for record in linked_records:
                create_log_record(model=table, context=self.context, obj=self.instance, now=self.now,
                                  validated_data=record, action=settings.DEFAULT_LOG_DELETE,
                                  signature=self.signature, central=False)

        return fields


# read logs
class WorkflowsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WorkflowsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED


# read logs steps
class WorkflowsStepsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = WorkflowsStepsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_SUB + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
