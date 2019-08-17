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
from urp.models.workflows import Workflows, WorkflowsLog
from urp.models.tags import Tags
from urp.serializers import GlobalReadWriteSerializer
from urp.fields import StepsField
from urp.models.roles import Roles
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii
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
            model.objects.GET_BASE_CALCULATED

    def validate_tag(self, value):
        if value:
            allowed = Tags.objects.get_by_natural_key_productive_list('tag')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_steps(self, value):
        allowed = Roles.objects.get_by_natural_key_productive_list('role')
        # get all steps
        steps = []
        predecessors = []
        has_sequence_zero = False
        sequences = []
        for item in value:
            if 'step' not in item.keys():
                raise serializers.ValidationError('Step ist required.')
            # FO-191: moved step validation before anything else
            try:
                validate_only_ascii(item['step'])
                validate_no_specials_reduced(item['step'])
                validate_no_space(item['step'])
                validate_no_numbers(item['step'])
            except serializers.ValidationError as e:
                raise serializers.ValidationError(
                    'Not allowed to use step {}. {}'.format(item['step'], e.detail[0]))
            steps.append(item['step'])

            # validate that mandatory field sequence is in payload and collect for later unique check
            if 'sequence' not in item.keys():
                raise serializers.ValidationError('Sequence is required.')
            sequences.append(item['sequence'])

            # predecessors are optional
            if 'predecessors' in item.keys():
                if not isinstance(item['predecessors'], list):
                    raise serializers.ValidationError('Predecessor not a valid array.')
                predecessors.append(item['predecessors'])

            # check that all steps except first have predecessors
            if item['sequence'] != 0:
                if 'predecessors' not in item.keys():
                    raise serializers.ValidationError('Steps after initial step need predecessors.')
                # FO-191: steps can not be self referenced anymore
                if item['step'] in item['predecessors']:
                    raise serializers.ValidationError('Step can not be self referenced in predecessors.')

            # check if item has sequence zero, if it may not have predecessors, skip if sequence 0 was already checked
            if not has_sequence_zero:
                if item['sequence'] == 0:
                    has_sequence_zero = True
                    if 'predecessors' in item.keys() and item['predecessors']:
                        raise serializers.ValidationError('First step can not have predecessors.')

            # validate role field
            if 'role' not in item.keys():
                raise serializers.ValidationError('Role ist required.')
            if item['role'] not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item['role']))

            # validate text
            if 'text' in item:
                if len(item['text']) > CHAR_BIG:
                    raise serializers.ValidationError('Text must not be longer than {} characters.'.format(CHAR_BIG))

            # transform predecessors to string
            if 'predecessors' in item.keys():
                string_value = ''
                for pred in item['predecessors']:
                    if not isinstance(pred, str):
                        raise serializers.ValidationError('Predecessors must be strings.')
                    string_value += '{},'.format(pred)
                item['predecessors'] = string_value[:-1]

        # raise error if no step was sequence 0
        if not has_sequence_zero:
            raise serializers.ValidationError('First step without predecessors required.')

        # validate sequence unique characteristic
        if len(sequences) != len(set(sequences)):
            raise serializers.ValidationError('Sequence of steps must be unique within a workflow.')

        # validate step unique characteristic
        if len(steps) != len(set(steps)):
            raise serializers.ValidationError('Steps must be unique within a workflow.')

        # validate predecessors
        for item in predecessors:
            for each in item:
                if each not in steps:
                    raise serializers.ValidationError('Predecessors must only contain valid steps.')

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
            model.objects.GET_BASE_CALCULATED


# delete
class WorkflowsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Workflows
        fields = ()


# read logs
class WorkflowsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WorkflowsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
