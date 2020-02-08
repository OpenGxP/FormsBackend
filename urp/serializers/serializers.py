"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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
from pytz import timezone as pytz_timezone, utc as pytz_utc

# rest imports
from rest_framework import serializers

# custom imports
from urp.models import Permissions, Users, Roles, AccessLog, PermissionsLog, LDAP, Vault
from basics.custom import generate_checksum, generate_to_hash, value_to_int
from basics.models import Status, AVAILABLE_STATUS, StatusLog, CentralLog, Settings, CHAR_DEFAULT
from urp.decorators import require_STATUS_CHANGE, require_POST, require_DELETE, require_PATCH, require_NONE, \
    require_NEW_VERSION, require_status, require_USERS, require_NEW, require_SETTINGS, require_SOD, \
    require_EMAIL, require_ROLES, require_PROFILE
from urp.custom import create_log_record, validate_comment, validate_signature
from urp.backends.Email import MyEmailBackend
from urp.vault import validate_password_input
from urp.models.profile import Profile
from urp.models.workflows.workflows import Workflows
from urp.models.logs.signatures import SignaturesLog
from urp.validators import validate_only_ascii, validate_no_specials_reduced, validate_no_space, validate_no_numbers

# django imports
from django.utils import timezone
from django.db import IntegrityError
from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import ValidationError as DjangoValidationError


##########
# GLOBAL #
##########

class GlobalReadWriteSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        serializers.ModelSerializer.__init__(self, *args, **kwargs)

        # flags
        self.new_version = False
        self.status_change = False

        # set workflow flag
        self.context['workflow'] = {}

        # sub elements
        self.sub_parents = []
        # sequence check
        self.global_sequence_check = {}

        self._signature = None
        self.now = timezone.now()

        self.user = None
        if 'user' in self.context.keys():
            self.user = self.context['user']

    valid = serializers.BooleanField(source='verify_checksum', read_only=True)
    # unique attribute for frontend selection
    unique = serializers.CharField(source='unique_id', read_only=True)

    # timestamp for log records
    timestamp_local = serializers.SerializerMethodField()
    valid_from_local = serializers.SerializerMethodField()
    valid_to_local = serializers.SerializerMethodField()

    # comment and signatures
    com = serializers.CharField(write_only=True, required=False, allow_blank=True)
    sig_user = serializers.CharField(write_only=True, required=False, allow_blank=True)
    sig_pw = serializers.CharField(write_only=True, required=False, allow_blank=True)

    @staticmethod
    def make_list_to_string(value):
        string_value = ''
        for item in value:
            if not isinstance(item, str):
                raise serializers.ValidationError('Value of array not a valid string.')
            string_value += '{},'.format(item)
        return string_value[:-1]

    def localize_timestamp(self, obj, field):
        if not getattr(obj, field):
            return None
        tz = Profile.objects.timezone(username=self.context['user'])
        timezone.activate(tz)
        _return = timezone.localtime(value=getattr(obj, field)).strftime(Settings.objects.core_timestamp_format)
        timezone.deactivate()
        return _return

    def get_timestamp_local(self, obj):
        return self.localize_timestamp(obj=obj, field='timestamp')

    def get_valid_from_local(self, obj):
        return self.localize_timestamp(obj=obj, field='valid_from')

    def get_valid_to_local(self, obj):
        return self.localize_timestamp(obj=obj, field='valid_to')

    # model
    @property
    def model(self):
        return getattr(getattr(self, 'Meta', None), 'model', None)

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, value):
        self._signature = value

    @staticmethod
    def new_version_check(data):
        if 'lifecycle_id' in data and 'version' in data:
            return True
        return

    def validate_predecessors(self, value, key):
        predecessors_check = []
        for item in value:
            # predecessors are optional
            if 'predecessors' in item.keys():
                if not isinstance(item['predecessors'], list):
                    raise serializers.ValidationError('Predecessor not a valid array.')
                if not item['predecessors']:
                    del item['predecessors']
                    continue
                # validate predecessors for string items
                for pred in item['predecessors']:
                    if not isinstance(pred, str):
                        raise serializers.ValidationError('Predecessors must be strings.')
                predecessors_check.append(item['predecessors'])

                # FO-191: unique items shall not self reference
                if item[key] in item['predecessors']:
                    raise serializers.ValidationError('{} can not be self referenced in predecessors.'
                                                      .format(key.capitalize()))

        # check that predecessors exist
        for item in predecessors_check:
            for each in item:
                # FO-196: treat [""] array as no predecessor
                if each == '':
                    continue
                if each not in self.sub_parents:
                    raise serializers.ValidationError('Predecessors must only contain valid {}s.'.format(key))

    def validate_sequence_plain(self, value, form=None):
        sequence_check = []
        for item in value:
            # validate that mandatory field sequence is in payload and collect for later unique check
            if 'sequence' not in item.keys():
                raise serializers.ValidationError('Sequence is required.')
            if not isinstance(item['sequence'], int):
                raise serializers.ValidationError('Sequence field must be integer.')
            sequence_check.append(item['sequence'])
            if form:
                try:
                    self.global_sequence_check[item['section']].append(item['sequence'])
                except KeyError:
                    self.global_sequence_check[item['section']] = [item['sequence']]

        # validate sequence unique characteristic
        if not form:
            if len(sequence_check) != len(set(sequence_check)):
                raise serializers.ValidationError('Sequence must be unique.')

    def validate_sub(self, value, key, parent=None):
        unique_check = []

        for item in value:
            if key not in item.keys():
                raise serializers.ValidationError('{} is required.'.format(key.capitalize()))
            try:
                validate_only_ascii(item[key])
                validate_no_specials_reduced(item[key])
                validate_no_space(item[key])
                validate_no_numbers(item[key])
            except serializers.ValidationError as e:
                raise serializers.ValidationError(
                    'Not allowed to use {} {}. {}'.format(key, item[key], e.detail[0]))
            unique_check.append(item[key])

        # validate key unique characteristic
        if len(unique_check) != len(set(unique_check)):
            raise serializers.ValidationError('{} must be unique.'.format(key.capitalize()))

        if parent:
            self.sub_parents = unique_check

        return value

    def validated_form_fields(self, value):
        for item in value:
            # validate mandatory field
            if 'mandatory' not in item.keys():
                raise serializers.ValidationError('Mandatory field ist required.')
            if not isinstance(item['mandatory'], bool):
                raise serializers.ValidationError('Mandatory field must be boolean.')

            # field must be in existing section
            if item['section'] not in self.sub_parents:
                raise serializers.ValidationError('Field must be in valid section.')

            # validate optional instruction
            if 'instruction' in item.keys():
                if not isinstance(item['instruction'], str):
                    raise serializers.ValidationError('Instruction field must be string.')
                if len(item['instruction']) > CHAR_DEFAULT:
                    raise serializers.ValidationError('Instruction must not be longer than {} characters.'
                                                      .format(CHAR_DEFAULT))
        return value

    def update_sub(self, validated_data, instance):
        for table, key in instance.sub_tables().items():
            # new / updated items
            existing_items = []
            if key in validated_data:
                for item in validated_data[key]:
                    _filter = {table.UNIQUE: item[table.UNIQUE],
                               'lifecycle_id': instance.lifecycle_id,
                               'version': instance.version}

                    # passed keys
                    keys = item.keys()
                    flag_change = False

                    try:
                        # record already exists, update of data possible
                        record = table.objects.filter(**_filter).get()
                        action = settings.DEFAULT_LOG_UPDATE
                    except table.DoesNotExist:
                        # no record was found, so new item
                        record = table()
                        action = settings.DEFAULT_LOG_CREATE
                        setattr(record, 'lifecycle_id', instance.lifecycle_id)
                        setattr(record, 'version', instance.version)

                    # add present items
                    fields_for_hash = {}
                    for attr in table.HASH_SEQUENCE:
                        if attr in keys:
                            compare = getattr(record, attr)
                            if attr == 'predecessors':
                                compare = getattr(record, attr).split(',')

                            if item[attr] != compare:
                                flag_change = True
                                # new data differs from present data, can be change or new item
                                fields_for_hash[attr] = item[attr]
                                setattr(record, attr, item[attr])
                            else:
                                fields_for_hash[attr] = getattr(record, attr)
                                if attr == 'predecessors':
                                    value = getattr(record, attr).split(',')
                                    setattr(record, attr, value)
                                    fields_for_hash[attr] = value
                        else:
                            fields_for_hash[attr] = getattr(record, attr)
                            if attr == 'predecessors':
                                value = getattr(record, attr).split(',')
                                setattr(record, attr, value)
                                fields_for_hash[attr] = value
                    # generate hash
                    to_hash = generate_to_hash(fields=fields_for_hash, hash_sequence=table.HASH_SEQUENCE,
                                               unique_id=record.id, lifecycle_id=record.lifecycle_id)
                    record.checksum = generate_checksum(to_hash)
                    record.full_clean()
                    record.save()

                    existing_items.append(getattr(record, table.UNIQUE))

                    if flag_change:
                        create_log_record(model=table, context=self.context, obj=instance, now=self.now,
                                          validated_data=fields_for_hash, action=action,
                                          signature=self.signature, central=False)

                # get data from updated record
                new_instance = self.model.objects.filter(lifecycle_id=self.instance.lifecycle_id,
                                                         version=self.instance.version).get()
                sub_table_data = getattr(new_instance, '{}_values'.format(key))

                for item in sub_table_data:
                    if item[table.UNIQUE] not in existing_items:
                        workflow_log_data = {}
                        _filter = {table.UNIQUE: item[table.UNIQUE],
                                   'lifecycle_id': instance.lifecycle_id,
                                   'version': instance.version}
                        del_item = table.objects.filter(**_filter).get()
                        for attr in table.HASH_SEQUENCE:
                            workflow_log_data[attr] = getattr(del_item, attr)

                        create_log_record(model=table, context=self.context, obj=instance,
                                          now=self.now, validated_data=workflow_log_data,
                                          action=settings.DEFAULT_LOG_DELETE,
                                          signature=self.signature, central=False)

                        del_item.delete()

    def create_specific(self, validated_data, obj):
        return validated_data, obj

    # function for create (POST)
    def create(self, validated_data):
        # get meta model assigned in custom serializer
        model = self.model
        obj = model()
        hash_sequence = obj.HASH_SEQUENCE
        # check if new version or initial create
        if self.context['function'] == 'new_version':
            self.new_version = True
            # lifecycle_id
            setattr(obj, 'lifecycle_id', self.instance.lifecycle_id)
            # version
            for attr in hash_sequence:
                validated_data[attr] = getattr(self.instance, attr)
            validated_data['version'] = self.instance.version + 1

        else:
            validated_data['version'] = 1
            if model.objects.HAS_STATUS and not model.objects.IS_RT:

                # get local timezone of user
                user_tz = pytz_timezone(Profile.objects.timezone(username=self.context['user']))
                # FO-197: validate if timestamp values are not Null / None
                if 'valid_from' in validated_data:
                    if validated_data['valid_from']:
                        validated_data['valid_from'] = user_tz.localize(
                            timezone.make_naive(validated_data['valid_from']),
                            is_dst=None).astimezone(pytz_utc)
                if 'valid_to' in validated_data:
                    if validated_data['valid_to']:
                        validated_data['valid_to'] = user_tz.localize(
                            timezone.make_naive(validated_data['valid_to']),
                            is_dst=None).astimezone(pytz_utc)

        # add default fields for new objects
        if model.objects.HAS_STATUS and not model.objects.IS_RT:
            validated_data['status_id'] = Status.objects.draft

        # specific
        validated_data, obj = self.create_specific(validated_data, obj)

        # passed keys
        keys = validated_data.keys()
        # set attributes of validated data
        for attr in hash_sequence:
            if attr in keys:
                setattr(obj, attr, validated_data[attr])
        # generate hash
        to_hash = generate_to_hash(fields=validated_data, hash_sequence=hash_sequence, unique_id=obj.id,
                                   lifecycle_id=obj.lifecycle_id)
        obj.checksum = generate_checksum(to_hash)
        # save obj
        try:
            obj.save()
            # log record
            if model.objects.LOG_TABLE:
                create_log_record(model=model, context=self.context, obj=obj, validated_data=validated_data,
                                  action=settings.DEFAULT_LOG_CREATE, signature=self.signature, now=self.now)

                if obj.sub_tables():
                    for table, key in obj.sub_tables().items():
                        if key in validated_data:
                            for record in validated_data[key]:
                                create_log_record(model=table, context=self.context, obj=obj, now=self.now,
                                                  validated_data=record, action=settings.DEFAULT_LOG_CREATE,
                                                  signature=self.signature, central=False)

        except IntegrityError as e:
            if 'UNIQUE constraint' in e.args[0]:
                raise serializers.ValidationError('Object already exists.')
        else:
            # update instance in case of POST methods with initial instance (e.g. new version)
            self.instance = obj
            return obj

    def update_specific(self, validated_data, instance):
        return validated_data, instance

    # update
    def update(self, instance, validated_data, self_call=None, now=None):
        action = settings.DEFAULT_LOG_UPDATE
        model = self.model
        if 'function' in self.context.keys():
            if self.context['function'] == 'status_change':
                self.status_change = True
                action = settings.DEFAULT_LOG_STATUS
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])

                # if "valid_from" is empty, set "valid_from" to timestamp of set productive
                if self.context['status'] == 'productive' and not self.instance.valid_from and not self_call:
                    validated_data['valid_from'] = self.now

                # change "valid_to" of previous version to "valid from" of new version
                # only for set productive step
                if self.context['status'] == 'productive' and self.instance.version > 1 and not self_call:
                    prev_instance = model.objects.get_previous_version(instance)
                    data = {'valid_to': self.instance.valid_from}
                    # if no valid_to, always set
                    valid_to_prev_version = getattr(prev_instance, 'valid_to')
                    if not valid_to_prev_version:
                        self.update(instance=prev_instance, validated_data=data, self_call=True, now=self.now)
                    else:
                        # only overlapping validity ranges
                        if getattr(instance, 'valid_from') < valid_to_prev_version:
                            self.update(instance=prev_instance, validated_data=data, self_call=True, now=self.now)
            else:
                if model.objects.HAS_STATUS:
                    # get local timezone of user
                    user_tz = pytz_timezone(Profile.objects.timezone(username=self.context['user']))
                    # FO-197: validate if timestamp values are not Null / None
                    if 'valid_from' in validated_data:
                        if validated_data['valid_from']:
                            validated_data['valid_from'] = user_tz.localize(
                                timezone.make_naive(validated_data['valid_from']),
                                is_dst=None).astimezone(pytz_utc)
                    if 'valid_to' in validated_data:
                        if validated_data['valid_to']:
                            validated_data['valid_to'] = user_tz.localize(
                                timezone.make_naive(validated_data['valid_to']),
                                is_dst=None).astimezone(pytz_utc)

        # specific
        validated_data, instance = self.update_specific(validated_data, instance)

        hash_sequence = instance.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            if attr in validated_data.keys():
                fields[attr] = validated_data[attr]
                setattr(instance, attr, validated_data[attr])
            else:
                fields[attr] = getattr(instance, attr)
        to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, unique_id=instance.id,
                                   lifecycle_id=instance.lifecycle_id)
        instance.checksum = generate_checksum(to_hash)
        instance.save()
        # log record
        if model.objects.LOG_TABLE:
            # for workflows
            if model.MODEL_ID == '04':
                if not instance.ldap:
                    # add initial password to validated data for logging
                    vault = Vault.objects.filter(username=instance.username).get()
                    fields['initial_password'] = vault.initial_password
                else:
                    # ldap is always false
                    fields['initial_password'] = False
            # route now for activate user and set password at same time
            if 'now' in self.context.keys():
                now = self.context['now']
            else:
                now = self.now
            create_log_record(model=model, context=self.context, obj=instance, validated_data=fields,
                              action=action, now=now, signature=self.signature)
        return instance

    def delete_specific(self, fields):
        return fields

    def delete(self):
        # get meta model assigned in custom serializer
        model = self.model
        hash_sequence = model.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            fields[attr] = getattr(self.instance, attr)

        if model.objects.LOG_TABLE:
            # specific
            fields = self.delete_specific(fields)

            create_log_record(model=model, context=self.context, obj=self.instance, validated_data=fields,
                              action=settings.DEFAULT_LOG_DELETE, signature=self.signature, now=self.now)

        # move delete otherwise log records can not be generated
        self.instance.delete_me()

    def validate_patch_specific(self, data):
        pass

    def validate_post_specific(self, data):
        pass

    def validate_delete_specific(self, data):
        pass

    class Validate:
        def __init__(self, validate_method):
            self.model = getattr(getattr(validate_method, 'Meta', None), 'model', None)
            self.context = validate_method.context
            self.instance = validate_method.instance
            self.function = validate_method.context['function']
            self.validate_method = validate_method

            self.user = None
            if 'user' in self.context.keys():
                self.user = self.context['user']

            self.method_list = [func for func in dir(self) if callable(getattr(self, func))]
            self.validate()

        def validate(self):
            for method in self.method_list:
                if method.startswith('validate_'):
                    getattr(self, method)()

    def validate(self, data):
        if self.context['function'] == 'init':
            return data

        # decorators for status catch
        require_draft = require_status(Status.objects.draft)
        require_circulation = require_status(Status.objects.circulation)
        require_productive = require_status(Status.objects.productive)
        require_blocked = require_status(Status.objects.blocked)
        require_inactive = require_status(Status.objects.inactive)
        require_archived = require_status(Status.objects.archived)

        @require_PATCH
        class Patch(self.Validate):
            def validate_patch_specific(self):
                self.validate_method.validate_patch_specific(data)

            @require_STATUS_CHANGE
            def validate_correct_status(self):
                # verify if valid status
                if self.context['status'] not in AVAILABLE_STATUS:
                    raise serializers.ValidationError('Target status not valid. Only "{}" are allowed.'
                                                      .format(AVAILABLE_STATUS))

            @require_STATUS_CHANGE
            @require_draft
            def validate_draft(self):
                if self.context['status'] != 'circulation':
                    raise serializers.ValidationError('Circulation can only be started from status draft.')

                # validate for "valid from" of new version shall not be before old version
                # only for circulations of version 2 and higher
                if self.instance.version > 1:
                    last_version = self.instance.version - 1
                    query = self.model.objects.filter(lifecycle_id=self.instance.lifecycle_id). \
                        filter(version=last_version).get()
                    if self.instance.valid_from < query.valid_from:
                        raise serializers.ValidationError('Valid from can not be before valid from '
                                                          'of previous version')

                # check if object is workflow managed
                if self.model.objects.WF_MGMT:
                    # check if workflow is productive and valid
                    valid_wf = Workflows.objects.verify_prod_valid(self.instance.workflow)
                    if not valid_wf:
                        raise serializers.ValidationError('Workflow not productive and/or valid.')

                    # set validated workflow record for further use
                    self.context['workflow']['workflow'] = valid_wf
                    self.context['workflow']['step'] = Settings.objects.core_devalue
                    self.context['workflow']['sequence'] = Settings.objects.core_devalue
                    self.context['workflow']['action'] = settings.DEFAULT_LOG_WF_CIRCULATION

                    # get last cycle
                    executed_steps = SignaturesLog.objects.filter(
                        object_lifecycle_id=self.instance.lifecycle_id,
                        object_version=self.instance.version).order_by('-timestamp').all()
                    # default set cycle to 1
                    self.context['workflow']['cycle'] = 1
                    # in case of previous steps determine last cycle + 1
                    if executed_steps:
                        self.context['workflow']['cycle'] = executed_steps[0].cycle + 1

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='circulation')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='circulation',
                                                                    now=self.validate_method.now)

            @require_STATUS_CHANGE
            @require_circulation
            def validate_circulation(self):
                if self.context['status'] not in ['productive', 'draft']:
                    raise serializers.ValidationError('From circulation only reject to draft and set '
                                                      'productive are allowed.')

                perm = ''

                # FO-122: SoD check only for set productive
                if self.context['status'] == 'productive':
                    perm = 'productive'
                    # SoD
                    if 'disable-sod' not in self.context.keys() and not self.model.objects.WF_MGMT:
                        log = self.model.objects.LOG_TABLE
                        previous_user = log.objects.get_circulation_user_for_sod(self.instance)
                        if previous_user == self.context['user']:
                            raise serializers.ValidationError('SoD conflict - set productive can not be performed by '
                                                              'the same user as set in circulation.')
                if self.context['status'] == 'draft':
                    perm = 'reject'

                # check if object is workflow managed
                if self.model.objects.WF_MGMT:
                    # check if workflow is productive and valid
                    workflow = self.instance.workflow
                    valid_wf = Workflows.objects.verify_prod_valid(workflow)
                    if not valid_wf:
                        raise serializers.ValidationError('Workflow not productive and/or valid.')

                    # get all steps of workflow
                    steps = valid_wf.linked_steps

                    # if no workflow for that cycle was started for that object
                    executed_steps = SignaturesLog.objects.filter(
                        object_lifecycle_id=self.instance.lifecycle_id,
                        object_version=self.instance.version).order_by('-timestamp').all()

                    if executed_steps[0].action == settings.DEFAULT_LOG_WF_CIRCULATION:
                        # get first step of workflow
                        for step in steps:
                            if step.sequence == 0 and not step.predecessors:
                                # validate if current user is in role of first step
                                if not self.context['request'].user.has_role(step.role):
                                    raise serializers.ValidationError('You are not allowed to perform '
                                                                      'that workflow step.')
                                if self.context['status'] == 'productive':
                                    self.context['workflow']['step'] = step.step
                                    self.context['workflow']['sequence'] = step.sequence
                                    self.context['workflow']['action'] = settings.DEFAULT_LOG_WF_WORKFLOW
                                else:
                                    self.context['workflow']['step'] = Settings.objects.core_devalue
                                    self.context['workflow']['sequence'] = Settings.objects.core_devalue
                                    self.context['workflow']['action'] = settings.DEFAULT_LOG_WF_REJECT
                                self.context['workflow']['cycle'] = executed_steps[0].cycle
                                break
                    # if last step was recorded
                    else:
                        # verify if last step was performed with same workflow version
                        if executed_steps[0].workflow != workflow or \
                                executed_steps[0].workflow_version != valid_wf.version:
                            raise serializers.ValidationError('Workflow was updated since last step, '
                                                              'please set record back to status draft and '
                                                              'restart circulation.')

                        # SoD for all circulation steps
                        if 'disable-sod' not in self.context.keys():
                            signatures = SignaturesLog.objects.filter(
                                object_lifecycle_id=self.instance.lifecycle_id,
                                object_version=self.instance.version,
                                action=settings.DEFAULT_LOG_WF_WORKFLOW,
                                cycle=executed_steps[0].cycle).all()
                            for record in signatures:
                                if self.context['user'] == record.user:
                                    raise serializers.ValidationError(
                                        'SoD conflict - The workflow step {} was already performed by user {}.'
                                        .format(record.step, self.context['user']))

                        # COMPARE TARGET ACTUAL
                        history = SignaturesLog.objects.filter(
                            object_lifecycle_id=self.instance.lifecycle_id, cycle=executed_steps[0].cycle,
                            object_version=self.instance.version,
                            action=settings.DEFAULT_LOG_WF_WORKFLOW).order_by('-timestamp').all()
                        next_steps = valid_wf.linked_steps_next_incl_parallel(history=history)

                        flag_in = False
                        for step in next_steps:
                            # validate if current user is in role of next step
                            if self.context['request'].user.has_role(step.role):
                                flag_in = True
                                if self.context['status'] == 'productive':
                                    self.context['workflow']['step'] = step.step
                                    self.context['workflow']['sequence'] = step.sequence
                                    self.context['workflow']['action'] = settings.DEFAULT_LOG_WF_WORKFLOW
                                else:
                                    self.context['workflow']['step'] = Settings.objects.core_devalue
                                    self.context['workflow']['sequence'] = Settings.objects.core_devalue
                                    self.context['workflow']['action'] = settings.DEFAULT_LOG_WF_REJECT
                                self.context['workflow']['cycle'] = executed_steps[0].cycle
                                break

                        if not flag_in:
                            raise serializers.ValidationError('You are not allowed to perform that '
                                                              'workflow step.')

                    # set validated workflow record for further use
                    self.context['workflow']['workflow'] = valid_wf

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm=perm)
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm=perm,
                                                                    now=self.validate_method.now)

            @require_STATUS_CHANGE
            @require_USERS
            @require_draft
            def validate_users(self):
                # check if used roles are not in status draft any more that natural key can not be changed anymore
                query = Users.objects.filter(lifecycle_id=self.instance.lifecycle_id,
                                             version=self.instance.version).get()
                raw_roles = query.roles.split(',')
                for role in raw_roles:
                    try:
                        Roles.objects.get_by_natural_key_not_draft(role)
                    except Roles.DoesNotExist:
                        raise serializers.ValidationError('Role "{}" still in status draft.'.format(role))

            @require_STATUS_CHANGE
            @require_productive
            def validate_productive(self):
                if self.context['status'] not in ['blocked', 'inactive', 'archived']:
                    raise serializers.ValidationError('From productive only block, archive and inactivate are '
                                                      'allowed.')

                dialog = self.model.MODEL_CONTEXT.lower()
                if self.context['status'] == 'blocked':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='block')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='block')
                if self.context['status'] == 'inactive':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='inactivate')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='inactivate')
                if self.context['status'] == 'archived':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='archive')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='archive')

            @require_STATUS_CHANGE
            @require_ROLES
            @require_productive
            def validate_initial_all_role(self):
                if self.instance.role == Settings.objects.core_initial_role:
                    if self.context['status'] in ['blocked', 'inactive', 'archived']:
                        raise serializers.ValidationError('Initial role {} can not be changed.'
                                                          .format(self.instance.role))

            @require_STATUS_CHANGE
            @require_blocked
            def validate_blocked(self):
                if self.context['status'] != 'productive':
                    raise serializers.ValidationError('From blocked only back to productive is allowed')

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='productive')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='productive')

            @require_STATUS_CHANGE
            @require_inactive
            def validate_inactive(self):
                if self.context['status'] != 'blocked':
                    raise serializers.ValidationError('From inactive only blocked is allowed')

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='block')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='block')

            @require_STATUS_CHANGE
            @require_archived
            def validate_archived(self):
                raise serializers.ValidationError('No status change is allowed from archived.')

            @require_NONE
            def validate_updates_only_in_draft(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Updates are only permitted in status draft.')

                    # verify that record remains unique
                    if self.instance.version > 1:
                        if isinstance(self.model.UNIQUE, list):
                            for field in self.model.UNIQUE:
                                if getattr(self.instance, field) != data[field]:
                                    raise serializers.ValidationError('Attribute "{}" is unique and can not be changed.'
                                                                      .format(field))
                        else:
                            if getattr(self.instance, self.model.UNIQUE) != data[self.model.UNIQUE]:
                                raise serializers.ValidationError('Attribute "{}" is unique and can not be changed.'
                                                                  .format(self.model.UNIQUE))
                    else:
                        # if unique is not only one, but a list of fields
                        if isinstance(self.model.UNIQUE, list):
                            _filter = dict()
                            for field in self.model.UNIQUE:
                                _filter[field] = data[field]
                        else:
                            _filter = {self.model.UNIQUE: data[self.model.UNIQUE]}
                        query = self.model.objects.filter(**_filter).exists()
                        if query:
                            records = self.model.objects.filter(**_filter).all()
                            for item in records:
                                if self.instance.lifecycle_id != item.lifecycle_id:
                                    raise serializers.ValidationError('Record(s) with data "{}" already exists'
                                                                      .format(_filter))

            @require_NONE
            def validate_comment_signature_edit(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='edit')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='edit')

            @require_NONE
            @require_EMAIL
            def validate_server_check_email(self):
                try:
                    MyEmailBackend(**data, check_call=True).open()
                except ImproperlyConfigured as e:
                    raise serializers.ValidationError(e)

            @require_NONE
            @require_USERS
            def validate_ldap_and_password(self):
                if data['ldap']:
                    # in case a password was passed, set to none
                    data['password'] = ''
                    LDAP.objects.search(data)
                else:
                    # check if previous record was ldap managed
                    if self.instance.ldap:
                        validate_password_input(data=data, initial=True)

            # FO-156: for user updates email shall only be used by own lifecycle record, not by other users
            @require_NONE
            @require_USERS
            def validate_email_not_used_by_other_lifecycle_id(self):
                references = Users.objects.filter(email__contains=data['email']).values_list('lifecycle_id', flat=True)
                for ref in references:
                    if ref != self.instance.lifecycle_id:
                        raise serializers.ValidationError('Email is is use by another user used.')

            @require_NONE
            @require_SETTINGS
            def validate_settings(self):
                # validate maximum login attempts and maximum inactive time and run time data number range start
                if self.instance.key == 'auth.max_login_attempts' or self.instance.key == 'core.auto_logout' \
                        or self.instance.key == 'core.password_reset_time' or self.instance.key == 'rtd.number_range':
                    try:
                        # try to convert to integer
                        data['value'] = value_to_int(data['value'])
                        # verify that integer is positive
                        if self.instance.key == 'rtd.number_range':
                            # 0 is allowed as number range
                            if data['value'] < 0:
                                raise ValueError
                        else:
                            if data['value'] < 1:
                                raise ValueError
                    except ValueError:
                        raise serializers.ValidationError('Setting "{}" must be a positive integer.'
                                                          .format(self.instance.key))

                # FO-177: added validation for sender email setting
                if self.instance.key == 'email.sender':
                    try:
                        validate_email(data['value'])
                    except DjangoValidationError as e:
                        raise serializers.ValidationError(e.message)

                # validate allowed settings for signatures
                if 'dialog' in self.instance.key and 'signature' in self.instance.key:
                    if data['value'] not in ['logging', 'signature']:
                        raise serializers.ValidationError('For signature settings, only "logging" and "signature" '
                                                          'are allowed.')
                        # validate allowed settings for signatures
                if 'dialog' in self.instance.key and 'comment' in self.instance.key:
                    if data['value'] not in ['none', 'optional', 'mandatory']:
                        raise serializers.ValidationError('For signature settings, only "none", "optional" and '
                                                          '"mandatory" are allowed.')

                # validate profile timezone default
                if self.instance.key == 'profile.default.timezone':
                    if data['value'] not in settings.PROFILE_TIMEZONES:
                        raise serializers.ValidationError({'value': ['Selected timezone is not supported.']})

            @require_NONE
            @require_PROFILE
            def validate_profile(self):
                if self.instance.key == 'loc.timezone':
                    if data['value'] not in settings.PROFILE_TIMEZONES:
                        raise serializers.ValidationError({'value': ['Selected timezone is not supported.']})

                if self.instance.key == 'loc.language':
                    if data['value'] not in ['en_EN', 'de_DE']:
                        raise serializers.ValidationError({'value': ['Selected language is not supported.']})

                if self.instance.key == 'gui.pagination':
                    try:
                        # try to convert to integer
                        data['value'] = value_to_int(data['value'])
                        # verify that integer is positive
                        if data['value'] not in settings.PROFILE_PAGINATION_SELECTIONS:
                            raise ValueError
                    except ValueError:
                        raise serializers.ValidationError('Value must be one integer of {}.'
                                                          .format(settings.PROFILE_PAGINATION_SELECTIONS))

            @require_NONE
            @require_SOD
            def validate_roles(self):
                if data['base'] == data['conflict']:
                    raise serializers.ValidationError('Role "{}" cannot be in self-conflict.'.format(data['base']))
                for field in self.model.UNIQUE:
                    if not Roles.objects.filter(role=data[field]).exists():
                        raise serializers.ValidationError('Role "{}" does not exist.'.format(data[field]))

        @require_POST
        class Post(self.Validate):
            def validate_post_specific(self):
                self.validate_method.validate_post_specific(data)

            @require_NEW
            def validate_unique(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    # if unique is not only one, but a list of fields
                    if isinstance(self.model.UNIQUE, list):
                        _filter = dict()
                        for field in self.model.UNIQUE:
                            _filter[field] = data[field]
                    else:
                        _filter = {self.model.UNIQUE: data[self.model.UNIQUE]}
                    query = self.model.objects.filter(**_filter).exists()
                    if query:
                        raise serializers.ValidationError('Record(s) with data "{}" already exists'.format(_filter))

            @require_NEW
            def validate_comment_signature_add(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='add')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='add',
                                                                    now=self.validate_method.now)

            @require_NEW_VERSION
            def validate_only_draft_or_circulation(self):
                if self.instance.status.id == Status.objects.draft or \
                        self.instance.status.id == Status.objects.circulation:
                    raise serializers.ValidationError('New versions can only be created in status productive, '
                                                      'blocked, inactive or archived.')

            @require_NEW_VERSION
            def validate_second_new_version(self):
                new_version = self.instance.version + 1
                if self.model.objects.filter(lifecycle_id=self.instance.lifecycle_id, version=new_version).exists():
                    raise serializers.ValidationError('New version already exists.')

            @require_NEW_VERSION
            def validate_comment_signature_nv(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                if self.context['nv'] == 'regular':
                    validate_comment(dialog=dialog, data=data, perm='version')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='version')
                if self.context['nv'] == 'archived':
                    validate_comment(dialog=dialog, data=data, perm='version_archived')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='version_archived')

            @require_NEW_VERSION
            @require_ROLES
            def validate_initial_all_role(self):
                if self.instance.role == Settings.objects.core_initial_role:
                    raise serializers.ValidationError('No new version of initial role {} can be changed.'
                                                      .format(self.instance.role))

            @require_NEW
            @require_EMAIL
            def validate_server_check_email(self):
                try:
                    MyEmailBackend(**data, check_call=True).open()
                except ImproperlyConfigured as e:
                    raise serializers.ValidationError(e)

            @require_NEW
            @require_USERS
            def validate_ldap(self):
                if data['ldap']:
                    # in case a password was passed, set to none
                    data['password'] = ''
                    LDAP.objects.search(data)

            @require_NEW
            @require_USERS
            def validate_password(self):
                # FO-143: password check for non-ldap managed users only
                if not data['ldap']:
                    # perform password check
                    validate_password_input(data=data, initial=True)

            # FO-156: for new users email must not yet be used by other users
            @require_NEW
            @require_USERS
            def validate_email_not_used_by_other_lifecycle_id(self):
                if Users.objects.filter(email__contains=data['email']):
                    raise serializers.ValidationError('Email is is use by another user used.')

            @require_NEW
            @require_SOD
            def validate_roles(self):
                if data['base'] == data['conflict']:
                    raise serializers.ValidationError('Role "{}" cannot be in self-conflict.'.format(data['base']))

                for field in self.model.UNIQUE:
                    if not Roles.objects.filter(role=data[field]).exists():
                        raise serializers.ValidationError('Role "{}" does not exist.'.format(data[field]))

        @require_DELETE
        class Delete(self.Validate):
            def validate_delete_specific(self):
                self.validate_method.validate_delete_specific(data)

            def validate_delete_only_in_draft(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Delete is only permitted in status draft.')

            def validate_comment_signature_delete(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='delete')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='delete')

        Patch(self)
        Post(self)
        Delete(self)
        return data


##########
# STATUS #
##########

# read
class StatusReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Status
        fields = Status.objects.GET_MODEL_ORDER + Status.objects.GET_BASE_CALCULATED


# read
class StatusLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = StatusLog
        fields = Status.objects.GET_MODEL_ORDER + Status.objects.GET_BASE_ORDER_LOG + Status.objects.GET_BASE_CALCULATED


###############
# PERMISSIONS #
###############

# read
class PermissionsReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Permissions
        fields = Permissions.objects.GET_MODEL_ORDER + Permissions.objects.GET_BASE_CALCULATED


# read
class PermissionsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = PermissionsLog
        fields = PermissionsLog.objects.GET_MODEL_ORDER + PermissionsLog.objects.GET_BASE_ORDER_LOG + \
            PermissionsLog.objects.GET_BASE_CALCULATED


##############
# CENTRALLOG #
##############

# read
class CentralLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = CentralLog
        fields = CentralLog.objects.GET_MODEL_ORDER + CentralLog.objects.GET_BASE_CALCULATED


#############
# ACCESSLOG #
#############

# read
class AccessLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = AccessLog
        fields = AccessLog.objects.GET_MODEL_ORDER + AccessLog.objects.GET_BASE_CALCULATED


################
# USER_PROFILE #
################

# read
class UserProfile(GlobalReadWriteSerializer):
    class Meta:
        model = Vault
        fields = ('valid', 'unique', 'question_one', 'question_two', 'question_three')
