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
from urp.models.workflows import WorkflowsSteps
from basics.custom import generate_checksum, generate_to_hash, value_to_int
from basics.models import Status, AVAILABLE_STATUS, StatusLog, CentralLog, Settings
from urp.decorators import require_STATUS_CHANGE, require_POST, require_DELETE, require_PATCH, require_NONE, \
    require_NEW_VERSION, require_status, require_LDAP, require_USERS, require_NEW, require_SETTINGS, require_SOD, \
    require_EMAIL, require_ROLES, require_PROFILE
from urp.custom import create_log_record, create_central_log_record, create_signatures_record, validate_comment, \
    validate_signature
from urp.backends.ldap import server_check
from urp.backends.Email import MyEmailBackend
from urp.vault import create_update_vault, validate_password_input
from urp.crypto import encrypt
from urp.models.profile import Profile
from urp.models.workflows import Workflows
from urp.models.logs.signatures import SignaturesLog

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

        self._workflows_changed_steps = []
        self._workflows_delete_steps = []
        self.workflow_step_logs = {}
        self.workflow_step_log_decision = {}

        # set workflow flag
        self.context['workflow'] = {}
        self.context['workflow']['productive'] = False

        self._signature = None
        self.now = timezone.now()

    valid = serializers.BooleanField(source='verify_checksum', read_only=True)
    # unique attribute for frontend selection
    unique = serializers.CharField(source='unique_id', read_only=True)

    # timestamp for log records
    timestamp_local = serializers.SerializerMethodField()
    valid_from_local = serializers.SerializerMethodField()
    valid_to_local = serializers.SerializerMethodField()

    # comment and signatures
    com = serializers.CharField(write_only=True, required=False)
    sig_user = serializers.CharField(write_only=True, required=False)
    sig_pw = serializers.CharField(write_only=True, required=False)

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
    def workflows_changed_steps(self):
        return self._workflows_changed_steps

    @workflows_changed_steps.setter
    def workflows_changed_steps(self, value):
        self._workflows_changed_steps.append(value)

    @property
    def workflows_delete_steps(self):
        return self._workflows_delete_steps

    @workflows_delete_steps.setter
    def workflows_delete_steps(self, value):
        self._workflows_delete_steps.append(value)

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

            # for users
            if model.MODEL_ID == '04':
                # use users initial_password property method
                validated_data['initial_password'] = self.instance.initial_password

            # for workflows
            if model.MODEL_ID == '26':
                validated_data['linked_steps'] = self.instance.linked_steps_values
                for record in validated_data['linked_steps']:
                    # make predecessors an array
                    if 'predecessors' in record.keys():
                        record['predecessors'] = record['predecessors'].split(',')
                    record['version'] = self.instance.version + 1
                    step = WorkflowsSteps()
                    steps_hash_sequence = step.HASH_SEQUENCE
                    setattr(step, 'lifecycle_id', obj.lifecycle_id)
                    # passed keys
                    keys = record.keys()
                    # set attributes of validated data
                    for attr in steps_hash_sequence:
                        if attr in keys:
                            setattr(step, attr, record[attr])
                    # generate hash
                    to_hash = generate_to_hash(fields=record, hash_sequence=steps_hash_sequence, unique_id=step.id,
                                               lifecycle_id=step.lifecycle_id)
                    step.checksum = generate_checksum(to_hash)
                    step.full_clean()
                    step.save()

        else:
            validated_data['version'] = 1
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

            # for users
            if obj.MODEL_ID == '04':
                # add is_active because django framework needs it
                validated_data['is_active'] = True
                # default initial password is false for ldap (initial_password required for log record)
                validated_data['initial_password'] = False

                # if not ldap managed user create vault record
                if not validated_data['ldap']:
                    # default initial password for not ldap managed users is true
                    validated_data['initial_password'] = True

                    # create vault record
                    create_update_vault(data=validated_data, log=False, initial=True, signature=self.signature,
                                        now=self.now)

                # create profile
                Profile.objects.generate_profile(username=validated_data['username'], log_user=self.context['user'])

            # for workflows
            if obj.MODEL_ID == '26':
                for record in validated_data['linked_steps']:
                    # make predecessors an array
                    if 'predecessors' in record.keys():
                        record['predecessors'] = record['predecessors'].split(',')
                    record['version'] = validated_data['version']
                    step = WorkflowsSteps()
                    steps_hash_sequence = step.HASH_SEQUENCE
                    setattr(step, 'lifecycle_id', obj.lifecycle_id)
                    # passed keys
                    keys = record.keys()
                    # set attributes of validated data
                    for attr in steps_hash_sequence:
                        if attr in keys:
                            setattr(step, attr, record[attr])
                    # generate hash
                    to_hash = generate_to_hash(fields=record, hash_sequence=steps_hash_sequence, unique_id=step.id,
                                               lifecycle_id=step.lifecycle_id)
                    step.checksum = generate_checksum(to_hash)
                    step.full_clean()
                    step.save()

            # for access log
            if obj.MODEL_ID == '05':
                create_central_log_record(log_id=obj.id, now=validated_data['timestamp'], context=model.MODEL_CONTEXT,
                                          action=validated_data['action'], user=validated_data['user'])

            # ldap and email encrypt password before save to db
            if obj.MODEL_ID == '11' or obj.MODEL_ID == '18':
                raw_pw = validated_data['password']
                validated_data['password'] = encrypt(raw_pw)

        # add default fields for new objects
        if model.objects.HAS_STATUS:
            validated_data['status_id'] = Status.objects.draft
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
                # for workflows
                if obj.MODEL_ID == '26':
                    for record in validated_data['linked_steps']:
                        if 'predecessors' in record:
                            record['predecessors'] = self.make_list_to_string(record['predecessors'])
                        workflow_log_data = {}
                        for field in model.objects.LOG_TABLE.HASH_SEQUENCE:
                            if field in validated_data:
                                workflow_log_data[field] = validated_data[field]
                            if field in record:
                                workflow_log_data[field] = record[field]
                        create_log_record(model=model, context=self.context, obj=obj, validated_data=workflow_log_data,
                                          action=settings.DEFAULT_LOG_CREATE, signature=self.signature, now=self.now)
                else:
                    create_log_record(model=model, context=self.context, obj=obj, validated_data=validated_data,
                                      action=settings.DEFAULT_LOG_CREATE, signature=self.signature, now=self.now)
        except IntegrityError as e:
            if 'UNIQUE constraint' in e.args[0]:
                raise serializers.ValidationError('Object already exists.')
        else:
            # update instance in case of POST methods with initial instance (e.g. new version)
            self.instance = obj
            return obj

    # update
    def update(self, instance, validated_data, self_call=None, now=None):
        action = settings.DEFAULT_LOG_UPDATE
        model = self.model
        if 'function' in self.context.keys():
            if self.context['function'] == 'status_change':
                self.status_change = True
                action = settings.DEFAULT_LOG_STATUS
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])

                # check if workflow is used
                """
                if self.context['workflow'] and self.model.objects.WF_MGMT:
                    # write log record for electronic signature
                    if not now:
                        now = timezone.now()
                    create_signatures_record(workflow=self.context['workflow']['workflow'],
                                             user=self.context['user'],
                                             timestamp=now, context=self.model.MODEL_CONTEXT, obj=self.instance,
                                             step=self.context['workflow']['step'],
                                             sequence=self.context['workflow']['sequence'])

                    if self.context['status'] == 'productive' and not self.context['workflow']['productive']:
                        self.context['status'] = 'circulation'
                        validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])
                """

                # if "valid_from" is empty, set "valid_from" to timestamp of set productive
                if self.context['status'] == 'productive' and not self.instance.valid_from and not self_call:
                    now = self.now
                    validated_data['valid_from'] = now

                # change "valid_to" of previous version to "valid from" of new version
                # only for set productive step
                if self.context['status'] == 'productive' and self.instance.version > 1 and not self_call:
                    now = self.now
                    prev_instance = model.objects.get_previous_version(instance)
                    data = {'valid_to': self.instance.valid_from}
                    # if no valid_to, always set
                    valid_to_prev_version = getattr(prev_instance, 'valid_to')
                    if not valid_to_prev_version:
                        self.update(instance=prev_instance, validated_data=data, self_call=True, now=now)
                    else:
                        # only overlapping validity ranges
                        if getattr(instance, 'valid_from') < valid_to_prev_version:
                            self.update(instance=prev_instance, validated_data=data, self_call=True, now=now)
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

                # FO-132: hash password before saving
                if model.MODEL_ID == '04':
                    # draft updates shall be reflected in vault
                    if not validated_data['ldap']:
                        # check if previous record was ldap managed
                        if instance.ldap:
                            # create new vault, because now is password managed
                            create_update_vault(data=validated_data, log=False, initial=True, signature=self.signature,
                                                now=self.now)
                        else:
                            # get existing vault for that user
                            vault = Vault.objects.filter(username=instance.username).get()

                            # update vault
                            create_update_vault(data=validated_data, instance=vault, log=False, initial=True,
                                                signature=self.signature, now=self.now)

                    else:
                        # check if previous record was ldap managed
                        if not instance.ldap:
                            # delete existing vault for that user because not password managed anymore
                            Vault.objects.filter(username=instance.username).delete()

                # for workflows
                if model.MODEL_ID == '26':
                    workflows_linked_steps = WorkflowsSteps.objects.filter(lifecycle_id=instance.lifecycle_id,
                                                                           version=instance.version).all()
                    for record in validated_data['linked_steps']:
                        # make predecessors an array
                        if 'predecessors' in record.keys():
                            record['predecessors'] = record['predecessors'].split(',')
                        # get version from parent element
                        record['version'] = instance.version
                        # check if step already exist
                        try:
                            step = WorkflowsSteps.objects.filter(step=record['step'],
                                                                 lifecycle_id=instance.lifecycle_id,
                                                                 version=instance.version).get()
                            self.workflows_changed_steps = record['step']
                            self.workflow_step_logs[record['step']] = settings.DEFAULT_LOG_UPDATE
                        except WorkflowsSteps.DoesNotExist:
                            step = WorkflowsSteps()
                            setattr(step, 'lifecycle_id', instance.lifecycle_id)
                            self.workflows_changed_steps = record['step']
                            self.workflow_step_logs[record['step']] = settings.DEFAULT_LOG_CREATE
                        steps_hash_sequence = step.HASH_SEQUENCE
                        # passed keys
                        keys = record.keys()
                        # set attributes of validated data
                        fields = {}
                        self.workflow_step_log_decision[record['step']] = False
                        for attr in steps_hash_sequence:
                            if attr in keys:
                                # only attributes of record / keys may be a change
                                if record[attr] != getattr(step, attr):
                                    self.workflow_step_log_decision[record['step']] = True
                                fields[attr] = record[attr]
                                setattr(step, attr, record[attr])
                            else:
                                fields[attr] = getattr(step, attr)
                        # generate hash
                        to_hash = generate_to_hash(fields=fields, hash_sequence=steps_hash_sequence, unique_id=step.id,
                                                   lifecycle_id=step.lifecycle_id)
                        step.checksum = generate_checksum(to_hash)
                        step.full_clean()
                        step.save()

                    # delete steps that have not been updated (all steps are send)
                    for step in workflows_linked_steps:
                        if step.step not in self.workflows_changed_steps:
                            del_step = WorkflowsSteps.objects.filter(step=step.step,
                                                                     lifecycle_id=instance.lifecycle_id,
                                                                     version=instance.version).get()
                            self.workflows_delete_steps = del_step
                            del_step.delete()

                # ldap and email encrypt password before save to db
                if model.MODEL_ID == '11' or model.MODEL_ID == '18':
                    raw_pw = validated_data['password']
                    validated_data['password'] = encrypt(raw_pw)

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
            if instance.MODEL_ID == '26':
                for record in instance.linked_steps:
                    workflow_log_data = {}
                    for field in model.objects.LOG_TABLE.HASH_SEQUENCE:
                        if hasattr(instance, field):
                            workflow_log_data[field] = getattr(instance, field)
                        else:
                            if hasattr(record, field):
                                workflow_log_data[field] = getattr(record, field)
                    if not self.status_change:
                        action = self.workflow_step_logs[record.step]
                        if not self.workflow_step_log_decision[record.step]:
                            continue
                    create_log_record(model=model, context=self.context, obj=instance, validated_data=workflow_log_data,
                                      action=action, now=now, signature=self.signature)

                # log deleted ones
                if not self.status_change:
                    for record in self.workflows_delete_steps:
                        workflow_log_data = {}
                        for field in model.objects.LOG_TABLE.HASH_SEQUENCE:
                            if hasattr(instance, field):
                                workflow_log_data[field] = getattr(instance, field)
                            else:
                                if hasattr(record, field):
                                    workflow_log_data[field] = getattr(record, field)
                        create_log_record(model=model, context=self.context, obj=instance,
                                          validated_data=workflow_log_data,
                                          action=settings.DEFAULT_LOG_DELETE, now=now, signature=self.signature)

            else:
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
                create_log_record(model=model, context=self.context, obj=instance, validated_data=fields,
                                  action=action, now=now, signature=self.signature)
        return instance

    def delete(self):
        # get meta model assigned in custom serializer
        model = self.model
        hash_sequence = model.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            fields[attr] = getattr(self.instance, attr)
        self.instance.delete()

        if model.objects.LOG_TABLE:
            if model.MODEL_ID == '04':
                if not self.instance.ldap:
                    # add initial password to validated data for logging
                    vault = Vault.objects.filter(username=self.instance.username).get()
                    fields['initial_password'] = vault.initial_password
                else:
                    fields['initial_password'] = False
                # FO-140: delete vault record after deleting object, only for version 1
                if not self.instance.ldap and self.instance.version == 1:
                    vault = Vault.objects.filter(username=self.instance.username).get()
                    vault.delete()

                # delete profile
                Profile.objects.delete_profile(username=self.instance.username, log_user=self.context['user'])

            if model.MODEL_ID == '26':
                steps = WorkflowsSteps.objects.filter(version=self.instance.version,
                                                      lifecycle_id=self.instance.lifecycle_id).all()
                for step in steps:
                    workflow_fields = fields.copy()
                    for attr in model.objects.LOG_TABLE.HASH_SEQUENCE:
                        if hasattr(step, attr):
                            workflow_fields[attr] = getattr(step, attr)
                    create_log_record(model=model, context=self.context, obj=self.instance, signature=self.signature,
                                      validated_data=workflow_fields, action=settings.DEFAULT_LOG_DELETE, now=self.now)
            else:
                create_log_record(model=model, context=self.context, obj=self.instance, validated_data=fields,
                                  action=settings.DEFAULT_LOG_DELETE, signature=self.signature, now=self.now)

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

        class Validate:
            def __init__(self, validate_method):
                self.model = getattr(getattr(validate_method, 'Meta', None), 'model', None)
                self.context = validate_method.context
                self.instance = validate_method.instance
                self.function = validate_method.context['function']
                self.validate_method = validate_method
                self.method_list = [func for func in dir(self) if callable(getattr(self, func))]
                self.validate()

            def validate(self):
                for method in self.method_list:
                    if method.startswith('validate_'):
                        getattr(self, method)()

        @require_PATCH
        class Patch(Validate):
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
                """
                if self.model.objects.WF_MGMT:
                    # check if workflow is productive and valid
                    workflow = self.instance.workflow
                    valid_record = Workflows.objects.verify_prod_valid(workflow)
                    if valid_record:
                        # check if user is in the role of the first step of the valid workflow
                        for step in valid_record.linked_steps_roles:
                            if step['sequence'] == 0:
                                if not self.context['request'].user.has_role(step['role']):
                                    raise serializers.ValidationError('User is not a member of the workflow step role: '
                                                                      '{}.'.format(step['role']))
                                # set used step for further use
                                self.context['workflow']['step'] = step['step']
                                self.context['workflow']['sequence'] = step['sequence']
                                break
                    else:
                        raise serializers.ValidationError('Workflow not productive and/or valid.')

                    # set validated workflow record for further use
                    self.context['workflow']['workflow'] = valid_record

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='circulation')
                self.signautre = validate_signature(dialog=dialog, data=data, perm='circulation')
                """

            @require_STATUS_CHANGE
            @require_circulation
            def validate_circulation(self):
                if self.context['status'] not in ['productive', 'draft']:
                    raise serializers.ValidationError('From circulation only reject to draft and set '
                                                      'productive are allowed.')

                # FO-122: SoD check only for set productive
                if self.context['status'] == 'productive':
                    # SoD
                    if 'disable-sod' not in self.context.keys():
                        log = self.model.objects.LOG_TABLE
                        previous_user = log.objects.get_circulation_user_for_sod(self.instance)
                        if previous_user == self.context['user']:
                            raise serializers.ValidationError('SoD conflict - set productive can not be performed by '
                                                              'the same user as set in circulation.')

                    # check if object is workflow managed
                    """
                    if self.model.objects.WF_MGMT:
                        # check if workflow is productive and valid
                        workflow = self.instance.workflow
                        valid_record = Workflows.objects.verify_prod_valid(workflow)
                        if valid_record:
                            # check next workflow step
                            last_step = SignaturesLog.objects.filter(object_lifecycle_id=self.instance.lifecycle_id,
                                                                     object_version=self.instance.version).order_by(
                                                                     '-sequence')[0]

                            # verify if last step was performed with same workflow version
                            if last_step.workflow != workflow or last_step.workflow_version != valid_record.version:
                                raise serializers.ValidationError('Workflow was updated since last step, '
                                                                  'please set record back to status draft and '
                                                                  'restart circulation.')

                            # SoD for all circulation steps
                            if 'disable-sod' not in self.context.keys():
                                signatures = SignaturesLog.objects.filter(
                                    object_lifecycle_id=self.instance.lifecycle_id,
                                    object_version=self.instance.version).all()
                                for record in signatures:
                                    if self.context['user'] == record.user:
                                        raise serializers.ValidationError(
                                            'SoD conflict - The workflow step {} was already signed by this user.'
                                            .format(record.step))

                            # check if user is in the role of the step of the valid workflow
                            steps_count = len(valid_record.linked_steps_roles)
                            if steps_count == last_step.sequence + 2:
                                self.context['workflow']['productive'] = True
                            for step in valid_record.linked_steps_roles:
                                if step['sequence'] == last_step.sequence + 1:
                                    if not self.context['request'].user.has_role(step['role']):
                                        raise serializers.ValidationError(
                                            'User is not a member of the workflow step role: '
                                            '{}.'.format(step['role']))
                                    # set used step for further use
                                    self.context['workflow']['step'] = step['step']
                                    self.context['workflow']['sequence'] = step['sequence']
                                    break
                        else:
                            raise serializers.ValidationError('Workflow not productive and/or valid.')

                        # set validated workflow record for further use
                        self.context['workflow']['workflow'] = valid_record
                        """

                    # validate comment
                    dialog = self.model.MODEL_CONTEXT.lower()
                    validate_comment(dialog=dialog, data=data, perm='productive')
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='productive',
                                                                        now=self.validate_method.now)

                if self.context['status'] == 'draft':
                    # validate comment
                    dialog = self.model.MODEL_CONTEXT.lower()
                    validate_comment(dialog=dialog, data=data, perm='reject')
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='reject')

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
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='block')
                if self.context['status'] == 'inactive':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='inactivate')
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='inactivate')
                if self.context['status'] == 'archived':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='archive')
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='archive')

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
                self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='productive')

            @require_STATUS_CHANGE
            @require_inactive
            def validate_inactive(self):
                if self.context['status'] != 'blocked':
                    raise serializers.ValidationError('From inactive only blocked is allowed')

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='block')
                self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='block')

            @require_STATUS_CHANGE
            @require_archived
            def validate_archived(self):
                raise serializers.ValidationError('No status change is allowed from archived.')

            @require_NONE
            def validate_updates_only_in_draft(self):
                if self.model.objects.HAS_STATUS:
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
                self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='edit')

            @require_NONE
            @require_LDAP
            def validate_server_check_ldap(self):
                server_check(data)

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
                # validate maximum login attempts and maximum inactive time
                if self.instance.key == 'auth.max_login_attempts' or self.instance.key == 'core.auto_logout' \
                        or self.instance.key == 'core.password_reset_time':
                    try:
                        # try to convert to integer
                        data['value'] = value_to_int(data['value'])
                        # verify that integer is positive
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
        class Post(Validate):
            @require_NEW
            def validate_unique(self):
                if self.model.objects.HAS_STATUS:
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
                self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='add',
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
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='version')
                if self.context['nv'] == 'archived':
                    validate_comment(dialog=dialog, data=data, perm='version_archived')
                    self.validate_method.signature = validate_signature(dialog=dialog, data=data,
                                                                        perm='version_archived')

            @require_NEW_VERSION
            @require_ROLES
            def validate_initial_all_role(self):
                if self.instance.role == Settings.objects.core_initial_role:
                    raise serializers.ValidationError('No new version of initial role {} can be changed.'
                                                      .format(self.instance.role))

            @require_NEW
            @require_LDAP
            def validate_server_check_ldap(self):
                server_check(data)

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
        class Delete(Validate):
            def validate_delete_only_in_draft(self):
                if self.model.objects.HAS_STATUS:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Delete is only permitted in status draft.')

            def validate_comment_signature_delete(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='delete')
                self.validate_method.signature = validate_signature(dialog=dialog, data=data, perm='delete')

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
