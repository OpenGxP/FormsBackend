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
from collections import OrderedDict

# rest imports
from rest_framework import serializers
from rest_framework.settings import api_settings
from rest_framework.compat import Mapping
from rest_framework.fields import get_error_detail, set_value, SkipField

# custom imports
from urp.models import Permissions, Users, Roles, AccessLog, PermissionsLog, Vault
from basics.custom import generate_checksum, generate_to_hash
from basics.models import Status, AVAILABLE_STATUS, StatusLog, CentralLog, CHAR_DEFAULT
from urp.models.settings import Settings
from urp.decorators import require_STATUS_CHANGE, require_POST, require_DELETE, require_PATCH, require_NONE, \
    require_NEW_VERSION, require_status, require_USERS, require_NEW, require_EMAIL, require_ROLES
from urp.custom import create_log_record, validate_comment, validate_signature
from urp.backends.Email import MyEmailBackend
from urp.models.profile import Profile
from urp.models.workflows.workflows import Workflows
from urp.models.logs.signatures import SignaturesLog
from urp.validators import validate_only_ascii, validate_no_specials_reduced, validate_no_space, validate_no_numbers

# django imports
from django.db.models import CharField, IntegerField, DateTimeField, BooleanField
from django.utils import timezone
from django.db import IntegrityError
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import ValidationError as DjangoValidationError


##########
# GLOBAL #
##########

class GlobalReadWriteSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        serializers.ModelSerializer.__init__(self, *args, **kwargs)

        # request
        if 'request' in self.context:
            self.request = self.context['request']
        else:
            self.request = None

        # function
        if 'function' in self.context:
            self.function = self.context['function']

        # validate only
        if 'validate_only' in self.context:
            self.validate_only = self.context['validate_only']
        else:
            self.validate_only = False

        # flags
        self.new_version = False
        self.status_change = False

        # set workflow flag
        self.context['workflow'] = {}

        # sub elements
        self.sub_parents = []
        self.sub_parent_sequences = []
        # sequence check
        self.global_sequence_check = {}

        self._signature = None
        if 'signature' in self.context.keys():
            self.signature = self.context['signature']

        self.now = getattr(self.request, settings.ATTR_NOW, timezone.now())
        if 'now' in self.context.keys():
            self.now = self.context['now']

        self.user = None
        if 'user' in self.context.keys():
            self.user = self.context['user']

        self.my_errors = OrderedDict()

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

    @staticmethod
    # FO-282: adapted this method to control the item key, default is sequence to not alter workflow behavior
    def create_update_record(error_dict, item, value, key='sequence'):
        if item[key] in error_dict:
            error_dict[item[key]].update(value)
        else:
            error_dict[item[key]] = value

    # FO-282: new method to update error dictionaries containing sections, for forms only
    @staticmethod
    def create_update_record_section(error_dict, item, value):
        if item['section'] in error_dict.keys():
            if item['sequence'] in error_dict[item['section']].keys():
                error_dict[item['section']][item['sequence']].update(value)
            else:
                error_dict[item['section']][item['sequence']] = value
        else:
            error_dict[item['section']] = {item['sequence']: value}

    # FO-282: new method to merge error dicts on section and sequence level, for forms only
    @staticmethod
    def merge_error_dicts(base, merge):
        for section in merge:
            if section in base:
                for sequence in merge[section]:
                    if sequence in base[section]:
                        base[section][sequence].update(merge[section][sequence])
                    else:
                        base[section][sequence] = merge[section][sequence]
            else:
                base[section] = merge[section]

    def validate_predecessors(self, value, key):
        error_dict = {}
        predecessors_check = []
        for item in value:
            # predecessors are optional
            if 'predecessors' in item.keys():
                if not isinstance(item['predecessors'], list):
                    error_dict[item['sequence']] = {'predecessors': ['Predecessors not a valid array.']}
                elif not item['predecessors']:
                    del item['predecessors']
                    continue
                # validate predecessors for string items
                for pred in item['predecessors']:
                    if not isinstance(pred, str):
                        error_dict[item['sequence']] = {'predecessors': ['This field requires data type string.']}
                predecessors_check.append(item['predecessors'])

                # FO-191: unique items shall not self reference
                if item[key] in item['predecessors']:
                    error_dict[item['sequence']] = {'predecessors': ['Predecessors can not be self referenced.']}

        # check that predecessors exist
        for item in predecessors_check:
            for each in item:
                # FO-196: treat [""] array as no predecessor
                if each == '':
                    continue
                if each not in self.sub_parents:
                    for i in value:
                        if 'predecessors' in i.keys():
                            if each in i['predecessors']:
                                error_dict[i['sequence']] = {'predecessors':
                                                             ['Predecessors must only contain valid {}s.'.format(key)]}

        if error_dict:
            raise serializers.ValidationError(error_dict)

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
            # FO-282: save sequences of parents (sections)
            self.sub_parent_sequences = sequence_check

    # FO-239: to control workflow keys, new variable error_key
    def validate_sub(self, value, key, error_key, parent=None):
        error_dict = {}
        unique_check = []

        for item in value:
            if key not in item.keys():
                # FO-282: for sub elements inf forms, consider section
                if not parent:
                    error = {item['sequence']: {key: ['This field is required.']}}
                    # FO-239: pass error_key to field based error collection method
                    self.create_update_record(error_dict=error_dict, item=item, value=error, key=error_key)
                else:
                    error_dict[item['sequence']] = {key: ['This field is required.']}
            else:
                if not item[key]:
                    # FO-282: for sub elements inf forms, consider section
                    if not parent:
                        error = {item['sequence']: {key: ['This field is required.']}}
                        # FO-239: pass error_key to field based error collection method
                        self.create_update_record(error_dict=error_dict, item=item, value=error, key=error_key)
                    else:
                        error_dict[item['sequence']] = {key: ['This field is required.']}

            # continue if no value
            # FO-292: do not validate further if errors exist must look on new level of sections in forms
            if parent:
                if item['sequence'] in error_dict:
                    continue
            else:
                if item[error_key] in error_dict:
                    if item['sequence'] in error_dict[item[error_key]]:
                        continue

            try:
                validate_only_ascii(item[key])
                validate_no_specials_reduced(item[key])
                validate_no_space(item[key])
                validate_no_numbers(item[key])
            except serializers.ValidationError as e:
                # FO-282: for sub elements inf forms, consider section
                if not parent:
                    error = {item['sequence']: {key: e.detail}}
                    # FO-239: pass error_key to field based error collection method
                    self.create_update_record(error_dict=error_dict, item=item, value=error, key=error_key)
                else:
                    error_dict[item['sequence']] = {key: e.detail}
            unique_check.append(item[key])

        if error_dict:
            raise serializers.ValidationError(error_dict)

        # validate key unique characteristic
        if len(unique_check) != len(set(unique_check)):
            duplicates = set([x for x in unique_check if unique_check.count(x) > 1])
            for item in duplicates:
                for record in value:
                    if record[key] == item:
                        # FO-282: for sub elements inf forms, consider section
                        if not parent:
                            error = {item['sequence']: {key: ['This field must be unique.']}}
                            # FO-239: pass error_key to field based error collection method
                            self.create_update_record(error_dict=error_dict, item=item, value=error, key=error_key)
                        else:
                            error_dict[record['sequence']] = {key: ['This field must be unique.']}

        if parent:
            self.sub_parents = unique_check

        if error_dict:
            raise serializers.ValidationError(error_dict)

        return value

    def validated_form_fields(self, value):
        error_dict = {}
        for item in value:
            # validate mandatory field
            if 'mandatory' not in item.keys():
                # FO-282: for sub elements inf forms, consider section
                self.create_update_record_section(error_dict=error_dict, item=item,
                                                  value={'mandatory': ['This field is required.']})
            elif not isinstance(item['mandatory'], bool):
                # FO-282: for sub elements inf forms, consider section
                self.create_update_record_section(error_dict=error_dict, item=item,
                                                  value={'mandatory': ['This field requires data type boolean.']})

            # field must be in existing section
            # FO-282: for sub elements inf forms, consider section
            if 'section' not in item.keys():
                self.create_update_record_section(error_dict=error_dict, item=item,
                                                  value={'section': ['This field is required.']})
            elif not isinstance(item['section'], int):
                self.create_update_record_section(error_dict=error_dict, item=item,
                                                  value={'section': ['This field requires data type integer.']})
            elif item['section'] not in self.sub_parent_sequences:
                self.create_update_record_section(error_dict=error_dict, item=item,
                                                  value={'section': ['Section must be valid.']})

            # validate optional instruction
            if 'instruction' in item.keys():
                if not isinstance(item['instruction'], str):
                    # FO-282: for sub elements inf forms, consider section
                    self.create_update_record_section(error_dict=error_dict, item=item,
                                                      value={'instruction': ['This field requires data type string.']})
                elif len(item['instruction']) > CHAR_DEFAULT:
                    # FO-282: for sub elements inf forms, consider section
                    self.create_update_record_section(error_dict=error_dict, item=item,
                                                      value={'instruction':
                                                             ['This field must not be longer than {} characters.'
                                                              .format(CHAR_DEFAULT)]})

        if error_dict:
            raise serializers.ValidationError(error_dict)

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

    # Fo-251: new method to deal with valid to upgrade and consider no valid from
    def update_previous_version_valid_to(self):
        prev_instance = self.model.objects.get_previous_version(self.instance)
        if not self.instance.valid_from:
            valid_to = self.now
        else:
            valid_to = self.instance.valid_from
        data = {'valid_to': valid_to}
        # if no valid_to, always set
        valid_to_prev_version = getattr(prev_instance, 'valid_to')
        if not valid_to_prev_version:
            self.update(instance=prev_instance, validated_data=data, self_call=True, now=self.now)
        else:
            # only overlapping validity ranges
            valid_from = getattr(self.instance, 'valid_from', None)
            if not valid_from:
                if self.now < valid_to_prev_version:
                    self.update(instance=prev_instance, validated_data=data, self_call=True,
                                now=self.now)
            else:
                if getattr(self.instance, 'valid_from') < valid_to_prev_version:
                    self.update(instance=prev_instance, validated_data=data, self_call=True,
                                now=self.now)

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
                # FO-239: remove valid from/to of new version objects
                if attr == 'valid_from' or attr == 'valid_to':
                    continue
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
                                  action=settings.DEFAULT_LOG_CREATE, signature=self.signature, now=self.now,
                                  request=self.request)

                if obj.sub_tables():
                    for table, key in obj.sub_tables().items():
                        if key in validated_data:
                            for record in validated_data[key]:
                                create_log_record(model=table, context=self.context, obj=obj, now=self.now,
                                                  validated_data=record, action=settings.DEFAULT_LOG_CREATE,
                                                  signature=self.signature, central=False, request=self.request)

        except IntegrityError as e:
            if 'UNIQUE constraint' in e.args[0]:
                raise serializers.ValidationError('Object already exists.')
        else:
            # update instance in case of POST methods with initial instance (e.g. new version)
            self.instance = obj
            return obj

    # FO-251: route self_call
    def update_specific(self, validated_data, instance, self_call=None):
        return validated_data, instance

    # update
    def update(self, instance, validated_data, self_call=None, now=None):
        action = settings.DEFAULT_LOG_UPDATE
        model = self.model
        if 'function' in self.context.keys():
            # FO-251: in self call self.x attributes remain, therefore exclude this when self_call
            if self.context['function'] == 'status_change' and not self_call:
                self.status_change = True
                action = settings.DEFAULT_LOG_STATUS
                # FO-221: changed action to "update" for valid to updates of previous version
                if self_call:
                    action = settings.DEFAULT_LOG_UPDATE
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])

                # if "valid_from" is empty, set "valid_from" to timestamp of set productive
                # FO-234: do not set valid from via regular mechanism
                if self.context['status'] == 'productive' and not self.instance.valid_from and not self_call \
                        and not self.model.objects.WF_MGMT:
                    validated_data['valid_from'] = self.now

                # change "valid_to" of previous version to "valid from" of new version
                # only for set productive step
                # Fo-251: call previous version method
                if self.context['status'] == 'productive' and self.instance.version > 1 and not self_call \
                        and not self.model.objects.WF_MGMT:
                    self.update_previous_version_valid_to()
            else:
                # FO-251: in self call attributes remain, therefore exclude this when self_call
                if model.objects.HAS_STATUS and not self_call:
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
        # FO-251: route self_call
        validated_data, instance = self.update_specific(validated_data, instance, self_call)

        hash_sequence = instance.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            # FO-246: do not update fields that shall not be altered by users
            if attr in model.NO_UPDATE:
                fields[attr] = getattr(instance, attr)
                continue
            if attr in validated_data.keys():
                fields[attr] = validated_data[attr]
                setattr(instance, attr, validated_data[attr])
            else:
                # FO-246: delete field values if no data is received
                if self.status_change:
                    fields[attr] = getattr(instance, attr)
                else:
                    field = getattr(model, '_meta').get_field(attr)
                    if getattr(instance, attr, None):
                        if attr == 'status_id':
                            fields[attr] = getattr(instance, attr)
                        elif isinstance(field, CharField):
                            setattr(instance, attr, '')
                            fields[attr] = ''
                        elif isinstance(field, DateTimeField) or isinstance(field, IntegerField):
                            setattr(instance, attr, None)
                            fields[attr] = None
                        elif isinstance(field, BooleanField):
                            setattr(instance, attr, False)
                            fields[attr] = False
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
            self.request = validate_method.request
            self.instance = validate_method.instance
            self.function = validate_method.context['function']
            self.validate_method = validate_method
            self.now = validate_method.now
            self.my_errors = validate_method.my_errors
            self.validate_only = validate_method.validate_only

            self.user = None
            if 'user' in self.context.keys():
                self.user = self.context['user']

            self.method_list = [func for func in dir(self) if callable(getattr(self, func))]
            self.validate()

        def validate(self):
            if self.__class__.__name__ == 'Post':
                rem = 'validate_post_specific'
                if rem in self.method_list:
                    self.method_list.remove(rem)
                    getattr(self, 'validate_post_specific')()
            elif self.__class__.__name__ == 'Patch':
                rem = 'validate_patch_specific'
                if rem in self.method_list:
                    self.method_list.remove(rem)
                    getattr(self, 'validate_patch_specific')()
            elif self.__class__.__name__ == 'Delete':
                rem = 'validate_delete_specific'
                if rem in self.method_list:
                    self.method_list.remove(rem)
                    getattr(self, 'validate_delete_specific')()

            for method in self.method_list:
                if method.startswith('validate_'):
                    getattr(self, method)()

    def to_internal_value(self, data):
        """
        Dict of native values <- Dict of primitive datatypes.
        """
        if not isinstance(data, Mapping):
            message = self.error_messages['invalid'].format(
                datatype=type(data).__name__
            )
            raise serializers.ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: [message]
            }, code='invalid')

        ret = OrderedDict()
        fields = self._writable_fields

        for field in fields:
            validate_method = getattr(self, 'validate_' + field.field_name, None)
            primitive_value = field.get_value(data)
            try:
                validated_value = field.run_validation(primitive_value)
                if validate_method is not None:
                    validated_value = validate_method(validated_value)
            except serializers.ValidationError as exc:
                self.my_errors[field.field_name] = exc.detail
            except DjangoValidationError as exc:
                self.my_errors[field.field_name] = get_error_detail(exc)
            except SkipField:
                pass
            else:
                set_value(ret, field.source_attrs, validated_value)

        # if self.my_errors:
        # raise serializers.ValidationError(self.my_errors)
        if self.model == Users:
            if 'password' in data:
                set_value(ret, ['password'], data['password'])
            if 'password_verification' in data:
                set_value(ret, ['password_verification'], data['password_verification'])

        return ret

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

                # FO-292: execute unique field validation if no errors exist for relevant field(s)
                if isinstance(self.model.UNIQUE, list):
                    if not any(e in self.my_errors.keys() for e in self.model.UNIQUE):
                        self.field_unique()
                else:
                    if self.model.UNIQUE not in self.my_errors.keys():
                        self.field_unique()

                if self.my_errors:
                    raise serializers.ValidationError(self.my_errors)

            # FO-292: renamed field to not perform validation again
            @require_NONE
            def field_unique(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    # verify that record remains unique
                    if self.instance.version > 1:
                        if isinstance(self.model.UNIQUE, list):
                            for field in self.model.UNIQUE:
                                if getattr(self.instance, field) != data[field]:
                                    self.my_errors[field] = ['Attribute is immutable.']
                        else:
                            if getattr(self.instance, self.model.UNIQUE) != data[self.model.UNIQUE]:
                                self.my_errors[self.model.UNIQUE] = ['Attribute is immutable.']
                    else:
                        # if unique is not only one, but a list of fields
                        if isinstance(self.model.UNIQUE, list):
                            _filter = dict()
                            for field in self.model.UNIQUE:
                                _filter[field] = data[field]
                        else:
                            _filter = {self.model.UNIQUE: data[self.model.UNIQUE]}
                        query = self.model.objects.filter(**_filter).all()
                        if query:
                            for item in query:
                                if self.instance.lifecycle_id != item.lifecycle_id:
                                    # FO-210: improve error message
                                    tag = getattr(query[0], 'tag', None)
                                    # FO-292: adapted error collection to provide field based error messages
                                    if tag:
                                        error = 'Record(s) already exists. Record is only visible ' \
                                                'for users with access to tag "{}".'.format(tag)
                                    else:
                                        error = 'Record(s) already exist.'

                                    if isinstance(self.model.UNIQUE, list):
                                        for f in self.model.UNIQUE:
                                            self.my_errors[f] = [error]
                                    else:
                                        self.my_errors[self.model.UNIQUE] = [error]
                                    break

            @require_STATUS_CHANGE
            def validate_correct_status(self):
                # verify if valid status
                if self.context['status'] not in AVAILABLE_STATUS:
                    raise serializers.ValidationError('Target status not valid. Only "{}" are allowed.'
                                                      .format(AVAILABLE_STATUS))

            # FO-228: validate valid from/to at start circulation
            @require_STATUS_CHANGE
            @require_draft
            def validate_draft_validity_ranges(self):
                if 'disable-sod' not in self.context:
                    # if record has valid_from, validate it is not in the past
                    if self.instance.valid_from:
                        if self.instance.valid_from < self.now:
                            raise serializers.ValidationError('Valid from can not be in the past.')
                    # if record has valid_to, validate it is not in the past
                    if self.instance.valid_to:
                        if self.instance.valid_to < self.now:
                            raise serializers.ValidationError('Valid to can not be in the past.')
                    # if record has both, valid_from and valid_to, validate from can not be after two
                    if self.instance.valid_to and self.instance.valid_from:
                        if self.instance.valid_from > self.instance.valid_to:
                            raise serializers.ValidationError('Valid from can not be after valid to.')

            # FO-228: validate valid from/to at set productive
            @require_STATUS_CHANGE
            @require_circulation
            def validate_circulation_validity_range(self):
                if 'disable-sod' not in self.context:
                    # because set productive can be anytime after set in circulation, validity range is validated again
                    if self.context['status'] == 'productive':
                        # if record has valid_from, validate it is not in the past
                        if self.instance.valid_from:
                            if self.instance.valid_from < self.now:
                                raise serializers.ValidationError('Valid from can not be in the past.')
                        # if record has valid_to, validate it is not in the past
                        if self.instance.valid_to:
                            if self.instance.valid_to < self.now:
                                raise serializers.ValidationError('Valid to can not be in the past.')

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
                    # FO-251: record may not have valid from, therefore only check, if own valid from available
                    if self.instance.valid_from:
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
                                                                    data=data, perm='circulation', request=self.request)

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
                    if 'disable-sod' not in self.context.keys() and not self.model.objects.WF_MGMT \
                            and not self.request.user.has_role(Settings.objects.core_initial_role):
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
                                if not self.request.user.has_role(step.role):
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
                            if self.request.user.has_role(step.role):
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
                                                                    data=data, perm=perm, request=self.request)

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
                                                                        data=data, perm='block', request=self.request)
                if self.context['status'] == 'inactive':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='inactivate')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='inactivate',
                                                                        request=self.request)
                if self.context['status'] == 'archived':
                    # validate comment
                    validate_comment(dialog=dialog, data=data, perm='archive')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='archive', request=self.request)

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
                                                                    data=data, perm='productive', request=self.request)

            @require_STATUS_CHANGE
            @require_inactive
            def validate_inactive(self):
                if self.context['status'] != 'blocked':
                    raise serializers.ValidationError('From inactive only blocked is allowed')

                # validate comment
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='block')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='block', request=self.request)

            @require_STATUS_CHANGE
            @require_archived
            def validate_archived(self):
                raise serializers.ValidationError('No status change is allowed from archived.')

            @require_NONE
            def validate_updates_only_in_draft(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Updates are only permitted in status draft.')

            @require_NONE
            def validate_comment_signature_edit(self):
                if not self.validate_only:
                    dialog = self.model.MODEL_CONTEXT.lower()
                    validate_comment(dialog=dialog, data=data, perm='edit')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='edit', request=self.request)

            @require_NONE
            @require_EMAIL
            def validate_server_check_email(self):
                try:
                    MyEmailBackend(**data, check_call=True).open()
                except ImproperlyConfigured as e:
                    raise serializers.ValidationError(e)

        @require_POST
        class Post(self.Validate):
            def validate_post_specific(self):
                self.validate_method.validate_post_specific(data)

                # FO-292: execute unique field validation if no errors exist for relevant field(s)
                if isinstance(self.model.UNIQUE, list):
                    if not any(e in self.my_errors.keys() for e in self.model.UNIQUE):
                        self.field_unique()
                else:
                    if self.model.UNIQUE not in self.my_errors.keys():
                        self.field_unique()

                if self.my_errors:
                    raise serializers.ValidationError(self.my_errors)

            # FO-292: renamed field to not perform validation again
            @require_NEW
            def field_unique(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    # if unique is not only one, but a list of fields
                    if isinstance(self.model.UNIQUE, list):
                        _filter = dict()
                        for field in self.model.UNIQUE:
                            _filter[field] = data[field]
                    else:
                        _filter = {self.model.UNIQUE: data[self.model.UNIQUE]}
                    query = self.model.objects.filter(**_filter).all()
                    if query:
                        # FO-210: improve error message
                        tag = getattr(query[0], 'tag', None)
                        # FO-292: adapted error collection to provide field based error messages
                        if tag:
                            error = 'Record(s) already exists. Record is only visible for users with access to '
                            'tag "{}".'.format(tag)
                        else:
                            error = 'Record(s) already exist.'

                        if isinstance(self.model.UNIQUE, list):
                            for f in self.model.UNIQUE:
                                self.my_errors[f] = [error]
                        else:
                            self.my_errors[self.model.UNIQUE] = [error]

            @require_NEW
            def validate_comment_signature_add(self):
                if not self.validate_only:
                    dialog = self.model.MODEL_CONTEXT.lower()
                    validate_comment(dialog=dialog, data=data, perm='add')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='add', request=self.request)

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
                                                                        data=data, perm='version', request=self.request)
                if self.context['nv'] == 'archived':
                    validate_comment(dialog=dialog, data=data, perm='version_archived')
                    self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                        data=data, perm='version_archived',
                                                                        request=self.request)

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

        @require_DELETE
        class Delete(self.Validate):
            def validate_delete_specific(self):
                self.validate_method.validate_delete_specific(data)

                if self.my_errors:
                    raise serializers.ValidationError(self.my_errors)

            def validate_delete_only_in_draft(self):
                if self.model.objects.HAS_STATUS and not self.model.objects.IS_RT:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Delete is only permitted in status draft.')

            def validate_comment_signature_delete(self):
                dialog = self.model.MODEL_CONTEXT.lower()
                validate_comment(dialog=dialog, data=data, perm='delete')
                self.validate_method.signature = validate_signature(logged_in_user=self.user, dialog=dialog,
                                                                    data=data, perm='delete', request=self.request)

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
