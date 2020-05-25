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

# rest imports
from rest_framework import serializers

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError

# app imports
from basics.models import CentralLog
from urp.models.settings import Settings
from basics.custom import generate_checksum, generate_to_hash, str_list_change
from urp.models.logs.signatures import SignaturesLog


def create_central_log_record(log_id, now, action, context, user):
    obj = CentralLog()
    data = dict()
    data['action'] = action
    data['user'] = user
    data['timestamp'] = now
    data['context'] = context
    data['log_id'] = log_id
    hash_sequence = obj.HASH_SEQUENCE
    for attr in hash_sequence:
        if attr in data.keys():
            setattr(obj, attr, data[attr])
    to_hash = generate_to_hash(fields=data, hash_sequence=hash_sequence, unique_id=obj.id)
    obj.checksum = generate_checksum(to_hash)
    try:
        obj.full_clean()
    except ValidationError as e:
        raise e
    else:
        obj.save()


def create_log_record(model, context, action, validated_data, signature, obj=None, now=None, central=True):
    if not now:
        now = timezone.now()
    log_obj = model.objects.LOG_TABLE()
    log_hash_sequence = log_obj.HASH_SEQUENCE

    # get data of last log record instead of new data
    if not obj:
        filter_dict = {model.UNIQUE: context['user']}
        obj = model.objects.LOG_TABLE.objects.last_record(filter_dict=filter_dict, order_str='timestamp')

    # add log related data
    if context['function'] == 'init':
        validated_data['user'] = Settings.objects.core_system_username
    else:
        validated_data['user'] = context['user']
    validated_data['timestamp'] = now
    validated_data['action'] = action

    # for delete make predecessors a list, because internal value
    validated_data = str_list_change(data=validated_data, key='predecessors', target=list)

    # add signature log
    if signature:
        validated_data['way'] = 'signature'
    else:
        validated_data['way'] = 'logging'

    # comment checking
    if 'comment' not in validated_data.keys():
        validated_data['comment'] = Settings.objects.core_devalue
    # if comment is provided and empty then devalue
    else:
        if validated_data['comment'] == '' or not validated_data['comment']:
            validated_data['comment'] = Settings.objects.core_devalue

    # generate hash
    for attr in log_hash_sequence:
        if attr in validated_data.keys():
            setattr(log_obj, attr, validated_data[attr])
        else:
            if log_obj.MODEL_ID == '27':
                continue
            try:
                setattr(log_obj, attr, getattr(obj, attr))
                validated_data[attr] = getattr(obj, attr)
            except AttributeError:
                pass
    setattr(log_obj, 'lifecycle_id', obj.lifecycle_id)
    fields = validated_data.copy()
    fields = str_list_change(data=fields, key='predecessors', target=str)
    to_hash = generate_to_hash(fields=fields, hash_sequence=log_hash_sequence, unique_id=log_obj.id,
                               lifecycle_id=obj.lifecycle_id)
    log_obj.checksum = generate_checksum(to_hash)
    try:
        log_obj.full_clean()
    except ValidationError as e:
        raise e
    else:
        if central:
            create_central_log_record(log_id=log_obj.id, now=now, action=action, context=model.MODEL_CONTEXT,
                                      user=validated_data['user'])
        log_obj.save()


def create_signatures_record(user, timestamp, context, obj, workflow, step, sequence, action, cycle):
    log_obj = SignaturesLog()
    log_hash_sequence = log_obj.HASH_SEQUENCE
    validated_data = dict()

    validated_data['user'] = user
    validated_data['timestamp'] = timestamp
    validated_data['workflow'] = workflow.workflow
    validated_data['workflow_lifecycle_id'] = workflow.lifecycle_id
    validated_data['workflow_version'] = workflow.version
    validated_data['context'] = context
    validated_data['object'] = getattr(obj, obj.UNIQUE)
    validated_data['object_version'] = obj.version
    validated_data['object_lifecycle_id'] = obj.lifecycle_id
    validated_data['step'] = step
    validated_data['sequence'] = sequence
    validated_data['cycle'] = cycle
    validated_data['action'] = action

    # generate hash
    for attr in log_hash_sequence:
        setattr(log_obj, attr, validated_data[attr])
    to_hash = generate_to_hash(fields=validated_data, hash_sequence=log_hash_sequence, unique_id=log_obj.id,
                               lifecycle_id=log_obj.lifecycle_id)
    log_obj.checksum = generate_checksum(to_hash)

    try:
        log_obj.full_clean()
    except ValidationError as e:
        raise e
    else:
        log_obj.save()


def validate_comment(dialog, data, perm):
    if dialog not in ['accesslog', 'profile']:
        if Settings.objects.dialog_comment(dialog=dialog, perm=perm) == 'mandatory':
            # validate if comment field in payload
            if 'com' not in data:
                raise serializers.ValidationError({'comment': ['This field is required.']})
            # validate if comment not empty
            if data['com'] == '' or not data['com']:
                raise serializers.ValidationError({'comment': ['This field is required.']})

            # change "com" to "comment" for natural log record
            data['comment'] = data['com']
            del data['com']

        if Settings.objects.dialog_comment(dialog=dialog, perm=perm) == 'optional':
            # validate if comment field in payload
            if 'com' in data:
                # change "com" to "comment" for natural log record
                data['comment'] = data['com']
                del data['com']


def validate_signature(request, dialog, data, perm, logged_in_user=None):
    if dialog not in ['accesslog', 'profile']:
        error_dict = {}
        error_text = ['This filed is required.']
        error_text_data_type = ['This filed requires data type string.']
        if Settings.objects.dialog_signature(dialog=dialog, perm=perm):
            # validate for signature username and password field
            if 'sig_user' not in data:
                error_dict['sig_user'] = error_text
            elif data['sig_user'] == '' or not data['sig_user']:
                error_dict['sig_user'] = error_text
            elif not isinstance(data['sig_user'], str):
                error_dict['sig_user'] = error_text_data_type
            if 'sig_pw' not in data:
                error_dict['sig_pw'] = error_text
            elif data['sig_pw'] == '' or not data['sig_pw']:
                error_dict['sig_pw'] = error_text
            elif not isinstance(data['sig_pw'], str):
                error_dict['sig_pw'] = error_text_data_type

            if error_dict:
                raise serializers.ValidationError(error_dict)

            # auth check
            try:
                authenticate(request=request, username=data['sig_user'], password=data['sig_pw'], signature=True)
            except serializers.ValidationError as e:
                error_dict['sig_user'] = e.detail
                error_dict['sig_pw'] = e.detail
                raise serializers.ValidationError(error_dict)
            else:
                if logged_in_user:
                    if data['sig_user'] != logged_in_user and settings.DEFAULT_SIGNATURE_USER_LOCK:
                        error_dict['sig_user'] = ['Signature user must be logged in user.']
                        raise serializers.ValidationError(error_dict)

            # return true for success
            return True
