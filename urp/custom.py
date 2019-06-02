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

# django imports
from django.utils import timezone
from django.core.exceptions import ValidationError

# app imports
from basics.models import CentralLog, Settings
from basics.custom import generate_checksum, generate_to_hash


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


def create_log_record(model, context, action, obj=None, validated_data=None, now=None):
    if not now:
        now = timezone.now()
    log_obj = model.objects.LOG_TABLE()
    log_hash_sequence = log_obj.HASH_SEQUENCE

    # get data of last log record instead of new data
    if not validated_data:
        obj = model.objects.LOG_TABLE.objects.last_record(order_str='timestamp')
        validated_data = dict()
        for attr in log_hash_sequence:
            validated_data[attr] = getattr(obj, attr)

    # add log related data
    if context['function'] == 'init':
        validated_data['user'] = Settings.objects.core_system_username
    else:
        validated_data['user'] = context['user']
    validated_data['timestamp'] = now
    validated_data['action'] = action
    # generate hash
    for attr in log_hash_sequence:
        if attr in validated_data.keys():
            setattr(log_obj, attr, validated_data[attr])
    setattr(log_obj, 'lifecycle_id', obj.lifecycle_id)
    to_hash = generate_to_hash(fields=validated_data, hash_sequence=log_hash_sequence, unique_id=log_obj.id,
                               lifecycle_id=obj.lifecycle_id)
    log_obj.checksum = generate_checksum(to_hash)
    try:
        log_obj.full_clean()
    except ValidationError as e:
        raise e
    else:
        create_central_log_record(log_id=log_obj.id, now=now, action=action, context=model.MODEL_CONTEXT,
                                  user=validated_data['user'])
        log_obj.save()
