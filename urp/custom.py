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

from django.utils import timezone
from django.core.exceptions import ValidationError

# app imports
from django.conf import settings
from basics.models import CentralLog
from basics.custom import generate_checksum, generate_to_hash


class UserName(object):
    def __init__(self, first_name, last_name, existing_users):
        self.first_name = first_name.lower()
        self.last_name = last_name.lower()
        self.length = len(first_name)
        self._tmp_first_name = str()
        self.existing = existing_users

    @property
    def tmp_first_name(self):
        return self._tmp_first_name

    @tmp_first_name.setter
    def tmp_first_name(self, value):
        self._tmp_first_name = value

    @property
    def algorithm(self):
        """Function to generate unique user names.

            :returns: username
            :rtype: str
        """
        for x in range(self.length):
            first_name = '{}{}'.format(self.tmp_first_name, self.first_name[x])
            username = '{}{}'.format(self.last_name, first_name)
            if username in self.existing:
                self.tmp_first_name = first_name
            else:
                return username
        for x in range(1000):
            first_name = '{}{}'.format(self.first_name, x + 1)
            username = '{}{}'.format(self.last_name, first_name)
            if username in self.existing:
                self.tmp_first_name = first_name
            else:
                return username


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


def create_log_record(model, context, obj, validated_data, action):
    now = timezone.now()
    log_obj = model.objects.LOG_TABLE()
    # add log related data
    if context['function'] == 'init':
        validated_data['user'] = settings.DEFAULT_SYSTEM_USER
    else:
        validated_data['user'] = context['user']
    validated_data['timestamp'] = now
    validated_data['action'] = action
    # generate hash
    log_hash_sequence = log_obj.HASH_SEQUENCE
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
