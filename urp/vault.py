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

# django imports
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

# app imports
from basics.custom import generate_to_hash, generate_checksum
from .custom import create_log_record
from .models import Users


def validate_password_input(data):
    # field validation
    if 'password_new' not in data:
        raise serializers.ValidationError({'password_new': ['This filed is required.']})
    if 'password_new_verification' not in data:
        raise serializers.ValidationError({'password_new_verification': ['This filed is required.']})

    # django password validation
    try:
        validate_password(data['password_new'])
    except ValidationError as e:
        raise serializers.ValidationError(e)

    # compare passwords
    if data['password_new'] != data['password_new_verification']:
        raise serializers.ValidationError('Passwords must match.')


def create_vault_record():
    pass


def update_vault_record(data, instance, action, user):
    hash_sequence = instance.HASH_SEQUENCE
    fields = dict()
    for attr in hash_sequence:
        if attr in data.keys():
            fields[attr] = data[attr]
            setattr(instance, attr, data[attr])
        else:
            fields[attr] = getattr(instance, attr)
    to_hash = generate_to_hash(fields, hash_sequence=hash_sequence, unique_id=instance.id)
    instance.checksum = generate_checksum(to_hash)
    try:
        instance.full_clean()
    except ValidationError as e:
        raise serializers.ValidationError(e)
    instance.save()

    # create log record
    context = dict()
    context['function'] = 'update_vault'
    context['user'] = user
    create_log_record(model=Users, context=context, action=action, validated_data=data)
