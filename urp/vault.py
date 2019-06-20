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
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import validate_password

# app imports
from basics.custom import generate_to_hash, generate_checksum
from .custom import create_log_record
from .models import Users, Vault


def validate_password_input(data, instance=None, password='password_new', initial=False,
                            password_verification='password_new_verification'):
    if initial:
        password = 'password'
        password_verification = 'password_verification'

    # field validation
    error_dict = dict()
    field_error = ['This filed is required.']

    if password not in data:
        error_dict[password] = field_error
    if password_verification not in data:
        error_dict[password] = field_error

    if error_dict:
        raise serializers.ValidationError(error_dict)

    # django password validation
    try:
        validate_password(data[password])
    except ValidationError as e:
        raise serializers.ValidationError(e)

    # compare passwords
    if data[password] != data[password_verification]:
        raise serializers.ValidationError('Passwords must match.')

    # FO-147: new password can not be equal to previous password
    if instance:
        if check_password(data[password], instance.password):
            raise serializers.ValidationError('New password is identical to previous password. '
                                              'Password must be changed.')


def create_update_vault(data, password='password_new', initial=False, instance=None, action=None, user=None, log=True,
                        now=None):
    # create new instance if not passed
    if not instance:
        instance = Vault()

    if initial:
        password = 'password'

    # FO-132: hash password before saving
    if password in data.keys():
        raw_pw = data[password]
        hashed_pw = make_password(raw_pw)
        data['password'] = hashed_pw
        data['initial_password'] = True

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
    if log:
        context = dict()
        context['function'] = 'update_vault'
        context['user'] = user
        create_log_record(model=Users, context=context, action=action, validated_data=data, now=now)
