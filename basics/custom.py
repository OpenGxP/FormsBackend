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
from passlib.hash import sha512_crypt

# django imports
from django.conf import settings
from django.utils import timezone


##########
# GLOBAL #
##########

HASH_ALGORITHM = sha512_crypt


###########
# HASHING #
###########

def generate_checksum(to_hash):
    """
    Generates a hash string.
    """
    return HASH_ALGORITHM.using(rounds=1000).hash(to_hash)


def generate_to_hash(fields, hash_sequence, unique_id, lifecycle_id=None):
    """
    Generic function to build hash string for record fields.
    """
    to_hash = 'id:{};'.format(unique_id)
    if lifecycle_id:
        to_hash += 'lifecycle_id:{};'.format(lifecycle_id)
    # add static fields
    for attr in hash_sequence:
        try:
            to_hash += '{}:{};'.format(attr, fields[attr])
        except KeyError:
            if attr == 'valid_to' or attr == 'valid_from':
                to_hash += '{}:None;'.format(attr)
            else:
                to_hash += '{}:;'.format(attr)
    # some pepper for the soup
    to_hash += settings.SECRET_HASH_KEY
    return to_hash


def intersection_two(list_one, list_two):
    return list(set(list_one) & set(list_two))


def create_log_record(model, context, obj, validated_data, action):
    log_obj = model.objects.LOG_TABLE()
    # add log related data
    if context['function'] == 'init':
        validated_data['user'] = settings.DEFAULT_SYSTEM_USER
    else:
        validated_data['user'] = context['user']
    validated_data['timestamp'] = timezone.now()
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
    log_obj.save()
