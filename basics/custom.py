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
from django.apps import apps
from django.core.exceptions import ValidationError


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


def get_model_by_string(model_str):
    models = apps.all_models['urp']
    models.update(apps.all_models['basics'])
    for model in models:
        if models[model].MODEL_CONTEXT:
            if models[model].MODEL_CONTEXT.lower() == model_str.lower():
                return models[model]
    raise ValidationError('Requested model "{}" does not exist.'.format(model_str))
