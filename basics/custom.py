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


##########
# GLOBAL #
##########

HASH_ALGORITHM = sha512_crypt


###########
# HASHING #
###########

def generate_checksum(to_hash):
    """Generates a hash string.

        :param to_hash: string to hash
        :type to_hash: str

        :returns: hash string
        :rtype: str
    """
    if not isinstance(to_hash, str):
        raise TypeError('Argument "to_hash" expects type str.')
    return HASH_ALGORITHM.using(rounds=1000).hash(to_hash)


def generate_to_hash(fields, hash_sequence, hash_sequence_mtm=list(), record_id=None, fixtures=False):
    """Generic function to build hash string for record fields.

    :param fields: dictionary containing all mandatory fields and values
    :type fields: dict

    :param hash_sequence: list of fields in correct hash order
    :type hash_sequence: list

    :param hash_sequence_mtm: list of many to many fields in correct hash order, default is None
    :type hash_sequence_mtm: list

    :param record_id: id of the record to hash, default is no id
    :type record_id: int / AutoField

    :param fixtures: flag to determine internal call or for fixtures, default is False for internal
    :type fixtures: bool

    :return: string to hash
    :rtype: str
    """
    if record_id:
        to_hash = 'id:{};'.format(record_id)
    else:
        to_hash = str()
    # add static fields
    for field in hash_sequence:
        to_hash += '{}:{};'.format(field, fields[field])
    # add many to many fields
    if hash_sequence_mtm:
        for mtm_field in hash_sequence_mtm:
            # check if mtm field is in the fields dict
            if mtm_field in fields.keys():
                # deal with plain list of integers from fixtures
                if fixtures:
                    fields[mtm_field].sort()
                    to_hash += '{}:{};'.format(mtm_field, fields[mtm_field])
                else:
                    tmp_list = list()
                    for item in fields[mtm_field]:
                        tmp_list.append(item.id)
                        # sort lists to guarantee same has results every time
                    tmp_list.sort()
                    to_hash += '{}:{};'.format(mtm_field, tmp_list)
            else:
                to_hash += '{}:[];'.format(mtm_field)
    # some pepper for the soup
    to_hash += settings.SECRET_HASH_KEY
    return to_hash


def intersection_two(list_one, list_two):
    return list(set(list_one) & set(list_two))
