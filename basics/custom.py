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


def generate_to_hash(fields, ids, hash_sequence, hash_sequence_mtm=list(), fixtures=False):
    """Generic function to build hash string for record fields.

    :param fields: dictionary containing all mandatory fields and values
    :type fields: dict

    :param hash_sequence: list of fields in correct hash order
    :type hash_sequence: list

    :param hash_sequence_mtm: list of many to many fields in correct hash order, default is None
    :type hash_sequence_mtm: list

    :param ids: uuid of record and integrity id of versioned objects over their life cycle
    :type ids: dict

    :param fixtures: flag to determine internal call or for fixtures, default is False for internal
    :type fixtures: bool

    :return: string to hash
    :rtype: str
    """
    to_hash = 'id:{};lifecycle_id:{};'.format(ids['id'], ids['lifecycle_id'])
    # add static fields
    for field in hash_sequence:
        if field == 'valid_to' or 'valid_from':
            try:
                to_hash += '{}:{};'.format(field, fields[field])
            except KeyError:
                to_hash += '{}:None;'.format(field)
        else:
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
                        tmp_list.append(str(item.id))
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
