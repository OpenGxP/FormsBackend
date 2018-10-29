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


def generate_to_hash(fields, hash_sequence, record_id=None):
    """Generic function to build hash string for record fields.

    :param fields: dictionary containing all mandatory fields and values
    :type fields: dict

    :param hash_sequence: list of fields in correct hash order
    :type hash_sequence: list

    :param record_id: id of the record to hash, default is no id
    :type record_id: int / AutoField

    :return: string to hash
    :rtype: str
    """
    if record_id:
        to_hash = 'id:{};'.format(record_id)
    else:
        to_hash = str()
    for field in hash_sequence:
        to_hash += '{}:{};'.format(field, fields[field])
    to_hash += settings.SECRET_HASH_KEY
    return to_hash
