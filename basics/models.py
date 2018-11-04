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
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# app imports
from .custom import generate_checksum, generate_to_hash, HASH_ALGORITHM, intersection_two


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255

# default fields
FIELD_VERSION = models.PositiveIntegerField()


class GlobalManager(models.Manager):
    # hashing
    HASH_SEQUENCE = list()
    HASH_SEQUENCE_MTM = list()
    # many to many
    MTM_TABLES = dict()
    SELF_FIELDS = list()

    # flags
    HAS_VERSION = True
    HAS_STATUS = True

    # many to many function
    def _add_many_to_many(self, record, fields):
        for field_name, values in fields.items():
            field = getattr(record, field_name)
            if field_name in self.SELF_FIELDS:
                for value in values:
                    rel = self.get(pk=value.id)
                    field.add(rel)
            else:
                for value in values:
                    rel = self.MTM_TABLES[field_name].objects.get(pk=value.id)
                    field.add(rel)
        return record

    def _generate_to_hash(self, fields, hash_sequence_mtm=None, record_id=None):
        """Generic function to build hash string for record fields.

        :param fields: dictionary containing all mandatory fields and values
        :type fields: dict

        :param hash_sequence_mtm: list of many to many fields in correct hash order, default is None
        :type hash_sequence_mtm: list

        :param record_id: id of the record to hash, default is no id
        :type record_id: int / AutoField

        :return: string to hash
        :rtype: str
        """
        return generate_to_hash(fields=fields, hash_sequence=self.HASH_SEQUENCE, hash_sequence_mtm=hash_sequence_mtm,
                                record_id=record_id)

    def new(self, **fields):
        """Generic function to create new records, including hashing. "id" is always fist, "checksum" always last.

            :param fields: dictionary containing all mandatory fields and values excluding "id", "version", "status"
            and "checksum", many to many fields must be passed via a list containing integers on the pk/id of the
            related record
            :type fields: dict

            :return: success flag
            :rtype: bool
        """
        # new records that have versions always start with version = 1
        if self.HAS_VERSION:
            fields['version'] = 1
        # new records that have status always start with status = 1 (Draft)
        if self.HAS_STATUS:
            fields['status_id'] = 1
        # save to db to get ID, checksum field is set to "tbd"
        # "tbd" is no valid hash string and therefore always return False on check
        fields['checksum'] = 'tbd'
        # reduce fields by many to many fields, they are added later
        tmp_fields = dict(fields)
        if self.HASH_SEQUENCE_MTM:
            # in case of models that have many to many fields get the fields that are shipped
            intersection = intersection_two(fields.keys(), self.HASH_SEQUENCE_MTM)
            if intersection:
                for field in intersection:
                    tmp_fields.pop(field)
        record = self.create(**tmp_fields)
        # build string with row id to generate complete hash string
        if self.HASH_SEQUENCE_MTM:
            to_hash = self._generate_to_hash(fields, hash_sequence_mtm=self.HASH_SEQUENCE_MTM, record_id=record.id)
            # add many to many fields
            mtm_fields = {k: fields[k] for k in (fields.keys() & intersection)}
            record = self._add_many_to_many(record=record, fields=mtm_fields)
        else:
            to_hash = self._generate_to_hash(fields, record_id=record.id)
        # save valid checksum to record, including id
        record.checksum = generate_checksum(to_hash)
        record.save()
        return record


class GlobalModel(models.Model):
    # id
    id = models.AutoField(primary_key=True)
    checksum = models.CharField(_('checksum'), max_length=CHAR_MAX)

    class Meta:
        abstract = True

    def _verify_checksum(self, to_hash_payload):
        to_hash = 'id:{};'.format(self.id)
        to_hash += to_hash_payload
        to_hash += settings.SECRET_HASH_KEY
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False


##########
# STATUS #
##########

# manager
class StatusManager(GlobalManager):
    # hashing
    HASH_SEQUENCE = ['status']

    # flags
    HAS_VERSION = False
    HAS_STATUS = False


# table
class Status(GlobalModel):
    # custom fields
    status = models.CharField(_('status'), max_length=CHAR_DEFAULT, unique=True)

    # manager
    objects = StatusManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'status:{};'.format(self.status)
        return self._verify_checksum(to_hash_payload=to_hash_payload)
