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
import uuid as python_uuid

# django imports
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

# app imports
from .custom import HASH_ALGORITHM


##########
# GLOBAL #
##########

# char lengths
CHAR_DEFAULT = 100
CHAR_MAX = 255

# default fields
FIELD_VERSION = models.PositiveIntegerField()


class GlobalManager(models.Manager):
    # flags
    HAS_VERSION = True
    HAS_STATUS = True

    def validate_unique(self, instance):
        model_unique = self.model.UNIQUE
        unique = getattr(instance, self.model.UNIQUE)
        _filter = {model_unique: unique}
        try:
            query = self.filter(**_filter).filter(~Q(lifecycle_id=getattr(instance, 'lifecycle_id'))).\
                filter(Q(status=Status.objects.circulation) | Q(status=Status.objects.productive)).all()
            for item in query:
                return (_('{} "{}" does already exist in status "{}" and version "{}".'.format(
                    model_unique.capitalize(), unique, item.status.status, item.version)))
        except self.model.DoesNotExist:
            return None


class GlobalModel(models.Model):
    # id
    id = models.UUIDField(primary_key=True, default=python_uuid.uuid4)
    lifecycle_id = models.UUIDField(default=python_uuid.uuid4)
    checksum = models.CharField(_('checksum'), max_length=CHAR_MAX)
    valid_from = models.DateTimeField(blank=True, null=True)
    valid_to = models.DateTimeField(blank=True, null=True)

    class Meta:
        abstract = True

    HASH_SEQUENCE = []
    UNIQUE = None

    def _verify_checksum(self, to_hash_payload):
        if not self.lifecycle_id:
            to_hash = 'id:{};'.format(self.id)
        else:
            to_hash = 'id:{};lifecycle_id:{};'.format(self.id, self.lifecycle_id)
        to_hash += '{}{}'.format(to_hash_payload, settings.SECRET_HASH_KEY)
        try:
            return HASH_ALGORITHM.verify(to_hash, self.checksum)
        except ValueError:
            return False

    @property
    def verify_validity_range(self):
        now = timezone.now()
        if now > self.valid_from and self.valid_to is None:
            return True
        if self.valid_to > now > self.valid_from:
            return True


##########
# STATUS #
##########

# manager
class StatusManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    def status_by_text(self, value):
        try:
            if self.filter(status=value).exists():
                return self.filter(status=value).get().id
            else:
                return False
        except IndexError:
            return False

    @property
    def draft(self):
        return self.filter(status='draft').get().id

    @property
    def circulation(self):
        return self.filter(status='circulation').get().id

    @property
    def productive(self):
        return self.filter(status='productive').get().id

    @property
    def blocked(self):
        return self.filter(status='blocked').get().id

    @property
    def inactive(self):
        return self.filter(status='inactive').get().id

    @property
    def archived(self):
        return self.filter(status='archived').get().id


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

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['status']

    # permissions
    perms = ['read']
