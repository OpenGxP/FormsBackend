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

# django imports
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError


# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Settings
from basics.custom import generate_checksum, generate_to_hash


# tokens manager
class TokensManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    def check_token_exists(self, token):
        record = self.filter(id=token).get()
        if record.verify_checksum():
            return record
        raise ValidationError

    def check_token_valid(self, token):
        record = self.filter(id=token).get()
        if record.verify_checksum():
            if timezone.now() - record.timestamp \
                    < timezone.timedelta(minutes=Settings.objects.core_password_reset_time):
                return True
        return False

    def create_token(self, username, email):
        hash_sequence = self.model.HASH_SEQUENCE

        def create():
            fields = {'username': username,
                      'email': email,
                      'timestamp': timezone.now()}
            record = self.model(**fields)
            to_hash = generate_to_hash(fields, hash_sequence=hash_sequence, unique_id=record.id)
            record.checksum = generate_checksum(to_hash)

            # save record
            record.full_clean()
            record.save()
            return record

        try:
            existing_record = self.filter(username=username).get()
        except self.model.DoesNotExist:
            token = create()
        else:
            existing_record.delete()
            token = create()
        return token


# table
class Tokens(GlobalModel):
    # custom fields
    username = models.CharField(max_length=CHAR_DEFAULT, unique=True)
    email = models.CharField(max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField()

    # manager
    objects = TokensManager()

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['username', 'email', 'timestamp']

    # permissions
    perms = None

    # unique field
    UNIQUE = 'username'

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};email:{};timestamp:{};'.format(self.username, self.email, self.timestamp)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    # expiry timestamp
    @property
    def expiry_timestamp(self):
        non_formatted = self.timestamp + timezone.timedelta(minutes=Settings.objects.core_password_reset_time)
        return non_formatted.strftime('%d-%b-%Y %H:%M:%S %Z')
