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
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.core.exceptions import ValidationError

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, LOG_HASH_SEQUENCE
from basics.custom import generate_checksum, generate_to_hash
from urp.custom import create_log_record


# log manager
class ProfileLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False

    # meta
    GET_MODEL_ORDER = ('username',
                       'key',
                       'default',
                       'value',)


# log table
class ProfileLog(GlobalModel):
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)
    # log specific fields
    user = models.CharField(_('User'), max_length=CHAR_DEFAULT)
    timestamp = models.DateTimeField(_('Timestamp'))
    action = models.CharField(_('Action'), max_length=CHAR_DEFAULT)

    # manager
    objects = ProfileLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};key:{};default:{};value:{};' \
                          'user:{};timestamp:{};action:{};' \
            .format(self.username, self.key, self.default, self.value,
                    self.user, self.timestamp, self.action)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['username', 'key', 'default', 'value'] + LOG_HASH_SEQUENCE

    # permissions
    MODEL_ID = '29'
    MODEL_CONTEXT = 'ProfileLog'
    perms = None


# profile manager
class ProfileManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    LOG_TABLE = ProfileLog

    # meta
    GET_MODEL_ORDER = ('username',
                       'key',
                       'default',
                       'value')
    POST_MODEL_EXCLUDE = ('default',)

    # generate profile
    def generate_profile(self, username, log_user=None):
        now = timezone.now()
        for item in settings.PROFILE_DATA:
            data = item.copy()
            data['username'] = username
            profile = self.model(**data)
            # generate hash
            to_hash = generate_to_hash(data, hash_sequence=self.model.HASH_SEQUENCE, unique_id=profile.id)
            profile.checksum = generate_checksum(to_hash)

            try:
                profile.full_clean()
            except ValidationError as e:
                raise e.message
            else:
                profile.save()

            # log record
            context = dict()
            if not log_user:
                context['function'] = 'init'
            else:
                context['function'] = ''
                context['user'] = log_user
            create_log_record(model=self.model, context=context, obj=profile, validated_data=data,
                              action=settings.DEFAULT_LOG_CREATE, now=now)

    # delete profile
    def delete_profile(self, username, log_user):
        now = timezone.now()
        query = self.filter(username=username).all()
        for item in query:
            item.delete()
            # log record
            context = dict()
            context['function'] = ''
            context['user'] = log_user
            create_log_record(model=self.model, context=context, obj=item, validated_data={},
                              action=settings.DEFAULT_LOG_DELETE, now=now)

    # profile calls
    def initial_timezone(self, username):
        try:
            tz = self.filter(username=username, key='loc.timezone').get().value
        except self.model.DoesNotExist:
            tz = settings.PROFILE_DEFAULT_TIMEZONE
        if tz == 'UTC':
            return True
        return False

    def timezone(self, username):
        try:
            return self.filter(username=username, key='loc.timezone').get().value
        except self.model.DoesNotExist:
            return settings.PROFILE_DEFAULT_TIMEZONE

    def language(self, username):
        try:
            return self.filter(username=username, key='loc.language').get().value
        except self.model.DoesNotExist:
            return settings.PROFILE_DEFAULT_LANGUAGE


class Profile(GlobalModel):
    # custom fields
    username = models.CharField(_('Username'), max_length=CHAR_DEFAULT)
    key = models.CharField(_('Key'), max_length=CHAR_DEFAULT)
    human_readable = models.CharField(_('Human readable'), max_length=CHAR_DEFAULT)
    default = models.CharField(_('Default'), max_length=CHAR_DEFAULT)
    value = models.CharField(_('Value'), max_length=CHAR_DEFAULT)

    # manager
    objects = ProfileManager()

    valid_from = None
    valid_to = None
    lifecycle_id = None

    # hashing
    HASH_SEQUENCE = ['username', 'key', 'default', 'value']

    # permissions
    MODEL_ID = '28'
    MODEL_CONTEXT = 'Profile'
    perms = None

    # unique field
    UNIQUE = 'username'

    def unique_id(self):
        return self.username + '_' + self.key

    class Meta:
        unique_together = ('username', 'key')

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'username:{};key:{};default:{};value:{};' \
            .format(self.username, self.key, self.default, self.value)
        return self._verify_checksum(to_hash_payload=to_hash_payload)
